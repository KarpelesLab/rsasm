//! Expression syntax tree, parser and evaluator.
//!
//! Expressions are stored in an arena so a [`ExprRef`] can be embedded in
//! fixups and symbol definitions without boxing or lifetimes. Evaluation
//! yields a [`Value`], which is *relocatable*: it may carry a symbol reference
//! that only becomes a number once addresses are assigned (or never, if it has
//! to be handed to the linker as a relocation).

use crate::cursor::Cursor;
use crate::diag::{DiagBag, Diagnostic};
use crate::intern::{Interner, Name};
use crate::lexer::{LocalDir, Punct, TokKind};
use crate::source::Span;
use crate::symbol::{SymbolId, SymbolTable, SymbolValue};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ExprRef(u32);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum UnOp {
    Neg,
    Not,
    LogicalNot,
    Plus,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shl,
    Shr,
    And,
    Or,
    Xor,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    LogicalAnd,
    LogicalOr,
}

impl BinOp {
    fn precedence(self) -> u8 {
        use BinOp::*;
        match self {
            LogicalOr => 1,
            LogicalAnd => 2,
            Or | Xor => 3,
            And => 4,
            Eq | Ne | Lt | Gt | Le | Ge => 5,
            Shl | Shr => 6,
            Add | Sub => 7,
            Mul | Div | Rem => 8,
        }
    }

    fn symbol(self) -> &'static str {
        use BinOp::*;
        match self {
            Add => "+", Sub => "-", Mul => "*", Div => "/", Rem => "%",
            Shl => "<<", Shr => ">>", And => "&", Or => "|", Xor => "^",
            Eq => "==", Ne => "!=", Lt => "<", Gt => ">", Le => "<=", Ge => ">=",
            LogicalAnd => "&&", LogicalOr => "||",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExprKind {
    Int(u64),
    /// A named symbol, resolved at evaluation time.
    Sym(Name),
    /// An already-resolved symbol. Positional references (`.`, `1f`) are
    /// rewritten into this once the statement they appear in is parsed.
    SymId(SymbolId),
    /// `1f` / `2b`: nearest numeric local label in the given direction.
    LocalRef(u32, LocalDir),
    /// The current location counter (`.` in GAS, `$` in NASM).
    Here,
    /// The start of the current section (`$$` in NASM).
    SectionStart,
    Unary(UnOp, ExprRef),
    Binary(BinOp, ExprRef, ExprRef),
    /// A relocation modifier such as `foo@PLT`, `foo@GOTPCREL` or `:lo12:foo`.
    /// The architecture interprets the name.
    Modifier(Name, ExprRef),
}

#[derive(Clone, Debug)]
pub struct ExprNode {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Default)]
pub struct ExprArena {
    pub(crate) nodes: Vec<ExprNode>,
}

impl ExprArena {
    pub fn new() -> ExprArena {
        ExprArena::default()
    }

    pub fn alloc(&mut self, kind: ExprKind, span: Span) -> ExprRef {
        let r = ExprRef(self.nodes.len() as u32);
        self.nodes.push(ExprNode { kind, span });
        r
    }

    pub fn get(&self, r: ExprRef) -> &ExprNode {
        &self.nodes[r.0 as usize]
    }

    pub fn span(&self, r: ExprRef) -> Span {
        self.nodes[r.0 as usize].span
    }

    /// Convenience for building a constant.
    pub fn int(&mut self, v: u64, span: Span) -> ExprRef {
        self.alloc(ExprKind::Int(v), span)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// The result of evaluating an expression.
///
/// `plus - minus + addend`. When both symbol slots are empty the value is a
/// plain constant; when only `plus` is set it is a relocatable address; when
/// both are set it is a difference, which collapses to a constant if the two
/// symbols end up in the same section.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Value {
    pub addend: i64,
    pub plus: Option<SymbolId>,
    pub minus: Option<SymbolId>,
}

impl Value {
    pub fn abs(v: i64) -> Value {
        Value { addend: v, plus: None, minus: None }
    }

    pub fn sym(s: SymbolId, addend: i64) -> Value {
        Value { addend, plus: Some(s), minus: None }
    }

    pub fn is_absolute(&self) -> bool {
        self.plus.is_none() && self.minus.is_none()
    }

    /// The constant value, if this needs no relocation.
    pub fn as_abs(&self) -> Option<i64> {
        self.is_absolute().then_some(self.addend)
    }
}

/// What an expression evaluator needs from the assembler.
pub trait EvalCtx {
    /// Resolves a name to a value, interning the symbol if it is new.
    fn lookup_symbol(&mut self, name: Name, span: Span) -> Result<Value, EvalError>;
    /// Resolves an already-identified symbol.
    fn symbol_value(&mut self, id: SymbolId, span: Span) -> Result<Value, EvalError>;
    /// The current location counter.
    fn here(&mut self, span: Span) -> Result<Value, EvalError>;
    /// The start of the current section.
    fn section_start(&mut self, span: Span) -> Result<Value, EvalError>;
    /// Resolves `1f` / `2b`.
    fn local_ref(&mut self, n: u32, dir: LocalDir, span: Span) -> Result<Value, EvalError>;
    /// Handles `expr@MODIFIER`. Most contexts reject these; fixup lowering
    /// peels them off before evaluating.
    fn modifier(&mut self, name: Name, inner: Value, span: Span) -> Result<Value, EvalError>;
}

#[derive(Clone, Debug)]
pub struct EvalError {
    pub span: Span,
    pub msg: String,
}

impl EvalError {
    pub fn new(span: Span, msg: impl Into<String>) -> EvalError {
        EvalError { span, msg: msg.into() }
    }

    pub fn into_diagnostic(self) -> Diagnostic {
        Diagnostic::error(self.span, self.msg)
    }
}

pub fn eval(arena: &ExprArena, r: ExprRef, cx: &mut dyn EvalCtx) -> Result<Value, EvalError> {
    let node = arena.get(r);
    let span = node.span;
    match &node.kind {
        ExprKind::Int(v) => Ok(Value::abs(*v as i64)),
        ExprKind::Sym(n) => cx.lookup_symbol(*n, span),
        ExprKind::SymId(id) => cx.symbol_value(*id, span),
        ExprKind::LocalRef(n, dir) => cx.local_ref(*n, *dir, span),
        ExprKind::Here => cx.here(span),
        ExprKind::SectionStart => cx.section_start(span),
        ExprKind::Modifier(name, inner) => {
            let v = eval(arena, *inner, cx)?;
            cx.modifier(*name, v, span)
        }
        ExprKind::Unary(op, inner) => {
            let v = eval(arena, *inner, cx)?;
            let Some(a) = v.as_abs() else {
                if *op == UnOp::Plus {
                    return Ok(v);
                }
                return Err(EvalError::new(span, "operand of unary operator must be an absolute value"));
            };
            Ok(Value::abs(match op {
                UnOp::Neg => a.wrapping_neg(),
                UnOp::Not => !a,
                UnOp::LogicalNot => (a == 0) as i64,
                UnOp::Plus => a,
            }))
        }
        ExprKind::Binary(op, l, r2) => {
            let lv = eval(arena, *l, cx)?;
            let rv = eval(arena, *r2, cx)?;
            eval_binary(*op, lv, rv, span)
        }
    }
}

fn eval_binary(op: BinOp, l: Value, r: Value, span: Span) -> Result<Value, EvalError> {
    use BinOp::*;

    // Addition and subtraction are the only operators that may keep a symbol.
    match op {
        Add => {
            return match (l.plus, l.minus, r.plus, r.minus) {
                // Cancel `a - b` against `+ b`.
                (lp, Some(lm), Some(rp), None) if lm == rp => {
                    Ok(Value { addend: l.addend.wrapping_add(r.addend), plus: lp, minus: None })
                }
                (Some(lp), None, _, Some(rm)) if lp == rm => {
                    Ok(Value { addend: l.addend.wrapping_add(r.addend), plus: r.plus, minus: None })
                }
                (lp, lm, rp, rm) => {
                    let (plus, minus) = match (lp, rp) {
                        (Some(_), Some(_)) => {
                            return Err(EvalError::new(span, "cannot add two relocatable symbols"));
                        }
                        (a, b) => (a.or(b), match (lm, rm) {
                            (Some(_), Some(_)) => {
                                return Err(EvalError::new(span, "cannot subtract two relocatable symbols here"));
                            }
                            (a, b) => a.or(b),
                        }),
                    };
                    Ok(Value { addend: l.addend.wrapping_add(r.addend), plus, minus })
                }
            };
        }
        Sub => {
            return match (l.plus, l.minus, r.plus, r.minus) {
                // sym - sym: a difference, resolvable if both land in the
                // same section.
                (Some(lp), None, Some(rp), None) => {
                    if lp == rp {
                        Ok(Value::abs(l.addend.wrapping_sub(r.addend)))
                    } else {
                        Ok(Value {
                            addend: l.addend.wrapping_sub(r.addend),
                            plus: Some(lp),
                            minus: Some(rp),
                        })
                    }
                }
                (lp, lm, None, None) => {
                    Ok(Value { addend: l.addend.wrapping_sub(r.addend), plus: lp, minus: lm })
                }
                _ => Err(EvalError::new(span, "unsupported combination of relocatable values in `-`")),
            };
        }
        _ => {}
    }

    let (Some(a), Some(b)) = (l.as_abs(), r.as_abs()) else {
        return Err(EvalError::new(
            span,
            format!("operands of `{}` must be absolute values", op.symbol()),
        ));
    };

    let v = match op {
        Add | Sub => unreachable!("handled above"),
        Mul => a.wrapping_mul(b),
        Div => {
            if b == 0 {
                return Err(EvalError::new(span, "division by zero"));
            }
            a.wrapping_div(b)
        }
        Rem => {
            if b == 0 {
                return Err(EvalError::new(span, "remainder by zero"));
            }
            a.wrapping_rem(b)
        }
        // Shift counts of 64 or more produce 0, matching GAS rather than
        // panicking or wrapping the count around.
        Shl => {
            if (b as u64) >= 64 { 0 } else { ((a as u64) << b) as i64 }
        }
        Shr => {
            if (b as u64) >= 64 { 0 } else { ((a as u64) >> b) as i64 }
        }
        And => a & b,
        Or => a | b,
        Xor => a ^ b,
        Eq => (a == b) as i64,
        Ne => (a != b) as i64,
        Lt => (a < b) as i64,
        Gt => (a > b) as i64,
        Le => (a <= b) as i64,
        Ge => (a >= b) as i64,
        LogicalAnd => (a != 0 && b != 0) as i64,
        LogicalOr => (a != 0 || b != 0) as i64,
    };
    Ok(Value::abs(v))
}

/// Evaluates against a finished symbol table, without recording uses.
///
/// This is the read-only counterpart of the assembler's own evaluator: it
/// resolves `.set` chains, which is what lets an immediate written as a named
/// constant still pick the shortest encoding.
pub struct SymbolEnv<'a> {
    pub exprs: &'a ExprArena,
    pub symbols: &'a SymbolTable,
    depth: u32,
}

impl<'a> SymbolEnv<'a> {
    pub fn new(exprs: &'a ExprArena, symbols: &'a SymbolTable) -> SymbolEnv<'a> {
        SymbolEnv { exprs, symbols, depth: 0 }
    }

    /// Evaluates `e`, or returns `None` if anything in it is still unknown.
    pub fn value(&mut self, e: ExprRef) -> Option<Value> {
        let exprs = self.exprs;
        eval(exprs, e, self).ok()
    }

    /// Evaluates `e` to a plain number, or `None` if it is not one yet.
    pub fn constant(&mut self, e: ExprRef) -> Option<i64> {
        self.value(e)?.as_abs()
    }
}

impl EvalCtx for SymbolEnv<'_> {
    fn lookup_symbol(&mut self, name: Name, span: Span) -> Result<Value, EvalError> {
        match self.symbols.lookup(name) {
            Some(id) => self.symbol_value(id, span),
            None => Err(EvalError::new(span, "undefined symbol")),
        }
    }

    fn symbol_value(&mut self, id: SymbolId, span: Span) -> Result<Value, EvalError> {
        match self.symbols.get(id).value {
            SymbolValue::Expr(e) => {
                if self.depth > 64 {
                    return Err(EvalError::new(span, "symbol definition is circular"));
                }
                self.depth += 1;
                let exprs = self.exprs;
                let v = eval(exprs, e, self);
                self.depth -= 1;
                v
            }
            _ => Ok(Value::sym(id, 0)),
        }
    }

    fn here(&mut self, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(span, "`.` cannot be used here"))
    }

    fn section_start(&mut self, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(span, "`$$` is not supported yet"))
    }

    fn local_ref(&mut self, n: u32, _: LocalDir, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(span, format!("local label `{n}` is not resolved yet")))
    }

    fn modifier(&mut self, _name: Name, inner: Value, _span: Span) -> Result<Value, EvalError> {
        Ok(inner)
    }
}

/// Evaluates an expression that must not mention any symbol.
///
/// Used where a width has to be chosen before addresses are known: an
/// immediate or displacement that folds to a constant can pick the shortest
/// encoding, while anything symbolic falls back to the widest one.
pub fn const_fold(arena: &ExprArena, r: ExprRef) -> Option<i64> {
    struct NoSymbols;
    impl EvalCtx for NoSymbols {
        fn lookup_symbol(&mut self, _: Name, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
        fn symbol_value(&mut self, _: SymbolId, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
        fn here(&mut self, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
        fn section_start(&mut self, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
        fn local_ref(&mut self, _: u32, _: LocalDir, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
        fn modifier(&mut self, _: Name, _: Value, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "not a constant"))
        }
    }
    eval(arena, r, &mut NoSymbols).ok().and_then(|v| v.as_abs())
}

/// Rewrites every `Here` and `LocalRef` node added since `from` into a plain
/// symbol reference.
///
/// Both depend on *where in the file* they appear, so they are bound as soon
/// as the statement containing them is parsed rather than at evaluation time,
/// when that position is long gone.
pub fn bind_positional(
    arena: &mut ExprArena,
    from: usize,
    mut resolve: impl FnMut(&ExprKind, Span) -> Option<ExprKind>,
) {
    for i in from..arena.nodes.len() {
        let span = arena.nodes[i].span;
        if !matches!(
            arena.nodes[i].kind,
            ExprKind::Here | ExprKind::LocalRef(..) | ExprKind::SectionStart
        ) {
            continue;
        }
        if let Some(new) = resolve(&arena.nodes[i].kind, span) {
            arena.nodes[i].kind = new;
        }
    }
}

/// Parses expressions out of a statement's token stream.
pub struct ExprParser<'a> {
    pub arena: &'a mut ExprArena,
    pub interner: &'a mut Interner,
    pub diags: &'a mut DiagBag,
    /// In NASM, `$` is the location counter; in GAS it introduces an immediate
    /// and must not be consumed here.
    pub dollar_is_here: bool,
}

impl<'a> ExprParser<'a> {
    pub fn parse(&mut self, cur: &mut Cursor<'_>) -> Option<ExprRef> {
        self.parse_bp(cur, 0)
    }

    fn parse_bp(&mut self, cur: &mut Cursor<'_>, min_prec: u8) -> Option<ExprRef> {
        let mut lhs = self.parse_prefix(cur)?;
        while let Some(op) = peek_binop(cur) {
            let prec = op.precedence();
            if prec < min_prec {
                break;
            }
            cur.advance();
            // All operators here are left-associative.
            let rhs = self.parse_bp(cur, prec + 1)?;
            let span = self.arena.span(lhs).to(self.arena.span(rhs));
            lhs = self.arena.alloc(ExprKind::Binary(op, lhs, rhs), span);
        }
        Some(self.parse_postfix(cur, lhs))
    }

    /// Handles `expr@MODIFIER`, the ELF relocation-modifier syntax.
    fn parse_postfix(&mut self, cur: &mut Cursor<'_>, mut e: ExprRef) -> ExprRef {
        while cur.check_punct(Punct::At) {
            let at = cur.advance();
            let tok = cur.peek();
            let name = match tok.kind {
                TokKind::Ident(n) => {
                    cur.advance();
                    self.interner.intern_lower(&self.interner_get(n))
                }
                _ => {
                    self.diags.error(at.span.to(tok.span), "expected a relocation name after `@`");
                    break;
                }
            };
            let span = self.arena.span(e).to(tok.span);
            e = self.arena.alloc(ExprKind::Modifier(name, e), span);
        }
        e
    }

    fn interner_get(&self, n: Name) -> String {
        self.interner.get(n).to_string()
    }

    fn parse_prefix(&mut self, cur: &mut Cursor<'_>) -> Option<ExprRef> {
        let tok = cur.peek();
        let unop = match tok.kind {
            TokKind::Punct(Punct::Minus) => Some(UnOp::Neg),
            TokKind::Punct(Punct::Tilde) => Some(UnOp::Not),
            TokKind::Punct(Punct::Bang) => Some(UnOp::LogicalNot),
            TokKind::Punct(Punct::Plus) => Some(UnOp::Plus),
            _ => None,
        };
        if let Some(op) = unop {
            cur.advance();
            // Unary binds tighter than every binary operator.
            let inner = self.parse_prefix(cur)?;
            let inner = self.parse_postfix(cur, inner);
            let span = tok.span.to(self.arena.span(inner));
            return Some(self.arena.alloc(ExprKind::Unary(op, inner), span));
        }

        match tok.kind {
            TokKind::Int(v) => {
                cur.advance();
                Some(self.arena.alloc(ExprKind::Int(v), tok.span))
            }
            TokKind::Ident(n) => {
                cur.advance();
                Some(self.arena.alloc(ExprKind::Sym(n), tok.span))
            }
            TokKind::LocalRef(n, dir) => {
                cur.advance();
                Some(self.arena.alloc(ExprKind::LocalRef(n, dir), tok.span))
            }
            TokKind::Punct(Punct::Dot) => {
                cur.advance();
                Some(self.arena.alloc(ExprKind::Here, tok.span))
            }
            TokKind::Punct(Punct::Dollar) if self.dollar_is_here => {
                cur.advance();
                if cur.check_punct(Punct::Dollar) {
                    let t2 = cur.advance();
                    return Some(self.arena.alloc(ExprKind::SectionStart, tok.span.to(t2.span)));
                }
                Some(self.arena.alloc(ExprKind::Here, tok.span))
            }
            TokKind::Punct(Punct::LParen) => {
                cur.advance();
                let inner = self.parse_bp(cur, 0)?;
                if cur.eat_punct(Punct::RParen).is_none() {
                    self.diags.emit(
                        Diagnostic::error(cur.peek().span, "expected `)`")
                            .with_note(tok.span, "to match this `(`"),
                    );
                    return None;
                }
                Some(inner)
            }
            _ => {
                let what = describe(cur, tok.kind);
                self.diags.error(tok.span, format!("expected an expression, found {what}"));
                None
            }
        }
    }
}

fn describe(_cur: &Cursor<'_>, k: TokKind) -> String {
    match k {
        TokKind::Eof | TokKind::Eol => "end of statement".into(),
        TokKind::Punct(p) => format!("`{}`", p.as_str()),
        TokKind::Str(_) => "a string literal".into(),
        _ => "this token".into(),
    }
}

fn peek_binop(cur: &Cursor<'_>) -> Option<BinOp> {
    use BinOp::*;
    let TokKind::Punct(p) = cur.peek().kind else { return None };
    Some(match p {
        Punct::Plus => Add,
        Punct::Minus => Sub,
        Punct::Star => Mul,
        Punct::Slash => Div,
        Punct::Percent => Rem,
        Punct::Shl => Shl,
        Punct::Shr => Shr,
        Punct::Amp => And,
        Punct::Pipe => Or,
        Punct::Caret => Xor,
        Punct::EqEq => Eq,
        Punct::Ne => Ne,
        Punct::Lt => Lt,
        Punct::Gt => Gt,
        Punct::Le => Le,
        Punct::Ge => Ge,
        Punct::AndAnd => LogicalAnd,
        Punct::OrOr => LogicalOr,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::{Dialect, LexConfig, Lexer, LitPool};
    use crate::source::SourceMap;
    use crate::symbol::SymbolId;
    use std::collections::HashMap;

    struct TestCtx {
        syms: HashMap<String, Value>,
        names: HashMap<Name, String>,
        here: i64,
    }

    impl EvalCtx for TestCtx {
        fn lookup_symbol(&mut self, name: Name, span: Span) -> Result<Value, EvalError> {
            let s = self.names.get(&name).cloned().unwrap_or_default();
            self.syms.get(&s).copied().ok_or_else(|| EvalError::new(span, format!("undefined: {s}")))
        }
        fn symbol_value(&mut self, _: SymbolId, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, "no such symbol"))
        }
        fn here(&mut self, _: Span) -> Result<Value, EvalError> {
            Ok(Value::abs(self.here))
        }
        fn section_start(&mut self, _: Span) -> Result<Value, EvalError> {
            Ok(Value::abs(0))
        }
        fn local_ref(&mut self, n: u32, _: LocalDir, span: Span) -> Result<Value, EvalError> {
            Err(EvalError::new(span, format!("no local label {n}")))
        }
        fn modifier(&mut self, _: Name, inner: Value, _: Span) -> Result<Value, EvalError> {
            Ok(inner)
        }
    }

    fn eval_str(src: &str, syms: &[(&str, Value)]) -> Result<Value, String> {
        let mut sm = SourceMap::new();
        let f = sm.add("t.s", src);
        let mut interner = Interner::new();
        let mut diags = DiagBag::new();
        let mut toks = Vec::new();
        {
            let mut pool = LitPool::new();
            let mut lx = Lexer::new(&sm, f, LexConfig::for_dialect(Dialect::Gas));
            loop {
                let t = lx.next_token(&mut interner, &mut pool, &mut diags);
                if matches!(t.kind, TokKind::Eof | TokKind::Eol) {
                    break;
                }
                toks.push(t);
            }
        }
        let mut arena = ExprArena::new();
        let mut cur = Cursor::new(&toks);
        let r = {
            let mut p = ExprParser {
                arena: &mut arena,
                interner: &mut interner,
                diags: &mut diags,
                dollar_is_here: false,
            };
            p.parse(&mut cur)
        };
        if diags.has_errors() {
            return Err(diags.render(&sm, false));
        }
        let r = r.ok_or_else(|| "no expression".to_string())?;
        let mut names = HashMap::new();
        let mut map = HashMap::new();
        for (n, v) in syms {
            if let Some(id) = interner.lookup(n) {
                names.insert(id, n.to_string());
            }
            map.insert(n.to_string(), *v);
        }
        let mut cx = TestCtx { syms: map, names, here: 0x1000 };
        eval(&arena, r, &mut cx).map_err(|e| e.msg)
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(eval_str("1 + 2 * 3", &[]).unwrap(), Value::abs(7));
        assert_eq!(eval_str("(1 + 2) * 3", &[]).unwrap(), Value::abs(9));
        assert_eq!(eval_str("1 << 4 | 3", &[]).unwrap(), Value::abs(19));
        assert_eq!(eval_str("-5 + 3", &[]).unwrap(), Value::abs(-2));
        assert_eq!(eval_str("~0 & 0xff", &[]).unwrap(), Value::abs(0xff));
        assert_eq!(eval_str("10 - 4 - 3", &[]).unwrap(), Value::abs(3));
        assert_eq!(eval_str("2 * 3 + 4 * 5", &[]).unwrap(), Value::abs(26));
        assert_eq!(eval_str("1 < 2 && 3 > 2", &[]).unwrap(), Value::abs(1));
    }

    #[test]
    fn location_counter() {
        assert_eq!(eval_str(". + 4", &[]).unwrap(), Value::abs(0x1004));
    }

    #[test]
    fn symbol_plus_constant_stays_relocatable() {
        let a = SymbolId(7);
        let v = eval_str("foo + 8", &[("foo", Value::sym(a, 0))]).unwrap();
        assert_eq!(v, Value { addend: 8, plus: Some(a), minus: None });
    }

    #[test]
    fn difference_of_symbols() {
        let a = SymbolId(1);
        let b = SymbolId(2);
        let v = eval_str("foo - bar", &[("foo", Value::sym(a, 4)), ("bar", Value::sym(b, 1))]).unwrap();
        assert_eq!(v, Value { addend: 3, plus: Some(a), minus: Some(b) });
        // Same symbol on both sides collapses to a constant.
        let v = eval_str("foo - bar", &[("foo", Value::sym(a, 9)), ("bar", Value::sym(a, 2))]).unwrap();
        assert_eq!(v, Value::abs(7));
    }

    #[test]
    fn rejects_nonsense_relocatable_arithmetic() {
        let a = SymbolId(1);
        let b = SymbolId(2);
        let e = eval_str("foo + bar", &[("foo", Value::sym(a, 0)), ("bar", Value::sym(b, 0))]).unwrap_err();
        assert!(e.contains("cannot add two relocatable"), "{e}");
        let e = eval_str("foo * 2", &[("foo", Value::sym(a, 0))]).unwrap_err();
        assert!(e.contains("absolute"), "{e}");
    }

    #[test]
    fn division_by_zero_is_an_error() {
        assert!(eval_str("1 / 0", &[]).unwrap_err().contains("division by zero"));
    }

    #[test]
    fn oversized_shift_yields_zero() {
        assert_eq!(eval_str("1 << 64", &[]).unwrap(), Value::abs(0));
    }

    #[test]
    fn reports_missing_paren() {
        let e = eval_str("(1 + 2", &[]).unwrap_err();
        assert!(e.contains("expected `)`"), "{e}");
    }
}
