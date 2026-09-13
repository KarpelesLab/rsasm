//! x86 operand parsing, for both AT&T and Intel syntax.
//!
//! Both parsers produce the same [`Operand`], so the instruction matcher and
//! encoder never need to know which syntax the source used. The two grammars
//! differ more than the sigils suggest:
//!
//! ```text
//! AT&T    seg:disp(base, index, scale)   $imm   %reg   *%reg   label(%rip)
//! Intel   seg:[base + index*scale + disp]  imm    reg    [reg]   [rip + label]
//! ```

use super::reg::{self, Reg, RegClass};
use crate::arch::{AsmCtx, Syntax};
use crate::cursor::Cursor;
use crate::expr::{ExprKind, ExprRef};
use crate::lexer::{Punct, TokKind, Token};
use crate::source::Span;

#[derive(Clone, Debug)]
pub struct Mem {
    pub seg: Option<Reg>,
    pub base: Option<Reg>,
    pub index: Option<Reg>,
    pub scale: u8,
    pub disp: Option<ExprRef>,
    /// `disp(%rip)` / `[rip + disp]`.
    pub rip_relative: bool,
    /// Address-size of the base/index registers, in bytes.
    pub addr_size: u8,
    pub span: Span,
}

impl Mem {
    fn empty(span: Span) -> Mem {
        Mem {
            seg: None,
            base: None,
            index: None,
            scale: 1,
            disp: None,
            rip_relative: false,
            addr_size: 8,
            span,
        }
    }
}

#[derive(Clone, Debug)]
pub enum OperandKind {
    Reg(Reg),
    Imm(ExprRef),
    Mem(Mem),
    /// A branch target given as a plain label or expression.
    Rel(ExprRef),
    /// `jmp *%rax` / `jmp rax`: an indirect branch through a register or
    /// memory operand.
    Indirect(Box<OperandKind>),
}

#[derive(Clone, Debug)]
pub struct Operand {
    pub kind: OperandKind,
    /// Explicit operand size in bytes from `dword ptr` or an AT&T suffix.
    pub size_hint: Option<u8>,
    pub span: Span,
}

impl Operand {
    pub fn reg(&self) -> Option<Reg> {
        match &self.kind {
            OperandKind::Reg(r) => Some(*r),
            _ => None,
        }
    }

    pub fn is_mem(&self) -> bool {
        matches!(self.kind, OperandKind::Mem(_))
    }

    pub fn describe(&self) -> String {
        match &self.kind {
            OperandKind::Reg(r) => format!("register `{}`", reg::name_of(*r)),
            OperandKind::Imm(_) => "an immediate".into(),
            OperandKind::Mem(_) => "a memory operand".into(),
            OperandKind::Rel(_) => "a branch target".into(),
            OperandKind::Indirect(_) => "an indirect branch target".into(),
        }
    }
}

/// Maps `byte`/`word`/`dword`/`qword`/`xmmword` to a width in bytes.
pub fn size_keyword(name: &str) -> Option<u8> {
    Some(match name {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "qword" => 8,
        "tbyte" | "tword" => 10,
        "xmmword" | "oword" => 16,
        "ymmword" => 32,
        "zmmword" => 64,
        _ => return None,
    })
}

pub struct OperandParser<'c, 'a> {
    pub cx: &'c mut AsmCtx<'a>,
    pub syntax: Syntax,
    /// Address size in bytes implied by the current mode.
    pub addr_size: u8,
}

impl OperandParser<'_, '_> {
    pub fn parse(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        match self.syntax {
            Syntax::Att => self.parse_att(cur),
            Syntax::Intel => self.parse_intel(cur),
        }
    }

    fn expr(&mut self, cur: &mut Cursor<'_>) -> Option<ExprRef> {
        let mut p = self.cx.expr_parser();
        p.parse(cur)
    }

    // ---- AT&T -------------------------------------------------------------

    fn parse_att(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        let start = cur.peek().span;

        // `*` marks an indirect branch target.
        if cur.eat_punct(Punct::Star).is_some() {
            let inner = self.parse_att(cur)?;
            return Some(Operand {
                kind: OperandKind::Indirect(Box::new(inner.kind)),
                size_hint: inner.size_hint,
                span: start.to(inner.span),
            });
        }

        // `$imm`
        if cur.eat_punct(Punct::Dollar).is_some() {
            let e = self.expr(cur)?;
            return Some(Operand {
                kind: OperandKind::Imm(e),
                size_hint: None,
                span: start.to(self.cx.exprs.span(e)),
            });
        }

        // `%reg`, or `%seg:` introducing a memory operand.
        if cur.check_punct(Punct::Percent) {
            let r = self.att_register(cur)?;
            if r.class == RegClass::Segment && cur.check_punct(Punct::Colon) {
                cur.advance();
                let mut m = self.att_memory(cur, start)?;
                m.seg = Some(r);
                let span = start.to(m.span);
                return Some(Operand { kind: OperandKind::Mem(m), size_hint: None, span });
            }
            return Some(Operand { kind: OperandKind::Reg(r), size_hint: Some(r.size), span: start });
        }

        // Anything else is a memory operand: `disp`, `disp(...)` or `(...)`.
        let m = self.att_memory(cur, start)?;
        let span = start.to(m.span);
        Some(Operand { kind: OperandKind::Mem(m), size_hint: None, span })
    }

    fn att_register(&mut self, cur: &mut Cursor<'_>) -> Option<Reg> {
        let pct = cur.advance(); // `%`
        let tok = cur.peek();
        let TokKind::Ident(n) = tok.kind else {
            self.cx.error(pct.span.to(tok.span), "expected a register name after `%`");
            return None;
        };
        cur.advance();
        let text = self.cx.interner.get(n).to_ascii_lowercase();
        match reg::lookup(&text) {
            Some(r) => Some(r),
            None => {
                self.cx.error(pct.span.to(tok.span), format!("unknown register `%{text}`"));
                None
            }
        }
    }

    /// `disp(base, index, scale)`, any part of which may be absent.
    fn att_memory(&mut self, cur: &mut Cursor<'_>, start: Span) -> Option<Mem> {
        let mut m = Mem::empty(start);
        m.addr_size = self.addr_size;

        if !cur.check_punct(Punct::LParen) {
            m.disp = Some(self.expr(cur)?);
        }

        if cur.eat_punct(Punct::LParen).is_none() {
            m.span = start.to(cur.peek().span.shrink_to_lo());
            return Some(m);
        }

        // base
        if cur.check_punct(Punct::Percent) {
            let r = self.att_register(cur)?;
            if r.class == RegClass::Rip {
                m.rip_relative = true;
            } else if r.class == RegClass::Gpr {
                m.base = Some(r);
                m.addr_size = r.size;
            } else {
                self.cx.error(cur.peek().span, "invalid base register");
                return None;
            }
        }

        // index and scale
        if cur.eat_punct(Punct::Comma).is_some() {
            if cur.check_punct(Punct::Percent) {
                let r = self.att_register(cur)?;
                if !r.valid_index() {
                    self.cx.error(
                        cur.peek().span,
                        format!("`%{}` cannot be used as an index register", reg::name_of(r)),
                    );
                    return None;
                }
                m.index = Some(r);
                m.addr_size = r.size;
            }
            if cur.eat_punct(Punct::Comma).is_some() {
                let tok = cur.peek();
                let e = self.expr(cur)?;
                match self.cx.constant(e) {
                    Some(s @ (1 | 2 | 4 | 8)) => m.scale = s as u8,
                    _ => {
                        self.cx.error(tok.span, "scale must be 1, 2, 4 or 8");
                        return None;
                    }
                }
            }
        }

        let close = cur.peek();
        if cur.eat_punct(Punct::RParen).is_none() {
            self.cx.error(close.span, "expected `)` to close a memory operand");
            return None;
        }
        m.span = start.to(close.span);
        Some(m)
    }

    // ---- Intel ------------------------------------------------------------

    fn parse_intel(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        let start = cur.peek().span;
        let mut size_hint = None;

        // `dword ptr [...]`, or just `dword [...]` as NASM allows.
        if let TokKind::Ident(n) = cur.peek().kind {
            let text = self.cx.interner.get(n).to_ascii_lowercase();
            if let Some(sz) = size_keyword(&text) {
                // Only a size keyword if what follows can start a memory
                // operand; `byte` might legitimately be a symbol name.
                let next = cur.nth(1);
                let looks_like_ptr = matches!(next.kind, TokKind::Ident(m)
                    if self.cx.interner.get(m).eq_ignore_ascii_case("ptr"))
                    || next.is_punct(Punct::LBracket);
                if looks_like_ptr {
                    cur.advance();
                    if let TokKind::Ident(m) = cur.peek().kind
                        && self.cx.interner.get(m).eq_ignore_ascii_case("ptr") {
                            cur.advance();
                        }
                    size_hint = Some(sz);
                }
            }
        }

        // A bare register.
        if let TokKind::Ident(n) = cur.peek().kind {
            let text = self.cx.interner.get(n).to_ascii_lowercase();
            if let Some(r) = reg::lookup(&text) {
                cur.advance();
                // `seg:[...]`
                if r.class == RegClass::Segment && cur.check_punct(Punct::Colon) {
                    cur.advance();
                    let mut m = self.intel_memory(cur, start)?;
                    m.seg = Some(r);
                    let span = start.to(m.span);
                    return Some(Operand { kind: OperandKind::Mem(m), size_hint, span });
                }
                return Some(Operand {
                    kind: OperandKind::Reg(r),
                    size_hint: size_hint.or(Some(r.size)),
                    span: start,
                });
            }
        }

        if cur.check_punct(Punct::LBracket) {
            let m = self.intel_memory(cur, start)?;
            let span = start.to(m.span);
            return Some(Operand { kind: OperandKind::Mem(m), size_hint, span });
        }

        // Otherwise an immediate or branch target; the matcher decides which.
        let e = self.expr(cur)?;
        Some(Operand {
            kind: OperandKind::Imm(e),
            size_hint,
            span: start.to(self.cx.exprs.span(e)),
        })
    }

    /// `[ base + index*scale + disp ]`, in any order.
    fn intel_memory(&mut self, cur: &mut Cursor<'_>, start: Span) -> Option<Mem> {
        let open = cur.peek();
        if cur.eat_punct(Punct::LBracket).is_none() {
            self.cx.error(open.span, "expected `[` to start a memory operand");
            return None;
        }
        let mut m = Mem::empty(start);
        m.addr_size = self.addr_size;

        // Terms are accumulated into a displacement expression as they are
        // recognised, so `[rax + 4*8 + sym]` folds naturally.
        let mut disp: Option<ExprRef> = None;
        let mut negate_next = false;
        loop {
            if cur.check_punct(Punct::RBracket) || cur.at_end() {
                break;
            }
            let term_start = cur.peek().span;
            let term = self.intel_term(cur, &mut m, negate_next)?;
            if let Some(e) = term {
                let e = if negate_next {
                    let span = self.cx.exprs.span(e);
                    self.cx.exprs.alloc(ExprKind::Unary(crate::expr::UnOp::Neg, e), span)
                } else {
                    e
                };
                disp = Some(match disp {
                    None => e,
                    Some(prev) => {
                        let span = self.cx.exprs.span(prev).to(self.cx.exprs.span(e));
                        self.cx.exprs.alloc(ExprKind::Binary(crate::expr::BinOp::Add, prev, e), span)
                    }
                });
            }
            match cur.peek().kind {
                TokKind::Punct(Punct::Plus) => {
                    cur.advance();
                    negate_next = false;
                }
                TokKind::Punct(Punct::Minus) => {
                    cur.advance();
                    negate_next = true;
                }
                TokKind::Punct(Punct::RBracket) => break,
                _ => {
                    let t = cur.peek();
                    if t.span == term_start {
                        // No progress: bail rather than spin.
                        self.cx.error(t.span, "expected `+`, `-` or `]` in memory operand");
                        return None;
                    }
                    self.cx.error(t.span, "expected `+`, `-` or `]` in memory operand");
                    return None;
                }
            }
        }

        let close = cur.peek();
        if cur.eat_punct(Punct::RBracket).is_none() {
            self.cx
                .error(close.span, "expected `]` to close a memory operand");
            return None;
        }
        m.disp = disp;
        m.span = start.to(close.span);
        Some(m)
    }

    /// One `+`-separated term inside `[...]`. Registers are stored into `m`;
    /// anything else is returned as part of the displacement.
    fn intel_term(
        &mut self,
        cur: &mut Cursor<'_>,
        m: &mut Mem,
        negated: bool,
    ) -> Option<Option<ExprRef>> {
        // `reg` or `reg*scale`
        if let TokKind::Ident(n) = cur.peek().kind {
            let text = self.cx.interner.get(n).to_ascii_lowercase();
            if let Some(r) = reg::lookup(&text) {
                let tok = cur.advance();
                if negated {
                    self.cx.error(tok.span, "a register cannot be subtracted in a memory operand");
                    return None;
                }
                if r.class == RegClass::Rip {
                    m.rip_relative = true;
                    return Some(None);
                }
                if r.class != RegClass::Gpr {
                    self.cx.error(tok.span, "only general-purpose registers may address memory");
                    return None;
                }
                // `reg * scale` makes it the index.
                if cur.check_punct(Punct::Star) {
                    cur.advance();
                    let stok = cur.peek();
                    // Only the scale itself, not the `+ disp` that may follow.
                    let e = self.intel_disp_term(cur)?;
                    let Some(s @ (1 | 2 | 4 | 8)) = self.cx.constant(e) else {
                        self.cx.error(stok.span, "scale must be 1, 2, 4 or 8");
                        return None;
                    };
                    if m.index.is_some() {
                        self.cx.error(tok.span, "a memory operand may have only one index register");
                        return None;
                    }
                    if !r.valid_index() {
                        self.cx.error(tok.span, format!("`{}` cannot be used as an index register", reg::name_of(r)));
                        return None;
                    }
                    m.index = Some(r);
                    m.scale = s as u8;
                    m.addr_size = r.size;
                    return Some(None);
                }
                // First bare register is the base, a second becomes the index.
                if m.base.is_none() {
                    m.base = Some(r);
                } else if m.index.is_none() {
                    if !r.valid_index() {
                        // `[rax + rsp]` is invalid, but `[rsp + rax]` is fine:
                        // swap so the unusable register becomes the base.
                        if m.base.is_some_and(|b| b.valid_index()) {
                            m.index = m.base;
                            m.base = Some(r);
                        } else {
                            self.cx.error(tok.span, format!("`{}` cannot be used as an index register", reg::name_of(r)));
                            return None;
                        }
                    } else {
                        m.index = Some(r);
                    }
                } else {
                    self.cx.error(tok.span, "too many registers in a memory operand");
                    return None;
                }
                m.addr_size = r.size;
                return Some(None);
            }
        }

        // `scale * reg`
        if let TokKind::Int(v) = cur.peek().kind
            && cur.nth(1).is_punct(Punct::Star)
                && let TokKind::Ident(n) = cur.nth(2).kind {
                    let text = self.cx.interner.get(n).to_ascii_lowercase();
                    if let Some(r) = reg::lookup(&text) {
                        let tok = cur.peek();
                        if !matches!(v, 1 | 2 | 4 | 8) {
                            self.cx.error(tok.span, "scale must be 1, 2, 4 or 8");
                            return None;
                        }
                        if !r.valid_index() {
                            self.cx.error(tok.span, format!("`{}` cannot be used as an index register", reg::name_of(r)));
                            return None;
                        }
                        cur.advance();
                        cur.advance();
                        cur.advance();
                        m.index = Some(r);
                        m.scale = v as u8;
                        m.addr_size = r.size;
                        return Some(None);
                    }
                }

        // Everything else contributes to the displacement. Parse at a
        // precedence above `+`/`-` so those stay term separators.
        let e = self.intel_disp_term(cur)?;
        Some(Some(e))
    }

    /// A displacement term: a full expression except that top-level `+` and
    /// `-` are left for [`Self::intel_memory`] to consume.
    fn intel_disp_term(&mut self, cur: &mut Cursor<'_>) -> Option<ExprRef> {
        let sub = take_until_term_break(cur);
        let mut sub_cur = Cursor::new(sub);
        let e = {
            let mut p = self.cx.expr_parser();
            p.parse(&mut sub_cur)?
        };
        if !sub_cur.at_end() && !sub_cur.is_empty() {
            self.cx.error(sub_cur.peek().span, "unexpected token in memory operand");
            return None;
        }
        Some(e)
    }
}

/// Consumes tokens up to the next top-level `+`, `-` or `]`.
fn take_until_term_break<'t>(cur: &mut Cursor<'t>) -> &'t [Token] {
    let rest = cur.rest();
    let mut depth = 0i32;
    let mut end = rest.len();
    for (i, t) in rest.iter().enumerate() {
        match t.kind {
            TokKind::Punct(Punct::LParen | Punct::LBracket) => depth += 1,
            TokKind::Punct(Punct::RParen) => depth -= 1,
            TokKind::Punct(Punct::RBracket) => {
                if depth == 0 {
                    end = i;
                    break;
                }
                depth -= 1;
            }
            TokKind::Punct(Punct::Plus | Punct::Minus) if depth == 0 && i > 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let out = &rest[..end];
    cur.set_pos(cur.pos() + end);
    out
}
