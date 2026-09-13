//! Statement-level parsing.
//!
//! The parser is deliberately thin: it splits the token stream into statements
//! and recognises labels, directives, assignments and instructions. It does not
//! look inside operands — that grammar belongs to the architecture backend,
//! which receives the raw token tail.

use crate::cursor::Cursor;
use crate::diag::DiagBag;
use crate::intern::{Interner, Name};
use crate::lexer::{Dialect, LexConfig, Lexer, LitPool, Punct, TokKind, Token};
use crate::source::{FileId, SourceMap, Span};

#[derive(Clone, Debug)]
pub enum LabelDef {
    Named(Name, Span),
    /// A numeric local label such as `1:`.
    Numeric(u32, Span),
}

#[derive(Clone, Debug)]
pub enum Body {
    /// `.section .text` and friends.
    Directive { name: Name, span: Span },
    /// A machine instruction, handed to the current architecture.
    Insn { mnemonic: Name, span: Span },
    /// `sym = expr`, equivalent to `.set sym, expr`.
    Assign { name: Name, span: Span },
    /// `. = expr`: move the location counter.
    SetLocation { span: Span },
    /// Something that starts with none of the above.
    ///
    /// The parser classifies rather than judges: a line beginning with `\` is
    /// nonsense on its own but perfectly ordinary inside a macro body, and the
    /// parser cannot know which it is looking at. Reporting it is the
    /// assembler's job, once it knows whether the statement is going to be
    /// executed or captured.
    Unknown { span: Span },
}

#[derive(Clone, Debug)]
pub struct Statement {
    pub labels: Vec<LabelDef>,
    pub body: Option<Body>,
    /// A name written before a directive without a colon, in the CC-RL and
    /// CC-RH dialects: the section name of `CODE .CSEG`, the macro name of
    /// `ADMAC .MACRO`. It is not a label, so it defines nothing by itself;
    /// the directive decides what it means, or that it is not allowed.
    pub symbol: Option<(Name, Span)>,
    /// All tokens of the statement, excluding the terminator.
    pub toks: Vec<Token>,
    /// Index into `toks` of the first argument token.
    pub args: usize,
    pub span: Span,
}

impl Statement {
    pub fn arg_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.toks[self.args.min(self.toks.len())..])
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty() && self.body.is_none()
    }
}

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    /// One token of lookahead held across `next_statement` calls.
    peeked: Option<Token>,
}

impl<'a> Parser<'a> {
    pub fn new(sm: &'a SourceMap, file: FileId, config: LexConfig) -> Parser<'a> {
        Parser {
            lexer: Lexer::new(sm, file, config),
            peeked: None,
        }
    }

    /// The live lexer configuration. Directives mutate this to change how the
    /// rest of the file is tokenized.
    pub fn config_mut(&mut self) -> &mut LexConfig {
        &mut self.lexer.config
    }

    pub fn dialect(&self) -> Dialect {
        self.lexer.config.dialect
    }

    fn bump(&mut self, interner: &mut Interner, pool: &mut LitPool, diags: &mut DiagBag) -> Token {
        match self.peeked.take() {
            Some(t) => t,
            None => self.lexer.next_token(interner, pool, diags),
        }
    }

    /// Reads the next non-empty statement, or `None` at end of file.
    pub fn next_statement(
        &mut self,
        interner: &mut Interner,
        pool: &mut LitPool,
        diags: &mut DiagBag,
    ) -> Option<Statement> {
        loop {
            let mut toks = Vec::new();
            loop {
                let t = self.bump(interner, pool, diags);
                match t.kind {
                    TokKind::Eof => {
                        if toks.is_empty() {
                            return None;
                        }
                        // Put the EOF back so the next call also sees it.
                        self.peeked = Some(t);
                        break;
                    }
                    TokKind::Eol => break,
                    _ => toks.push(t),
                }
            }
            if toks.is_empty() {
                continue;
            }
            return Some(self.build(toks, interner, diags));
        }
    }

    fn build(&self, toks: Vec<Token>, interner: &mut Interner, diags: &mut DiagBag) -> Statement {
        build_statement(toks, self.lexer.config.dialect, interner, diags)
    }
}

/// Splits a statement's tokens into labels and a body.
///
/// Exposed separately from [`Parser`] so that anything holding a bare token
/// vector — a macro expansion, say — can turn it into a statement without a
/// lexer.
pub fn build_statement(
    toks: Vec<Token>,
    dialect: Dialect,
    interner: &mut Interner,
    diags: &mut DiagBag,
) -> Statement {
    Builder { dialect }.build(toks, interner, diags)
}

struct Builder {
    dialect: Dialect,
}

impl Builder {
    fn build(&self, toks: Vec<Token>, interner: &mut Interner, diags: &mut DiagBag) -> Statement {
        let stmt_span = toks
            .first()
            .zip(toks.last())
            .map(|(a, b)| a.span.to(b.span))
            .unwrap_or(Span::DUMMY);
        let span = stmt_span;

        let mut i = 0usize;
        let mut labels = Vec::new();

        // In Motorola source anything that starts in the first column is a
        // label, colon or not, and an instruction has to be indented to be one.
        // vasm and GNU as --mri both assemble `rts` written in column 0 to no
        // code at all: it defines a label called `rts`.
        if self.dialect == Dialect::Motorola
            && let Some(t) = toks.first()
            && let TokKind::Ident(n) = t.kind
            && !t.preceded_by_space
        {
            labels.push(LabelDef::Named(n, t.span));
            i = 1;
            if toks.get(i).map(|t| t.kind) == Some(TokKind::Punct(Punct::Colon)) {
                i += 1;
            }
        }

        // Leading labels. A label is an identifier or a plain integer followed
        // by `:`; several may share a line with a statement.
        loop {
            match (toks.get(i).map(|t| t.kind), toks.get(i + 1).map(|t| t.kind)) {
                (Some(TokKind::Ident(n)), Some(TokKind::Punct(Punct::Colon))) => {
                    labels.push(LabelDef::Named(n, toks[i].span));
                    i += 2;
                    // `foo::` marks a global label in some dialects; accept and
                    // let the caller decide what it means.
                    if toks.get(i).map(|t| t.kind) == Some(TokKind::Punct(Punct::Colon)) {
                        i += 1;
                    }
                }
                (Some(TokKind::Int(v)), Some(TokKind::Punct(Punct::Colon))) => {
                    labels.push(LabelDef::Numeric(v as u32, toks[i].span));
                    i += 2;
                }
                _ => break,
            }
        }

        // `NAME equ value`, the vendor spelling of `.set NAME, value`. The name
        // may already have been taken as a label — by a colon, or by starting
        // in the first column — in which case it is the name being defined
        // rather than a place.
        if let Some(word) = toks.get(i).and_then(|t| t.ident())
            && self.is_equate_word(interner.get(word))
            && let [LabelDef::Named(name, name_span)] = labels.as_slice()
        {
            let (name, span) = (*name, *name_span);
            return Statement {
                labels: Vec::new(),
                body: Some(Body::Assign { name, span }),
                symbol: None,
                args: i + 1,
                toks,
                span: stmt_span,
            };
        }
        if labels.is_empty()
            && let (Some(name), Some(word)) = (
                toks.first().and_then(|t| t.ident()),
                toks.get(1).and_then(|t| t.ident()),
            )
            && self.is_equate_word(interner.get(word))
        {
            let span = toks[0].span;
            return Statement {
                labels,
                body: Some(Body::Assign { name, span }),
                symbol: None,
                args: 2,
                toks,
                span: stmt_span,
            };
        }

        let mut symbol = None;
        if self.dialect.is_cc() {
            // A control instruction is `$` and a word, spaces allowed around
            // the `$` (CC-RL §5.3, pages 539-555; CC-RH §5.3, pages 469-487).
            // It becomes a directive named `$word`.
            if let (Some(dollar), Some(word)) = (toks.get(i), toks.get(i + 1))
                && dollar.is_punct(Punct::Dollar)
                && let Some(n) = word.ident()
            {
                let name = interner.intern(&format!("${}", interner.get(n).to_ascii_lowercase()));
                return Statement {
                    labels,
                    body: Some(Body::Directive {
                        name,
                        span: dollar.span.to(word.span),
                    }),
                    symbol: None,
                    args: i + 2,
                    toks,
                    span: stmt_span,
                };
            }
            // `NAME .DIRECTIVE`: a symbol field without a colon, which only
            // the section and macro directives take (CC-RL §5.1.2 (3)(a),
            // page 427). Section names may start with a dot (`.text .CSEG`),
            // so the directive decides, not the name.
            if let (Some(name_tok), Some(dir)) = (toks.get(i), toks.get(i + 1))
                && let (Some(n), Some(d)) = (name_tok.ident(), dir.ident())
                && matches!(
                    interner.get(d).to_ascii_lowercase().as_str(),
                    ".cseg" | ".dseg" | ".bseg" | ".macro" | ".vector" | ".dbit"
                )
            {
                symbol = Some((n, name_tok.span));
                i += 1;
            }
        }

        let body = self.classify(&toks, &mut i, interner, diags);
        Statement {
            labels,
            body,
            symbol,
            toks,
            args: i,
            span,
        }
    }

    /// The vendor keyword for defining a symbol, in dialects that have one.
    ///
    /// `set` is only taken where it cannot be an instruction: the Z80 has a
    /// `set 3, a` and is assembled in the NASM dialect, so NASM gets `equ`
    /// alone, which is also all NASM itself has.
    fn is_equate_word(&self, word: &str) -> bool {
        match self.dialect {
            Dialect::Gas => false,
            Dialect::Nasm => word.eq_ignore_ascii_case("equ"),
            Dialect::Motorola | Dialect::Renesas => {
                word.eq_ignore_ascii_case("equ") || word.eq_ignore_ascii_case("set")
            }
            // `NAME .EQU value` and `NAME .SET value` (CC-RL §5.2.3, pages
            // 502-504; CC-RH §5.2.3, pages 435-436).
            Dialect::CcRl | Dialect::CcRh => {
                word.eq_ignore_ascii_case(".equ") || word.eq_ignore_ascii_case(".set")
            }
        }
    }

    fn classify(
        &self,
        toks: &[Token],
        i: &mut usize,
        interner: &mut Interner,
        diags: &mut DiagBag,
    ) -> Option<Body> {
        let first = *toks.get(*i)?;

        // `. = expr` sets the location counter.
        if first.is_punct(Punct::Dot) && toks.get(*i + 1).is_some_and(|t| t.is_punct(Punct::Eq)) {
            *i += 2;
            return Some(Body::SetLocation { span: first.span });
        }

        let TokKind::Ident(name) = first.kind else {
            *i = toks.len();
            let _ = &diags;
            return Some(Body::Unknown { span: first.span });
        };

        // `sym = expr` is an assignment, not an instruction called `sym`.
        if toks.get(*i + 1).is_some_and(|t| t.is_punct(Punct::Eq)) {
            *i += 2;
            return Some(Body::Assign {
                name,
                span: first.span,
            });
        }

        *i += 1;

        // Mnemonics and directives are case-insensitive; symbol names are not.
        let (is_directive, folded) = {
            let text = interner.get(name);
            let is_directive = match self.dialect {
                // GAS spells every directive with a leading dot. A bare `.` is
                // the location counter and was handled above.
                Dialect::Gas => text.starts_with('.') && text.len() > 1,
                // NASM directives are bare words; the assembler resolves them
                // against its directive table and falls back to an instruction.
                Dialect::Nasm => false,
                // Bare words are resolved the same way. A dotted spelling is a
                // directive too: Renesas's newer assemblers write `.DB` and
                // `.CSEG`, and a Motorola `.local` label never reaches here,
                // because a first-column word has already been taken as one.
                Dialect::Motorola | Dialect::Renesas => text.starts_with('.') && text.len() > 1,
                // Every CC-RL and CC-RH directive is dotted and every bare word
                // is an instruction or a macro call (CC-RL Table 5.13, page
                // 484).
                Dialect::CcRl | Dialect::CcRh => text.starts_with('.') && text.len() > 1,
            };
            let folded = text
                .bytes()
                .any(|b| b.is_ascii_uppercase())
                .then(|| text.to_ascii_lowercase());
            (is_directive, folded)
        };
        let lowered = match folded {
            Some(t) => interner.intern(&t),
            None => name,
        };
        if is_directive {
            Some(Body::Directive {
                name: lowered,
                span: first.span,
            })
        } else {
            Some(Body::Insn {
                mnemonic: lowered,
                span: first.span,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct H {
        sm: SourceMap,
        interner: Interner,
        pool: LitPool,
        diags: DiagBag,
    }

    fn parse(src: &str) -> (Vec<Statement>, H) {
        let mut h = H {
            sm: SourceMap::new(),
            interner: Interner::new(),
            pool: LitPool::new(),
            diags: DiagBag::new(),
        };
        let f = h.sm.add("t.s", src);
        let mut out = Vec::new();
        {
            let mut p = Parser::new(&h.sm, f, LexConfig::for_dialect(Dialect::Gas));
            while let Some(s) = p.next_statement(&mut h.interner, &mut h.pool, &mut h.diags) {
                out.push(s);
            }
        }
        (out, h)
    }

    #[test]
    fn splits_labels_from_instructions() {
        let (st, h) = parse("foo: bar: movq %rax, %rbx\n");
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].labels.len(), 2);
        let Some(Body::Insn { mnemonic, .. }) = st[0].body else {
            panic!("{:?}", st[0].body)
        };
        assert_eq!(h.interner.get(mnemonic), "movq");
        assert_eq!(st[0].arg_cursor().rest().len(), 5);
    }

    #[test]
    fn recognises_directives_and_numeric_labels() {
        let (st, h) = parse("1: .byte 1, 2\n");
        assert!(matches!(st[0].labels[0], LabelDef::Numeric(1, _)));
        let Some(Body::Directive { name, .. }) = st[0].body else {
            panic!()
        };
        assert_eq!(h.interner.get(name), ".byte");
    }

    #[test]
    fn assignment_beats_instruction() {
        let (st, h) = parse("count = 4 * 2\n");
        let Some(Body::Assign { name, .. }) = st[0].body else {
            panic!("{:?}", st[0].body)
        };
        assert_eq!(h.interner.get(name), "count");
        assert_eq!(st[0].arg_cursor().rest().len(), 3);
    }

    #[test]
    fn location_counter_assignment() {
        let (st, _) = parse(". = . + 16\n");
        assert!(matches!(st[0].body, Some(Body::SetLocation { .. })));
    }

    #[test]
    fn semicolons_separate_statements_in_gas() {
        let (st, _) = parse("nop; nop; nop\n");
        assert_eq!(st.len(), 3);
    }

    #[test]
    fn label_only_lines_and_blank_lines() {
        let (st, _) = parse("\n\nfoo:\n\n  nop\n");
        assert_eq!(st.len(), 2);
        assert!(st[0].body.is_none());
        assert_eq!(st[0].labels.len(), 1);
    }

    #[test]
    fn mnemonics_fold_case_but_labels_do_not() {
        let (st, h) = parse("Foo: NOP\n");
        let Some(Body::Insn { mnemonic, .. }) = st[0].body else {
            panic!()
        };
        assert_eq!(h.interner.get(mnemonic), "nop");
        let LabelDef::Named(n, _) = st[0].labels[0] else {
            panic!()
        };
        assert_eq!(h.interner.get(n), "Foo");
    }

    #[test]
    fn last_line_without_newline_still_parses() {
        let (st, _) = parse("nop");
        assert_eq!(st.len(), 1);
    }
}
