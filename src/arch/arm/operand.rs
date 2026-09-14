//! ARM operand parsing, shared by the A32 and T32 encoders.
//!
//! Two things make ARM operands awkward for a comma-splitting parser. A
//! shifted register is written as *two* comma-separated pieces that belong to
//! one operand (`add r0, r1, r2, lsl #3`), and a post-indexed address puts the
//! offset after the closing bracket (`ldr r0, [r1], #4`). Both are handled by
//! parsing the operand list as a whole with a little lookahead, rather than
//! splitting on commas first the way the x86 backend can.
//!
//! Note on `#`: GAS-dialect lexing treats `#` as a line comment, so in this
//! assembler an ARM immediate is written bare (`add r0, r1, 1`). A `#` is
//! accepted where the lexer ever delivers one, so sources keep working if the
//! core learns the ARM comment character.

use super::reg::{self, Reg};
use crate::arch::AsmCtx;
use crate::cursor::Cursor;
use crate::expr::ExprRef;
use crate::lexer::{Punct, TokKind};
use crate::source::Span;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
    /// Rotate right through carry: a one-bit shift with no amount.
    Rrx,
}

impl Shift {
    pub fn from_name(name: &str) -> Option<Shift> {
        Some(match name {
            "lsl" | "asl" => Shift::Lsl,
            "lsr" => Shift::Lsr,
            "asr" => Shift::Asr,
            "ror" => Shift::Ror,
            "rrx" => Shift::Rrx,
            _ => return None,
        })
    }

    /// The two-bit shift-type field. `rrx` shares `ror`'s encoding, with a
    /// zero amount.
    pub fn code(self) -> u32 {
        match self {
            Shift::Lsl => 0,
            Shift::Lsr => 1,
            Shift::Asr => 2,
            Shift::Ror | Shift::Rrx => 3,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Shift::Lsl => "lsl",
            Shift::Lsr => "lsr",
            Shift::Asr => "asr",
            Shift::Ror => "ror",
            Shift::Rrx => "rrx",
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ShiftAmt {
    Imm(u32),
    Reg(Reg),
    /// `rrx`, which encodes as `ror` by zero.
    None,
}

/// How a load or store updates its base register.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Index {
    /// `[rn, off]`: the base is unchanged.
    Offset,
    /// `[rn, off]!`
    PreIndex,
    /// `[rn], off`
    PostIndex,
}

#[derive(Copy, Clone, Debug)]
pub enum MemOffset {
    None,
    /// A signed byte count; the sign becomes the U bit.
    Imm(i64),
    Reg {
        rm: Reg,
        add: bool,
        shift: Shift,
        amount: u32,
    },
}

#[derive(Copy, Clone, Debug)]
pub struct Mem {
    pub base: Reg,
    pub offset: MemOffset,
    pub index: Index,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum OperandKind {
    Reg(Reg),
    /// A register with a barrel shift applied.
    Shifted {
        rm: Reg,
        shift: Shift,
        amount: ShiftAmt,
    },
    /// An immediate or a branch target; which one depends on the instruction.
    Imm(ExprRef),
    Mem(Mem),
    /// `{r0-r3, lr}`, as a bitmask of registers.
    List(u16),
    /// `=expr`: a value for `ldr` to load from the literal pool.
    Literal(ExprRef),
}

#[derive(Clone, Debug)]
pub struct Operand {
    pub kind: OperandKind,
    pub span: Span,
    /// Set when the operand was a single bare identifier, so instructions with
    /// keyword operands (`dmb sy`, `mrs r0, cpsr`) can read it without
    /// re-parsing. Such an operand is *also* available as an expression, since
    /// only the instruction knows which reading is meant.
    pub word: Option<String>,
    /// True when the register was followed by `!` (writeback on `ldm`/`stm`).
    pub writeback: bool,
}

impl Operand {
    pub fn reg(&self) -> Option<Reg> {
        match self.kind {
            OperandKind::Reg(r) => Some(r),
            _ => None,
        }
    }

    pub fn imm(&self) -> Option<ExprRef> {
        match self.kind {
            OperandKind::Imm(e) => Some(e),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match &self.kind {
            OperandKind::Reg(r) => format!("register `{}`", reg::name_of(*r)),
            OperandKind::Shifted { .. } => "a shifted register".into(),
            OperandKind::Imm(_) => "an immediate".into(),
            OperandKind::Mem(_) => "a memory operand".into(),
            OperandKind::List(_) => "a register list".into(),
            OperandKind::Literal(_) => "a literal pool value".into(),
        }
    }
}

pub struct Parser<'c, 'a> {
    pub cx: &'c mut AsmCtx<'a>,
}

impl Parser<'_, '_> {
    /// Parses the whole operand list of one instruction.
    pub fn parse_list(&mut self, cur: &mut Cursor<'_>) -> Option<Vec<Operand>> {
        let mut out = Vec::new();
        if cur.at_end() {
            return Some(out);
        }
        loop {
            let op = self.parse_one(cur)?;
            out.push(op);
            // A shift keyword after a comma continues the previous operand
            // rather than starting a new one.
            while cur.check_punct(Punct::Comma) && self.peek_shift(cur, 1).is_some() {
                cur.advance();
                let last = out.len() - 1;
                out[last] = self.apply_shift(cur, out[last].clone())?;
            }
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        if !cur.at_end() {
            let span = cur.peek().span;
            self.cx.error(span, "unexpected token after operand");
            return None;
        }
        Some(out)
    }

    /// The shift keyword `n` tokens ahead, if there is one.
    fn peek_shift(&self, cur: &Cursor<'_>, n: usize) -> Option<Shift> {
        match cur.nth(n).kind {
            TokKind::Ident(name) => {
                Shift::from_name(&self.cx.interner.get(name).to_ascii_lowercase())
            }
            _ => None,
        }
    }

    /// Turns `base` into a shifted register, having consumed the comma.
    fn apply_shift(&mut self, cur: &mut Cursor<'_>, base: Operand) -> Option<Operand> {
        let start = cur.peek().span;
        let OperandKind::Reg(rm) = base.kind else {
            self.cx
                .error(start, "a shift can only be applied to a register");
            return None;
        };
        let Some(shift) = self.peek_shift(cur, 0) else {
            self.cx.error(start, "expected a shift");
            return None;
        };
        cur.advance();
        let amount = if shift == Shift::Rrx {
            ShiftAmt::None
        } else if let Some(r) = self.eat_register(cur) {
            ShiftAmt::Reg(r)
        } else {
            cur.eat_punct(Punct::Hash);
            let e = self.cx.expr_parser().parse(cur)?;
            let Some(v) = self.cx.constant(e) else {
                self.cx
                    .error(start, "a shift amount must be a constant expression");
                return None;
            };
            // `lsr #32` and `asr #32` are real shifts, encoded as zero; `lsl`
            // and `ror` stop at 31.
            let max = match shift {
                Shift::Lsr | Shift::Asr => 32,
                _ => 31,
            };
            if v < 0 || v > max {
                self.cx.error(
                    start,
                    format!(
                        "shift amount {v} is out of range for `{}` (0 to {max})",
                        shift.name()
                    ),
                );
                return None;
            }
            ShiftAmt::Imm(v as u32)
        };
        let span = base.span.to(cur.nth(0).span);
        Some(Operand {
            kind: OperandKind::Shifted { rm, shift, amount },
            span,
            word: None,
            writeback: false,
        })
    }

    fn eat_register(&mut self, cur: &mut Cursor<'_>) -> Option<Reg> {
        let TokKind::Ident(name) = cur.peek().kind else {
            return None;
        };
        let r = reg::lookup(&self.cx.interner.get(name).to_ascii_lowercase())?;
        cur.advance();
        Some(r)
    }

    fn parse_one(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        let start = cur.peek().span;
        if cur.check_punct(Punct::LBrace) {
            return self.parse_reglist(cur);
        }
        if cur.eat_punct(Punct::Eq).is_some() {
            cur.eat_punct(Punct::Hash);
            let e = self.cx.expr_parser().parse(cur)?;
            return Some(Operand {
                kind: OperandKind::Literal(e),
                span: start.to(cur.nth(0).span),
                word: None,
                writeback: false,
            });
        }
        if cur.check_punct(Punct::LBracket) {
            return self.parse_mem(cur);
        }
        if let Some(r) = self.eat_register(cur) {
            let writeback = cur.eat_punct(Punct::Bang).is_some();
            return Some(Operand {
                kind: OperandKind::Reg(r),
                span: start.to(cur.nth(0).span),
                word: None,
                writeback,
            });
        }
        // Everything else is an expression: an immediate, a branch target, or
        // a keyword operand such as a barrier option.
        let word = match cur.peek().kind {
            TokKind::Ident(n) if cur.nth(1).is_eol() || cur.nth(1).is_punct(Punct::Comma) => {
                Some(self.cx.interner.get(n).to_ascii_lowercase())
            }
            _ => None,
        };
        cur.eat_punct(Punct::Hash);
        let e = self.cx.expr_parser().parse(cur)?;
        Some(Operand {
            kind: OperandKind::Imm(e),
            span: start.to(cur.nth(0).span),
            word,
            writeback: false,
        })
    }

    fn parse_reglist(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        let start = cur.advance().span; // `{`
        let mut mask = 0u16;
        if cur.eat_punct(Punct::RBrace).is_some() {
            self.cx.error(start, "empty register list");
            return None;
        }
        loop {
            let span = cur.peek().span;
            let Some(lo) = self.eat_register(cur) else {
                self.cx.error(span, "expected a register in the list");
                return None;
            };
            let hi = if cur.eat_punct(Punct::Minus).is_some() {
                let span = cur.peek().span;
                match self.eat_register(cur) {
                    Some(r) => r,
                    None => {
                        self.cx.error(span, "expected a register after `-`");
                        return None;
                    }
                }
            } else {
                lo
            };
            if hi < lo {
                self.cx.error(
                    span,
                    format!(
                        "register range `{}-{}` runs backwards",
                        reg::name_of(lo),
                        reg::name_of(hi)
                    ),
                );
                return None;
            }
            for r in lo..=hi {
                mask |= 1 << r;
            }
            if cur.eat_punct(Punct::Comma).is_some() {
                continue;
            }
            if cur.eat_punct(Punct::RBrace).is_some() {
                break;
            }
            let span = cur.peek().span;
            self.cx
                .error(span, "expected `,` or `}` in a register list");
            return None;
        }
        Some(Operand {
            kind: OperandKind::List(mask),
            span: start.to(cur.nth(0).span),
            word: None,
            writeback: false,
        })
    }

    fn parse_mem(&mut self, cur: &mut Cursor<'_>) -> Option<Operand> {
        let start = cur.advance().span; // `[`
        let span = cur.peek().span;
        let Some(base) = self.eat_register(cur) else {
            self.cx.error(span, "expected a base register");
            return None;
        };

        let mut offset = MemOffset::None;
        if cur.eat_punct(Punct::Comma).is_some() {
            offset = self.parse_mem_offset(cur)?;
        }
        if cur.eat_punct(Punct::RBracket).is_none() {
            let span = cur.peek().span;
            self.cx.error(span, "expected `]`");
            return None;
        }

        let index = if cur.eat_punct(Punct::Bang).is_some() {
            Index::PreIndex
        } else if matches!(offset, MemOffset::None) && cur.check_punct(Punct::Comma) {
            // `[rn], off`: the offset written after the bracket is applied
            // after the transfer. A memory operand is always last, so there is
            // nothing else this comma could introduce.
            cur.advance();
            offset = self.parse_mem_offset(cur)?;
            Index::PostIndex
        } else {
            Index::Offset
        };

        Some(Operand {
            kind: OperandKind::Mem(Mem {
                base,
                offset,
                index,
                span: start.to(cur.nth(0).span),
            }),
            span: start.to(cur.nth(0).span),
            word: None,
            writeback: false,
        })
    }

    fn parse_mem_offset(&mut self, cur: &mut Cursor<'_>) -> Option<MemOffset> {
        let start = cur.peek().span;
        // A sign directly in front of a register is the U bit, not arithmetic.
        let mut add = true;
        let save = cur.pos();
        if cur.eat_punct(Punct::Minus).is_some() {
            add = false;
        } else {
            cur.eat_punct(Punct::Plus);
        }
        if let Some(rm) = self.eat_register(cur) {
            let mut shift = Shift::Lsl;
            let mut amount = 0u32;
            if cur.check_punct(Punct::Comma) && self.peek_shift(cur, 1).is_some() {
                cur.advance();
                let s = self.peek_shift(cur, 0)?;
                cur.advance();
                shift = s;
                if s != Shift::Rrx {
                    cur.eat_punct(Punct::Hash);
                    let e = self.cx.expr_parser().parse(cur)?;
                    let Some(v) = self.cx.constant(e) else {
                        self.cx
                            .error(start, "a shift amount must be a constant expression");
                        return None;
                    };
                    let max = match s {
                        Shift::Lsr | Shift::Asr => 32,
                        _ => 31,
                    };
                    if v < 0 || v > max {
                        self.cx.error(
                            start,
                            format!("shift amount {v} is out of range (0 to {max})"),
                        );
                        return None;
                    }
                    amount = v as u32;
                }
            }
            return Some(MemOffset::Reg {
                rm,
                add,
                shift,
                amount,
            });
        }
        // Not a register after all; re-read the whole thing as an expression
        // so that `[r0, -4]` keeps its sign.
        cur.set_pos(save);
        cur.eat_punct(Punct::Hash);
        let e = self.cx.expr_parser().parse(cur)?;
        let Some(v) = self.cx.constant(e) else {
            self.cx
                .error(start, "a memory offset must be a constant expression");
            return None;
        };
        Some(MemOffset::Imm(v))
    }
}
