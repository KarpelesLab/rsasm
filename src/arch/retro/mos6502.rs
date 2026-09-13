//! The MOS 6502 opcode table and encoder.
//!
//! # Where the table comes from
//!
//! Every opcode below is derived from the published MOS opcode matrix rather
//! than listed instruction by instruction. Sources:
//!
//! * MOS Technology, *MCS6500 Microcomputer Family Programming Manual*
//!   (January 1976): the per-instruction summaries, each listing the opcode
//!   of every addressing mode the instruction has.
//! * The `aaabbbcc` decomposition of that matrix, as laid out in Neil
//!   Parker's "The 6502/65C02/65C816 Instruction Set Decoded"
//!   (`llx.com/~nparker/a2/opcodes.html`), whose group tables for `cc = 01`,
//!   `10` and `00` are exactly `G1_MODES`, `G2_MODES` and `G0_MODES` below.
//!
//! The matrix is regular: an opcode byte splits as `aaabbbcc`, where `cc`
//! picks one of three groups, `bbb` the addressing mode *within* that group,
//! and `aaa` the operation. Encoding that regularity, rather than 151 hand
//! written rows, means a transcription slip shows up as a whole broken row —
//! and `tests/retro.rs` checks the generated map against an independently
//! written list of all 151 opcodes.
//!
//! # Syntax
//!
//! Traditional 6502 syntax is unwritable in this assembler's GAS lexer, which
//! takes `#` to start a comment and has no `$`-prefixed hexadecimal (see the
//! module comment on [`super`]). So:
//!
//! ```text
//!   lda $12        immediate 0x12      (traditional: lda #$12)
//!   lda #0x12      the same, in the NASM dialect where `#` is a token
//!   lda 0x12       zero page
//!   lda 0x1234     absolute
//!   lda 0x12,x     zero page,X         sta 0x1234,y   absolute,Y
//!   asl a          accumulator         asl            the same
//!   jmp (0x1234)   indirect
//!   lda (0x12,x)   indexed indirect    lda (0x12),y   indirect indexed
//!   bne label      relative
//! ```

use super::common::{self, Enc};
use crate::arch::{AsmCtx, InsnRequest};
use crate::cursor::Cursor;
use crate::expr::ExprRef;
use crate::lexer::Punct;
use crate::section::Variant;
use crate::source::Span;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    Imp,
    Acc,
    Imm,
    Zp,
    ZpX,
    ZpY,
    Abs,
    AbsX,
    AbsY,
    Ind,
    IndX,
    IndY,
    Rel,
}

use Mode::*;

impl Mode {
    /// Operand bytes after the opcode.
    pub fn operand_len(self) -> usize {
        match self {
            Imp | Acc => 0,
            Imm | Zp | ZpX | ZpY | IndX | IndY | Rel => 1,
            Abs | AbsX | AbsY | Ind => 2,
        }
    }

    /// How the mode is spelled in a diagnostic.
    fn describe(self) -> &'static str {
        match self {
            Imp => "implied",
            Acc => "accumulator",
            Imm => "immediate",
            Zp => "zero page",
            ZpX => "zero page,X",
            ZpY => "zero page,Y",
            Abs => "absolute",
            AbsX => "absolute,X",
            AbsY => "absolute,Y",
            Ind => "indirect",
            IndX => "(indirect,X)",
            IndY => "(indirect),Y",
            Rel => "relative",
        }
    }
}

/// The index register an operand was suffixed with.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Index {
    X,
    Y,
}

// ---- the matrix -----------------------------------------------------------

/// `cc = 01`: the accumulator ALU group, the only group with no holes in its
/// mode column — except `STA #imm`, which would be a store to a constant.
const G1_OPS: [&str; 8] = ["ora", "and", "eor", "adc", "sta", "lda", "cmp", "sbc"];

/// `bbb` for `cc = 01`, in column order.
const G1_MODES: [Mode; 8] = [IndX, Zp, Imm, Abs, IndY, ZpX, AbsY, AbsX];

/// `bbb` for `cc = 10`. Columns 4 and 6 are unused by every official row.
const G2_MODES: [Option<Mode>; 8] = [
    Some(Imm),
    Some(Zp),
    Some(Acc),
    Some(Abs),
    None,
    Some(ZpX),
    None,
    Some(AbsX),
];

/// `bbb` for `cc = 00`. Column 2 is where the implied instructions live and
/// column 4 is where the branches do, so neither is a mode here.
const G0_MODES: [Option<Mode>; 8] = [
    Some(Imm),
    Some(Zp),
    None,
    Some(Abs),
    None,
    Some(ZpX),
    None,
    Some(AbsX),
];

/// `cc = 10`, as (mnemonic, `aaa`, the `bbb` columns that exist, the index
/// register columns 5 and 7 use).
///
/// `STX` and `LDX` are the reason the index register is a column property:
/// they index by Y where the shifts index by X, using the same `bbb` value.
const G2_ROWS: [(&str, u8, &[u8], Index); 8] = [
    ("asl", 0, &[1, 2, 3, 5, 7], Index::X),
    ("rol", 1, &[1, 2, 3, 5, 7], Index::X),
    ("lsr", 2, &[1, 2, 3, 5, 7], Index::X),
    ("ror", 3, &[1, 2, 3, 5, 7], Index::X),
    ("stx", 4, &[1, 3, 5], Index::Y),
    ("ldx", 5, &[0, 1, 3, 5, 7], Index::Y),
    ("dec", 6, &[1, 3, 5, 7], Index::X),
    ("inc", 7, &[1, 3, 5, 7], Index::X),
];

/// `cc = 00`, as (mnemonic, `aaa`, the `bbb` columns that exist). `aaa = 0`
/// is not a row: that quarter of the group is `BRK`, `JSR`, `RTI` and `RTS`,
/// which are listed among the irregular encodings below.
const G0_ROWS: [(&str, u8, &[u8]); 6] = [
    ("bit", 1, &[1, 3]),
    ("jmp", 2, &[3]),
    ("sty", 4, &[1, 3, 5]),
    ("ldy", 5, &[0, 1, 3, 5, 7]),
    ("cpy", 6, &[0, 1, 3]),
    ("cpx", 7, &[0, 1, 3]),
];

/// The eight branches are `xxy10000`: `xx` selects the flag and `y` the value
/// it is tested against. Listed here as (branch-if-clear, branch-if-set) per
/// flag, in flag order N, V, C, Z.
const BRANCH_ROWS: [(&str, &str); 4] = [
    ("bpl", "bmi"),
    ("bvc", "bvs"),
    ("bcc", "bcs"),
    ("bne", "beq"),
];

/// Everything the `aaabbbcc` decomposition does not reach: the single-byte
/// implied instructions that fill the `bbb = 010` and `bbb = 110` columns of
/// groups 0 and 2, plus `JSR abs` and the indirect `JMP`.
const IRREGULAR: [(&str, Mode, u8); 27] = [
    ("brk", Imp, 0x00),
    ("php", Imp, 0x08),
    ("clc", Imp, 0x18),
    ("jsr", Abs, 0x20),
    ("plp", Imp, 0x28),
    ("sec", Imp, 0x38),
    ("rti", Imp, 0x40),
    ("pha", Imp, 0x48),
    ("cli", Imp, 0x58),
    ("rts", Imp, 0x60),
    ("pla", Imp, 0x68),
    ("jmp", Ind, 0x6c),
    ("sei", Imp, 0x78),
    ("dey", Imp, 0x88),
    ("txa", Imp, 0x8a),
    ("tya", Imp, 0x98),
    ("txs", Imp, 0x9a),
    ("tay", Imp, 0xa8),
    ("tax", Imp, 0xaa),
    ("clv", Imp, 0xb8),
    ("tsx", Imp, 0xba),
    ("iny", Imp, 0xc8),
    ("dex", Imp, 0xca),
    ("cld", Imp, 0xd8),
    ("inx", Imp, 0xe8),
    ("nop", Imp, 0xea),
    ("sed", Imp, 0xf8),
];

/// Walks the whole official instruction set, calling `f` with each
/// (mnemonic, mode, opcode). The encoder and the completeness test both read
/// the matrix through this, so there is no second copy of it anywhere.
pub fn for_each_opcode(mut f: impl FnMut(&'static str, Mode, u8)) {
    for (aaa, op) in G1_OPS.iter().enumerate() {
        for (bbb, mode) in G1_MODES.iter().enumerate() {
            // `STA #imm` (0x89) would store the accumulator into a literal.
            if *op == "sta" && *mode == Imm {
                continue;
            }
            f(op, *mode, (aaa as u8) << 5 | (bbb as u8) << 2 | 0b01);
        }
    }
    for (op, aaa, cols, index) in G2_ROWS {
        for bbb in cols {
            let Some(mode) = G2_MODES[*bbb as usize] else {
                continue;
            };
            let mode = if index == Index::Y {
                match mode {
                    ZpX => ZpY,
                    AbsX => AbsY,
                    m => m,
                }
            } else {
                mode
            };
            f(op, mode, aaa << 5 | bbb << 2 | 0b10);
        }
    }
    for (op, aaa, cols) in G0_ROWS {
        for bbb in cols {
            let Some(mode) = G0_MODES[*bbb as usize] else {
                continue;
            };
            // `cc = 00`, so there is nothing to or in for the group.
            f(op, mode, aaa << 5 | bbb << 2);
        }
    }
    for (flag, (clear, set)) in BRANCH_ROWS.iter().enumerate() {
        f(clear, Rel, 0x10 | (flag as u8) << 6);
        f(set, Rel, 0x10 | (flag as u8) << 6 | 0x20);
    }
    for (op, mode, opcode) in IRREGULAR {
        f(op, mode, opcode);
    }
}

/// Every (mode, opcode) pair `mnemonic` has. Empty when the mnemonic is not a
/// 6502 instruction at all.
fn forms(mnemonic: &str) -> Vec<(Mode, u8)> {
    let mut out = Vec::new();
    for_each_opcode(|name, mode, opcode| {
        if name == mnemonic {
            out.push((mode, opcode));
        }
    });
    out
}

fn opcode_for(forms: &[(Mode, u8)], mode: Mode) -> Option<u8> {
    forms.iter().find(|(m, _)| *m == mode).map(|(_, o)| *o)
}

// ---- operands -------------------------------------------------------------

enum Arg {
    Implied,
    Acc,
    Imm(ExprRef, Span),
    /// `expr`, `expr,x` or `expr,y`: zero page or absolute, decided by value.
    Direct(ExprRef, Option<Index>, Span),
    /// `(expr)`, `(expr,x)` or `(expr),y`.
    Indirect(ExprRef, Mode, Span),
}

fn parse_index(cx: &AsmCtx<'_>, toks: &[crate::lexer::Token]) -> Option<Index> {
    match common::sole_ident(cx, toks)?.as_str() {
        "x" => Some(Index::X),
        "y" => Some(Index::Y),
        _ => None,
    }
}

fn parse_operand(cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>, forms: &[(Mode, u8)]) -> Option<Arg> {
    let parts = common::operands(insn.operands);
    let whole = insn.span;
    match parts.as_slice() {
        [] => Some(Arg::Implied),
        [part] => {
            let part = *part;
            let span = common::span_of(part, whole);
            let Some((first, after)) = part.split_first() else {
                cx.error(span, "expected an operand");
                return None;
            };
            // `asl a`. Only the shift group has an accumulator mode, so `a`
            // stays an ordinary symbol name everywhere else.
            if opcode_for(forms, Acc).is_some()
                && common::sole_ident(cx, part).as_deref() == Some("a")
            {
                return Some(Arg::Acc);
            }
            // Both spellings of the immediate marker; see the module comment.
            if first.is_punct(Punct::Hash) || first.is_punct(Punct::Dollar) {
                let e = common::expr_of(cx, after, span)?;
                return Some(Arg::Imm(e, span));
            }
            if common::parenthesised(part) {
                let inner = common::inside_parens(part);
                match Cursor::new(inner).split_commas().as_slice() {
                    [_] | [] => {}
                    [base, index] => {
                        if parse_index(cx, index) != Some(Index::X) {
                            cx.error(span, "expected `x` in an indexed indirect operand");
                            return None;
                        }
                        let e = common::expr_of(cx, base, span)?;
                        return Some(Arg::Indirect(e, IndX, span));
                    }
                    _ => {
                        cx.error(span, "too many operands inside `( )`");
                        return None;
                    }
                }
                // `(expr)` is an indirect operand only where the instruction
                // has one; for everything else the parentheses are just
                // grouping, as in `lda (base+2)`.
                if opcode_for(forms, Ind).is_some() {
                    let e = common::expr_of(cx, inner, span)?;
                    return Some(Arg::Indirect(e, Ind, span));
                }
            }
            if let Some(reg @ ("a" | "x" | "y")) = common::sole_ident(cx, part).as_deref() {
                cx.error(
                    span,
                    format!(
                        "`{reg}` is a register, and `{}` takes an address here",
                        cx.name(insn.mnemonic)
                    ),
                );
                return None;
            }
            let e = common::expr_of(cx, part, span)?;
            Some(Arg::Direct(e, None, span))
        }
        [base, idx] => {
            let (base, idx) = (*base, *idx);
            let span = common::span_of(base, whole).to(common::span_of(idx, whole));
            let Some(index) = parse_index(cx, idx) else {
                cx.error(
                    common::span_of(idx, whole),
                    "expected `x` or `y` after the comma",
                );
                return None;
            };
            if common::parenthesised(base) && opcode_for(forms, IndY).is_some() {
                if index != Index::Y {
                    cx.error(span, "an indirect operand can only be indexed by `y`");
                    return None;
                }
                let e = common::expr_of(cx, common::inside_parens(base), span)?;
                return Some(Arg::Indirect(e, IndY, span));
            }
            let e = common::expr_of(cx, base, span)?;
            Some(Arg::Direct(e, Some(index), span))
        }
        _ => {
            cx.error(insn.span, "too many operands");
            None
        }
    }
}

// ---- encoding -------------------------------------------------------------

pub fn assemble(
    cx: &mut AsmCtx<'_>,
    insn: &InsnRequest<'_>,
    mnemonic: &str,
) -> Option<Vec<Variant>> {
    let forms = forms(mnemonic);
    if forms.is_empty() {
        return common::unknown(cx, insn.mnemonic_span, "6502", mnemonic);
    }
    if forms.iter().all(|(m, _)| *m == Imp) && !insn.operands.is_empty() {
        cx.error(insn.span, format!("`{mnemonic}` takes no operand"));
        return None;
    }
    let arg = parse_operand(cx, insn, &forms)?;

    match arg {
        Arg::Implied => {
            // A shift written without an operand means the accumulator, which
            // is how most 6502 sources spell it.
            let op = opcode_for(&forms, Imp).or_else(|| opcode_for(&forms, Acc));
            match op {
                Some(op) => Enc::op(&[op]).done(),
                None => {
                    cx.error(insn.span, format!("`{mnemonic}` needs an operand"));
                    None
                }
            }
        }
        Arg::Acc => match opcode_for(&forms, Acc) {
            Some(op) => Enc::op(&[op]).done(),
            None => common::bad_operands(cx, insn.span, mnemonic),
        },
        Arg::Imm(e, span) => match opcode_for(&forms, Imm) {
            Some(op) => {
                let mut enc = Enc::op(&[op]);
                enc.imm8(e, span);
                enc.done()
            }
            None => {
                cx.error(span, format!("`{mnemonic}` has no immediate form"));
                None
            }
        },
        Arg::Indirect(e, mode, span) => match opcode_for(&forms, mode) {
            Some(op) => {
                let mut enc = Enc::op(&[op]);
                if mode == Ind {
                    enc.imm16(e, span);
                } else {
                    enc.imm8(e, span);
                }
                enc.done()
            }
            None => {
                cx.error(
                    span,
                    format!("`{mnemonic}` has no {} form", mode.describe()),
                );
                None
            }
        },
        Arg::Direct(e, index, span) => direct(cx, mnemonic, &forms, e, index, span),
    }
}

/// Encodes a `expr` / `expr,x` / `expr,y` operand, choosing between the zero
/// page and absolute forms.
fn direct(
    cx: &mut AsmCtx<'_>,
    mnemonic: &str,
    forms: &[(Mode, u8)],
    e: ExprRef,
    index: Option<Index>,
    span: Span,
) -> Option<Vec<Variant>> {
    // A branch has no other form to compete with.
    if index.is_none()
        && let Some(op) = opcode_for(forms, Rel)
    {
        let mut enc = Enc::op(&[op]);
        enc.rel8(e, span);
        return enc.done();
    }

    let (zp_mode, abs_mode) = match index {
        None => (Zp, Abs),
        Some(Index::X) => (ZpX, AbsX),
        Some(Index::Y) => (ZpY, AbsY),
    };
    let zp = opcode_for(forms, zp_mode);
    let abs = opcode_for(forms, abs_mode);

    let zero_page = |op: u8| {
        let mut enc = Enc::op(&[op]);
        enc.imm8(e, span);
        enc.into_variant()
    };
    let absolute = |op: u8| {
        let mut enc = Enc::op(&[op]);
        enc.imm16(e, span);
        enc.into_variant()
    };

    match (cx.constant(e), zp, abs) {
        (_, None, None) => {
            cx.error(
                span,
                format!("`{mnemonic}` has no {} form", abs_mode.describe()),
            );
            None
        }
        // Known now: pick the short form when it exists and the value is in
        // the zero page, and diagnose an address that cannot be reached at
        // all (`stx 0x1234,y` has no absolute form).
        (Some(v), Some(op), _) if (0..=0xff).contains(&v) => Some(vec![zero_page(op)]),
        (Some(_), _, Some(op)) => Some(vec![absolute(op)]),
        (Some(v), Some(_), None) => {
            cx.error(
                span,
                format!(
                    "`{mnemonic}` only has a {} form, and {v} is outside the zero page (0 to 255)",
                    zp_mode.describe()
                ),
            );
            None
        }
        // Not known yet — a label, or an equate defined further down. The
        // natural answer is to offer both forms and let relaxation pick, but
        // that is wrong under `--base`: the layout pass relaxes with every
        // section at address 0 and only applies the base afterwards, so a
        // label at offset 0x13 of a ROM based at 0x8000 would be judged to be
        // in the zero page and then fail to fit. Until the core relaxes
        // against final addresses, a symbolic operand takes the absolute
        // form, which is always correct and costs one byte. Zero-page
        // variables defined before use still get the short form above.
        (None, _, Some(a)) => Some(vec![absolute(a)]),
        // No absolute form to fall back on (`stx sym,y`, `lda (sym),y`): the
        // final fixup check, which does see real addresses, will diagnose a
        // symbol that is not in the zero page.
        (None, Some(z), None) => Some(vec![zero_page(z)]),
    }
}
