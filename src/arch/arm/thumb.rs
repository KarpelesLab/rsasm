//! The T32 (Thumb) encoder.
//!
//! Thumb is variable length: most instructions are one halfword, but the
//! Thumb-2 additions are two, and many operations exist in both widths. Where
//! both are possible this returns the 16-bit encoding first and the 32-bit one
//! second, and lets the layout pass raise the choice when a branch turns out
//! not to reach. Everything else picks a width here, because the choice
//! depends on the operands rather than on an address.
//!
//! A 32-bit Thumb instruction is *two little-endian halfwords*, not one
//! little-endian word, so it is assembled here as `(hw2 << 16) | hw1` and
//! written out as four bytes — which is also the order a scatter function
//! sees, since the core reads the field back as a little-endian integer.

use super::imm;
use super::insn::{AL, Mnem, Width};
use super::operand::{Index, Mem, MemOffset, OperandKind, Shift};
use super::reg::{self, Reg};
use super::{Insn, encode, reloc};
use crate::arch::AsmCtx;
use crate::expr::ExprRef;
use crate::section::{Fixup, FixupKind, Variant};
use crate::source::Span;

pub const NOP: u16 = 0xbf00;

fn low(r: Reg) -> bool {
    r < 8
}

fn narrow(w: u16) -> Vec<Variant> {
    vec![Variant::new(w.to_le_bytes().to_vec())]
}

fn wide_bytes(hw1: u16, hw2: u16) -> Vec<u8> {
    let mut v = hw1.to_le_bytes().to_vec();
    v.extend_from_slice(&hw2.to_le_bytes());
    v
}

fn wide(hw1: u16, hw2: u16) -> Vec<Variant> {
    vec![Variant::new(wide_bytes(hw1, hw2))]
}

/// Rejects a condition suffix on anything but a branch: predication in Thumb
/// comes from an enclosing `it` block, which this backend does not implement.
fn unconditional(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<()> {
    if ins.cond_written && ins.cond != AL {
        cx.error(
            ins.span,
            format!(
                "`{}` is conditional, which in Thumb needs an `it` block; \
                 `it` is not supported by this backend",
                ins.text
            ),
        );
        return None;
    }
    Some(())
}

fn want_narrow(ins: &Insn<'_>) -> bool {
    ins.width != Width::Wide
}

fn want_wide(ins: &Insn<'_>) -> bool {
    ins.width != Width::Narrow
}

/// Reports that no encoding of this width exists, once every candidate has
/// been ruled out.
fn no_encoding(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    let hint = match ins.width {
        Width::Narrow => " as a 16-bit instruction",
        Width::Wide => " as a 32-bit instruction",
        Width::Any => "",
    };
    cx.error(
        ins.span,
        format!(
            "`{}` cannot be encoded in Thumb{hint} with these operands",
            ins.text
        ),
    );
    None
}

pub fn assemble(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    use Mnem::*;
    match ins.mnem {
        B | Bl | Bx | Blx => branch(cx, ins),
        Mov | Mvn => mov(cx, ins),
        Add | Sub => add_sub(cx, ins),
        Cmp => compare(cx, ins),
        Cmn | Tst => test(cx, ins),
        And | Eor | Orr | Bic | Adc | Sbc | Rsb => alu_reg(cx, ins),
        Lsl | Lsr | Asr | Ror => shift_insn(cx, ins),
        Rrx => {
            cx.error(ins.span, "`rrx` has no 16-bit Thumb encoding");
            None
        }
        Ldr | Str | Ldrb | Strb | Ldrh | Strh | Ldrsb | Ldrsh => load_store(cx, ins),
        Push | Pop => push_pop(cx, ins),
        Ldm(_) | Stm(_) => block_transfer(cx, ins),
        Mul | Mla | Mls | Umull | Umlal | Smull | Smlal => multiply(cx, ins),
        Movw | Movt => move_wide(cx, ins),
        Clz => clz(cx, ins),
        Rev | Rev16 | Revsh | Uxtb | Uxth | Sxtb | Sxth => unary(cx, ins),
        Nop => {
            unconditional(cx, ins)?;
            encode::arity(cx, ins, &[0])?;
            if want_narrow(ins) {
                Some(narrow(NOP))
            } else {
                Some(wide(0xf3af, 0x8000))
            }
        }
        Svc => {
            unconditional(cx, ins)?;
            encode::arity(cx, ins, &[1])?;
            let v = encode::imm_bits(cx, &ins.ops[0], 8)?;
            Some(narrow(0xdf00 | v as u16))
        }
        Bkpt => {
            unconditional(cx, ins)?;
            encode::arity(cx, ins, &[1])?;
            let v = encode::imm_bits(cx, &ins.ops[0], 8)?;
            Some(narrow(0xbe00 | v as u16))
        }
        Rsc | Teq | Mrs | Msr | Dmb | Dsb | Isb => {
            cx.error(
                ins.span,
                format!("`{}` is not supported in Thumb by this backend", ins.text),
            );
            None
        }
    }
}

// ---- branches --------------------------------------------------------------

/// 16-bit `b <label>`: an 11-bit halfword offset.
fn scatter_b16(w: u64, v: i64) -> u64 {
    (w & 0xf800) | (((v >> 1) as u64) & 0x7ff)
}

/// 16-bit `b<cond> <label>`: an 8-bit halfword offset.
fn scatter_bcc16(w: u64, v: i64) -> u64 {
    (w & 0xff00) | (((v >> 1) as u64) & 0xff)
}

/// The J-bit encoding shared by `b.w` and `bl`: the two bits that
/// extend the range are stored inverted relative to the sign bit, so that a
/// short forward branch has them clear.
fn scatter_t4(v: i64, low_bits: u64) -> u64 {
    let v = v as u64;
    let s = (v >> 24) & 1;
    let i1 = (v >> 23) & 1;
    let i2 = (v >> 22) & 1;
    let j1 = (i1 ^ 1) ^ s;
    let j2 = (i2 ^ 1) ^ s;
    let hw1 = 0xf000 | (s << 10) | ((v >> 12) & 0x3ff);
    let hw2 = low_bits | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7ff);
    (hw2 << 16) | hw1
}

fn scatter_bw(_word: u64, v: i64) -> u64 {
    scatter_t4(v, 0x9000)
}

fn scatter_bl(_word: u64, v: i64) -> u64 {
    scatter_t4(v, 0xd000)
}

/// `b<cond>.w`: a 20-bit range with the condition in the first halfword and
/// the J bits stored directly rather than inverted.
fn scatter_bcc_w(w: u64, v: i64) -> u64 {
    let cond = (w >> 6) & 0xf;
    let v = v as u64;
    let s = (v >> 20) & 1;
    let j2 = (v >> 19) & 1;
    let j1 = (v >> 18) & 1;
    let hw1 = 0xf000 | (s << 10) | (cond << 6) | ((v >> 12) & 0x3f);
    let hw2 = 0x8000 | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7ff);
    (hw2 << 16) | hw1
}

fn fixed(bytes: Vec<u8>, expr: ExprRef, kind: FixupKind, span: Span) -> Variant {
    Variant {
        bytes,
        fixups: vec![Fixup {
            offset: 0,
            expr,
            kind,
            span,
        }],
    }
}

fn branch(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[1])?;
    let op = &ins.ops[0];

    if matches!(ins.mnem, Mnem::Bx | Mnem::Blx) && op.reg().is_some() {
        unconditional(cx, ins)?;
        let rm = encode::reg_of(cx, op)? as u16;
        let base = if ins.mnem == Mnem::Bx { 0x4700 } else { 0x4780 };
        return Some(narrow(base | (rm << 3)));
    }

    let Some(e) = op.imm() else {
        cx.error(op.span, "expected a branch target");
        return None;
    };

    // Thumb reads the PC as the address of the instruction plus four,
    // whatever the instruction's own length.
    match ins.mnem {
        Mnem::Bl => {
            unconditional(cx, ins)?;
            let kind = FixupKind::pcrel(4, 4)
                .with_field(25, 2)
                .with_reloc(reloc::THM_CALL)
                .scatter(scatter_bl);
            Some(vec![fixed(wide_bytes(0xf000, 0xd000), e, kind, ins.span)])
        }
        Mnem::Blx => {
            // Thumb `blx <label>` measures its offset from the PC rounded down
            // to a word boundary, which depends on where the instruction lands
            // and so cannot be expressed as a fixed PC adjustment.
            cx.error(
                op.span,
                "`blx <label>` from Thumb is not supported; use `bl` for Thumb \
                 targets or `blx <register>`",
            );
            None
        }
        Mnem::Bx => {
            cx.error(op.span, "`bx` takes a register");
            None
        }
        _ if ins.cond != AL => {
            let mut out = Vec::new();
            if want_narrow(ins) {
                // No relocation: a 2-byte field cannot carry one, so an
                // unresolved target escalates to the wide form instead.
                let kind = FixupKind::pcrel(2, 4)
                    .with_field(9, 2)
                    .scatter(scatter_bcc16);
                out.push(fixed(
                    (0xd000u16 | ((ins.cond as u16) << 8))
                        .to_le_bytes()
                        .to_vec(),
                    e,
                    kind,
                    ins.span,
                ));
            }
            if want_wide(ins) {
                let kind = FixupKind::pcrel(4, 4)
                    .with_field(21, 2)
                    .with_reloc(reloc::THM_JUMP19)
                    .scatter(scatter_bcc_w);
                // The condition sits in the first halfword; the scatter
                // function reads it back out of the placeholder.
                out.push(fixed(
                    wide_bytes(0xf000 | ((ins.cond as u16) << 6), 0x8000),
                    e,
                    kind,
                    ins.span,
                ));
            }
            if out.is_empty() {
                return no_encoding(cx, ins);
            }
            Some(out)
        }
        _ => {
            let mut out = Vec::new();
            if want_narrow(ins) {
                let kind = FixupKind::pcrel(2, 4)
                    .with_field(12, 2)
                    .scatter(scatter_b16);
                out.push(fixed(0xe000u16.to_le_bytes().to_vec(), e, kind, ins.span));
            }
            if want_wide(ins) {
                let kind = FixupKind::pcrel(4, 4)
                    .with_field(25, 2)
                    .with_reloc(reloc::THM_JUMP24)
                    .scatter(scatter_bw);
                out.push(fixed(wide_bytes(0xf000, 0x9000), e, kind, ins.span));
            }
            if out.is_empty() {
                return no_encoding(cx, ins);
            }
            Some(out)
        }
    }
}

// ---- moves -----------------------------------------------------------------

/// Splits the twelve bits of a `ThumbExpandImm` across the two halfwords.
fn expand_parts(imm12: u32) -> (u16, u16) {
    let i = ((imm12 >> 11) & 1) as u16;
    let rest = (((imm12 >> 8) & 7) << 12) as u16 | (imm12 & 0xff) as u16;
    (i, rest)
}

fn mov(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let src = &ins.ops[1];
    let s = u16::from(ins.set_flags);

    if ins.mnem == Mnem::Mvn {
        // Only the flag-setting low-register form is 16 bits.
        if let Some(rm) = src.reg()
            && ins.set_flags
            && low(rd)
            && low(rm)
            && want_narrow(ins)
        {
            return Some(narrow(0x43c0 | ((rm as u16) << 3) | rd as u16));
        }
        return no_encoding(cx, ins);
    }

    if let Some(rm) = src.reg() {
        if ins.set_flags && low(rd) && low(rm) && want_narrow(ins) {
            // `movs rd, rm` is `lsls rd, rm, #0`.
            return Some(narrow(((rm as u16) << 3) | rd as u16));
        }
        if !ins.set_flags && want_narrow(ins) {
            let rd = rd as u16;
            return Some(narrow(
                0x4600 | ((rd & 8) << 4) | ((rm as u16) << 3) | (rd & 7),
            ));
        }
        return no_encoding(cx, ins);
    }

    let v = encode::imm32(cx, src)?;
    if ins.set_flags && low(rd) && v <= 0xff && want_narrow(ins) {
        return Some(narrow(0x2000 | ((rd as u16) << 8) | v as u16));
    }
    if !want_wide(ins) {
        return no_encoding(cx, ins);
    }
    if let Some(imm12) = imm::thumb_expand(v) {
        let (i, rest) = expand_parts(imm12);
        return Some(wide(
            0xf04f | (i << 10) | (s << 4),
            rest | ((rd as u16) << 8),
        ));
    }
    // `movw` reaches any 16-bit constant, but has no flag-setting form.
    if v <= 0xffff && !ins.set_flags {
        return Some(move_wide_bits(rd, v, false));
    }
    // Last, the complement: `mov r0, #-2` is `mvn r0, #1`. LLVM stops short of
    // doing this for `movs`, and so does this.
    if !ins.set_flags
        && let Some(imm12) = imm::thumb_expand(!v)
    {
        let (i, rest) = expand_parts(imm12);
        return Some(wide(0xf06f | (i << 10), rest | ((rd as u16) << 8)));
    }
    cx.error(
        src.span,
        format!(
            "{} (0x{v:08x}) is not a Thumb expandable immediate, does not fit in \
             the 16 bits of `movw`, and its complement is not expandable either",
            v as i32
        ),
    );
    None
}

fn move_wide_bits(rd: Reg, v: u32, top: bool) -> Vec<Variant> {
    let imm4 = ((v >> 12) & 0xf) as u16;
    let i = ((v >> 11) & 1) as u16;
    let imm3 = ((v >> 8) & 7) as u16;
    let imm8 = (v & 0xff) as u16;
    let base = if top { 0xf2c0 } else { 0xf240 };
    wide(
        base | (i << 10) | imm4,
        (imm3 << 12) | ((rd as u16) << 8) | imm8,
    )
}

fn move_wide(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let v = encode::imm_bits(cx, &ins.ops[1], 16)?;
    Some(move_wide_bits(rd, v, ins.mnem == Mnem::Movt))
}

// ---- add and subtract ------------------------------------------------------

fn add_sub(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::arity(cx, ins, &[2, 3])?;
    let sub = ins.mnem == Mnem::Sub;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let two_operand = ins.ops.len() == 2;
    // `add r0, r1` and `add r0, #1` both leave the first source implicit.
    let (rn, src) = if two_operand {
        (rd, &ins.ops[1])
    } else {
        (encode::reg_of(cx, &ins.ops[1])?, &ins.ops[2])
    };
    let s = u16::from(ins.set_flags);

    if let Some(rm) = src.reg() {
        if ins.set_flags && low(rd) && low(rn) && low(rm) && want_narrow(ins) {
            let base = if sub { 0x1a00 } else { 0x1800 };
            return Some(narrow(
                base | ((rm as u16) << 6) | ((rn as u16) << 3) | rd as u16,
            ));
        }
        if !ins.set_flags && !sub && rd == rn && want_narrow(ins) {
            let rd = rd as u16;
            return Some(narrow(
                0x4400 | ((rd & 8) << 4) | ((rm as u16) << 3) | (rd & 7),
            ));
        }
        if want_wide(ins) {
            let base = if sub { 0xeba0 } else { 0xeb00 };
            return Some(wide(
                base | (s << 4) | rn as u16,
                ((rd as u16) << 8) | rm as u16,
            ));
        }
        return no_encoding(cx, ins);
    }
    if let OperandKind::Shifted { .. } = src.kind {
        return no_encoding(cx, ins);
    }

    let written = encode::imm_of(cx, src)?;
    // A negative constant is the other operation with the sign removed, the
    // same substitution A32 makes.
    let sub = if written < 0 { !sub } else { sub };
    let Some(v) = u32::try_from(written.unsigned_abs()).ok() else {
        cx.error(
            src.span,
            format!("immediate {written} does not fit in 32 bits"),
        );
        return None;
    };

    if want_narrow(ins) {
        if rn == reg::SP && rd == reg::SP && v.is_multiple_of(4) && v / 4 <= 0x7f {
            let base = if sub { 0xb080 } else { 0xb000 };
            return Some(narrow(base | (v / 4) as u16));
        }
        if !sub
            && rn == reg::SP
            && low(rd)
            && !ins.set_flags
            && v.is_multiple_of(4)
            && v / 4 <= 0xff
        {
            return Some(narrow(0xa800 | ((rd as u16) << 8) | (v / 4) as u16));
        }
        if ins.set_flags && low(rd) && low(rn) {
            // Which 16-bit form wins depends on how the source spelled it:
            // `adds r0, #1` is the 8-bit form and `adds r0, r0, #1` the 3-bit
            // one, even though they mean the same thing. Both GNU as and LLVM
            // keep the shape the programmer wrote.
            let imm8 = rd == rn && v <= 0xff;
            let base8 = if sub { 0x3800 } else { 0x3000 };
            if imm8 && two_operand {
                return Some(narrow(base8 | ((rd as u16) << 8) | v as u16));
            }
            if v <= 7 {
                let base = if sub { 0x1e00 } else { 0x1c00 };
                return Some(narrow(
                    base | ((v as u16) << 6) | ((rn as u16) << 3) | rd as u16,
                ));
            }
            if imm8 {
                return Some(narrow(base8 | ((rd as u16) << 8) | v as u16));
            }
        }
    }
    if !want_wide(ins) {
        return no_encoding(cx, ins);
    }
    if let Some(imm12) = imm::thumb_expand(v) {
        let (i, rest) = expand_parts(imm12);
        let base = if sub { 0xf1a0 } else { 0xf100 };
        return Some(wide(
            base | (i << 10) | (s << 4) | rn as u16,
            rest | ((rd as u16) << 8),
        ));
    }
    // `addw`/`subw` take a plain twelve-bit constant, but cannot set flags.
    if v <= 0xfff && !ins.set_flags {
        let i = ((v >> 11) & 1) as u16;
        let imm3 = ((v >> 8) & 7) as u16;
        let imm8 = (v & 0xff) as u16;
        let base = if sub { 0xf2a0 } else { 0xf200 };
        return Some(wide(
            base | (i << 10) | rn as u16,
            (imm3 << 12) | ((rd as u16) << 8) | imm8,
        ));
    }
    cx.error(
        src.span,
        format!(
            "{v} is neither a Thumb expandable immediate nor a 12-bit constant, so \
             `{}` cannot encode it",
            ins.text
        ),
    );
    None
}

// ---- comparisons and the register ALU forms --------------------------------

fn compare(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rn = encode::reg_of(cx, &ins.ops[0])?;
    let src = &ins.ops[1];
    if let Some(rm) = src.reg() {
        if want_narrow(ins) {
            if low(rn) && low(rm) {
                return Some(narrow(0x4280 | ((rm as u16) << 3) | rn as u16));
            }
            let rn = rn as u16;
            return Some(narrow(
                0x4500 | ((rn & 8) << 4) | ((rm as u16) << 3) | (rn & 7),
            ));
        }
        return no_encoding(cx, ins);
    }
    let v = encode::imm32(cx, src)?;
    if low(rn) && v <= 0xff && want_narrow(ins) {
        return Some(narrow(0x2800 | ((rn as u16) << 8) | v as u16));
    }
    if !want_wide(ins) {
        return no_encoding(cx, ins);
    }
    if let Some(imm12) = imm::thumb_expand(v) {
        let (i, rest) = expand_parts(imm12);
        return Some(wide(0xf1b0 | (i << 10) | rn as u16, rest | 0x0f00));
    }
    // `cmp r0, #-300` compares against the negation: `cmn r0, #300`.
    if let Some(imm12) = imm::thumb_expand(v.wrapping_neg()) {
        let (i, rest) = expand_parts(imm12);
        return Some(wide(0xf110 | (i << 10) | rn as u16, rest | 0x0f00));
    }
    cx.error(
        src.span,
        format!(
            "{} (0x{v:08x}) is not a Thumb expandable immediate, and neither is \
             its negation",
            v as i32
        ),
    );
    None
}

fn test(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rn = encode::reg_of(cx, &ins.ops[0])?;
    let Some(rm) = ins.ops[1].reg() else {
        return no_encoding(cx, ins);
    };
    if !low(rn) || !low(rm) || !want_narrow(ins) {
        return no_encoding(cx, ins);
    }
    let op: u16 = if ins.mnem == Mnem::Tst { 8 } else { 11 };
    Some(narrow(0x4000 | (op << 6) | ((rm as u16) << 3) | rn as u16))
}

/// The 16-bit register-to-register ALU group, which always sets the flags and
/// only reaches `r0`-`r7`.
fn alu_reg(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    let op: u16 = match ins.mnem {
        Mnem::And => 0,
        Mnem::Eor => 1,
        Mnem::Adc => 5,
        Mnem::Sbc => 6,
        Mnem::Rsb => 9,
        Mnem::Orr => 12,
        _ => 14,
    };
    // `rsbs rd, rn, #0` is Thumb's negate; the immediate is part of the
    // spelling and carries no bits.
    if ins.mnem == Mnem::Rsb {
        encode::arity(cx, ins, &[3])?;
        let rd = encode::reg_of(cx, &ins.ops[0])?;
        let rn = encode::reg_of(cx, &ins.ops[1])?;
        let v = encode::imm_of(cx, &ins.ops[2])?;
        if v != 0 || !ins.set_flags || !low(rd) || !low(rn) || !want_narrow(ins) {
            return no_encoding(cx, ins);
        }
        return Some(narrow(0x4000 | (op << 6) | ((rn as u16) << 3) | rd as u16));
    }
    encode::arity(cx, ins, &[2, 3])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let (rn, src) = if ins.ops.len() == 2 {
        (rd, &ins.ops[1])
    } else {
        (encode::reg_of(cx, &ins.ops[1])?, &ins.ops[2])
    };
    let Some(rm) = src.reg() else {
        return no_encoding(cx, ins);
    };
    if !ins.set_flags || rd != rn || !low(rd) || !low(rm) || !want_narrow(ins) {
        return no_encoding(cx, ins);
    }
    Some(narrow(0x4000 | (op << 6) | ((rm as u16) << 3) | rd as u16))
}

fn shift_insn(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::arity(cx, ins, &[2, 3])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let (rm, amount) = if ins.ops.len() == 2 {
        (rd, &ins.ops[1])
    } else {
        (encode::reg_of(cx, &ins.ops[1])?, &ins.ops[2])
    };
    if !ins.set_flags || !low(rd) || !low(rm) || !want_narrow(ins) {
        return no_encoding(cx, ins);
    }
    // A register shift amount is the flag-setting two-operand form, so the
    // destination has to be the value being shifted.
    if let Some(rs) = amount.reg() {
        if rd != rm || !low(rs) {
            return no_encoding(cx, ins);
        }
        let op: u16 = match ins.mnem {
            Mnem::Lsl => 2,
            Mnem::Lsr => 3,
            Mnem::Asr => 4,
            _ => 7,
        };
        return Some(narrow(0x4000 | (op << 6) | ((rs as u16) << 3) | rd as u16));
    }
    if ins.mnem == Mnem::Ror {
        cx.error(
            ins.span,
            "`ror` by an immediate has no 16-bit Thumb encoding",
        );
        return None;
    }
    let v = encode::imm_of(cx, amount)?;
    let (lo, hi) = match ins.mnem {
        Mnem::Lsl => (0, 31),
        _ => (1, 32),
    };
    if v < lo || v > hi {
        cx.error(
            amount.span,
            format!("shift amount {v} is out of range ({lo} to {hi})"),
        );
        return None;
    }
    let field = (v as u16) & 0x1f;
    let base: u16 = match ins.mnem {
        Mnem::Lsl => 0x0000,
        Mnem::Lsr => 0x0800,
        _ => 0x1000,
    };
    Some(narrow(base | (field << 6) | ((rm as u16) << 3) | rd as u16))
}

// ---- loads and stores ------------------------------------------------------

fn load_store(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rt = encode::reg_of(cx, &ins.ops[0])?;
    let OperandKind::Mem(mem) = ins.ops[1].kind else {
        cx.error(
            ins.ops[1].span,
            format!("expected a memory operand, found {}", ins.ops[1].describe()),
        );
        return None;
    };
    if mem.index != Index::Offset {
        cx.error(
            mem.span,
            "pre- and post-indexed addressing is not supported in Thumb by this backend",
        );
        return None;
    }
    if want_narrow(ins)
        && let Some(v) = narrow_load_store(ins.mnem, rt, &mem)
    {
        return Some(narrow(v));
    }
    if !want_wide(ins) {
        return no_encoding(cx, ins);
    }
    let MemOffset::Imm(off) = mem.offset else {
        if matches!(mem.offset, MemOffset::None) {
            return wide_load_store(cx, ins, rt, mem.base, 0);
        }
        return no_encoding(cx, ins);
    };
    if !(0..=0xfff).contains(&off) {
        cx.error(
            mem.span,
            format!("offset {off} does not fit in the 12-bit Thumb field (0 to 4095)"),
        );
        return None;
    }
    wide_load_store(cx, ins, rt, mem.base, off as u16)
}

fn narrow_load_store(mnem: Mnem, rt: Reg, mem: &Mem) -> Option<u16> {
    let base = mem.base;
    match mem.offset {
        MemOffset::None | MemOffset::Imm(_) => {
            let off = match mem.offset {
                MemOffset::Imm(v) => v,
                _ => 0,
            };
            // Negative or huge offsets have no 16-bit form; the caller's wide
            // path reports the range.
            let Ok(off) = u32::try_from(off) else {
                return None;
            };
            // The stack forms have their own opcodes and a wider offset.
            if base == reg::SP && low(rt) && matches!(mnem, Mnem::Ldr | Mnem::Str) {
                if !off.is_multiple_of(4) || off / 4 > 0xff {
                    return None;
                }
                let opc: u16 = if mnem == Mnem::Ldr { 0x9800 } else { 0x9000 };
                return Some(opc | ((rt as u16) << 8) | (off / 4) as u16);
            }
            if !low(rt) || !low(base) {
                return None;
            }
            let (opc, scale, max): (u16, u32, u32) = match mnem {
                Mnem::Ldr => (0x6800, 4, 31),
                Mnem::Str => (0x6000, 4, 31),
                Mnem::Ldrb => (0x7800, 1, 31),
                Mnem::Strb => (0x7000, 1, 31),
                Mnem::Ldrh => (0x8800, 2, 31),
                Mnem::Strh => (0x8000, 2, 31),
                _ => return None,
            };
            if !off.is_multiple_of(scale) || off / scale > max {
                return None;
            }
            Some(opc | ((off / scale) as u16) << 6 | ((base as u16) << 3) | rt as u16)
        }
        MemOffset::Reg {
            rm,
            add,
            shift,
            amount,
        } => {
            if !add || amount != 0 || shift != Shift::Lsl {
                return None;
            }
            if !low(rt) || !low(base) || !low(rm) {
                return None;
            }
            let opc: u16 = match mnem {
                Mnem::Str => 0x5000,
                Mnem::Strh => 0x5200,
                Mnem::Strb => 0x5400,
                Mnem::Ldrsb => 0x5600,
                Mnem::Ldr => 0x5800,
                Mnem::Ldrh => 0x5a00,
                Mnem::Ldrb => 0x5c00,
                Mnem::Ldrsh => 0x5e00,
                _ => return None,
            };
            Some(opc | ((rm as u16) << 6) | ((base as u16) << 3) | rt as u16)
        }
    }
}

fn wide_load_store(
    cx: &mut AsmCtx<'_>,
    ins: &Insn<'_>,
    rt: Reg,
    base: Reg,
    off: u16,
) -> Option<Vec<Variant>> {
    let opc: u16 = match ins.mnem {
        Mnem::Strb => 0xf880,
        Mnem::Ldrb => 0xf890,
        Mnem::Strh => 0xf8a0,
        Mnem::Ldrh => 0xf8b0,
        Mnem::Str => 0xf8c0,
        Mnem::Ldr => 0xf8d0,
        Mnem::Ldrsb => 0xf990,
        Mnem::Ldrsh => 0xf9b0,
        _ => return no_encoding(cx, ins),
    };
    Some(wide(opc | base as u16, ((rt as u16) << 12) | off))
}

fn push_pop(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[1])?;
    let OperandKind::List(mask) = ins.ops[0].kind else {
        cx.error(ins.ops[0].span, "expected a register list");
        return None;
    };
    let push = ins.mnem == Mnem::Push;
    // The 16-bit forms carry r0-r7 plus exactly one of lr (push) or pc (pop).
    let extra = if push { 1 << reg::LR } else { 1 << reg::PC };
    if mask & !(0xff | extra) != 0 {
        cx.error(
            ins.ops[0].span,
            format!(
                "a 16-bit Thumb `{}` can only list r0-r7 and {}",
                ins.text,
                if push { "lr" } else { "pc" }
            ),
        );
        return None;
    }
    let base: u16 = if push { 0xb400 } else { 0xbc00 };
    let bit = u16::from(mask & extra != 0) << 8;
    Some(narrow(base | bit | (mask & 0xff)))
}

fn block_transfer(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let (Mnem::Ldm(mode) | Mnem::Stm(mode)) = ins.mnem else {
        return None;
    };
    let load = matches!(ins.mnem, Mnem::Ldm(_));
    if mode.before || !mode.increment {
        cx.error(
            ins.span,
            "only the increment-after form of `ldm`/`stm` has a 16-bit Thumb encoding",
        );
        return None;
    }
    let rn = encode::reg_of(cx, &ins.ops[0])?;
    let OperandKind::List(mask) = ins.ops[1].kind else {
        cx.error(ins.ops[1].span, "expected a register list");
        return None;
    };
    if !low(rn) || mask & !0xff != 0 {
        cx.error(ins.span, "a 16-bit Thumb `ldm`/`stm` only reaches r0-r7");
        return None;
    }
    if !ins.ops[0].writeback && (!load || mask & (1 << rn) == 0) {
        cx.error(
            ins.ops[0].span,
            "a 16-bit Thumb `ldm`/`stm` writes back unless the base is in the list",
        );
        return None;
    }
    let base: u16 = if load { 0xc800 } else { 0xc000 };
    Some(narrow(base | ((rn as u16) << 8) | mask))
}

// ---- 32-bit arithmetic -----------------------------------------------------

fn multiply(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    let ops = ins.ops;
    match ins.mnem {
        Mnem::Mul => {
            encode::arity(cx, ins, &[3])?;
            let rd = encode::reg_of(cx, &ops[0])?;
            let rn = encode::reg_of(cx, &ops[1])?;
            let rm = encode::reg_of(cx, &ops[2])?;
            // `muls rdm, rn, rdm` is the 16-bit form.
            if ins.set_flags && want_narrow(ins) {
                if low(rd) && low(rn) && rd == rm {
                    return Some(narrow(0x4340 | ((rn as u16) << 3) | rd as u16));
                }
                return no_encoding(cx, ins);
            }
            if ins.set_flags || !want_wide(ins) {
                return no_encoding(cx, ins);
            }
            Some(wide(
                0xfb00 | rn as u16,
                0xf000 | ((rd as u16) << 8) | rm as u16,
            ))
        }
        Mnem::Mla | Mnem::Mls => {
            encode::no_flags(cx, ins)?;
            encode::arity(cx, ins, &[4])?;
            let rd = encode::reg_of(cx, &ops[0])?;
            let rn = encode::reg_of(cx, &ops[1])?;
            let rm = encode::reg_of(cx, &ops[2])?;
            let ra = encode::reg_of(cx, &ops[3])?;
            let tail: u16 = if ins.mnem == Mnem::Mls { 0x10 } else { 0 };
            Some(wide(
                0xfb00 | rn as u16,
                ((ra as u16) << 12) | ((rd as u16) << 8) | tail | rm as u16,
            ))
        }
        _ => {
            encode::no_flags(cx, ins)?;
            encode::arity(cx, ins, &[4])?;
            let lo = encode::reg_of(cx, &ops[0])?;
            let hi = encode::reg_of(cx, &ops[1])?;
            let rn = encode::reg_of(cx, &ops[2])?;
            let rm = encode::reg_of(cx, &ops[3])?;
            let base: u16 = match ins.mnem {
                Mnem::Smull => 0xfb80,
                Mnem::Umlal => 0xfbe0,
                Mnem::Smlal => 0xfbc0,
                _ => 0xfba0,
            };
            Some(wide(
                base | rn as u16,
                ((lo as u16) << 12) | ((hi as u16) << 8) | rm as u16,
            ))
        }
    }
}

fn clz(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let rm = encode::reg_of(cx, &ins.ops[1])?;
    Some(wide(
        0xfab0 | rm as u16,
        0xf080 | ((rd as u16) << 8) | rm as u16,
    ))
}

fn unary(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    let rm = encode::reg_of(cx, &ins.ops[1])?;
    if !low(rd) || !low(rm) || !want_narrow(ins) {
        return no_encoding(cx, ins);
    }
    let base: u16 = match ins.mnem {
        Mnem::Rev => 0xba00,
        Mnem::Rev16 => 0xba40,
        Mnem::Revsh => 0xbac0,
        Mnem::Sxth => 0xb200,
        Mnem::Sxtb => 0xb240,
        Mnem::Uxth => 0xb280,
        _ => 0xb2c0,
    };
    Some(narrow(base | ((rm as u16) << 3) | rd as u16))
}
