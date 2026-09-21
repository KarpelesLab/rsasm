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
use crate::section::{Fixup, FixupKind, LinkValue, Variant};
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

/// Rejects a condition suffix on anything but a branch outside an `it` block:
/// predication in Thumb comes from the block. (Inside one, the condition has
/// already been checked against the block's and taken off.)
fn unconditional(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<()> {
    if ins.cond_written && ins.cond != AL {
        cx.error(
            ins.span,
            format!(
                "`{}` is conditional, which in Thumb takes an `it` block",
                ins.text
            ),
        );
        return None;
    }
    Some(())
}

/// Whether a 16-bit data-processing form that sets the flags outside an `it`
/// block, and does not inside one, fits: `adds r0, r1, r2` outside a block
/// and `addeq r0, r1, r2` inside one are both 16 bits, while `add` outside
/// and `addseq` inside need 32.
fn sets_flags16(ins: &Insn<'_>) -> bool {
    ins.set_flags != ins.in_it
}

/// Where an `it` block's state lives in `ArchState::private`: the ITSTATE
/// byte, the condition of the next instruction in the top nibble and the
/// mask of the ones after it below.
const IT_SHIFT: u32 = 8;

fn itstate(cx: &AsmCtx<'_>) -> u8 {
    (cx.state.private >> IT_SHIFT) as u8
}

fn set_itstate(cx: &mut AsmCtx<'_>, it: u8) {
    cx.state.private = (cx.state.private & !(0xff << IT_SHIFT)) | ((it as u64) << IT_SHIFT);
}

/// Whether an instruction leaves its `it` block by changing the PC, which
/// only the last instruction of a block may do.
fn is_branch(ins: &Insn<'_>) -> bool {
    matches!(ins.mnem, Mnem::B | Mnem::Bl | Mnem::Bx | Mnem::Blx)
        || (matches!(ins.mnem, Mnem::Mov | Mnem::Add | Mnem::Ldr)
            && ins.ops.first().and_then(|op| op.reg()) == Some(reg::PC))
}

/// `it`, `itt`, `ite` and the rest. `pattern` holds the letters after the
/// first `t` as bits, `e` set, from the high bit down, followed by a set
/// bit that ends them: the mask field for a condition whose low bit is
/// clear.
fn it_block(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, pattern: u8) -> Option<Vec<Variant>> {
    encode::arity(cx, ins, &[1])?;
    let op = &ins.ops[0];
    let Some(cond) = op.word.as_deref().and_then(super::insn::condition) else {
        cx.error(op.span, "expected a condition code");
        return None;
    };
    // The letters are relative to the condition: a `t` repeats it, so with
    // an odd condition every letter bit flips, and the end bit does not.
    let end = pattern & pattern.wrapping_neg();
    let letters = pattern & !end & 0xf;
    let mask = if cond & 1 != 0 {
        letters ^ (0xf & !(end | (end - 1)))
    } else {
        letters
    } | end;
    set_itstate(cx, (cond << 4) | mask);
    Some(narrow(0xbf00 | ((cond as u16) << 4) | mask as u16))
}

/// The ITSTATE after one instruction of a block: the mask shifts into the
/// condition's low bit, and the block ends with its end bit.
fn it_advance(it: u8) -> u8 {
    if it & 0x7 == 0 {
        0
    } else {
        (it & 0xe0) | ((it << 1) & 0x1f)
    }
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

/// Assembles one Thumb instruction, keeping track of the `it` block it is in.
///
/// The checks are GNU as's: an instruction in a block must carry the block's
/// condition, or its inverse where the block says `e`; one that changes the
/// PC must be the block's last; and an `al` block allows no instruction at
/// all. Outside a block only a branch may carry a condition, as GNU as's
/// default `-mimplicit-it=arm` has it: no block is made up for Thumb code.
/// The instruction is then encoded without its condition, which the block
/// supplies.
pub fn assemble(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    let it = itstate(cx);
    if let Mnem::It(pattern) = ins.mnem {
        if it & 0xf != 0 {
            cx.error(
                ins.span,
                "`it` falls within the range of a previous `it` block",
            );
            return None;
        }
        return it_block(cx, ins, pattern);
    }
    if it & 0xf == 0 {
        return encode_insn(cx, ins);
    }
    set_itstate(cx, it_advance(it));
    let expected = it >> 4;
    if !ins.cond_written || expected == AL {
        cx.error(
            ins.span,
            format!(
                "`{}` is not allowed in an `it` block without its condition",
                ins.text
            ),
        );
        return None;
    }
    if ins.cond != expected {
        let want = super::insn::condition_name(expected);
        cx.error(
            ins.span,
            format!(
                "`{}` has the wrong condition for this `it` block, which expects `{want}` here",
                ins.text
            ),
        );
        return None;
    }
    if is_branch(ins) && it & 0xf != 0x8 {
        cx.error(
            ins.span,
            format!(
                "`{}` is a branch, which must be the last instruction in its `it` block",
                ins.text
            ),
        );
        return None;
    }
    let inner = Insn {
        cond: AL,
        cond_written: false,
        in_it: true,
        ..*ins
    };
    encode_insn(cx, &inner)
}

fn encode_insn(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    use Mnem::*;
    match ins.mnem {
        It(_) => None,
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
        Adr => adr(cx, ins),
        Adrl => {
            cx.error(ins.span, "`adrl` is an ARM instruction; Thumb has `adr`");
            None
        }
        Ldm(_) | Stm(_) => block_transfer(cx, ins),
        Mul | Mla | Mls | Umull | Umlal | Smull | Smlal => multiply(cx, ins),
        Movw | Movt => move_wide(cx, ins),
        Ext(at) => super::generic::assemble(cx, ins, at),
        Rsc | Teq | Mrs | Msr => {
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

/// `blx <label>`, which clears bit 12 of the second halfword. Its offset is
/// from the PC rounded down to a word and lands on a word, and GNU as rounds
/// an odd one up rather than refuse it.
fn scatter_blx(_word: u64, v: i64) -> u64 {
    scatter_t4((v + 3) & !3, 0xc000)
}

/// Thumb `bl label`.
pub fn bl_kind() -> FixupKind {
    FixupKind::pcrel(4, 4)
        .with_field(25, 2)
        .with_reloc(reloc::THM_CALL)
        .link(LinkValue::Interwork(super::IW_THUMB_BL))
        .scatter(scatter_bl)
}

/// Thumb `blx label`, into ARM code.
pub fn blx_kind() -> FixupKind {
    FixupKind::pcrel(4, 4)
        .with_pc_align(4)
        .with_field(25, 2)
        .with_reloc(reloc::THM_CALL)
        .link(LinkValue::Interwork(super::IW_THUMB_BLX))
        .scatter(scatter_blx)
}

/// A `blx` GNU as turns into `bl`, for a call that stays in Thumb. It keeps
/// the `blx`'s base, the PC rounded down to a word, so a call from an
/// instruction that is not on a word boundary lands two bytes past its
/// target; GNU as does that, and warns.
pub fn blx_as_bl_kind() -> FixupKind {
    FixupKind {
        link: LinkValue::Plain,
        ..blx_kind()
    }
    .scatter(scatter_bl)
}

/// `bl` rewritten as `blx`: bit 12 of the second halfword cleared.
pub fn to_blx(w: u64) -> u64 {
    w & !(0x1000 << 16)
}

/// `blx` rewritten as `bl`.
pub fn to_bl(w: u64) -> u64 {
    w | (0x1000 << 16)
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
            Some(vec![fixed(
                wide_bytes(0xf000, 0xd000),
                e,
                bl_kind(),
                ins.span,
            )])
        }
        Mnem::Blx => {
            unconditional(cx, ins)?;
            Some(vec![fixed(
                wide_bytes(0xf000, 0xc000),
                e,
                blx_kind(),
                ins.span,
            )])
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
                    .link(LinkValue::Interwork(super::IW_THUMB_JUMP16))
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
                    .link(LinkValue::Interwork(super::IW_THUMB_JUMP))
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
                    .link(LinkValue::Interwork(super::IW_THUMB_JUMP16))
                    .scatter(scatter_b16);
                out.push(fixed(0xe000u16.to_le_bytes().to_vec(), e, kind, ins.span));
            }
            if want_wide(ins) {
                let kind = FixupKind::pcrel(4, 4)
                    .with_field(25, 2)
                    .with_reloc(reloc::THM_JUMP24)
                    .link(LinkValue::Interwork(super::IW_THUMB_JUMP))
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
            && sets_flags16(ins)
            && low(rd)
            && low(rm)
            && want_narrow(ins)
        {
            return Some(narrow(0x43c0 | ((rm as u16) << 3) | rd as u16));
        }
        return no_encoding(cx, ins);
    }

    if let Some(rm) = src.reg() {
        if ins.set_flags && !ins.in_it && low(rd) && low(rm) && want_narrow(ins) {
            // `movs rd, rm` is `lsls rd, rm, #0`, which in an `it` block
            // would not set the flags.
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
    if sets_flags16(ins) && low(rd) && v <= 0xff && want_narrow(ins) {
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
        if sets_flags16(ins) && low(rd) && low(rn) && low(rm) && want_narrow(ins) {
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
        if sets_flags16(ins) && low(rd) && low(rn) {
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
        if v != 0 || !sets_flags16(ins) || !low(rd) || !low(rn) || !want_narrow(ins) {
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
    if !sets_flags16(ins) || rd != rn || !low(rd) || !low(rm) || !want_narrow(ins) {
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
    if !sets_flags16(ins) || !low(rd) || !low(rm) || !want_narrow(ins) {
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
    if let OperandKind::Literal(e) = ins.ops[1].kind {
        return literal_load(cx, ins, rt, &ins.ops[1], e);
    }
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

/// 16-bit `adr rd, label`: a word count forward from the PC rounded down.
fn scatter_adr16(w: u64, v: i64) -> u64 {
    (w & 0xff00) | (((v >> 2) as u64) & 0xff)
}

/// 32-bit `addw rd, pc, #imm12`, or `subw` for a label behind.
fn scatter_adr32(w: u64, v: i64) -> u64 {
    let hw1: u64 = if v < 0 { 0xf2af } else { 0xf20f };
    let m = v.unsigned_abs() & 0xfff;
    let rd = (w >> 24) & 0xf;
    let hw2 = ((m >> 8) & 7) << 12 | rd << 8 | (m & 0xff);
    ((hw2 << 16) | hw1 | ((m >> 11) & 1) << 10) & 0xffff_ffff
}

/// `adr rd, label`. A low register gets GNU as's relaxable pair, a 16-bit
/// form reaching 1020 bytes forward to a word-aligned label and a 32-bit one
/// reaching 4095 bytes either way; anything else only the 32-bit form.
fn adr(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    unconditional(cx, ins)?;
    encode::no_flags(cx, ins)?;
    encode::arity(cx, ins, &[2])?;
    let rd = encode::reg_of(cx, &ins.ops[0])?;
    if rd == reg::SP || rd == reg::PC {
        cx.error(
            ins.ops[0].span,
            format!("`adr` cannot load `{}` in Thumb", reg::name_of(rd)),
        );
        return None;
    }
    let Some(e) = ins.ops[1].imm() else {
        cx.error(ins.ops[1].span, "expected a label");
        return None;
    };
    let span = ins.ops[1].span;
    let e = encode::thumb_function_address(cx, e);
    // Only the form GNU as relaxes learns about a Thumb function defined
    // after the `adr`; see `Arm::interwork`.
    let relaxed = low(rd) && ins.width == Width::Any;
    let mut out = Vec::new();
    if low(rd) && want_narrow(ins) {
        let mut kind = FixupKind::pcrel(2, 4)
            .with_pc_align(4)
            .with_field(12, 4)
            .with_limits(0, 1020)
            .scatter(scatter_adr16);
        if relaxed {
            kind = kind.link(LinkValue::Interwork(super::IW_THUMB_ADR16));
        }
        out.push(fixed(
            (0xa000u16 | ((rd as u16) << 8)).to_le_bytes().to_vec(),
            e,
            kind,
            span,
        ));
    }
    if want_wide(ins) {
        let mut kind = adr32_kind();
        if relaxed {
            kind = kind.link(LinkValue::Interwork(super::IW_THUMB_ADR));
        }
        out.push(fixed(wide_bytes(0xf20f, (rd as u16) << 8), e, kind, span));
    }
    if out.is_empty() {
        return no_encoding(cx, ins);
    }
    Some(out)
}

/// 32-bit `adr`: `addw` or `subw` from the PC rounded down to a word.
pub fn adr32_kind() -> FixupKind {
    FixupKind::pcrel(4, 4)
        .with_pc_align(4)
        .with_limits(-4095, 4095)
        .scatter(scatter_adr32)
}

/// 16-bit `ldr rt, [pc, #imm8 * 4]`.
fn scatter_literal16(w: u64, v: i64) -> u64 {
    (w & 0xff00) | (((v >> 2) as u64) & 0xff)
}

/// 32-bit `ldr.w rt, [pc, #±imm12]`: the U bit is bit 7 of the first
/// halfword, and set for an offset of zero.
fn scatter_literal32(w: u64, v: i64) -> u64 {
    let up = if v >= 0 { 0x80 } else { 0 };
    (w & !0x0fff_0080) | up | ((v.unsigned_abs() & 0xfff) << 16)
}

/// `ldr rt, =expr` in T32.
///
/// A number GNU as can move instead is moved, always with a 32-bit `mov.w`,
/// `mvn.w` or `movw` (a 16-bit `movs` would change the flags); the stack
/// pointer and the PC cannot take those, so they always load. Otherwise the
/// load reaches the pool from the PC rounded down to a word, as a 16-bit
/// instruction that reaches 1020 bytes forward if the register is a low one,
/// and as a 32-bit one that reaches 4095 bytes either way; layout picks.
fn literal_load(
    cx: &mut AsmCtx<'_>,
    ins: &Insn<'_>,
    rt: Reg,
    op: &crate::arch::arm::operand::Operand,
    e: ExprRef,
) -> Option<Vec<Variant>> {
    encode::literal_only_for_ldr(cx, ins, op)?;
    let constant = encode::literal_constant(cx, op, e)?;
    if let Some(v) = constant
        && rt != reg::SP
        && rt != reg::PC
    {
        if let Some(imm12) = imm::thumb_expand(v) {
            let (i, rest) = expand_parts(imm12);
            return Some(wide(0xf04f | (i << 10), rest | ((rt as u16) << 8)));
        }
        if let Some(imm12) = imm::thumb_expand(!v) {
            let (i, rest) = expand_parts(imm12);
            return Some(wide(0xf06f | (i << 10), rest | ((rt as u16) << 8)));
        }
        if v <= 0xffff {
            return Some(move_wide_bits(rt, v, false));
        }
    }
    let value = match cx.constant(e) {
        Some(v) if constant.is_some() => crate::arch::Literal::Const(v),
        _ => crate::arch::Literal::Expr(e),
    };
    let entry = cx.literal(value, 4, op.span);
    let hint = "the literal pool is too far away; put an `.ltorg` nearer";
    let mut out = Vec::new();
    if low(rt) && want_narrow(ins) {
        let kind = FixupKind::pcrel(2, 4)
            .with_pc_align(4)
            .with_field(12, 4)
            .with_limits(0, 1020)
            .with_range_hint(hint)
            .scatter(scatter_literal16);
        out.push(fixed(
            (0x4800u16 | ((rt as u16) << 8)).to_le_bytes().to_vec(),
            entry,
            kind,
            op.span,
        ));
    }
    if want_wide(ins) {
        let kind = FixupKind::pcrel(4, 4)
            .with_pc_align(4)
            .with_limits(-4095, 4095)
            .with_range_hint(hint)
            .scatter(scatter_literal32);
        out.push(fixed(
            wide_bytes(0xf85f, (rt as u16) << 12),
            entry,
            kind,
            op.span,
        ));
    }
    if out.is_empty() {
        return no_encoding(cx, ins);
    }
    Some(out)
}

fn narrow_load_store(mnem: Mnem, rt: Reg, mem: &Mem) -> Option<u16> {
    let base = mem.base;
    match mem.offset {
        MemOffset::Unindexed(_) => None,
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
            // `muls rdm, rn, rdm` is the 16-bit form, and `mul` in an `it`
            // block, where it does not set the flags.
            if sets_flags16(ins) && want_narrow(ins) && low(rd) && low(rn) && rd == rm {
                return Some(narrow(0x4340 | ((rn as u16) << 3) | rd as u16));
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
