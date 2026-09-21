//! The A32 (ARM) encoder.
//!
//! Every A32 instruction is one little-endian word whose top four bits are the
//! condition, so the encoder builds a `u32` and hands it over. Fields that
//! depend on a symbol are left zero and filled in by a [`Fixup`] whose scatter
//! function knows where the bits go.

use super::imm;
use super::insn::{AL, Mnem};
use super::operand::{Index, Mem, MemOffset, Operand, OperandKind, Shift, ShiftAmt};
use super::reg::{self, Reg};
use super::{Insn, reloc};
use crate::arch::{AsmCtx, Literal};
use crate::expr::ExprRef;
use crate::section::{Fixup, FixupKind, LinkValue, Variant};
use crate::source::Span;

/// `nop` in A32: `mov r0, r0` would do, but the architectural hint is this.
pub const NOP: u32 = 0xe320_f000;

fn word(cond: u8, bits: u32) -> u32 {
    ((cond as u32) << 28) | bits
}

fn one(w: u32) -> Vec<Variant> {
    vec![Variant::new(w.to_le_bytes().to_vec())]
}

// ---- shared operand helpers ------------------------------------------------

/// Checks the operand count, reporting the accepted arities on failure.
pub fn arity(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, allowed: &[usize]) -> Option<()> {
    if allowed.contains(&ins.ops.len()) {
        return Some(());
    }
    let want: Vec<String> = allowed.iter().map(|n| n.to_string()).collect();
    cx.error(
        ins.span,
        format!(
            "`{}` takes {} operand(s), but {} were given",
            ins.text,
            want.join(" or "),
            ins.ops.len()
        ),
    );
    None
}

pub fn reg_of(cx: &mut AsmCtx<'_>, op: &Operand) -> Option<Reg> {
    match op.reg() {
        Some(r) => Some(r),
        None => {
            cx.error(
                op.span,
                format!("expected a register, found {}", op.describe()),
            );
            None
        }
    }
}

/// The constant value of an immediate operand, which must not be symbolic.
pub fn imm_of(cx: &mut AsmCtx<'_>, op: &Operand) -> Option<i64> {
    let Some(e) = op.imm() else {
        cx.error(
            op.span,
            format!("expected an immediate, found {}", op.describe()),
        );
        return None;
    };
    match cx.constant(e) {
        Some(v) => Some(v),
        None => {
            cx.error(op.span, "this immediate must be a constant expression");
            None
        }
    }
}

/// A 32-bit immediate, accepting either the signed or the unsigned reading
/// (`-1` and `0xffffffff` are the same word).
pub fn imm32(cx: &mut AsmCtx<'_>, op: &Operand) -> Option<u32> {
    let v = imm_of(cx, op)?;
    if !(i32::MIN as i64..=u32::MAX as i64).contains(&v) {
        cx.error(op.span, format!("immediate {v} does not fit in 32 bits"));
        return None;
    }
    Some(v as u32)
}

/// An unsigned immediate that must fit in `bits` bits.
pub fn imm_bits(cx: &mut AsmCtx<'_>, op: &Operand, bits: u32) -> Option<u32> {
    let v = imm_of(cx, op)?;
    let max = if bits >= 32 {
        u32::MAX as i64
    } else {
        (1i64 << bits) - 1
    };
    if v < 0 || v > max {
        cx.error(
            op.span,
            format!("immediate {v} is out of range (0 to {max})"),
        );
        return None;
    }
    Some(v as u32)
}

/// Rejects a condition on an instruction whose encoding has none: the
/// condition field of `bkpt`, the barriers and `blx <label>` is part of the
/// opcode.
fn no_cond(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<()> {
    if ins.cond_written && ins.cond != AL {
        cx.error(ins.span, format!("`{}` cannot be conditional", ins.text));
        return None;
    }
    Some(())
}

pub fn no_flags(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<()> {
    if ins.set_flags {
        cx.error(ins.span, format!("`{}` cannot set the flags", ins.text));
        return None;
    }
    Some(())
}

// ---- fixups ----------------------------------------------------------------

/// `b`/`bl`: a 24-bit field counting words, with the PC two instructions
/// ahead of the branch.
fn scatter_branch(w: u64, v: i64) -> u64 {
    (w & 0xff00_0000) | (((v >> 2) as u64) & 0x00ff_ffff)
}

/// `blx <label>`: as `bl`, plus bit 24 carrying the odd halfword so the
/// ARM-to-Thumb call can land on a 2-byte boundary.
fn scatter_blx(w: u64, v: i64) -> u64 {
    (w & 0xfe00_0000) | ((((v >> 1) as u64) & 1) << 24) | (((v >> 2) as u64) & 0x00ff_ffff)
}

fn branch_variant(w: u32, expr: ExprRef, kind: FixupKind, span: Span) -> Vec<Variant> {
    vec![Variant {
        bytes: w.to_le_bytes().to_vec(),
        fixups: vec![Fixup {
            offset: 0,
            expr,
            kind,
            span,
        }],
    }]
}

// ---- entry point -----------------------------------------------------------

pub fn assemble(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    use Mnem::*;
    let ops = ins.ops;
    match ins.mnem {
        And | Eor | Sub | Rsb | Add | Adc | Sbc | Rsc | Tst | Teq | Cmp | Cmn | Orr | Mov | Bic
        | Mvn => data_processing(cx, ins),
        Lsl | Lsr | Asr | Ror | Rrx => shift_insn(cx, ins),
        Ldr | Str | Ldrb | Strb => load_store(cx, ins),
        Ldrh | Strh | Ldrsb | Ldrsh => load_store_extra(cx, ins),
        Ldm(_) | Stm(_) | Push | Pop => block_transfer(cx, ins),
        Adr | Adrl => adr(cx, ins),
        B | Bl | Bx | Blx => branch(cx, ins),
        Mul | Mla | Mls | Umull | Umlal | Smull | Smlal => multiply(cx, ins),
        Movw | Movt => move_wide(cx, ins),
        Mrs => status_read(cx, ins),
        Msr => status_write(cx, ins),
        Ext(at) => super::generic::assemble(cx, ins, at),
        // ARM instructions carry their own conditions, so GNU as takes an
        // `it` in ARM code for source shared with Thumb, and emits nothing.
        It(_) => {
            arity(cx, ins, &[1])?;
            if ops[0]
                .word
                .as_deref()
                .and_then(super::insn::condition)
                .is_none()
            {
                cx.error(ops[0].span, "expected a condition code");
            }
            None
        }
    }
}

// ---- data processing -------------------------------------------------------

/// Builds the twelve-bit second operand and, for immediates that only encode
/// with the complementary operation, the opcode that has to replace the one
/// the source wrote.
fn operand2(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, op: &Operand) -> Option<(u32, u32, u32)> {
    let base = ins.mnem.dp_opcode()?;
    match &op.kind {
        OperandKind::Reg(rm) => Some((base, 0, *rm as u32)),
        OperandKind::Shifted { rm, shift, amount } => {
            Some((base, 0, shift_field(cx, op.span, *rm, *shift, *amount)?))
        }
        OperandKind::Imm(_) => {
            let v = imm32(cx, op)?;
            if let Some(field) = imm::modified(v) {
                return Some((base, 1, field));
            }
            // `add rd, rn, #-1` has no encoding, but `sub rd, rn, #1` is the
            // same instruction; every ARM assembler makes the swap.
            if let Some((partner, negate)) = ins.mnem.immediate_partner() {
                let alt = if negate { v.wrapping_neg() } else { !v };
                if let Some(field) = imm::modified(alt)
                    && let Some(op) = partner.dp_opcode()
                {
                    return Some((op, 1, field));
                }
            }
            cx.error(
                op.span,
                format!(
                    "{} (0x{v:08x}) is not an ARM modified immediate: it must be an \
                     8-bit value rotated right by an even amount",
                    v as i32
                ),
            );
            None
        }
        _ => {
            cx.error(
                op.span,
                format!("expected a register or immediate, found {}", op.describe()),
            );
            None
        }
    }
}

/// The shifter field of a register operand: `shift_imm:type:0:Rm` or
/// `Rs:0:type:1:Rm`.
fn shift_field(
    cx: &mut AsmCtx<'_>,
    span: Span,
    rm: Reg,
    shift: Shift,
    amount: ShiftAmt,
) -> Option<u32> {
    let rm = rm as u32;
    Some(match amount {
        // `rrx` is `ror` by zero; a real `ror #0` has no encoding.
        ShiftAmt::None => (3 << 5) | rm,
        ShiftAmt::Reg(rs) => ((rs as u32) << 8) | (shift.code() << 5) | (1 << 4) | rm,
        ShiftAmt::Imm(n) => {
            let n = match shift {
                // `lsr #32` and `asr #32` are spelled with a zero amount,
                // which is why `lsr #0` cannot mean "no shift".
                Shift::Lsr | Shift::Asr if n == 32 => 0,
                Shift::Lsr | Shift::Asr if n == 0 => {
                    cx.error(
                        span,
                        format!("`{}` requires a shift of 1 to 32", shift.name()),
                    );
                    return None;
                }
                Shift::Ror if n == 0 => {
                    cx.error(span, "`ror #0` is not encodable; write `rrx` instead");
                    return None;
                }
                _ => n,
            };
            (n << 7) | (shift.code() << 5) | rm
        }
    })
}

fn data_processing(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    let ops = ins.ops;
    let m = ins.mnem;
    let (rd, rn, src) = if m.is_compare() {
        arity(cx, ins, &[2])?;
        (0u32, reg_of(cx, &ops[0])? as u32, &ops[1])
    } else if m.is_move() {
        arity(cx, ins, &[2])?;
        (reg_of(cx, &ops[0])? as u32, 0u32, &ops[1])
    } else {
        arity(cx, ins, &[2, 3])?;
        let rd = reg_of(cx, &ops[0])? as u32;
        if ops.len() == 2 {
            // `add r0, r1` is shorthand for `add r0, r0, r1`.
            (rd, rd, &ops[1])
        } else {
            (rd, reg_of(cx, &ops[1])? as u32, &ops[2])
        }
    };
    let (opcode, i, field) = operand2(cx, ins, src)?;
    // The comparisons have no S bit of their own: they always set the flags.
    let s = if m.is_compare() || ins.set_flags {
        1
    } else {
        0
    };
    Some(one(word(
        ins.cond,
        (i << 25) | (opcode << 21) | (s << 20) | (rn << 16) | (rd << 12) | field,
    )))
}

/// `lsl`/`lsr`/`asr`/`ror`/`rrx`, which A32 encodes as `mov` with a shift.
fn shift_insn(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    let ops = ins.ops;
    let shift = match ins.mnem {
        Mnem::Lsl => Shift::Lsl,
        Mnem::Lsr => Shift::Lsr,
        Mnem::Asr => Shift::Asr,
        Mnem::Ror => Shift::Ror,
        _ => Shift::Rrx,
    };
    let (rd, rm, amount) = if shift == Shift::Rrx {
        arity(cx, ins, &[2])?;
        (reg_of(cx, &ops[0])?, reg_of(cx, &ops[1])?, ShiftAmt::None)
    } else {
        arity(cx, ins, &[2, 3])?;
        let rd = reg_of(cx, &ops[0])?;
        // `lsl r0, #3` shifts the destination in place.
        let (rm, amt) = if ops.len() == 2 {
            (rd, &ops[1])
        } else {
            (reg_of(cx, &ops[1])?, &ops[2])
        };
        let amount = match amt.reg() {
            Some(rs) => ShiftAmt::Reg(rs),
            None => {
                let v = imm_of(cx, amt)?;
                let max = match shift {
                    Shift::Lsr | Shift::Asr => 32,
                    _ => 31,
                };
                if v < 0 || v > max {
                    cx.error(
                        amt.span,
                        format!("shift amount {v} is out of range (0 to {max})"),
                    );
                    return None;
                }
                ShiftAmt::Imm(v as u32)
            }
        };
        (rd, rm, amount)
    };
    let field = shift_field(cx, ins.span, rm, shift, amount)?;
    let s = u32::from(ins.set_flags);
    Some(one(word(
        ins.cond,
        (13 << 21) | (s << 20) | ((rd as u32) << 12) | field,
    )))
}

// ---- loads and stores ------------------------------------------------------

/// P and W, which together say whether and when the base register is updated.
fn index_bits(index: Index) -> (u32, u32) {
    match index {
        Index::Offset => (1, 0),
        Index::PreIndex => (1, 1),
        Index::PostIndex => (0, 0),
    }
}

fn memory_operand<'a>(cx: &mut AsmCtx<'_>, op: &'a Operand) -> Option<&'a Mem> {
    match &op.kind {
        OperandKind::Mem(m) => Some(m),
        _ => {
            cx.error(
                op.span,
                format!("expected a memory operand, found {}", op.describe()),
            );
            None
        }
    }
}

/// The value of `ldr rt, =expr` when it is a number, which GNU as loads with
/// a `mov` or `mvn` instead where one can hold it, and otherwise with a load
/// from the literal pool; `None` for a value the pool holds as an expression.
///
/// Either way the number has to fit in the word the pool would hold.
pub fn literal_constant(cx: &mut AsmCtx<'_>, op: &Operand, e: ExprRef) -> Option<Option<u32>> {
    let Some(v) = cx.constant(e) else {
        return Some(None);
    };
    if !(i32::MIN as i64..=u32::MAX as i64).contains(&v) {
        cx.error(
            op.span,
            format!("{v} does not fit in the 32-bit word of a literal pool entry"),
        );
        return None;
    }
    Some(Some(v as u32))
}

/// The error for an `=expr` operand on anything but `ldr`.
pub fn literal_only_for_ldr(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, op: &Operand) -> Option<()> {
    if ins.mnem == Mnem::Ldr {
        return Some(());
    }
    cx.error(
        op.span,
        format!(
            "`{}` cannot load from a literal pool; only `ldr` can",
            ins.text
        ),
    );
    None
}

/// A PC-relative load's 12-bit offset and its U bit. An offset of zero keeps
/// the U bit it was assembled with, which for a literal load is clear: GNU as
/// writes `ldr r0, [pc, #-0]`.
fn scatter_literal(w: u64, v: i64) -> u64 {
    if v == 0 {
        return w & !0xfff;
    }
    let up = if v > 0 { 0x0080_0000 } else { 0 };
    (w & !0x0080_0fff) | up | (v.unsigned_abs() & 0xfff)
}

/// `ldr rt, =expr` in A32.
fn literal_load(
    cx: &mut AsmCtx<'_>,
    ins: &Insn<'_>,
    rt: u32,
    op: &Operand,
    e: ExprRef,
) -> Option<Vec<Variant>> {
    literal_only_for_ldr(cx, ins, op)?;
    let constant = literal_constant(cx, op, e)?;
    if let Some(v) = constant {
        if let Some(field) = imm::modified(v) {
            return Some(one(word(ins.cond, 0x03a0_0000 | (rt << 12) | field)));
        }
        if let Some(field) = imm::modified(!v) {
            return Some(one(word(ins.cond, 0x03e0_0000 | (rt << 12) | field)));
        }
    }
    let value = match cx.constant(e) {
        Some(v) if constant.is_some() => Literal::Const(v),
        _ => Literal::Expr(e),
    };
    let entry = cx.literal(value, 4, op.span);
    // The PC reads two instructions ahead, and the load reaches 4095 bytes
    // either way from there.
    let kind = FixupKind::pcrel(4, 8)
        .with_limits(-4095, 4095)
        .with_range_hint("the literal pool is too far away; put an `.ltorg` nearer")
        .scatter(scatter_literal);
    Some(vec![Variant {
        bytes: word(ins.cond, 0x051f_0000 | (rt << 12))
            .to_le_bytes()
            .to_vec(),
        fixups: vec![Fixup {
            offset: 0,
            expr: entry,
            kind,
            span: op.span,
        }],
    }])
}

fn load_store(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let rt = reg_of(cx, &ins.ops[0])? as u32;
    if let OperandKind::Literal(e) = ins.ops[1].kind {
        return literal_load(cx, ins, rt, &ins.ops[1], e);
    }
    let mem = *memory_operand(cx, &ins.ops[1])?;
    let (p, w) = index_bits(mem.index);
    let l = u32::from(matches!(ins.mnem, Mnem::Ldr | Mnem::Ldrb));
    let b = u32::from(matches!(ins.mnem, Mnem::Ldrb | Mnem::Strb));
    let (i, u, field) = match mem.offset {
        MemOffset::None => (0, 1, 0),
        MemOffset::Unindexed(_) => {
            cx.error(mem.span, "only `ldc` and `stc` take `[rn], {option}`");
            return None;
        }
        MemOffset::Imm(v) => {
            let mag = v.unsigned_abs();
            if mag > 0xfff {
                cx.error(
                    mem.span,
                    format!("offset {v} does not fit in the 12-bit field (-4095 to 4095)"),
                );
                return None;
            }
            (0, u32::from(v >= 0), mag as u32)
        }
        MemOffset::Reg {
            rm,
            add,
            shift,
            amount,
        } => (
            1,
            u32::from(add),
            shift_field(cx, mem.span, rm, shift, ShiftAmt::Imm(amount))?,
        ),
    };
    Some(one(word(
        ins.cond,
        (1 << 26)
            | (i << 25)
            | (p << 24)
            | (u << 23)
            | (b << 22)
            | (w << 21)
            | (l << 20)
            | ((mem.base as u32) << 16)
            | (rt << 12)
            | field,
    )))
}

/// The halfword and signed-byte loads, which predate the main load encoding
/// and were squeezed into a gap in the data-processing space: their offset is
/// split into two nibbles around a `1SH1` marker.
fn load_store_extra(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let rt = reg_of(cx, &ins.ops[0])? as u32;
    let mem = *memory_operand(cx, &ins.ops[1])?;
    let (p, w) = index_bits(mem.index);
    let (l, sh) = match ins.mnem {
        Mnem::Strh => (0, 0b01),
        Mnem::Ldrh => (1, 0b01),
        Mnem::Ldrsb => (1, 0b10),
        _ => (1, 0b11),
    };
    let (i, u, field) = match mem.offset {
        MemOffset::None => (1, 1, 0),
        MemOffset::Unindexed(_) => {
            cx.error(mem.span, "only `ldc` and `stc` take `[rn], {option}`");
            return None;
        }
        MemOffset::Imm(v) => {
            let mag = v.unsigned_abs();
            if mag > 0xff {
                cx.error(
                    mem.span,
                    format!("offset {v} does not fit in the 8-bit field (-255 to 255)"),
                );
                return None;
            }
            let mag = mag as u32;
            (1, u32::from(v >= 0), ((mag & 0xf0) << 4) | (mag & 0xf))
        }
        MemOffset::Reg {
            rm,
            add,
            shift,
            amount,
        } => {
            if amount != 0 || shift != Shift::Lsl {
                cx.error(
                    mem.span,
                    "a halfword or signed load cannot scale its index register",
                );
                return None;
            }
            (0, u32::from(add), rm as u32)
        }
    };
    Some(one(word(
        ins.cond,
        (p << 24)
            | (u << 23)
            | (i << 22)
            | (w << 21)
            | (l << 20)
            | ((mem.base as u32) << 16)
            | (rt << 12)
            | (1 << 7)
            | (sh << 5)
            | (1 << 4)
            | field,
    )))
}

fn register_list(cx: &mut AsmCtx<'_>, op: &Operand) -> Option<u16> {
    match op.kind {
        OperandKind::List(m) => Some(m),
        _ => {
            cx.error(
                op.span,
                format!("expected a register list, found {}", op.describe()),
            );
            None
        }
    }
}

/// The single register of a one-element list, if that is what this is.
fn sole_register(list: u16) -> Option<u32> {
    (list.count_ones() == 1).then(|| list.trailing_zeros())
}

fn block_transfer(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    // `push`/`pop` are `stmdb sp!` / `ldmia sp!` under another name.
    let (rn, writeback, mode, load, list) = match ins.mnem {
        Mnem::Push => {
            arity(cx, ins, &[1])?;
            let list = register_list(cx, &ins.ops[0])?;
            // A one-register push is a plain pre-indexed store, which is one
            // cycle cheaper; GNU as and LLVM both rewrite it that way.
            if let Some(rt) = sole_register(list) {
                return Some(one(word(ins.cond, 0x052d_0004 | (rt << 12))));
            }
            (reg::SP, true, (true, false), false, list)
        }
        Mnem::Pop => {
            arity(cx, ins, &[1])?;
            let list = register_list(cx, &ins.ops[0])?;
            if let Some(rt) = sole_register(list) {
                return Some(one(word(ins.cond, 0x049d_0004 | (rt << 12))));
            }
            (reg::SP, true, (false, true), true, list)
        }
        Mnem::Ldm(m) | Mnem::Stm(m) => {
            arity(cx, ins, &[2])?;
            let rn = reg_of(cx, &ins.ops[0])?;
            (
                rn,
                ins.ops[0].writeback,
                (m.before, m.increment),
                matches!(ins.mnem, Mnem::Ldm(_)),
                register_list(cx, &ins.ops[1])?,
            )
        }
        _ => return None,
    };
    Some(one(word(
        ins.cond,
        (1 << 27)
            | (u32::from(mode.0) << 24)
            | (u32::from(mode.1) << 23)
            | (u32::from(writeback) << 21)
            | (u32::from(load) << 20)
            | ((rn as u32) << 16)
            | list as u32,
    )))
}

// ---- adr and adrl ------------------------------------------------------------

/// `add rd, pc, #imm` or `sub rd, pc, #imm` for a PC-relative value, as its
/// data-processing opcode bits and immediate field: GNU as's
/// `encode_arm_immediate`, then the negated value with the opposite
/// operation.
fn adr_one(v: i64) -> Option<(u32, u32)> {
    const ADD: u32 = 0x0080_0000;
    const SUB: u32 = 0x0040_0000;
    let v = v as u32;
    if (v as i32) >= 0
        && let Some(field) = imm::modified(v)
    {
        return Some((ADD, field));
    }
    imm::modified(v.wrapping_neg()).map(|field| (SUB, field))
}

/// GNU as's `validate_immediate_twopart`: `v` as the sum of two modified
/// immediates, the low one first.
fn adr_two(v: u32) -> Option<(u32, u32)> {
    for i in (0..32).step_by(2) {
        let a = v.rotate_left(i);
        if a & 0xff == 0 {
            continue;
        }
        let high = if a & 0xff00 != 0 {
            if a & !0xffff != 0 {
                continue;
            }
            (a >> 8) | ((i + 24) << 7)
        } else if a & 0x00ff_0000 != 0 {
            if a & 0xff00_0000 != 0 {
                continue;
            }
            (a >> 16) | ((i + 16) << 7)
        } else {
            (a >> 24) | ((i + 8) << 7)
        };
        return Some(((a & 0xff) | (i << 7), high));
    }
    None
}

fn adr_reaches(v: i64) -> bool {
    adr_one(v).is_some()
}

fn adrl_reaches(v: i64) -> bool {
    adr_one(v).is_some()
        || adr_two(v as u32).is_some()
        || adr_two((v as u32).wrapping_neg()).is_some()
}

/// `adr`: one `add` or `sub` from the PC.
fn scatter_adr(w: u64, v: i64) -> u64 {
    let (op, field) = adr_one(v).unwrap_or((0, 0));
    (w & 0xf000_f000) | 0x020f_0000 | op as u64 | field as u64
}

/// `adrl`: the `add` or `sub` of `adr` followed by a no-op where one
/// instruction reaches, and otherwise two, the second adding to (or
/// subtracting from) the register the first set. The field is both words,
/// the first in the low half.
fn scatter_adrl(w: u64, v: i64) -> u64 {
    let first = w & 0xf000_f000;
    let rd = (first >> 12) & 0xf;
    let (low, high) = match adr_one(v) {
        Some((op, field)) => (first | 0x020f_0000 | op as u64 | field as u64, 0xe1a0_0000),
        None => {
            let (op, (lo, hi)) = match adr_two(v as u32) {
                Some(parts) => (0x0080_0000, parts),
                None => (
                    0x0040_0000,
                    adr_two((v as u32).wrapping_neg()).unwrap_or((0, 0)),
                ),
            };
            let insn = first | 0x0200_0000 | op;
            (
                insn | 0x000f_0000 | lo as u64,
                insn | (rd << 16) | hi as u64,
            )
        }
    };
    low | (high << 32)
}

/// `adr rd, label` and `adrl rd, label`, which GNU as resolves within the
/// section and refuses to relocate.
fn adr(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let rd = reg_of(cx, &ins.ops[0])? as u32;
    let Some(e) = ins.ops[1].imm() else {
        cx.error(ins.ops[1].span, "expected a label");
        return None;
    };
    // GNU as sets the low bit for a Thumb function only when assembling for
    // interworking (`-mthumb-interwork`), which rsasm has no option for.
    let long = ins.mnem == Mnem::Adrl;
    let (size, reaches, what): (u8, fn(i64) -> bool, _) = if long {
        (
            8,
            adrl_reaches,
            "`adrl` reaches this far only with an address two `add`s can build",
        )
    } else {
        (
            4,
            adr_reaches,
            "`adr` reaches only an 8-bit value rotated by an even amount; try `adrl`",
        )
    };
    let kind = FixupKind::pcrel(size, 8)
        .accepting(reaches)
        .with_range_hint(what)
        .scatter(if long { scatter_adrl } else { scatter_adr });
    let w = word(ins.cond, rd << 12) as u64;
    let bytes = if long {
        (w | (0xe1a0_0000 << 32)).to_le_bytes().to_vec()
    } else {
        (w as u32).to_le_bytes().to_vec()
    };
    Some(vec![Variant {
        bytes,
        fixups: vec![Fixup {
            offset: 0,
            expr: e,
            kind,
            span: ins.ops[1].span,
        }],
    }])
}

// ---- branches --------------------------------------------------------------

fn branch(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[1])?;
    let op = &ins.ops[0];
    match ins.mnem {
        Mnem::Bx | Mnem::Blx if op.reg().is_some() => {
            let rm = reg_of(cx, op)? as u32;
            let sub = if ins.mnem == Mnem::Bx { 1 } else { 3 };
            Some(one(word(ins.cond, 0x012f_ff00 | (sub << 4) | rm)))
        }
        Mnem::Bx => {
            cx.error(op.span, "`bx` takes a register");
            None
        }
        Mnem::Blx => {
            // The label form of `blx` swaps to Thumb state, so it is
            // unconditional and its target is halfword-aligned.
            no_cond(cx, ins)?;
            let Some(e) = op.imm() else {
                cx.error(op.span, "expected a label or register");
                return None;
            };
            Some(branch_variant(0xfa00_0000, e, blx_kind(), ins.span))
        }
        _ => {
            let Some(e) = op.imm() else {
                cx.error(op.span, "expected a branch target");
                return None;
            };
            let link = ins.mnem == Mnem::Bl;
            // Only an unconditional `bl` is a call to the linker, which may
            // make it a `blx`; a conditional one cannot change state, and is
            // relocated as a jump.
            let call = link && ins.cond == AL;
            let kind = if call { bl_kind() } else { jump_kind() };
            let w = word(ins.cond, if link { 0x0b00_0000 } else { 0x0a00_0000 });
            Some(branch_variant(w, e, kind, ins.span))
        }
    }
}

/// `bl label`. The 24-bit field counts words, and the PC an instruction
/// reads is two instructions ahead of itself: hence the +8 adjustment.
pub fn bl_kind() -> FixupKind {
    FixupKind::pcrel(4, 8)
        .with_field(26, 4)
        .with_reloc(reloc::CALL)
        .link(LinkValue::Interwork(super::IW_ARM_BL))
        .scatter(scatter_branch)
}

/// `blx label`, which swaps to Thumb state, so its target is a halfword
/// boundary.
pub fn blx_kind() -> FixupKind {
    FixupKind::pcrel(4, 8)
        .with_field(26, 2)
        .with_reloc(reloc::CALL)
        .link(LinkValue::Interwork(super::IW_ARM_BLX))
        .scatter(scatter_blx)
}

/// `b label`, `b<cond> label` and `bl<cond> label`.
fn jump_kind() -> FixupKind {
    FixupKind::pcrel(4, 8)
        .with_field(26, 4)
        .with_reloc(reloc::JUMP24)
        .link(LinkValue::Interwork(super::IW_ARM_JUMP))
        .scatter(scatter_branch)
}

/// `bl` rewritten as `blx`, for a call into Thumb.
pub fn to_blx(w: u64) -> u64 {
    (w & 0x00ff_ffff) | 0xfa00_0000
}

/// `blx` rewritten as `bl`, for a call that stays in ARM.
pub fn to_bl(w: u64) -> u64 {
    (w & 0x00ff_ffff) | 0xeb00_0000
}

/// Thumb `adr` of a Thumb function sets the address's low bit, as GNU as
/// does where it already knows the label is one when it reads the `adr`.
pub fn thumb_function_address(cx: &mut AsmCtx<'_>, e: ExprRef) -> ExprRef {
    let v = crate::expr::SymbolEnv::new(cx.exprs, cx.symbols).value(e);
    let Some(crate::expr::Value {
        plus: Some(p),
        minus: None,
        ..
    }) = v
    else {
        return e;
    };
    let sym = cx.symbols.get(p);
    if !sym.is_defined() || !super::thumb_is_func(sym.target_flags, sym.ty) {
        return e;
    }
    let span = cx.exprs.span(e);
    let one = cx.exprs.int(1, span);
    cx.exprs.alloc(
        crate::expr::ExprKind::Binary(crate::expr::BinOp::Add, e, one),
        span,
    )
}

// ---- multiply --------------------------------------------------------------

fn multiply(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    let ops = ins.ops;
    let s = u32::from(ins.set_flags);
    let w = match ins.mnem {
        Mnem::Mul => {
            arity(cx, ins, &[3])?;
            let (rd, rn, rm) = (
                reg_of(cx, &ops[0])? as u32,
                reg_of(cx, &ops[1])? as u32,
                reg_of(cx, &ops[2])? as u32,
            );
            (s << 20) | (rd << 16) | (rm << 8) | (9 << 4) | rn
        }
        Mnem::Mla | Mnem::Mls => {
            arity(cx, ins, &[4])?;
            let (rd, rn, rm, ra) = (
                reg_of(cx, &ops[0])? as u32,
                reg_of(cx, &ops[1])? as u32,
                reg_of(cx, &ops[2])? as u32,
                reg_of(cx, &ops[3])? as u32,
            );
            if ins.mnem == Mnem::Mls {
                no_flags(cx, ins)?;
                (3 << 21) | (rd << 16) | (ra << 12) | (rm << 8) | (9 << 4) | rn
            } else {
                (1 << 21) | (s << 20) | (rd << 16) | (ra << 12) | (rm << 8) | (9 << 4) | rn
            }
        }
        _ => {
            arity(cx, ins, &[4])?;
            let (lo, hi, rn, rm) = (
                reg_of(cx, &ops[0])? as u32,
                reg_of(cx, &ops[1])? as u32,
                reg_of(cx, &ops[2])? as u32,
                reg_of(cx, &ops[3])? as u32,
            );
            let op = match ins.mnem {
                Mnem::Umull => 4,
                Mnem::Umlal => 5,
                Mnem::Smull => 6,
                _ => 7,
            };
            (op << 21) | (s << 20) | (hi << 16) | (lo << 12) | (rm << 8) | (9 << 4) | rn
        }
    };
    Some(one(word(ins.cond, w)))
}

// ---- movw / movt and the small unary operations ----------------------------

fn move_wide(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let rd = reg_of(cx, &ins.ops[0])? as u32;
    let v = imm_bits(cx, &ins.ops[1], 16)?;
    let top = if ins.mnem == Mnem::Movw {
        0x0300_0000
    } else {
        0x0340_0000
    };
    Some(one(word(
        ins.cond,
        top | ((v & 0xf000) << 4) | (rd << 12) | (v & 0xfff),
    )))
}

// ---- status registers and barriers -----------------------------------------

fn status_read(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let rd = reg_of(cx, &ins.ops[0])? as u32;
    let name = ins.ops[1].word.clone().unwrap_or_default();
    let spsr = match name.as_str() {
        "cpsr" | "apsr" => false,
        "spsr" => true,
        _ => {
            cx.error(ins.ops[1].span, "expected `cpsr`, `apsr` or `spsr`");
            return None;
        }
    };
    Some(one(word(
        ins.cond,
        0x010f_0000 | (u32::from(spsr) << 22) | (rd << 12),
    )))
}

/// `msr cpsr_<fields>, rm`. The four field letters select which byte of the
/// status register the write reaches; `_f` alone (the common case) touches
/// only the condition flags.
fn status_write(cx: &mut AsmCtx<'_>, ins: &Insn<'_>) -> Option<Vec<Variant>> {
    no_flags(cx, ins)?;
    arity(cx, ins, &[2])?;
    let spec = ins.ops[0].word.clone().unwrap_or_default();
    let (reg_name, fields) = match spec.split_once('_') {
        Some((r, f)) => (r, f),
        None => (spec.as_str(), "fc"),
    };
    let spsr = match reg_name {
        "cpsr" | "apsr" => false,
        "spsr" => true,
        _ => {
            cx.error(ins.ops[0].span, "expected `cpsr`, `apsr` or `spsr`");
            return None;
        }
    };
    let mut mask = 0u32;
    for c in fields.chars() {
        mask |= match c {
            'c' => 1,
            'x' => 2,
            's' => 4,
            'f' => 8,
            // `APSR_nzcvq` and friends name the flags the ARM way; they all
            // land in the same field byte.
            'n' | 'z' | 'v' | 'q' | 'g' => 8,
            _ => {
                cx.error(
                    ins.ops[0].span,
                    format!("unknown status register field `{c}`"),
                );
                return None;
            }
        };
    }
    let rm = reg_of(cx, &ins.ops[1])? as u32;
    Some(one(word(
        ins.cond,
        0x0120_f000 | (u32::from(spsr) << 22) | (mask << 16) | rm,
    )))
}
