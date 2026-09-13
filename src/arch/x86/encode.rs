//! Instruction encoding: prefixes, REX, opcode, ModRM/SIB, displacement and
//! immediate.

use super::insn::{DEF64, Def, IMM64, ModRm, NO_REX_W, NO64, ONLY64, Op, PLUSREG};
use super::operand::{Mem, Operand, OperandKind};
use super::reg::{self, Reg, RegClass};
use super::reloc;
use crate::arch::AsmCtx;
use crate::expr::ExprRef;
use crate::section::{Fixup, FixupKind, Variant};
use crate::source::Span;

/// Legacy prefixes contributed by `lock`, `rep` and friends.
#[derive(Clone, Copy, Default, Debug)]
pub struct Prefixes {
    pub lock: bool,
    /// 0xF3 (`rep`/`repe`) or 0xF2 (`repne`), whichever was written.
    pub rep: Option<u8>,
    /// A segment override written as a standalone prefix, as in `fs movq ...`.
    pub seg: Option<u8>,
}

/// Which operand fills which encoding slot, worked out from the pattern.
struct Roles<'o> {
    rm: Option<&'o Operand>,
    reg: Option<Reg>,
    /// (operand, encoded width in bytes, sign-extended-from-8)
    imm: Option<(ExprRef, u8)>,
    rel: Option<(ExprRef, u8)>,
}

pub fn segment_prefix(r: Reg) -> Option<u8> {
    Some(match r.num {
        0 => 0x26, // es
        1 => 0x2e, // cs
        2 => 0x36, // ss
        3 => 0x3e, // ds
        4 => 0x64, // fs
        5 => 0x65, // gs
        _ => return None,
    })
}

/// Extracts the operand expression a `Rel` slot refers to. A bare label parses
/// as an immediate in Intel syntax and as a displacement-only memory operand in
/// AT&T, so both spellings are accepted here.
pub fn rel_expr(o: &Operand) -> Option<ExprRef> {
    match &o.kind {
        OperandKind::Imm(e) => Some(*e),
        OperandKind::Mem(m) if m.base.is_none() && m.index.is_none() && !m.rip_relative => m.disp,
        _ => None,
    }
}

/// The register or memory operand behind an indirect branch target.
pub fn indirect_inner(o: &Operand) -> Option<Operand> {
    match &o.kind {
        OperandKind::Indirect(inner) => Some(Operand {
            kind: (**inner).clone(),
            size_hint: o.size_hint,
            span: o.span,
        }),
        // Intel syntax writes indirect branches without a sigil.
        OperandKind::Reg(_) | OperandKind::Mem(_) => Some(o.clone()),
        _ => None,
    }
}

/// Works out which operand fills which encoding slot.
///
/// The pattern says everything needed: the first r/m-capable operand goes to
/// ModRM.rm, a register operand goes to ModRM.reg (or the low bits of a `+r`
/// opcode), and immediates and branch targets go to their own fields.
/// The register behind an r/m operand, if it is a register rather than memory.
fn rm_register(o: &Operand) -> Option<Reg> {
    match &o.kind {
        OperandKind::Reg(r) => Some(*r),
        OperandKind::Indirect(inner) => match &**inner {
            OperandKind::Reg(r) => Some(*r),
            _ => None,
        },
        _ => None,
    }
}

fn assign_roles<'o>(def: &Def, ops: &'o [Operand]) -> Roles<'o> {
    let mut roles = Roles {
        rm: None,
        reg: None,
        imm: None,
        rel: None,
    };
    let takes_reg_field = def.modrm == ModRm::Reg || def.flags & PLUSREG != 0;
    for (pat, o) in def.ops.iter().zip(ops) {
        match *pat {
            Op::Rm(_) | Op::M(_) | Op::IndirectRm(_) if roles.rm.is_none() => roles.rm = Some(o),
            Op::R(_) if takes_reg_field && roles.reg.is_none() => roles.reg = o.reg(),
            // An encoding with no reg field puts its register in r/m instead.
            Op::R(_) if roles.rm.is_none() => roles.rm = Some(o),
            Op::Imm(w) => {
                if let OperandKind::Imm(e) = &o.kind {
                    roles.imm = Some((*e, w));
                }
            }
            Op::Imm8s => {
                if let OperandKind::Imm(e) = &o.kind {
                    roles.imm = Some((*e, 1));
                }
            }
            Op::Rel(w) => {
                if let Some(e) = rel_expr(o) {
                    roles.rel = Some((e, w));
                }
            }
            _ => {}
        }
    }
    roles
}

pub fn encode(
    cx: &mut AsmCtx<'_>,
    bits: u8,
    def: &Def,
    ops: &[Operand],
    prefixes: Prefixes,
    span: Span,
) -> Option<Variant> {
    if bits == 64 && def.flags & NO64 != 0 {
        cx.error(span, "this instruction is not encodable in 64-bit mode");
        return None;
    }
    if bits != 64 && def.flags & ONLY64 != 0 {
        cx.error(span, "this instruction is only encodable in 64-bit mode");
        return None;
    }

    let roles = assign_roles(def, ops);
    let mut bytes: Vec<u8> = Vec::with_capacity(8);
    let mut fixups: Vec<Fixup> = Vec::new();

    // ---- legacy prefixes --------------------------------------------------
    if prefixes.lock {
        bytes.push(0xf0);
    }
    if let Some(r) = prefixes.rep {
        bytes.push(r);
    }

    let mem = roles.rm.and_then(|o| match &o.kind {
        OperandKind::Mem(m) => Some(m.clone()),
        OperandKind::Indirect(inner) => match &**inner {
            OperandKind::Mem(m) => Some(m.clone()),
            _ => None,
        },
        _ => None,
    });

    let seg_override = match mem.as_ref().and_then(|m| m.seg) {
        Some(seg) => match segment_prefix(seg) {
            Some(p) => Some(p),
            None => {
                cx.error(
                    span,
                    format!("`{}` is not a valid segment override", reg::name_of(seg)),
                );
                return None;
            }
        },
        None => prefixes.seg,
    };
    if let Some(p) = seg_override {
        bytes.push(p);
    }

    // Address-size override: a 32-bit address in 64-bit mode, or vice versa.
    if let Some(m) = &mem {
        let uses_regs = m.base.is_some() || m.index.is_some();
        let native = if bits == 64 { 8 } else { 4 };
        if uses_regs && m.addr_size != native {
            if (bits == 64 && m.addr_size == 4) || (bits == 32 && m.addr_size == 2) {
                bytes.push(0x67);
            } else {
                cx.error(
                    m.span,
                    format!(
                        "{}-bit addressing is not available in {bits}-bit mode",
                        m.addr_size * 8
                    ),
                );
                return None;
            }
        }
    }

    // Operand-size override.
    let wants_66 = match def.opsize {
        16 => bits != 16,
        32 => bits == 16,
        _ => false,
    };
    if wants_66 {
        bytes.push(0x66);
    }
    if def.pfx != 0 {
        bytes.push(def.pfx);
    }

    // ---- REX --------------------------------------------------------------
    let rex_w =
        def.opsize == 64 && def.flags & NO_REX_W == 0 && !(bits == 64 && def.flags & DEF64 != 0);
    if def.opsize == 64 && bits != 64 && def.flags & DEF64 == 0 {
        cx.error(span, "64-bit operands require 64-bit mode");
        return None;
    }

    let rm_reg = roles.rm.and_then(rm_register);

    // With a `+r` opcode the register lives in the opcode's low three bits,
    // so its fourth bit is REX.B rather than REX.R.
    let plus_reg = def.flags & PLUSREG != 0;
    let rex_r = !plus_reg && roles.reg.is_some_and(|r| r.needs_rex_ext());
    let rex_b = rm_reg.is_some_and(|r| r.needs_rex_ext())
        || mem
            .as_ref()
            .and_then(|m| m.base)
            .is_some_and(|r| r.needs_rex_ext())
        || (plus_reg && roles.reg.is_some_and(|r| r.needs_rex_ext()));
    let rex_x = mem
        .as_ref()
        .and_then(|m| m.index)
        .is_some_and(|r| r.needs_rex_ext());

    // spl/bpl/sil/dil only exist with a REX prefix present, even an empty one.
    let forced_rex =
        roles.reg.is_some_and(|r| r.rex_required) || rm_reg.is_some_and(|r| r.rex_required);
    // ah/ch/dh/bh cannot coexist with REX.
    let has_high_byte = roles.reg.is_some_and(|r| r.class == RegClass::GprHigh)
        || rm_reg.is_some_and(|r| r.class == RegClass::GprHigh);

    let need_rex = rex_w || rex_r || rex_b || rex_x || forced_rex;
    if need_rex {
        if has_high_byte {
            cx.error(
                span,
                "`ah`, `ch`, `dh` and `bh` cannot be used in an instruction that needs a REX prefix",
            );
            return None;
        }
        if bits != 64 {
            cx.error(span, "this operand combination requires 64-bit mode");
            return None;
        }
        let rex = 0x40
            | ((rex_w as u8) << 3)
            | ((rex_r as u8) << 2)
            | ((rex_x as u8) << 1)
            | (rex_b as u8);
        bytes.push(rex);
    }

    // ---- opcode -----------------------------------------------------------
    let opcode_start = bytes.len();
    bytes.extend_from_slice(&def.opcode);
    if plus_reg {
        let Some(r) = roles.reg else {
            cx.error(span, "internal: `+r` encoding without a register operand");
            return None;
        };
        let last = bytes.len() - 1;
        bytes[last] += r.num & 7;
    }
    let _ = opcode_start;

    // ---- ModRM / SIB / displacement ---------------------------------------
    // A RIP-relative displacement is measured from the end of the whole
    // instruction, so its fixup is built after the immediate has been emitted.
    let mut disp_fixup: Option<(usize, ExprRef, Span, bool)> = None;

    match def.modrm {
        ModRm::None => {}
        ModRm::Reg | ModRm::Ext(_) => {
            let reg_field = match def.modrm {
                ModRm::Ext(e) => e,
                _ => match roles.reg {
                    Some(r) => r.num & 7,
                    None => {
                        cx.error(span, "internal: `/r` encoding without a register operand");
                        return None;
                    }
                },
            };
            let Some(rm_operand) = roles.rm else {
                cx.error(span, "internal: encoding needs an r/m operand");
                return None;
            };
            encode_rm(
                cx,
                bits,
                &mut bytes,
                &mut disp_fixup,
                reg_field,
                rm_operand,
                mem.as_ref(),
            )?;
        }
    }

    // ---- immediate --------------------------------------------------------
    if let Some((e, width)) = roles.imm {
        let offset = bytes.len() as u32;
        let folded = cx.constant(e);
        match folded {
            Some(v) => bytes.extend_from_slice(&v.to_le_bytes()[..width as usize]),
            None => {
                bytes.extend(std::iter::repeat_n(0u8, width as usize));
                // A 32-bit immediate in a 64-bit operation is sign-extended by
                // the CPU, so the linker must be told to range-check it as
                // signed rather than let it wrap.
                let sign_extended = def.opsize == 64 && width == 4;
                let r = if def.flags & IMM64 != 0 {
                    reloc::ABS64
                } else if sign_extended {
                    reloc::ABS32S
                } else {
                    reloc::abs(width).unwrap_or(0)
                };
                let mut kind = FixupKind::data(width).with_reloc(r);
                kind.signed = sign_extended;
                fixups.push(Fixup {
                    offset,
                    expr: e,
                    kind,
                    span: cx.exprs.span(e),
                });
            }
        }
    }

    // A displacement fixup can only be built now that the instruction length,
    // and therefore the RIP-relative bias, is known.
    if let Some((offset, e, dspan, rip_relative)) = disp_fixup {
        let trailing = (bytes.len() - offset - 4) as i8;
        let kind = if rip_relative {
            FixupKind::pcrel(4, trailing + 4).with_reloc(reloc::PC32)
        } else {
            FixupKind::data(4).with_reloc(reloc::ABS32S)
        };
        fixups.push(Fixup {
            offset: offset as u32,
            expr: e,
            kind,
            span: dspan,
        });
    }

    // ---- relative branch target -------------------------------------------
    if let Some((e, width)) = roles.rel {
        let offset = bytes.len() as u32;
        bytes.extend(std::iter::repeat_n(0u8, width as usize));
        let reloc = if width == 4 { reloc::PLT32 } else { 0 };
        fixups.push(Fixup {
            offset,
            expr: e,
            // The displacement is measured from the end of the instruction,
            // which is `width` bytes past the start of this field.
            kind: FixupKind::pcrel(width, width as i8).with_reloc(reloc),
            span: cx.exprs.span(e),
        });
    }

    Some(Variant { bytes, fixups })
}

/// Emits the ModRM byte plus any SIB and displacement.
fn encode_rm(
    cx: &mut AsmCtx<'_>,
    bits: u8,
    bytes: &mut Vec<u8>,
    disp_fixup: &mut Option<(usize, ExprRef, Span, bool)>,
    reg_field: u8,
    rm_operand: &Operand,
    mem: Option<&Mem>,
) -> Option<()> {
    // Register direct.
    if let Some(r) = rm_register(rm_operand) {
        bytes.push(0xc0 | ((reg_field & 7) << 3) | (r.num & 7));
        return Some(());
    }

    let Some(m) = mem else {
        cx.error(
            rm_operand.span,
            format!(
                "expected a register or memory operand, found {}",
                rm_operand.describe()
            ),
        );
        return None;
    };

    // RIP-relative: mod=00, rm=101, always a 32-bit displacement.
    if m.rip_relative {
        if bits != 64 {
            cx.error(m.span, "RIP-relative addressing requires 64-bit mode");
            return None;
        }
        if m.base.is_some() || m.index.is_some() {
            cx.error(
                m.span,
                "RIP-relative addressing cannot be combined with other registers",
            );
            return None;
        }
        bytes.push(((reg_field & 7) << 3) | 0b101);
        let at = bytes.len();
        bytes.extend_from_slice(&[0; 4]);
        // A constant here is the displacement itself: `2(%rip)` addresses two
        // bytes past the next instruction. Only a symbolic displacement is
        // turned into "distance from here to that symbol".
        match m.disp {
            None => {}
            Some(e) => match cx.constant(e) {
                Some(v) => {
                    if i32::try_from(v).is_err() {
                        cx.error(m.span, format!("displacement {v} does not fit in 32 bits"));
                        return None;
                    }
                    bytes[at..at + 4].copy_from_slice(&(v as i32).to_le_bytes());
                }
                None => *disp_fixup = Some((at, e, m.span, true)),
            },
        }
        return Some(());
    }

    let disp_const = m.disp.and_then(|e| cx.constant(e));
    let has_disp = m.disp.is_some();
    let symbolic_disp = has_disp && disp_const.is_none();

    // No base and no index: an absolute address.
    if m.base.is_none() && m.index.is_none() {
        if bits == 64 {
            // 64-bit mode has no ModRM form for a bare disp32, so the SIB
            // escape with no base and no index is used instead.
            bytes.push(((reg_field & 7) << 3) | 0b100);
            bytes.push((0b100 << 3) | 0b101);
        } else {
            bytes.push(((reg_field & 7) << 3) | 0b101);
        }
        push_disp32(cx, bytes, disp_fixup, m, disp_const);
        return Some(());
    }

    let base = m.base;
    let base_low = base.map_or(0, |b| b.num & 7);
    // rsp/r12 as a base always needs SIB; rbp/r13 always needs a displacement.
    let need_sib = m.index.is_some() || base.is_none() || base_low == 0b100;
    let base_forces_disp = base.is_some() && base_low == 0b101;

    let disp_size: u8 = if symbolic_disp {
        4
    } else if base.is_none() {
        // index-only addressing encodes disp32 with mod=00.
        4
    } else {
        match disp_const.unwrap_or(0) {
            0 if !base_forces_disp => 0,
            v if (-128..=127).contains(&v) => 1,
            _ => 4,
        }
    };

    let mod_bits = if base.is_none() {
        0b00
    } else {
        match disp_size {
            0 => 0b00,
            1 => 0b01,
            _ => 0b10,
        }
    };

    if need_sib {
        bytes.push((mod_bits << 6) | ((reg_field & 7) << 3) | 0b100);
        let scale_bits = match m.scale {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            s => {
                cx.error(m.span, format!("invalid scale {s}"));
                return None;
            }
        };
        let index_bits = match m.index {
            Some(i) => i.num & 7,
            None => 0b100, // no index
        };
        let base_bits = match base {
            Some(b) => b.num & 7,
            None => 0b101, // no base; disp32 follows
        };
        bytes.push((scale_bits << 6) | (index_bits << 3) | base_bits);
    } else {
        bytes.push((mod_bits << 6) | ((reg_field & 7) << 3) | base_low);
    }

    match disp_size {
        0 => {}
        1 => bytes.push(disp_const.unwrap_or(0) as u8),
        _ => push_disp32(cx, bytes, disp_fixup, m, disp_const),
    }
    Some(())
}

fn push_disp32(
    cx: &mut AsmCtx<'_>,
    bytes: &mut Vec<u8>,
    disp_fixup: &mut Option<(usize, ExprRef, Span, bool)>,
    m: &Mem,
    disp_const: Option<i64>,
) {
    match disp_const {
        Some(v) => bytes.extend_from_slice(&(v as i32).to_le_bytes()),
        None => {
            let at = bytes.len();
            bytes.extend_from_slice(&[0; 4]);
            let e = m.disp.unwrap_or_else(|| cx.exprs.int(0, m.span));
            *disp_fixup = Some((at, e, m.span, false));
        }
    }
}

/// The canonical multi-byte no-ops recommended by both vendors, indexed by
/// length. Padding with these keeps alignment padding executable and cheap.
///
/// The exact split differs from GNU as, which varies it by `-mtune`; any
/// sequence of no-ops of the right total length is correct.
pub fn nop_bytes(bits: u8, len: usize) -> Vec<u8> {
    // The long forms are `0f 1f`, which predates neither 16-bit mode nor the
    // pre-P6 processors that 16-bit code is usually written for.
    if bits < 32 {
        return vec![0x90; len];
    }
    #[rustfmt::skip]
    const NOPS: [&[u8]; 12] = [
        &[],
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    let mut out = Vec::with_capacity(len);
    let mut left = len;
    while left > 0 {
        let take = left.min(NOPS.len() - 1);
        out.extend_from_slice(NOPS[take]);
        left -= take;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::nop_bytes;

    #[test]
    fn nop_padding_has_the_requested_length() {
        for bits in [16u8, 32, 64] {
            for len in 0..64 {
                assert_eq!(nop_bytes(bits, len).len(), len, "bits={bits} len={len}");
            }
        }
    }

    #[test]
    fn sixteen_bit_mode_uses_only_the_one_byte_nop() {
        assert_eq!(nop_bytes(16, 3), vec![0x90, 0x90, 0x90]);
    }
}
