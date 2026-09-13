//! Instruction encoding: prefixes, REX/VEX/EVEX, opcode, ModRM/SIB,
//! displacement and immediate.

use super::insn::{
    DEF64, Def, EVEX_ER, EVEX_SAE, Enc, IMM64, ModRm, NEEDS_MASK, NO_REX_W, NO64, NOMASK, ONLY64,
    Op, PLUSREG, Tuple, Vk,
};
use super::operand::{Decor, Mem, Operand, OperandKind, RoundCtl};
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
    /// The non-destructive source VEX and EVEX carry in `vvvv`.
    nds: Option<Reg>,
    /// A register named by the top nibble of a trailing immediate byte.
    is4: Option<Reg>,
    /// (expression, encoded width in bytes)
    imm: Option<(ExprRef, u8)>,
    rel: Option<(ExprRef, u8)>,
    /// The decorators found on the operands, merged.
    decor: Decor,
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
            decor: o.decor,
            span: o.span,
        }),
        // Intel syntax writes indirect branches without a sigil.
        OperandKind::Reg(_) | OperandKind::Mem(_) => Some(o.clone()),
        _ => None,
    }
}

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

/// Works out which operand fills which encoding slot.
///
/// The pattern says everything needed: the first r/m-capable operand goes to
/// ModRM.rm, a register operand goes to ModRM.reg (or the low bits of a `+r`
/// opcode), and immediates and branch targets go to their own fields.
fn assign_roles<'o>(def: &Def, ops: &'o [Operand]) -> Roles<'o> {
    let mut roles = Roles {
        rm: None,
        reg: None,
        nds: None,
        is4: None,
        imm: None,
        rel: None,
        decor: Decor::default(),
    };
    let takes_reg_field = def.modrm == ModRm::Reg || def.flags & PLUSREG != 0;
    for (pat, o) in def.ops.iter().zip(ops) {
        // Decorators are written on whichever operand they qualify, but they
        // all end up in the one EVEX prefix, so they are merged here.
        if !o.decor.is_empty() {
            let d = &o.decor;
            roles.decor.mask = roles.decor.mask.or(d.mask);
            roles.decor.zeroing |= d.zeroing;
            roles.decor.broadcast = roles.decor.broadcast.or(d.broadcast);
            roles.decor.span = if roles.decor.span.is_dummy() {
                d.span
            } else {
                roles.decor.span
            };
        }
        match *pat {
            Op::Rm(_) | Op::M(_) | Op::IndirectRm(_) if roles.rm.is_none() => roles.rm = Some(o),
            Op::Vm(..) | Op::Vsib(_) if roles.rm.is_none() => roles.rm = Some(o),
            Op::V(_) if takes_reg_field && roles.reg.is_none() => roles.reg = o.reg(),
            // A `/digit` encoding has no reg field, so its register operand
            // goes to r/m instead: that is how the shift-by-immediate forms
            // of `psllw` and friends are built.
            Op::V(_) if roles.rm.is_none() => roles.rm = Some(o),
            Op::Nds(_) => roles.nds = o.reg(),
            Op::Is4(_) => roles.is4 = o.reg(),
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

/// The `pp` field VEX and EVEX use in place of a mandatory legacy prefix.
fn pp_bits(pfx: u8) -> u8 {
    match pfx {
        0x66 => 1,
        0xf3 => 2,
        0xf2 => 3,
        _ => 0,
    }
}

/// The `L'L` field: 0 = 128-bit, 1 = 256-bit, 2 = 512-bit.
fn len_bits(vlen: u16) -> u8 {
    match vlen {
        256 => 1,
        512 => 2,
        _ => 0,
    }
}

/// What an encoding depends on besides the instruction: the current mode, and
/// the relocation numbering of the object being written. They differ for a
/// `.code32` stretch inside an x86-64 object.
#[derive(Copy, Clone, Debug)]
pub struct Target {
    pub bits: u8,
    pub abi: reloc::Abi,
}

pub fn encode(
    cx: &mut AsmCtx<'_>,
    target: Target,
    def: &Def,
    ops: &[Operand],
    prefixes: Prefixes,
    rounding: Option<(RoundCtl, Span)>,
    span: Span,
) -> Option<Variant> {
    let Target { bits, abi } = target;
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

    check_decorators(cx, def, &roles, rounding, mem.is_some(), span)?;
    check_vsib(cx, def, mem.as_ref(), span)?;

    // Only EVEX has the fifth register-number bit, so `xmm16` and above are
    // unreachable from any other encoding even though they parse fine.
    if def.enc != Enc::Evex {
        let high = [
            roles.reg,
            roles.nds,
            roles.is4,
            roles.rm.and_then(rm_register),
        ]
        .into_iter()
        .flatten()
        .chain(mem.iter().flat_map(|m| [m.base, m.index]).flatten())
        .find(|r| r.needs_evex_ext());
        if let Some(r) = high {
            cx.error(
                span,
                format!(
                    "`{}` is only reachable through an EVEX-encoded instruction",
                    reg::name_of(r)
                ),
            );
            return None;
        }
    }

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

    let rm_reg = roles.rm.and_then(rm_register);
    let plus_reg = def.flags & PLUSREG != 0;

    // VEX and EVEX store their extension bits inverted so that outside 64-bit
    // mode an unextended prefix still decodes, there, as the `LES`/`LDS`/
    // `BOUND` opcode it overlays. Setting one would produce a different
    // instruction, so the registers that need one simply do not exist.
    // The legacy path makes the same check when it builds a REX byte.
    if bits != 64 && def.enc != Enc::Legacy {
        let all = [roles.reg, roles.nds, roles.is4, rm_reg]
            .into_iter()
            .flatten()
            .chain(mem.iter().flat_map(|m| [m.base, m.index]).flatten());
        for r in all {
            if r.num >= 8 || (r.is_gpr() && r.size == 8) {
                cx.error(
                    span,
                    format!("`{}` is only available in 64-bit mode", reg::name_of(r)),
                );
                return None;
            }
        }
    }

    // The REX-style register extension bits, worked out before deciding which
    // prefix will carry them. `X` doubles as the fifth bit of a register-direct r/m
    // operand under EVEX, which is how `xmm16`-`xmm31` are reached there.
    let base_reg = mem.as_ref().and_then(|m| m.base);
    let index_reg = mem.as_ref().and_then(|m| m.index);
    let ext_r = !plus_reg && roles.reg.is_some_and(|r| r.num & 8 != 0);
    let ext_b = rm_reg.is_some_and(|r| r.num & 8 != 0)
        || base_reg.is_some_and(|r| r.num & 8 != 0)
        || (plus_reg && roles.reg.is_some_and(|r| r.num & 8 != 0));
    let ext_x = match (&index_reg, rm_reg) {
        (Some(i), _) => i.num & 8 != 0,
        (None, Some(r)) if def.enc == Enc::Evex => r.num & 16 != 0,
        _ => false,
    };

    match def.enc {
        Enc::Legacy => {
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

            let rex_w = def.opsize == 64
                && def.flags & NO_REX_W == 0
                && !(bits == 64 && def.flags & DEF64 != 0);
            if def.opsize == 64 && bits != 64 && def.flags & DEF64 == 0 {
                cx.error(span, "64-bit operands require 64-bit mode");
                return None;
            }

            // spl/bpl/sil/dil only exist with a REX prefix present, even an
            // empty one.
            let forced_rex =
                roles.reg.is_some_and(|r| r.rex_required) || rm_reg.is_some_and(|r| r.rex_required);
            // ah/ch/dh/bh cannot coexist with REX.
            let has_high_byte = roles.reg.is_some_and(|r| r.class == RegClass::GprHigh)
                || rm_reg.is_some_and(|r| r.class == RegClass::GprHigh);

            let need_rex = rex_w || ext_r || ext_b || ext_x || forced_rex;
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
                    | ((ext_r as u8) << 2)
                    | ((ext_x as u8) << 1)
                    | (ext_b as u8);
                bytes.push(rex);
            }
        }
        Enc::Vex => {
            let vvvv = roles.nds.map_or(0, |r| r.num);
            let l = len_bits(def.vlen);
            let pp = pp_bits(def.pfx);
            let w = def.vex_w();
            // The two-byte form has no room for X, B or W, and only reaches
            // the `0F` map; anything else has to spell the prefix out.
            if def.map == 1 && !w && !ext_x && !ext_b {
                bytes.push(0xc5);
                bytes.push(((!ext_r as u8) << 7) | ((!vvvv & 0xf) << 3) | (l << 2) | pp);
            } else {
                bytes.push(0xc4);
                bytes.push(
                    ((!ext_r as u8) << 7)
                        | ((!ext_x as u8) << 6)
                        | ((!ext_b as u8) << 5)
                        | (def.map & 0x1f),
                );
                bytes.push(((w as u8) << 7) | ((!vvvv & 0xf) << 3) | (l << 2) | pp);
            }
        }
        Enc::Evex => {
            let vvvv = roles.nds.map_or(0, |r| r.num);
            let pp = pp_bits(def.pfx);
            let w = def.vex_w();
            let ext_r2 = roles.reg.is_some_and(|r| r.num & 16 != 0);
            // `V'` extends `vvvv`, except with a VSIB memory operand, where it
            // is the fifth bit of the vector index instead.
            let ext_v2 = match index_reg {
                Some(i) if i.is_vector() => i.num & 16 != 0,
                _ => vvvv & 16 != 0,
            };
            let broadcast = roles.decor.broadcast.is_some();
            // Embedded rounding replaces the vector length with the rounding
            // mode and sets `b`, which is why it only exists on register-only
            // forms: there is no memory operand left to broadcast or scale.
            let (ll, b_bit) = match rounding {
                Some((ctl, _)) => (ctl.ll(), true),
                None => (len_bits(def.vlen), broadcast),
            };
            let aaa = roles.decor.mask.map_or(0, |r| r.num);
            bytes.push(0x62);
            bytes.push(
                ((!ext_r as u8) << 7)
                    | ((!ext_x as u8) << 6)
                    | ((!ext_b as u8) << 5)
                    | ((!ext_r2 as u8) << 4)
                    | (def.map & 7),
            );
            bytes.push(((w as u8) << 7) | ((!vvvv & 0xf) << 3) | (1 << 2) | pp);
            bytes.push(
                ((roles.decor.zeroing as u8) << 7)
                    | (ll << 5)
                    | ((b_bit as u8) << 4)
                    | ((!ext_v2 as u8) << 3)
                    | (aaa & 7),
            );
        }
    }

    // ---- opcode -----------------------------------------------------------
    bytes.extend_from_slice(&def.opcode);
    if plus_reg {
        let Some(r) = roles.reg else {
            cx.error(span, "internal: `+r` encoding without a register operand");
            return None;
        };
        let last = bytes.len() - 1;
        bytes[last] += r.num & 7;
    }

    // ---- ModRM / SIB / displacement ---------------------------------------
    // A RIP-relative displacement is measured from the end of the whole
    // instruction, so its fixup is built after the immediate has been emitted.
    let mut disp_fixup: Option<(usize, ExprRef, Span, bool)> = None;

    // EVEX scales an 8-bit displacement by the size of the memory access, so
    // one byte still spans a 512-bit stride. See `Tuple`.
    let disp_scale = if def.enc == Enc::Evex {
        let vbytes = def.vlen as u32 / 8;
        match def
            .tuple
            .scale(vbytes, def.vex_w(), roles.decor.broadcast.is_some())
        {
            Some(n) => n,
            None => {
                if mem.is_some() {
                    cx.error(span, "internal: EVEX memory form with no tuple type");
                    return None;
                }
                1
            }
        }
    } else {
        1
    };

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
                disp_scale,
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
                let sign_extended = def.opsize == 64 && width == 4 && def.enc == Enc::Legacy;
                let r = if def.flags & IMM64 != 0 {
                    abi.abs(8).unwrap_or(0)
                } else if sign_extended {
                    abi.abs32_signed()
                } else {
                    abi.abs(width).unwrap_or(0)
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

    // `is4`: a whole immediate byte whose top nibble names a register.
    if let Some(r) = roles.is4 {
        bytes.push((r.num & 0xf) << 4);
    }

    // 3DNow! puts its opcode selector where an immediate would go.
    if let Some(s) = def.suffix {
        bytes.push(s);
    }

    // A displacement fixup can only be built now that the instruction length,
    // and therefore the RIP-relative bias, is known.
    if let Some((offset, e, dspan, rip_relative)) = disp_fixup {
        let trailing = (bytes.len() - offset - 4) as i8;
        let kind = if rip_relative {
            FixupKind::pcrel(4, trailing + 4).with_reloc(abi.pcrel(4).unwrap_or(0))
        } else if bits == 64 {
            // A 64-bit-mode displacement is sign-extended to the address
            // width, so the linker has to range-check it as signed.
            FixupKind::data(4).with_reloc(abi.abs32_signed())
        } else {
            FixupKind::data(4).with_reloc(abi.abs(4).unwrap_or(0))
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
        // GNU as routes a plain 64-bit-mode call through the PLT but leaves a
        // 32-bit-mode one PC-relative, and that follows the mode rather than
        // the object: `.code32` inside an x86-64 object gets `R_X86_64_PC32`.
        let reloc = match width {
            4 if bits == 64 => abi.plt32(),
            4 => abi.pcrel(4).unwrap_or(0),
            _ => 0,
        };
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

/// Rejects decorators the chosen encoding cannot carry.
fn check_decorators(
    cx: &mut AsmCtx<'_>,
    def: &Def,
    roles: &Roles<'_>,
    rounding: Option<(RoundCtl, Span)>,
    has_mem: bool,
    span: Span,
) -> Option<()> {
    let d = &roles.decor;
    if def.enc != Enc::Evex {
        if let Some((_, rspan)) = rounding {
            cx.error(
                rspan,
                "embedded rounding control is only available on AVX-512 forms",
            );
            return None;
        }
        if !d.is_empty() {
            cx.error(
                d.span,
                "operand decorators are only available on AVX-512 forms",
            );
            return None;
        }
        return Some(());
    }

    if let Some((ctl, rspan)) = rounding {
        if ctl.is_sae_only() {
            if def.flags & (EVEX_SAE | EVEX_ER) == 0 {
                cx.error(rspan, "this instruction does not take `{sae}`");
                return None;
            }
            // Rounding-capable instructions spell exception suppression with
            // an explicit mode; a bare `{sae}` is rejected there by both
            // reference assemblers.
            if def.flags & EVEX_SAE == 0 {
                cx.error(
                    rspan,
                    "this instruction takes a rounding mode such as `{rn-sae}`, not `{sae}`",
                );
                return None;
            }
        } else if def.flags & EVEX_ER == 0 {
            cx.error(rspan, "this instruction takes no embedded rounding control");
            return None;
        }
        if has_mem {
            cx.error(
                rspan,
                "embedded rounding control cannot be combined with a memory operand",
            );
            return None;
        }
    }
    if d.mask.is_some() && def.flags & NOMASK != 0 {
        cx.error(d.span, "this instruction takes no writemask");
        return None;
    }
    if d.mask.is_none() && def.flags & NEEDS_MASK != 0 {
        cx.error(
            span,
            "this instruction requires a writemask such as `{%k1}`",
        );
        return None;
    }
    if d.zeroing && d.mask.is_none() {
        cx.error(d.span, "`{z}` requires a writemask register");
        return None;
    }
    if let Some(b) = d.broadcast {
        let bspan = b.span;
        if !has_mem {
            cx.error(bspan, "a broadcast decorator needs a memory operand");
            return None;
        }
        if !def.tuple.broadcastable() {
            cx.error(bspan, "this instruction does not support broadcast");
            return None;
        }
        // N is redundant — it is the register's element count — so it is
        // recomputed and the source's spelling checked against it.
        let vbytes = def.vlen as u32 / 8;
        let n = match def.tuple {
            // A half-vector source is half the register, in dword elements.
            Tuple::Hv => vbytes / 2 / 4,
            _ => vbytes / if def.vex_w() { 8 } else { 4 },
        };
        if b.count != n {
            cx.error(bspan, format!("this operand broadcasts as `{{1to{n}}}`"));
            return None;
        }
    }
    Some(())
}

/// Checks that a VSIB pattern got a vector index and that nothing else did.
fn check_vsib(cx: &mut AsmCtx<'_>, def: &Def, mem: Option<&Mem>, span: Span) -> Option<()> {
    let want: Option<Vk> = def.ops.iter().find_map(|o| match o {
        Op::Vsib(k) => Some(*k),
        _ => None,
    });
    let index = mem.and_then(|m| m.index);
    match (want, index) {
        (Some(k), Some(i)) if k.accepts(i) => Some(()),
        (Some(_), _) => {
            cx.error(
                mem.map_or(span, |m| m.span),
                "this instruction needs a vector index register",
            );
            None
        }
        (None, Some(i)) if i.is_vector() => {
            cx.error(
                mem.map_or(span, |m| m.span),
                format!(
                    "`{}` can only index memory in a gather or scatter",
                    reg::name_of(i)
                ),
            );
            None
        }
        _ => Some(()),
    }
}

/// Emits the ModRM byte plus any SIB and displacement.
#[allow(clippy::too_many_arguments)]
fn encode_rm(
    cx: &mut AsmCtx<'_>,
    bits: u8,
    bytes: &mut Vec<u8>,
    disp_fixup: &mut Option<(usize, ExprRef, Span, bool)>,
    reg_field: u8,
    rm_operand: &Operand,
    mem: Option<&Mem>,
    disp_scale: u32,
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
    // A VSIB index also forces SIB, since that is where it lives.
    let need_sib = m.index.is_some() || base.is_none() || base_low == 0b100;
    let base_forces_disp = base.is_some() && base_low == 0b101;

    // index-only addressing encodes disp32 with mod=00.
    let disp_size: u8 = if symbolic_disp || base.is_none() {
        4
    } else {
        let v = disp_const.unwrap_or(0);
        // Under EVEX a one-byte displacement is stored pre-divided by the size
        // of the access, so it is only usable when the value divides exactly.
        let n = disp_scale as i64;
        let fits8 = v % n == 0 && (-128..=127).contains(&(v / n));
        match () {
            _ if v == 0 && !base_forces_disp => 0,
            _ if fits8 => 1,
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
        1 => bytes.push((disp_const.unwrap_or(0) / disp_scale as i64) as u8),
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
    use super::*;

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

    #[test]
    fn tuple_scales_match_the_manual() {
        // Full vector: the whole register, or one element under broadcast.
        assert_eq!(Tuple::Fv.scale(64, false, false), Some(64));
        assert_eq!(Tuple::Fv.scale(32, false, false), Some(32));
        assert_eq!(Tuple::Fv.scale(64, false, true), Some(4));
        assert_eq!(Tuple::Fv.scale(64, true, true), Some(8));
        // Scalars scale by their element, whatever the vector length.
        assert_eq!(Tuple::T1s.scale(64, false, false), Some(4));
        assert_eq!(Tuple::T1s.scale(16, true, false), Some(8));
        // The fractional-memory tuples follow the vector length.
        assert_eq!(Tuple::Hvm.scale(64, false, false), Some(32));
        assert_eq!(Tuple::Qvm.scale(64, false, false), Some(16));
        assert_eq!(Tuple::Ovm.scale(64, false, false), Some(8));
    }
}
