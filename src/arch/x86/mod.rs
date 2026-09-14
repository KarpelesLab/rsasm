//! The x86 / x86-64 backend.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, FlatModifier, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::lexer::TokKind;
use crate::section::Variant;
use crate::source::Span;
use encode::Prefixes;
use insn::{DEF64, Def, Enc, NO64, NOTACC, ONLY64, Op};
use operand::{Operand, OperandKind, OperandParser, RoundCtl};

pub const NAMES: &[&str] = &["x86-64", "i386", "i8086"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let bits = match name {
        "x86-64" | "x86_64" | "amd64" | "x64" => 64,
        "i386" | "x86" | "i486" | "i586" | "i686" => 32,
        "i8086" | "i286" | "16" => 16,
        _ => return None,
    };
    Some(Box::new(X86 { bits }))
}

pub struct X86 {
    /// Default operating mode, before any `.code16`/`.code32`/`.code64`.
    bits: u8,
}

impl Architecture for X86 {
    fn name(&self) -> &'static str {
        match self.bits {
            64 => "x86-64",
            32 => "i386",
            _ => "i8086",
        }
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["x86_64", "amd64", "x64", "x86", "i486", "i686", "i286"]
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn pointer_bytes(&self, state: &ArchState) -> u8 {
        state.bits / 8
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: self.bits,
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
            used: 0,
        }
    }

    fn supports_syntax(&self, _syntax: Syntax) -> bool {
        true
    }

    fn elf_machine(&self) -> u16 {
        match self.bits {
            64 => 62, // EM_X86_64
            _ => 3,   // EM_386
        }
    }

    fn pcrel_number_is_address(&self) -> bool {
        true
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        let abi = reloc::Abi::for_object_bits(self.bits);
        if pcrel {
            abi.pcrel(size)
        } else {
            abi.abs(size)
        }
    }

    fn modifier_reloc(&self, name: &str, size: u8, pcrel: bool) -> Option<u32> {
        let abi = reloc::Abi::for_object_bits(self.bits);
        match name {
            "plt" => Some(abi.plt32()),
            // NASM spells the RIP-relative GOT load `wrt ..got`; `..gotpcrel`
            // is accepted too, as the GNU `@GOTPCREL` name.
            "gotpcrel" => abi.gotpcrel(),
            "got" => abi.got(size, pcrel),
            "gotoff" => abi.gotoff(size),
            "gotpc" => abi.gotpc(size),
            // `wrt ..sym` relocates against the symbol itself, with the plain
            // absolute or PC-relative type for the field.
            "sym" => {
                if pcrel {
                    abi.pcrel(size)
                } else {
                    abi.abs(size)
                }
            }
            _ => None,
        }
    }

    /// `@PLT` is `L + A - P`, and in a static image the PLT entry `L` is the
    /// function itself; `@GOT` and `@GOTPCREL` need a GOT.
    fn flat_modifier(&self, name: &str) -> FlatModifier {
        if name == "plt" {
            FlatModifier::PcRelative
        } else {
            FlatModifier::LinkerOnly
        }
    }

    fn is_mnemonic(&self, name: &str) -> bool {
        insn::is_mnemonic(name) || prefix_kind(name).is_some()
    }

    fn nop_fill(&self, state: &ArchState, len: u64) -> Vec<u8> {
        encode::nop_bytes(state.bits, len as usize)
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(req.mnemonic).to_ascii_lowercase();
        let abi = reloc::Abi::for_object_bits(self.bits);
        assemble_inner(cx, req, &mnemonic, Prefixes::default(), abi, 0)
    }

    fn directive(&self, cx: &mut AsmCtx<'_>, name: &str, cur: &mut Cursor<'_>) -> bool {
        match name {
            ".code16" | ".code32" | ".code64" => {
                let bits: u8 = name[5..].parse().expect("literal is numeric");
                cx.state.bits = bits;
                true
            }
            ".intel_syntax" => {
                cx.state.syntax = Syntax::Intel;
                // `noprefix` (the usual spelling) means registers are written
                // bare; `prefix` keeps the AT&T `%` sigil.
                if let TokKind::Ident(n) = cur.peek().kind {
                    let word = cx.interner.get(n).to_ascii_lowercase();
                    cur.advance();
                    cx.state.intel_register_prefix = word == "prefix";
                }
                true
            }
            ".att_syntax" => {
                cx.state.syntax = Syntax::Att;
                if let TokKind::Ident(_) = cur.peek().kind {
                    cur.advance();
                }
                true
            }
            _ => false,
        }
    }
}

/// A prefix mnemonic, which attaches to the instruction written after it.
enum PrefixKind {
    Lock,
    Rep(u8),
    Segment(u8),
}

fn prefix_kind(mnemonic: &str) -> Option<PrefixKind> {
    Some(match mnemonic {
        "lock" => PrefixKind::Lock,
        "rep" | "repe" | "repz" => PrefixKind::Rep(0xf3),
        "repne" | "repnz" => PrefixKind::Rep(0xf2),
        "es" | "cs" | "ss" | "ds" | "fs" | "gs" => {
            let r = reg::lookup(mnemonic).expect("segment names are in the register table");
            PrefixKind::Segment(encode::segment_prefix(r).expect("segment has a prefix byte"))
        }
        _ => return None,
    })
}

fn assemble_inner(
    cx: &mut AsmCtx<'_>,
    req: &InsnRequest<'_>,
    mnemonic: &str,
    mut prefixes: Prefixes,
    abi: reloc::Abi,
    depth: u32,
) -> Option<Vec<Variant>> {
    if depth > 4 {
        cx.error(req.span, "too many instruction prefixes");
        return None;
    }

    // `lock`, `rep`, `fs` and friends prefix the instruction that follows.
    if let Some(kind) = prefix_kind(mnemonic) {
        match kind {
            PrefixKind::Lock => prefixes.lock = true,
            PrefixKind::Rep(r) => prefixes.rep = Some(r),
            PrefixKind::Segment(s) => prefixes.seg = Some(s),
        }
        let mut cur = req.cursor();
        if cur.at_end() {
            // A bare prefix on its own line emits just the prefix byte.
            let mut bytes = Vec::new();
            if prefixes.lock {
                bytes.push(0xf0);
            }
            if let Some(r) = prefixes.rep {
                bytes.push(r);
            }
            if let Some(s) = prefixes.seg {
                bytes.push(s);
            }
            return Some(vec![Variant::new(bytes)]);
        }
        let tok = cur.advance();
        let Some(next) = tok.ident() else {
            cx.error(tok.span, "expected an instruction after a prefix");
            return None;
        };
        let next_text = cx.name(next).to_ascii_lowercase();
        let sub = InsnRequest {
            mnemonic: next,
            mnemonic_span: tok.span,
            operands: cur.rest(),
            span: req.span,
        };
        return assemble_inner(cx, &sub, &next_text, prefixes, abi, depth + 1);
    }

    let syntax = cx.state.syntax;
    let bits = cx.state.bits;

    let Some(resolved) = resolve_mnemonic(mnemonic, syntax) else {
        cx.error(
            req.mnemonic_span,
            format!("unknown instruction `{mnemonic}`"),
        );
        return None;
    };

    // Parse the operand list.
    let cur = req.cursor();
    let pieces = cur.split_commas();
    let mut ops: Vec<Operand> = Vec::with_capacity(pieces.len());
    for piece in &pieces {
        if piece.is_empty() {
            cx.error(req.span, "empty operand");
            return None;
        }
        let mut pc = Cursor::new(piece);
        let mut p = OperandParser {
            cx,
            syntax,
            addr_size: if bits == 64 { 8 } else { bits / 8 },
        };
        let o = p.parse(&mut pc)?;
        if !pc.at_end() && !pc.is_empty() {
            cx.error(pc.peek().span, "unexpected token after operand");
            return None;
        }
        ops.push(o);
    }

    // The table is written in Intel order, so AT&T operands are reversed.
    if syntax == Syntax::Att {
        ops.reverse();
    }

    // NASM moves the accumulator to or from a bare address with the one-byte
    // `A0`-`A3` opcodes, a byte shorter than the ModRM form, which is why
    // `mov eax, [var]` is `a1` there and `8b 05` under GNU as.
    if cx.dialect == crate::lexer::Dialect::Nasm
        && (mnemonic == "mov" || mnemonic == "movq")
        && let Some(v) = try_moffs(cx, bits, abi, &ops, req.span)
    {
        return Some(vec![v]);
    }

    // A size keyword on one operand fixes the operation width: `mov [eax],
    // byte 1` is a byte store, though the memory operand itself is unsized.
    // NASM lets the keyword ride on whichever operand it likes, so the hint
    // is carried to an unsized memory operand from a sized sibling.
    if let Some(hint) = ops
        .iter()
        .find(|o| matches!(o.kind, OperandKind::Imm(_)) && o.size_hint.is_some())
        .and_then(|o| o.size_hint)
    {
        for o in &mut ops {
            if o.is_mem() && o.size_hint.is_none() {
                o.size_hint = Some(hint);
            }
        }
    }

    // `{rn-sae}` occupies an operand slot in the source but encodes as bits in
    // the EVEX prefix, so it is lifted out before the operands are matched.
    let mut rounding: Option<(RoundCtl, Span)> = None;
    for o in &ops {
        if let Some(ctl) = o.rounding() {
            if rounding.is_some() {
                cx.error(o.span, "only one rounding-control decorator is allowed");
                return None;
            }
            rounding = Some((ctl, o.span));
        }
    }
    ops.retain(|o| o.rounding().is_none());

    // NASM's default optimizer loads a 64-bit register from a non-negative
    // immediate that fits 32 bits with the `mov r32, imm32` form, which
    // zero-extends and is two bytes shorter than the sign-extending one. GNU
    // as leaves it as written; the difference shows only in the NASM dialect.
    if cx.dialect == crate::lexer::Dialect::Nasm
        && bits == 64
        && (mnemonic == "mov" || mnemonic == "movq")
        && let [dst, src] = ops.as_slice()
        && let (OperandKind::Reg(r), OperandKind::Imm(e)) = (&dst.kind, &src.kind)
        && r.is_gpr()
        && r.size == 8
        && cx
            .constant(*e)
            .is_some_and(|v| (0..=0xffff_ffff).contains(&v))
    {
        ops[0].kind = OperandKind::Reg(reg::Reg { size: 4, ..*r });
        ops[0].size_hint = Some(4);
    }

    let mut matches = select(cx, bits, resolved.defs, &resolved, &ops);
    if matches.is_empty() {
        report_no_match(cx, req, mnemonic, resolved.defs, &ops);
        return None;
    }

    // NASM loads a 64-bit register from a symbol with the full `movabs`
    // (64-bit immediate) form, since the address is unknown and might not fit
    // 32 bits; GNU as uses the sign-extending 32-bit form. This shows only in
    // the NASM dialect and only for a still-symbolic immediate.
    if cx.dialect == crate::lexer::Dialect::Nasm
        && bits == 64
        && (mnemonic == "mov" || mnemonic == "movq")
        && let [dst, src] = ops.as_slice()
        && let (OperandKind::Reg(r), OperandKind::Imm(e)) = (&dst.kind, &src.kind)
        && r.is_gpr()
        && r.size == 8
        && cx.constant(*e).is_none()
        && let Some(pos) = matches.iter().position(|d| d.flags & insn::IMM64 != 0)
    {
        matches.swap(0, pos);
    }

    let matches = prefer_default_size(bits, matches, &ops);
    let matches = prefer_evex_when_required(matches, &ops, rounding.is_some());

    // A relative branch gets one variant per displacement width, smallest
    // first, so the layout pass can shorten it once addresses are known.
    let is_rel = matches[0]
        .ops
        .first()
        .is_some_and(|o| matches!(o, Op::Rel(_)));
    let chosen: Vec<&Def> = if is_rel {
        let mut v: Vec<&Def> = matches
            .iter()
            .copied()
            .filter(|d| d.ops.first().is_some_and(|o| matches!(o, Op::Rel(_))))
            .collect();
        v.sort_by_key(|d| d.ops[0].width());
        v.dedup_by_key(|d| d.ops[0].width());
        v
    } else {
        vec![matches[0]]
    };

    let mut variants = Vec::with_capacity(chosen.len());
    for def in &chosen {
        variants.push(encode::encode(
            cx,
            encode::Target { bits, abi },
            def,
            &ops,
            prefixes,
            rounding,
            req.span,
        )?);
    }

    if !is_rel && chosen[0].enc == Enc::Vex {
        prefer_shorter_vex(
            cx,
            encode::Target { bits, abi },
            &matches,
            &ops,
            prefixes,
            &mut variants[0],
        );
    }
    Some(variants)
}

/// Narrows the candidates to EVEX forms when the operands need one.
///
/// Where AVX and AVX-512 both define an instruction, the VEX row comes first
/// and wins for plain operands, as it does in both reference assemblers. But
/// `xmm16`, a writemask, a broadcast or a rounding mode can only be carried by
/// EVEX; the VEX row still *matches* those operands by class, so it is set
/// aside here rather than left to fail during encoding.
///
/// When no EVEX form matched, the list is left alone, so the encoder can
/// explain what went wrong with the form that was closest.
fn prefer_evex_when_required<'d>(
    matches: Vec<&'d Def>,
    ops: &[Operand],
    rounding: bool,
) -> Vec<&'d Def> {
    let high = |r: &reg::Reg| r.needs_evex_ext();
    let needs_evex = rounding
        || ops.iter().any(|o| {
            !o.decor.is_empty()
                || match &o.kind {
                    OperandKind::Reg(r) => high(r),
                    OperandKind::Mem(m) => m.index.as_ref().is_some_and(high),
                    _ => false,
                }
        });
    if !needs_evex || !matches.iter().any(|d| d.enc == Enc::Evex) {
        return matches;
    }
    matches.into_iter().filter(|d| d.enc == Enc::Evex).collect()
}

/// Swaps in a later VEX form when it encodes shorter than the preferred one.
///
/// A register-to-register `vmovaps` can be written with the load opcode or the
/// store opcode, and the two put the source register in different ModRM
/// fields. When the source is `xmm8`-`xmm15` and the destination is not, only
/// the store opcode lets the extension bit ride in `R`, which the two-byte VEX
/// prefix has, rather than `B`, which it does not. GNU as and llvm-mc both
/// make that choice, so rsasm does too.
///
/// llvm-mc also swaps the two sources of a commutative operation such as
/// `vaddps` for the same reason. GNU as does not, and rsasm follows GNU as.
fn prefer_shorter_vex(
    cx: &mut AsmCtx<'_>,
    target: encode::Target,
    matches: &[&Def],
    ops: &[Operand],
    prefixes: Prefixes,
    best: &mut Variant,
) {
    // Only register operands can land in either field; with memory involved
    // the forms are not interchangeable.
    if !ops
        .iter()
        .all(|o| o.reg().is_some() || matches!(o.kind, OperandKind::Imm(_)))
    {
        return;
    }
    let first = matches[0];
    for alt in matches.iter().skip(1) {
        if alt.enc != Enc::Vex || alt.vlen != first.vlen {
            continue;
        }
        // An alternative that cannot be encoded is simply not a candidate, so
        // whatever it would have reported is discarded.
        let mark = cx.diags.len();
        let v = encode::encode(cx, target, alt, ops, prefixes, None, Span::DUMMY);
        truncate_diags(cx, mark);
        if let Some(v) = v
            && v.bytes.len() < best.bytes.len()
        {
            *best = v;
        }
    }
}

/// Drops every diagnostic recorded after the first `len`.
fn truncate_diags(cx: &mut AsmCtx<'_>, len: usize) {
    if cx.diags.len() <= len {
        return;
    }
    let kept: Vec<_> = cx.diags.take().into_iter().take(len).collect();
    for d in kept {
        cx.diags.emit(d);
    }
}

/// What a mnemonic resolved to, including any width implied by an AT&T suffix.
struct Resolved {
    defs: &'static [Def],
    /// Required `Def::opsize`, from a suffix such as the `l` in `movl`.
    opsize: Option<u8>,
    /// Required width of the r/m operand, for `movzbl`-style double suffixes.
    rm_width: Option<u8>,
    /// Rows to try, unconstrained, when nothing in `defs` matched. See the
    /// note on `movq` in `resolve_mnemonic`.
    fallback: &'static [Def],
}

fn suffix_width(c: u8) -> Option<u8> {
    Some(match c {
        b'b' => 1,
        b'w' => 2,
        b'l' => 4,
        b'q' => 8,
        _ => return None,
    })
}

fn resolve_mnemonic(mnemonic: &str, syntax: Syntax) -> Option<Resolved> {
    // `movq` names two instructions in AT&T syntax: `mov` with a `q` suffix,
    // and the MMX/SSE quadword move. The GPR reading is tried first, as GNU as
    // does, and the vector rows only if it matched nothing. Intel syntax has no
    // size suffixes, so there `movq` is only the vector instruction and the
    // ordinary exact lookup below handles it.
    if syntax == Syntax::Att
        && mnemonic == "movq"
        && let (Some(defs), Some(vector)) = (insn::lookup("mov"), insn::lookup("movq"))
    {
        return Some(Resolved {
            defs,
            opsize: Some(64),
            rm_width: None,
            fallback: vector,
        });
    }

    // An exact table entry always wins, so the string instruction `movsb` is
    // never mistaken for `movs` with a `b` suffix.
    if let Some(defs) = insn::lookup(mnemonic) {
        return Some(Resolved {
            defs,
            opsize: None,
            rm_width: None,
            fallback: &[],
        });
    }
    if syntax != Syntax::Att {
        return None;
    }
    let b = mnemonic.as_bytes();

    // `movzbl`, `movswq`, `movslq`: source width then destination width.
    if b.len() == 6
        && (mnemonic.starts_with("movz") || mnemonic.starts_with("movs"))
        && let (Some(src), Some(dst)) = (suffix_width(b[4]), suffix_width(b[5]))
        && src < dst
    {
        let base = if mnemonic.starts_with("movz") {
            "movzx"
        } else if src == 4 {
            // 32-to-64 sign extension has its own opcode.
            "movsxd"
        } else {
            "movsx"
        };
        if let Some(defs) = insn::lookup(base) {
            return Some(Resolved {
                defs,
                opsize: Some(dst * 8),
                rm_width: Some(src),
                fallback: &[],
            });
        }
    }

    // A single trailing size letter. Only an ASCII byte can be one, which is
    // also what makes `len - 1` a safe place to split.
    let last = *mnemonic.as_bytes().last()?;
    if !last.is_ascii() {
        return None;
    }
    let w = suffix_width(last)?;
    let defs = insn::lookup(&mnemonic[..mnemonic.len() - 1])?;
    Some(Resolved {
        defs,
        opsize: Some(w * 8),
        rm_width: None,
        fallback: &[],
    })
}

/// Every definition that accepts `ops`, in table (preference) order.
fn select<'d>(
    cx: &mut AsmCtx<'_>,
    bits: u8,
    defs: &'d [Def],
    resolved: &Resolved,
    ops: &[Operand],
) -> Vec<&'d Def> {
    let mut out = Vec::new();
    for def in defs {
        if def.ops.len() != ops.len() {
            continue;
        }
        // A form the mode cannot encode is not a candidate, so it never
        // shadows the one that can: the 32-bit `jmp r/m` is `NO64`, and the
        // 64-bit form `DEF64`, and only one applies in a given mode.
        if (bits == 64 && def.flags & NO64 != 0) || (bits != 64 && def.flags & ONLY64 != 0) {
            continue;
        }
        if let Some(want) = resolved.opsize
            && def.opsize != want
        {
            continue;
        }
        if let Some(want) = resolved.rm_width {
            let rm = def.ops.iter().find_map(|o| match o {
                Op::Rm(w) | Op::M(w) => Some(*w),
                _ => None,
            });
            if rm != Some(want) {
                continue;
            }
        }
        if def.flags & NOTACC != 0 && all_accumulator(ops) {
            continue;
        }
        if def
            .ops
            .iter()
            .zip(ops)
            .all(|(p, o)| op_matches(cx, bits, def, p, o))
        {
            out.push(def);
        }
    }
    // A suffix that matched nothing may still be part of a symbol-like
    // mnemonic; without one, fall back to the unconstrained set.
    if out.is_empty() && resolved.opsize.is_some() && resolved.rm_width.is_none() {
        for def in defs {
            if def.ops.len() == ops.len()
                && def.opsize == 0
                && def
                    .ops
                    .iter()
                    .zip(ops)
                    .all(|(p, o)| op_matches(cx, bits, def, p, o))
            {
                out.push(def);
            }
        }
    }
    if out.is_empty() {
        for def in resolved.fallback {
            if def.ops.len() == ops.len()
                && def
                    .ops
                    .iter()
                    .zip(ops)
                    .all(|(p, o)| op_matches(cx, bits, def, p, o))
            {
                out.push(def);
            }
        }
    }
    out
}

/// True when every operand is a register and all of them are the accumulator.
fn all_accumulator(ops: &[Operand]) -> bool {
    !ops.is_empty()
        && ops
            .iter()
            .all(|o| o.reg().is_some_and(|r| r.is_gpr() && r.num == 0))
}

fn fits_unsigned_or_signed(v: i64, width: u8) -> bool {
    match width {
        1 => (-128..=255).contains(&v),
        2 => (-32768..=65535).contains(&v),
        4 => (-(1i64 << 31)..=(1i64 << 32) - 1).contains(&v),
        _ => true,
    }
}

fn op_matches(cx: &mut AsmCtx<'_>, bits: u8, def: &Def, pat: &Op, o: &Operand) -> bool {
    match *pat {
        Op::R(w) => o.reg().is_some_and(|r| r.is_gpr() && r.size == w),
        Op::Rm(w) => match &o.kind {
            OperandKind::Reg(r) => r.is_gpr() && r.size == w,
            OperandKind::Mem(_) => o.size_hint.is_none_or(|h| h == w),
            _ => false,
        },
        Op::M(w) => {
            matches!(o.kind, OperandKind::Mem(_)) && (w == 0 || o.size_hint.is_none_or(|h| h == w))
        }
        Op::Imm(w) => {
            let OperandKind::Imm(e) = &o.kind else {
                return false;
            };
            match cx.constant(*e) {
                Some(v) => {
                    // A 32-bit immediate in a 64-bit operation is sign-extended
                    // to 64 bits, so it must fit as signed.
                    if w == 4 && def.opsize == 64 {
                        (-(1i64 << 31)..(1i64 << 31)).contains(&v)
                    } else {
                        fits_unsigned_or_signed(v, w)
                    }
                }
                // A symbolic value needs a field wide enough to relocate.
                None => w >= 2,
            }
        }
        Op::Imm8s => {
            let OperandKind::Imm(e) = &o.kind else {
                return false;
            };
            cx.constant(*e).is_some_and(|v| (-128..=127).contains(&v))
        }
        Op::One => {
            let OperandKind::Imm(e) = &o.kind else {
                return false;
            };
            cx.constant(*e) == Some(1)
        }
        Op::V(k) | Op::Nds(k) | Op::Is4(k) => o.reg().is_some_and(|r| k.accepts(r)),
        Op::Vm(k, msz) => match &o.kind {
            OperandKind::Reg(r) => k.accepts(*r),
            OperandKind::Mem(_) => {
                // Under `{1toN}` an Intel size keyword names the element being
                // broadcast, not the vector.
                let w = if o.decor.broadcast.is_some() {
                    match def.tuple {
                        insn::Tuple::Hv => 4,
                        _ if def.vex_w() => 8,
                        _ => 4,
                    }
                } else if msz == 0 {
                    k.width()
                } else {
                    msz
                };
                o.size_hint.is_none_or(|h| h == w)
            }
            _ => false,
        },
        // A vector index must be of the class this row expects, since that is
        // what tells a 128-bit gather from a 256-bit one with the same
        // destination. A GPR index or none at all is let through so the
        // encoder can say what is missing.
        Op::Vsib(k) => match &o.kind {
            OperandKind::Mem(m) => m.index.is_none_or(|i| !i.is_vector() || k.accepts(i)),
            _ => false,
        },
        Op::Fixed(name) => o.reg() == reg::lookup(name),
        Op::SReg => o.reg().is_some_and(|r| r.class == reg::RegClass::Segment),
        Op::CReg => o.reg().is_some_and(|r| r.class == reg::RegClass::Control),
        Op::DReg => o.reg().is_some_and(|r| r.class == reg::RegClass::Debug),
        Op::Rel(_) => encode::rel_expr(o).is_some(),
        Op::IndirectRm(w) => {
            // AT&T marks indirect branches with `*`; Intel does not.
            let explicit = matches!(o.kind, OperandKind::Indirect(_));
            if !explicit && cx.state.syntax == Syntax::Att && !o.is_mem() {
                return false;
            }
            match encode::indirect_inner(o) {
                Some(inner) => match inner.kind {
                    OperandKind::Reg(r) => r.is_gpr() && r.size == w,
                    OperandKind::Mem(_) => {
                        let _ = bits;
                        o.size_hint.is_none_or(|h| h == w)
                    }
                    _ => false,
                },
                None => false,
            }
        }
    }
}

/// Resolves an operand size the source never pinned down.
///
/// `mov $1, (%rax)` could store one, two, four or eight bytes. GNU as picks
/// the mode's default operand size — four bytes in 32- and 64-bit mode — and
/// existing sources rely on that, so rsasm does the same rather than
/// rejecting the line. NASM-dialect input should insist on an explicit size
/// instead; that belongs with the NASM front end, not here.
fn prefer_default_size<'d>(bits: u8, matches: Vec<&'d Def>, ops: &[Operand]) -> Vec<&'d Def> {
    let unsized_mem = ops.iter().any(|o| o.is_mem() && o.size_hint.is_none());
    if !unsized_mem || matches.len() < 2 {
        return matches;
    }
    // A branch whose direct form matched wins over any indirect one, so a bare
    // `call sym` stays `e8 rel32` and does not become an indirect call through
    // `[sym]` just because the memory operand has no size.
    if matches[0]
        .ops
        .first()
        .is_some_and(|o| matches!(o, Op::Rel(_)))
    {
        return matches;
    }
    let first = matches[0];
    // Instructions whose operand size already defaults to 64 bits in long
    // mode are not ambiguous there.
    if bits == 64 && first.flags & DEF64 != 0 {
        return matches;
    }
    if matches.iter().all(|d| d.opsize == first.opsize) {
        return matches;
    }
    let default_size: u8 = if bits == 16 { 16 } else { 32 };
    let mut matches = matches;
    if let Some(pos) = matches.iter().position(|d| d.opsize == default_size) {
        matches.swap(0, pos);
    }
    matches
}

fn report_no_match(
    cx: &mut AsmCtx<'_>,
    req: &InsnRequest<'_>,
    mnemonic: &str,
    defs: &[Def],
    ops: &[Operand],
) {
    let arities: Vec<usize> = {
        let mut v: Vec<usize> = defs.iter().map(|d| d.ops.len()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if !arities.contains(&ops.len()) {
        let want: Vec<String> = arities.iter().map(|n| n.to_string()).collect();
        cx.error(
            req.span,
            format!(
                "`{mnemonic}` takes {} operand(s), but {} were given",
                want.join(" or "),
                ops.len()
            ),
        );
        return;
    }
    let described: Vec<String> = ops.iter().map(|o| o.describe()).collect();
    cx.error(
        req.span,
        format!("no form of `{mnemonic}` accepts {}", described.join(", ")),
    );
}

/// Builds the accumulator-to-memory `mov` NASM prefers, `A0`-`A3` with the
/// address as a `moffs` of the current address size, if the operands fit that
/// shape: the accumulator and a bare-displacement memory operand with no base,
/// index or RIP. Returns `None` — building nothing — otherwise, so the caller
/// falls back to the ordinary encoding.
fn try_moffs(
    cx: &mut AsmCtx<'_>,
    bits: u8,
    abi: reloc::Abi,
    ops: &[Operand],
    span: Span,
) -> Option<crate::section::Variant> {
    use crate::section::{Fixup, FixupKind, Variant};
    let [a, b] = ops else { return None };
    // One operand is the accumulator, the other bare-displacement memory.
    let acc = a.reg().or_else(|| b.reg())?;
    if !(acc.is_gpr() && acc.num == 0) {
        return None;
    }
    let (mem_op, load) = match (&a.kind, &b.kind) {
        (OperandKind::Reg(_), OperandKind::Mem(m)) => (m, true),
        (OperandKind::Mem(m), OperandKind::Reg(_)) => (m, false),
        _ => return None,
    };
    if mem_op.base.is_some() || mem_op.index.is_some() || mem_op.rip_relative {
        return None;
    }
    // In long mode NASM uses `moffs` only for a genuine 64-bit address, not
    // for a symbol or a short constant, so the accumulator shortcut is a
    // 16-/32-bit affair here.
    if bits == 64 {
        return None;
    }
    let disp = mem_op.disp?;
    // moffs holds the whole address, in the mode's address size; a size
    // override would need a ModRM form, so this only fires at the native size.
    let addr_size = match bits {
        64 => 8u8,
        32 => 4,
        _ => 2,
    };
    let mut bytes = Vec::new();
    if let Some(seg) = mem_op.seg {
        bytes.push(encode::segment_prefix(seg)?);
    }
    // Operand-size prefix for a 16-bit accumulator outside 16-bit mode, or a
    // 32-bit one within it; REX.W for the 64-bit accumulator.
    if (acc.size == 2 && bits != 16) || (acc.size == 4 && bits == 16) {
        bytes.push(0x66);
    }
    if acc.size == 8 {
        bytes.push(0x48);
    }
    let opcode = match (acc.size == 1, load) {
        (true, true) => 0xa0,
        (true, false) => 0xa2,
        (false, true) => 0xa1,
        (false, false) => 0xa3,
    };
    bytes.push(opcode);
    let offset = bytes.len() as u32;
    let mut fixups = Vec::new();
    match cx.constant(disp) {
        Some(v) => bytes.extend_from_slice(&(v as u64).to_le_bytes()[..addr_size as usize]),
        None => {
            bytes.extend(std::iter::repeat_n(0u8, addr_size as usize));
            let reloc = cx
                .find_modifier_for(disp)
                .and_then(|m| {
                    // A `wrt ..got`/`..sym` on the address picks its own type.
                    let name = cx.name(m).to_string();
                    reloc_moffs_modifier(abi, &name, addr_size)
                })
                .or_else(|| abi.abs(addr_size))
                .unwrap_or(0);
            fixups.push(Fixup {
                offset,
                expr: disp,
                kind: FixupKind::data(addr_size).with_reloc(reloc),
                span: cx.exprs.span(disp),
            });
        }
    }
    let _ = span;
    Some(Variant { bytes, fixups })
}

/// The relocation a `wrt` modifier on a moffs address selects.
fn reloc_moffs_modifier(abi: reloc::Abi, name: &str, size: u8) -> Option<u32> {
    match name {
        "got" => abi.got(size, false),
        "gotoff" => abi.gotoff(size),
        "sym" => abi.abs(size),
        _ => None,
    }
}

/// True if `name` is a register, used by the generic parser to avoid treating
/// register names as symbols.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}

/// Convenience for tests and for the `--print-encoding` debug output.
pub fn describe_span(span: Span) -> String {
    format!("{span:?}")
}
