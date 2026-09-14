//! The x86 / x86-64 backend.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, FlatModifier, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::expr::{BinOp, ExprKind, ExprRef};
use crate::lexer::{LocalDir, TokKind};
use crate::section::Variant;
use crate::source::Span;
use encode::Prefixes;
use insn::{ATT_ONLY, DEF64, Def, Enc, INTEL_ONLY, NO64, NOTACC, ONLY64, Op};
use operand::{Operand, OperandKind, OperandParser, RoundCtl};
use reg::RegClass;

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
        if abi == reloc::Abi::I386 {
            // Every i386 modifier names a 32-bit relocation.
            return if size == 4 {
                reloc::Abi::i386_modifier(name)
            } else {
                None
            };
        }
        match name {
            "plt" => Some(abi.plt32()),
            "gotpcrel" => abi.gotpcrel(),
            "got" => Some(abi.got32()),
            _ => {
                let _ = (size, pcrel);
                None
            }
        }
    }

    fn fixup_modifier_reloc(&self, name: &str, kind: &crate::section::FixupKind) -> Option<u32> {
        let abi = reloc::Abi::for_object_bits(self.bits);
        if abi == reloc::Abi::I386 {
            // The encoder marks the `@GOT` loads the linker may relax.
            if name == "got" && kind.reloc == reloc::Abi::I386_GOT32X {
                return Some(kind.reloc);
            }
            // A modifier with no relocation at this width is an error, not a
            // plain reference to the symbol.
            return Some(
                self.modifier_reloc(name, kind.size, kind.pcrel)
                    .unwrap_or(0),
            );
        }
        self.modifier_reloc(name, kind.size, kind.pcrel)
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
                cx.state.features &= !CODE16GCC;
                true
            }
            ".code16gcc" => {
                cx.state.bits = 16;
                cx.state.features |= CODE16GCC;
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

/// Set in `ArchState::features` by `.code16gcc`: 16-bit code in which the
/// stack instructions and calls default to 32 bits, as GCC's 32-bit output
/// assumes when it is assembled to run in real mode.
pub const CODE16GCC: u64 = 1 << 0;

/// A prefix mnemonic, which attaches to the instruction written after it.
enum PrefixKind {
    Lock,
    Rep(u8),
    Segment(u8),
    /// `data16`/`data32`: the operand size override, with its size.
    Data(u8),
    /// `addr16`/`addr32`: the address size override, with its size.
    Addr(u8),
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
        "data16" => PrefixKind::Data(16),
        "data32" => PrefixKind::Data(32),
        "addr16" => PrefixKind::Addr(16),
        "addr32" => PrefixKind::Addr(32),
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
        let bits = cx.state.bits;
        match kind {
            PrefixKind::Lock => prefixes.lock = true,
            PrefixKind::Rep(r) => prefixes.rep = Some(r),
            PrefixKind::Segment(s) => prefixes.seg = Some(s),
            // A size prefix names the size it switches to, so the mode's own
            // size is refused as redundant, and long mode has no 32-bit
            // operand or 16-bit address prefix to write.
            PrefixKind::Data(size) | PrefixKind::Addr(size) => {
                let data = matches!(kind, PrefixKind::Data(_));
                let (native, missing) = if data { (32, 32) } else { (64, 16) };
                let native = if bits == 64 { native } else { bits };
                if bits == 64 && size == missing {
                    cx.error(
                        req.mnemonic_span,
                        format!("`{mnemonic}` is not available in 64-bit mode"),
                    );
                    return None;
                }
                if size == native {
                    cx.error(
                        req.mnemonic_span,
                        format!("`{mnemonic}` is redundant in {bits}-bit mode"),
                    );
                    return None;
                }
                if data {
                    prefixes.data = true;
                } else {
                    prefixes.addr = true;
                }
            }
        }
        let mut cur = req.cursor();
        if cur.at_end() {
            // A bare prefix on its own line emits just the prefix byte.
            let mut bytes = Vec::new();
            if let Some(s) = prefixes.seg {
                bytes.push(s);
            }
            if prefixes.addr {
                bytes.push(0x67);
            }
            if prefixes.data {
                bytes.push(0x66);
            }
            if let Some(r) = prefixes.rep {
                bytes.push(r);
            }
            if prefixes.lock {
                bytes.push(0xf0);
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
    // A `q` suffix names a size only long mode has. (`movq` in 32-bit code
    // is still the MMX and SSE move.)
    if bits != 64 && resolved.opsize == Some(64) && resolved.fallback.is_empty() {
        cx.error(
            req.mnemonic_span,
            format!("`{mnemonic}` is only available in 64-bit mode"),
        );
        return None;
    }

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
    for o in &mut ops {
        fold_operand(cx, o);
    }

    // The table is written in Intel order, so AT&T operands are reversed —
    // except for `enter` and `bound`, whose AT&T operands GNU as has always
    // taken in Intel order, and llvm-mc with it.
    let named = |name: &str| {
        mnemonic
            .strip_prefix(name)
            .is_some_and(|s| matches!(s, "" | "b" | "w" | "l" | "q"))
    };
    if syntax == Syntax::Att && !named("enter") && !named("bound") {
        ops.reverse();
    }
    // `imul $imm, %reg` multiplies the register in place: it is the
    // three-operand form with the register as both source and destination.
    if named("imul")
        && ops.len() == 2
        && ops[0].reg().is_some()
        && matches!(ops[1].kind, OperandKind::Imm(_))
    {
        ops.insert(1, ops[0].clone());
    }
    // AT&T writes a direct far pointer as two immediates, segment first.
    if syntax == Syntax::Att
        && ops.len() == 2
        && resolved.defs.iter().any(|d| d.ops == [Op::Far])
        && let (OperandKind::Imm(off), OperandKind::Imm(seg)) = (&ops[0].kind, &ops[1].kind)
    {
        let span = ops[1].span.to(ops[0].span);
        ops = vec![Operand {
            kind: OperandKind::FarPtr {
                seg: *seg,
                off: *off,
            },
            size_hint: None,
            decor: Default::default(),
            span,
        }];
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

    let matches = select(cx, bits, resolved.defs, &resolved, &ops);
    if matches.is_empty() {
        report_no_match(cx, req, mnemonic, &resolved, &ops);
        return None;
    }

    // Stack and branch instructions have a default operand size in every
    // mode, which the rest do not; the rows long mode widened say which.
    let stack = resolved.defs.iter().any(|d| d.flags & DEF64 != 0);
    if syntax == Syntax::Intel && !stack && ambiguous_memory_size(&matches, &ops) {
        cx.error(
            req.span,
            format!("`{mnemonic}` needs the size of its memory operand, as in `dword ptr [...]`"),
        );
        return None;
    }
    // `.code16gcc` widens what GCC's 32-bit code expects of the stack: the
    // pushes and pops, calls and returns, and the frame instructions. Jumps
    // and `iret` stay 16-bit.
    let gcc16 = cx.state.features & CODE16GCC != 0
        && matches!(
            mnemonic,
            "push"
                | "pop"
                | "pushf"
                | "popf"
                | "pusha"
                | "popa"
                | "call"
                | "ret"
                | "lret"
                | "retf"
                | "enter"
                | "leave"
        );
    let matches = prefer_default_size(bits, gcc16, stack, matches, &resolved);
    // A stack instruction with only immediates is the mode's size, and an
    // immediate that does not fit it is not a reason to pick another one:
    // `push $0xffffffff` in 64-bit code is an error, not a `pushw`.
    if stack
        && resolved.opsize.is_none()
        && !ops.is_empty()
        && ops.iter().all(|o| matches!(o.kind, OperandKind::Imm(_)))
        && matches[0].opsize != default_operand_size(bits, gcc16, stack)
    {
        cx.error(
            req.span,
            format!("the immediate does not fit `{mnemonic}` at the {bits}-bit mode's size"),
        );
        return None;
    }
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
            .filter(|d| {
                d.opsize == matches[0].opsize
                    && d.ops.first().is_some_and(|o| matches!(o, Op::Rel(_)))
            })
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
    /// The suffix is on `jmp` or `call`, where it can name the mode's size.
    branch: bool,
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
            branch: false,
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
            branch: false,
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
                branch: false,
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
    let stem = &mnemonic[..mnemonic.len() - 1];
    let defs = insn::lookup(stem)?;
    // On the Intel-style names of the extending moves, GNU as reads the
    // suffix as the width of the source: `movsxb %al, %ecx`.
    if matches!(stem, "movzx" | "movsx") {
        return Some(Resolved {
            defs,
            opsize: None,
            rm_width: Some(w),
            fallback: &[],
            branch: false,
        });
    }
    // Only an instruction that comes in more than one size takes a suffix:
    // `cwtl` and `lodsl` already name theirs, so `cwtll` is no instruction.
    if defs.iter().all(|d| d.opsize == defs[0].opsize) {
        return None;
    }
    Some(Resolved {
        defs,
        opsize: Some(w * 8),
        rm_width: None,
        fallback: &[],
        branch: matches!(stem, "jmp" | "call"),
    })
}

/// True if `def` exists in the current mode and syntax.
fn available(cx: &AsmCtx<'_>, bits: u8, def: &Def) -> bool {
    let mode_ok = if bits == 64 {
        def.flags & NO64 == 0
    } else {
        def.flags & ONLY64 == 0
    };
    let syntax_ok = match cx.state.syntax {
        Syntax::Att => def.flags & INTEL_ONLY == 0,
        Syntax::Intel => def.flags & ATT_ONLY == 0,
    };
    mode_ok && syntax_ok
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
        if def.ops.len() != ops.len() || !available(cx, bits, def) {
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
    // A relative `jmp` or `call` has no operand size of its own to match, but
    // takes the suffix of the mode's: `calll` in 32-bit code, `callq` in
    // 64-bit code. Any other suffix on an instruction without sizes is
    // refused, as GNU as refuses it.
    let branch_suffix = matches!((resolved.opsize, bits), (Some(32), 32) | (Some(64), 64));
    if out.is_empty() && resolved.branch && branch_suffix {
        for def in defs {
            if def.ops.len() == ops.len()
                && available(cx, bits, def)
                && matches!(def.ops.first(), Some(Op::Rel(_)))
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
                && available(cx, bits, def)
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
                    if w == 4 && def.opsize == 64 {
                        // A 32-bit immediate in a 64-bit operation is
                        // sign-extended to 64 bits, so it must fit as signed.
                        (-(1i64 << 31)..(1i64 << 31)).contains(&v)
                    } else if w * 8 == def.opsize {
                        // An immediate as wide as the operation is truncated
                        // to it: GNU as warns and llvm-mc agrees on the
                        // bytes, so `movb $0x100, %al` stores zero. A narrower
                        // field, like a shift count or the frame size of a
                        // 32-bit `enter`, has to hold the value.
                        true
                    } else {
                        fits_unsigned_or_signed(v, w)
                    }
                }
                // A symbolic value is relocated at whatever width the field
                // has.
                None => true,
            }
        }
        Op::Imm8s => {
            let OperandKind::Imm(e) = &o.kind else {
                return false;
            };
            // A value that fits the operation's size is taken at that size
            // first, so a 16-bit `0xffff` is the -1 that fits a sign-extended
            // byte. GNU as also reads anything that fits 32 bits as a 32-bit
            // value, so `0xffffffff` is -1 to a 16-bit operation too.
            cx.constant(*e).is_some_and(|v| {
                let v = match def.opsize {
                    16 if (0..=0xffff).contains(&v) => v as i16 as i64,
                    16 | 32 if (0..=0xffff_ffff).contains(&v) => v as i32 as i64,
                    _ => v,
                };
                (-128..=127).contains(&v)
            })
        }
        Op::One | Op::Three => {
            let OperandKind::Imm(e) = &o.kind else {
                return false;
            };
            cx.constant(*e) == Some(if *pat == Op::One { 1 } else { 3 })
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
        Op::Seg => o.reg().is_some_and(|r| r.class == RegClass::Segment),
        Op::Cr => o.reg().is_some_and(|r| r.class == RegClass::Control),
        Op::Dr => o.reg().is_some_and(|r| r.class == RegClass::Debug),
        Op::St => o.reg().is_some_and(|r| r.class == RegClass::St),
        Op::Moffs(w) => match &o.kind {
            OperandKind::Mem(m) => {
                // GNU as keeps a `@GOT` load in ModRM form, which is the
                // one a linker knows how to relax.
                m.base.is_none()
                    && m.index.is_none()
                    && !m.rip_relative
                    && m.disp
                        .is_some_and(|e| encode::modifier(cx, e).as_deref() != Some("got"))
                    && o.size_hint.is_none_or(|h| h == w)
            }
            _ => false,
        },
        Op::Far => matches!(o.kind, OperandKind::FarPtr { .. }),
        // Neither reference checks that a string operand names `si` or `di`:
        // the registers only give the address size.
        Op::StrSrc(w) | Op::StrDst(w) => o.is_mem() && o.size_hint.is_none_or(|h| h == w),
        Op::FarM | Op::Fword | Op::FarDword => {
            let is_mem = match &o.kind {
                OperandKind::Mem(_) => true,
                OperandKind::Indirect(inner) => matches!(**inner, OperandKind::Mem(_)),
                _ => false,
            };
            is_mem
                && match *pat {
                    Op::Fword => o.size_hint == Some(6),
                    Op::FarDword => {
                        o.size_hint == Some(4) && bits != 32 && cx.state.syntax == Syntax::Intel
                    }
                    _ => o.size_hint.is_none_or(|h| h == 6),
                }
        }
        Op::Dx => match &o.kind {
            OperandKind::Reg(r) => *r == reg::lookup("dx").expect("dx is a register"),
            // AT&T also spells the port `(%dx)`.
            OperandKind::Mem(m) => {
                m.base == reg::lookup("dx")
                    && m.index.is_none()
                    && m.disp.is_none()
                    && m.seg.is_none()
            }
            _ => false,
        },
        Op::Rel(_) => encode::rel_expr(o).is_some(),
        Op::IndirectRm(w) => {
            // AT&T marks indirect branches with `*`; Intel does not.
            // Without it GNU as still reads an address in parentheses as
            // one, with a warning, but a bare address is a direct target.
            let explicit = matches!(o.kind, OperandKind::Indirect(_));
            let bracketed = matches!(&o.kind, OperandKind::Mem(m) if m.bracketed);
            if !explicit && cx.state.syntax == Syntax::Att && !bracketed {
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
/// `mov $1, (%rax)` could store one, two, four or eight bytes, and `push $1`
/// or `pushf` could push two, four or eight. GNU as picks the mode's default
/// operand size — 16 bits in 16-bit mode, 32 in 32- and 64-bit mode, except
/// for the stack and branch instructions long mode widened to 64 — and
/// existing sources rely on that, so rsasm does the same rather than
/// rejecting the line. NASM-dialect input should insist on an explicit size
/// instead; that belongs with the NASM front end, not here.
///
/// `.code16gcc` makes the stack instructions default to 32 bits as well.
fn prefer_default_size<'d>(
    bits: u8,
    gcc16: bool,
    stack: bool,
    matches: Vec<&'d Def>,
    resolved: &Resolved,
) -> Vec<&'d Def> {
    let first = matches[0];
    // A row with no operand size, such as a relative branch that also reads
    // as an indirect one through memory, is preferred as it stands, except
    // where `.code16gcc` asks for a 32-bit call.
    if resolved.opsize.is_some()
        || first.opsize == 0 && !(gcc16 && bits == 16)
        || matches.iter().all(|d| d.opsize == first.opsize)
    {
        return matches;
    }
    let default_size = default_operand_size(bits, gcc16, stack);
    let mut matches = matches;
    if let Some(pos) = matches.iter().position(|d| d.opsize == default_size) {
        let chosen = matches.remove(pos);
        matches.insert(0, chosen);
    }
    matches
}

/// The operand size an instruction has when nothing in the source names one.
fn default_operand_size(bits: u8, gcc16: bool, stack: bool) -> u8 {
    match bits {
        64 if stack => 64,
        16 if !gcc16 => 16,
        _ => 32,
    }
}

/// Folds the label differences in an operand's expressions; see
/// [`fold_differences`].
fn fold_operand(cx: &mut AsmCtx<'_>, o: &mut Operand) {
    let fold = |cx: &mut AsmCtx<'_>, e: &mut ExprRef| {
        if cx.constant(*e).is_none() {
            *e = fold_differences(cx, *e);
        }
    };
    match &mut o.kind {
        OperandKind::Imm(e) | OperandKind::Rel(e) => fold(cx, e),
        OperandKind::Mem(m) => {
            if let Some(e) = &mut m.disp {
                fold(cx, e);
            }
        }
        OperandKind::FarPtr { seg, off } => {
            fold(cx, seg);
            fold(cx, off);
        }
        _ => {}
    }
}

/// Replaces each difference of two labels in `e` with the distance between
/// them, where nothing emitted in between can change size.
///
/// GNU as folds such a difference as it reads the expression, so
/// `addl $_GLOBAL_OFFSET_TABLE_+(.-1b), %ebx` is a relocation against the
/// GOT with a constant addend, and `movl $(2f-1f), %eax` a constant that can
/// choose a short immediate. The expression evaluator has room for only one
/// symbol on either side of a sum, so without this the first would be an
/// error.
fn fold_differences(cx: &mut AsmCtx<'_>, e: ExprRef) -> ExprRef {
    let node = cx.exprs.get(e).clone();
    match node.kind {
        ExprKind::Binary(op, l, r) => {
            if op == BinOp::Sub
                && let (Some(to), Some(from)) = (label_position(cx, l), label_position(cx, r))
                && let Some(d) = cx.fixed_distance(from, to)
            {
                return cx.exprs.int(d as u64, node.span);
            }
            let (fl, fr) = (fold_differences(cx, l), fold_differences(cx, r));
            if (fl, fr) == (l, r) {
                e
            } else {
                cx.exprs.alloc(ExprKind::Binary(op, fl, fr), node.span)
            }
        }
        ExprKind::Unary(op, x) => match fold_differences(cx, x) {
            fx if fx == x => e,
            fx => cx.exprs.alloc(ExprKind::Unary(op, fx), node.span),
        },
        ExprKind::Modifier(name, x) => match fold_differences(cx, x) {
            fx if fx == x => e,
            fx => cx.exprs.alloc(ExprKind::Modifier(name, fx), node.span),
        },
        _ => e,
    }
}

/// Where a label an expression names was defined, or where `.` is.
fn label_position(cx: &AsmCtx<'_>, e: ExprRef) -> Option<(crate::section::SectionId, u32)> {
    let node = cx.exprs.get(e);
    let id = match node.kind {
        ExprKind::Here => return Some(cx.here()),
        ExprKind::SymId(id) => id,
        ExprKind::Sym(name) => cx.symbols.lookup(name)?,
        ExprKind::LocalRef(n, LocalDir::Backward) => cx.symbols.local_backward(n, node.span)?,
        _ => return None,
    };
    cx.label_position(id)
}

/// True when an unsized memory operand leaves more than one width possible.
///
/// GNU as's Intel syntax refuses `add [eax], 1` and `fld [eax]` for want of a
/// `dword ptr`, where its AT&T syntax only warns and takes a default.
fn ambiguous_memory_size(matches: &[&Def], ops: &[Operand]) -> bool {
    let Some(slot) = ops.iter().position(|o| o.is_mem() && o.size_hint.is_none()) else {
        return false;
    };
    let width = |d: &Def| match d.ops[slot] {
        Op::Rm(w) | Op::M(w) | Op::Moffs(w) | Op::IndirectRm(w) | Op::StrSrc(w) | Op::StrDst(w) => {
            w
        }
        _ => 0,
    };
    let first = width(matches[0]);
    matches.iter().any(|d| width(d) != first)
}

fn report_no_match(
    cx: &mut AsmCtx<'_>,
    req: &InsnRequest<'_>,
    mnemonic: &str,
    resolved: &Resolved,
    ops: &[Operand],
) {
    let defs = resolved.defs;
    let bits = cx.state.bits;
    // Something that would have matched in another mode or syntax is worth
    // saying so about.
    let elsewhere = defs.iter().find(|def| {
        def.ops.len() == ops.len()
            && !available(cx, bits, def)
            && resolved.opsize.is_none_or(|w| def.opsize == w)
            && def
                .ops
                .iter()
                .zip(ops)
                .all(|(p, o)| op_matches(cx, bits, def, p, o))
    });
    if let Some(def) = elsewhere {
        let msg = if def.flags & NO64 != 0 && bits == 64 {
            format!("`{mnemonic}` with these operands is not available in 64-bit mode")
        } else if def.flags & ONLY64 != 0 && bits != 64 {
            format!("`{mnemonic}` with these operands is only available in 64-bit mode")
        } else {
            format!("`{mnemonic}` with these operands is not available in this syntax")
        };
        cx.error(req.span, msg);
        return;
    }
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

/// True if `name` is a register, used by the generic parser to avoid treating
/// register names as symbols.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}

/// Convenience for tests and for the `--print-encoding` debug output.
pub fn describe_span(span: Span) -> String {
    format!("{span:?}")
}
