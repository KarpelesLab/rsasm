//! The x86 / x86-64 backend.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::expr;
use crate::lexer::TokKind;
use crate::section::Variant;
use crate::source::Span;
use encode::Prefixes;
use insn::{Def, Op, DEF64};
use operand::{Operand, OperandKind, OperandParser};

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
        }
    }

    fn supports_syntax(&self, _syntax: Syntax) -> bool {
        true
    }

    fn elf_machine(&self) -> u16 {
        match self.bits {
            64 => 62,  // EM_X86_64
            _ => 3,    // EM_386
        }
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        if pcrel { reloc::pcrel(size) } else { reloc::abs(size) }
    }

    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        encode::nop_bytes(len as usize)
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(req.mnemonic).to_ascii_lowercase();
        assemble_inner(cx, req, &mnemonic, Prefixes::default(), 0)
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

/// Prefix mnemonics that attach to the instruction written after them.
fn prefix_byte(mnemonic: &str) -> Option<(bool, Option<u8>)> {
    Some(match mnemonic {
        "lock" => (true, None),
        "rep" | "repe" | "repz" => (false, Some(0xf3)),
        "repne" | "repnz" => (false, Some(0xf2)),
        _ => return None,
    })
}

fn assemble_inner(
    cx: &mut AsmCtx<'_>,
    req: &InsnRequest<'_>,
    mnemonic: &str,
    mut prefixes: Prefixes,
    depth: u32,
) -> Option<Vec<Variant>> {
    if depth > 4 {
        cx.error(req.span, "too many instruction prefixes");
        return None;
    }

    // `lock`, `rep` and friends prefix the instruction that follows them.
    if let Some((lock, rep)) = prefix_byte(mnemonic) {
        prefixes.lock |= lock;
        if let Some(r) = rep {
            prefixes.rep = Some(r);
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
        return assemble_inner(cx, &sub, &next_text, prefixes, depth + 1);
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

    let matches = select(cx, bits, resolved.defs, &resolved, &ops);
    if matches.is_empty() {
        report_no_match(cx, req, mnemonic, resolved.defs, &ops);
        return None;
    }

    if let Some(msg) = ambiguity(bits, &matches, &ops) {
        cx.error(req.span, msg);
        return None;
    }

    // A relative branch gets one variant per displacement width, smallest
    // first, so the layout pass can shorten it once addresses are known.
    let is_rel = matches[0].ops.first().is_some_and(|o| matches!(o, Op::Rel(_)));
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
    for def in chosen {
        variants.push(encode::encode(cx, bits, def, &ops, prefixes, req.span)?);
    }
    Some(variants)
}

/// What a mnemonic resolved to, including any width implied by an AT&T suffix.
struct Resolved {
    defs: &'static [Def],
    /// Required `Def::opsize`, from a suffix such as the `l` in `movl`.
    opsize: Option<u8>,
    /// Required width of the r/m operand, for `movzbl`-style double suffixes.
    rm_width: Option<u8>,
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
    // An exact table entry always wins, so the string instruction `movsb` is
    // never mistaken for `movs` with a `b` suffix.
    if let Some(defs) = insn::lookup(mnemonic) {
        return Some(Resolved { defs, opsize: None, rm_width: None });
    }
    if syntax != Syntax::Att {
        return None;
    }
    let b = mnemonic.as_bytes();

    // `movzbl`, `movswq`, `movslq`: source width then destination width.
    if b.len() == 6 && (mnemonic.starts_with("movz") || mnemonic.starts_with("movs")) {
        if let (Some(src), Some(dst)) = (suffix_width(b[4]), suffix_width(b[5])) {
            if src < dst {
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
                    });
                }
            }
        }
    }

    // A single trailing size letter.
    let (stem, last) = mnemonic.split_at(mnemonic.len().checked_sub(1)?);
    let w = suffix_width(last.as_bytes()[0])?;
    let defs = insn::lookup(stem)?;
    Some(Resolved { defs, opsize: Some(w * 8), rm_width: None })
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
        if let Some(want) = resolved.opsize {
            if def.opsize != want {
                continue;
            }
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
        if def.ops.iter().zip(ops).all(|(p, o)| op_matches(cx, bits, def, p, o)) {
            out.push(def);
        }
    }
    // A suffix that matched nothing may still be part of a symbol-like
    // mnemonic; without one, fall back to the unconstrained set.
    if out.is_empty() && resolved.opsize.is_some() && resolved.rm_width.is_none() {
        for def in defs {
            if def.ops.len() == ops.len()
                && def.opsize == 0
                && def.ops.iter().zip(ops).all(|(p, o)| op_matches(cx, bits, def, p, o))
            {
                out.push(def);
            }
        }
    }
    out
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
            let OperandKind::Imm(e) = &o.kind else { return false };
            match expr::const_fold(cx.exprs, *e) {
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
            let OperandKind::Imm(e) = &o.kind else { return false };
            expr::const_fold(cx.exprs, *e).is_some_and(|v| (-128..=127).contains(&v))
        }
        Op::One => {
            let OperandKind::Imm(e) = &o.kind else { return false };
            expr::const_fold(cx.exprs, *e) == Some(1)
        }
        Op::Fixed(name) => o.reg() == reg::lookup(name),
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

/// Detects an operand size that the source never pinned down, as in the AT&T
/// `mov $1, (%rax)` — which could store 1, 2, 4 or 8 bytes.
fn ambiguity(bits: u8, matches: &[&Def], ops: &[Operand]) -> Option<String> {
    let unsized_mem = ops.iter().any(|o| o.is_mem() && o.size_hint.is_none());
    if !unsized_mem {
        return None;
    }
    // Instructions whose operand size defaults to 64 bits in long mode are not
    // ambiguous there, even though a 16-bit form also exists.
    let first = matches[0];
    if bits == 64 && first.flags & DEF64 != 0 {
        return None;
    }
    let differing = matches.iter().any(|d| d.opsize != first.opsize);
    if !differing {
        return None;
    }
    let mut sizes: Vec<u8> = matches.iter().map(|d| d.opsize).collect();
    sizes.sort_unstable();
    sizes.dedup();
    let list: Vec<String> = sizes.iter().filter(|s| **s != 0).map(|s| s.to_string()).collect();
    Some(format!(
        "ambiguous operand size; add a suffix or a size specifier (could be {}-bit)",
        list.join(", ")
    ))
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

/// True if `name` is a register, used by the generic parser to avoid treating
/// register names as symbols.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}

/// Convenience for tests and for the `--print-encoding` debug output.
pub fn describe_span(span: Span) -> String {
    format!("{span:?}")
}
