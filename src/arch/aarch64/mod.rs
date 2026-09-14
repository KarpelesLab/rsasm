//! ARM 64-bit (A64). `EM_AARCH64`.
//!
//! A64 is fixed-width: every instruction is exactly four bytes, so this
//! backend always returns a single [`Variant`] and never asks the layout pass
//! to choose between encodings. What relaxation buys elsewhere, a fixup's
//! `value_bits` buys here — an out-of-range branch is a diagnostic rather than
//! a longer encoding, because there is no longer encoding.
//!
//! The other consequence of fixed width is that displacements never fit in one
//! contiguous field. Every PC-relative fixup therefore uses
//! [`crate::section::FieldEncoding::Scatter`] to weave its value through the
//! instruction word; the scatter functions live in [`encode`].
//!
//! # The `#` sigil
//!
//! A64 source conventionally writes immediates as `#imm`, and the operand
//! parser accepts that. The GAS-dialect lexer, however, currently treats `#`
//! as the start of a line comment for every architecture, so `add x0, x1, #1`
//! reaches this backend as `add x0, x1,`. GNU as only makes `#` a comment
//! at the start of a line on AArch64. Until the lexer learns that per
//! architecture, write immediates bare — `add x0, x1, 1` — which both GNU as
//! and llvm-mc accept too.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;
pub mod sysreg;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::dwarf::{CfiTarget, DwarfTarget, Flavor, cfi, numbered_register};
use crate::section::Variant;

pub const NAMES: &[&str] = &["aarch64"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    match name {
        "aarch64" | "arm64" | "armv8" | "armv8-a" | "aarch64le" => Some(Box::new(AArch64)),
        _ => None,
    }
}

pub struct AArch64;

/// The canonical `nop`. Alignment padding in an executable section must stay
/// executable, and unlike x86 there is only one no-op worth emitting.
const NOP: u32 = 0xd503_201f;

impl Architecture for AArch64 {
    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["arm64", "armv8", "armv8-a", "aarch64le"]
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        8
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: 64,
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
            used: 0,
        }
    }

    /// A64 has one operand syntax. `.intel_syntax` in a file that also has x86
    /// in it must not make A64 statements unassemblable, so both spellings are
    /// accepted and neither changes anything.
    fn supports_syntax(&self, _syntax: Syntax) -> bool {
        true
    }

    fn elf_machine(&self) -> u16 {
        183 // EM_AARCH64
    }

    fn align_is_log2(&self) -> bool {
        true
    }

    /// AArch64 writes immediates as `#1`, so `#` is a comment only in the
    /// first column and `//` is the comment everywhere else.
    fn comments(&self) -> crate::arch::CommentSyntax {
        crate::arch::CommentSyntax {
            anywhere: &["//"],
            line_start: &["#"],
        }
    }

    fn word_bytes(&self) -> u8 {
        4
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        if pcrel {
            reloc::pcrel(size)
        } else {
            reloc::abs(size)
        }
    }

    /// llvm-mc's conventions, as for every AArch64 encoding: code and
    /// addresses counted in bytes, where GNU as counts instructions.
    fn dwarf(&self, _state: &ArchState) -> DwarfTarget {
        DwarfTarget {
            cfi: Some(CfiTarget {
                data_align: -4,
                ra_column: 30,
                initial: vec![cfi::Insn::DefCfa(31, 0)],
                fde_encoding: 0x1b,
                eh_frame_align: 8,
                cie_version: 1,
            }),
            ..DwarfTarget::lines_only(Flavor::Llvm, 1)
        }
    }

    /// The AAPCS64 DWARF numbering of the names llvm-mc accepts: `x`/`w`
    /// registers 0-30, the stack pointer and zero register both 31, and a
    /// vector register as 64 up by whichever width names it.
    fn dwarf_register(&self, _state: &ArchState, name: &str) -> Option<u32> {
        match name {
            "sp" | "wsp" | "xzr" | "wzr" => return Some(31),
            "fp" => return Some(29),
            "lr" => return Some(30),
            _ => {}
        }
        numbered_register(name, "x", 31)
            .or_else(|| numbered_register(name, "w", 30))
            .or_else(|| {
                ["b", "h", "s", "d", "q"]
                    .iter()
                    .find_map(|p| numbered_register(name, p, 31))
                    .map(|n| 64 + n)
            })
    }

    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len as usize);
        // Padding to a boundary finer than four bytes cannot be instructions,
        // so the leftover is zeroed rather than pretending otherwise.
        let words = (len / 4) as usize;
        for _ in 0..words {
            out.extend_from_slice(&NOP.to_le_bytes());
        }
        out.resize(len as usize, 0);
        out
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(req.mnemonic).to_ascii_lowercase();
        let cur = req.cursor();
        let ops = operand::parse_list(cx, &cur)?;
        insn::assemble(cx, req, &mnemonic, &ops)
    }
}

/// True if `name` is a register, so the generic parser does not treat a
/// register name as a symbol.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}
