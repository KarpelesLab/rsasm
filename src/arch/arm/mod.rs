//! ARM 32-bit: the A32 (ARM) and T32 (Thumb) instruction sets. `EM_ARM`.
//!
//! The two instruction sets share a register file, a condition-code table and
//! an operand grammar, but not an encoding, so they share everything up to
//! [`Insn`] and then split into [`encode`] (A32) and [`thumb`] (T32). Which
//! one runs is a property of the *state*, not of the backend object: `.arm`
//! and `.thumb` switch between them mid-file, exactly as `.code32` and
//! `.code16` do on x86, and they are spelled that way too.
//!
//! The state's `bits` field carries the choice — 32 for ARM, 16 for Thumb —
//! because that is what `.code 16` and `.code 32` already mean in ARM sources.

pub mod encode;
pub mod imm;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;
pub mod thumb;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::dwarf::{CfiTarget, DwarfTarget, Flavor, cfi, numbered_register};
use crate::lexer::TokKind;
use crate::section::Variant;
use crate::source::Span;
use insn::{Mnem, Width};
use operand::Operand;

pub const NAMES: &[&str] = &["arm", "thumb"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let thumb = match name {
        "arm" | "armv7" | "armv7-a" | "arm32" => false,
        "thumb" | "thumbv7" | "thumb2" => true,
        _ => return None,
    };
    Some(Box::new(Arm { thumb }))
}

/// One instruction, after the mnemonic has been taken apart and the operands
/// parsed. Both encoders work from this.
pub struct Insn<'o> {
    pub mnem: Mnem,
    pub cond: u8,
    /// Whether the source wrote a condition, as opposed to defaulting to `al`.
    /// Some encodings exist only unconditionally and need to tell the two
    /// apart.
    pub cond_written: bool,
    pub set_flags: bool,
    pub width: Width,
    /// The mnemonic as written, for diagnostics.
    pub text: &'o str,
    pub ops: &'o [Operand],
    pub span: Span,
}

pub struct Arm {
    /// Whether a fresh state starts in Thumb mode.
    thumb: bool,
}

/// The state's `bits` value that means Thumb.
const THUMB_BITS: u8 = 16;

impl Architecture for Arm {
    fn name(&self) -> &'static str {
        if self.thumb { "thumb" } else { "arm" }
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["armv7", "armv7-a", "arm32", "thumbv7", "thumb2"]
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        4
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: if self.thumb { THUMB_BITS } else { 32 },
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
            used: 0,
        }
    }

    fn supports_syntax(&self, syntax: Syntax) -> bool {
        // ARM has one operand syntax; the x86 Intel/AT&T split does not apply.
        syntax == Syntax::Att
    }

    fn elf_machine(&self) -> u16 {
        40
    }

    /// `EF_ARM_EABI_VER5`, as llvm-mc writes for `arm-linux-gnueabi`; GNU ld
    /// refuses to mix EABI versions, and version 0 is not an EABI object.
    fn elf_flags(&self, _state: &ArchState) -> u32 {
        0x0500_0000
    }

    fn align_is_log2(&self) -> bool {
        true
    }

    /// llvm-mc, the reference, aligns `.text` to 4 bytes, in Thumb as in ARM
    /// code. GNU as instead aligns a section once an instruction is
    /// assembled into it, to 4 bytes for ARM and 2 for Thumb.
    fn section_align(
        &self,
        _state: &ArchState,
        name: &str,
        _flags: &crate::section::SectionFlags,
    ) -> u64 {
        if name == ".text" { 4 } else { 1 }
    }

    fn word_bytes(&self) -> u8 {
        4
    }

    /// ARM writes immediates as `#1`, so `#` is a comment only in the first column and `@` takes its place elsewhere.
    fn comments(&self) -> crate::arch::CommentSyntax {
        crate::arch::CommentSyntax {
            anywhere: &["@", "//"],
            line_start: &["#"],
        }
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        reloc::data(size, pcrel)
    }

    /// llvm-mc names a local label in every relocation but these two (its
    /// `ARMELFObjectWriter::needsRelocateWithSymbol`).
    fn relocates_with_label(&self, reloc: u32) -> bool {
        !matches!(reloc, reloc::ABS32 | reloc::PREL31)
    }

    /// llvm-mc's conventions, as for every ARM encoding, in either
    /// instruction set.
    fn dwarf(&self, _state: &ArchState) -> DwarfTarget {
        DwarfTarget {
            cfi: Some(CfiTarget {
                data_align: -4,
                ra_column: 14,
                initial: vec![cfi::Insn::DefCfa(13, 0)],
                fde_encoding: 0x1b,
                eh_frame_align: 4,
                cie_version: 1,
            }),
            ..DwarfTarget::lines_only(Flavor::Llvm, 1)
        }
    }

    /// The AAPCS DWARF numbering of the names llvm-mc accepts: the core
    /// registers under their numbers, APCS names and aliases, and the 64-bit
    /// VFP registers from 256. `fp` is `r11` in both instruction sets.
    fn dwarf_register(&self, _state: &ArchState, name: &str) -> Option<u32> {
        const APCS: [&str; 15] = [
            "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "ip", "sp",
            "lr",
        ];
        match name {
            "sb" => return Some(9),
            "sl" => return Some(10),
            "fp" => return Some(11),
            "pc" => return Some(15),
            _ => {}
        }
        if let Some(i) = APCS.iter().position(|r| *r == name) {
            return Some(i as u32);
        }
        numbered_register(name, "r", 15)
            .or_else(|| numbered_register(name, "d", 31).map(|n| 256 + n))
    }

    /// Alignment padding has to stay executable, and the two instruction sets
    /// have different no-ops, so the current mode picks.
    fn nop_fill(&self, state: &ArchState, len: u64) -> Vec<u8> {
        let len = len as usize;
        let mut out = Vec::with_capacity(len);
        if state.bits == THUMB_BITS {
            while out.len() + 2 <= len {
                out.extend_from_slice(&thumb::NOP.to_le_bytes());
            }
        } else {
            while out.len() + 4 <= len {
                out.extend_from_slice(&encode::NOP.to_le_bytes());
            }
        }
        // A misaligned remainder cannot hold an instruction; zero it.
        out.resize(len, 0);
        out
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let text = cx.name(req.mnemonic).to_ascii_lowercase();
        let Some(r) = insn::resolve(&text) else {
            cx.error(req.mnemonic_span, format!("unknown instruction `{text}`"));
            return None;
        };
        let ops = {
            let mut cur = req.cursor();
            let mut p = operand::Parser { cx };
            p.parse_list(&mut cur)?
        };
        // `!` requests writeback, which only the block transfers' base
        // register has; anywhere else it would be silently meaningless.
        let is_block = matches!(r.mnem, Mnem::Ldm(_) | Mnem::Stm(_));
        if let Some(op) = ops
            .iter()
            .enumerate()
            .find_map(|(i, op)| (op.writeback && !(is_block && i == 0)).then_some(op))
        {
            cx.error(
                op.span,
                "`!` (writeback) is only valid on the base register of `ldm`/`stm`",
            );
            return None;
        }
        let ins = Insn {
            mnem: r.mnem,
            cond: r.cond,
            cond_written: r.cond_written,
            set_flags: r.set_flags,
            width: r.width,
            text: &text,
            ops: &ops,
            span: req.span,
        };
        if cx.state.bits == THUMB_BITS {
            thumb::assemble(cx, &ins)
        } else {
            encode::assemble(cx, &ins)
        }
    }

    fn directive(&self, cx: &mut AsmCtx<'_>, name: &str, cur: &mut Cursor<'_>) -> bool {
        match name {
            ".arm" | ".code32" => {
                cx.state.bits = 32;
                true
            }
            ".thumb" | ".code16" => {
                cx.state.bits = THUMB_BITS;
                true
            }
            ".code" => {
                // `.code 16` / `.code 32`, the spelling ARM sources use.
                match cur.peek().kind {
                    TokKind::Int(16) => cx.state.bits = THUMB_BITS,
                    TokKind::Int(32) => cx.state.bits = 32,
                    _ => {
                        let span = cur.peek().span;
                        cx.error(span, "`.code` expects 16 or 32");
                        return true;
                    }
                }
                cur.advance();
                true
            }
            // Unified syntax is the only syntax this backend implements, and
            // `.thumb_func` only matters to the ELF symbol table, which the
            // core owns.
            ".syntax" | ".thumb_func" | ".fpu" | ".eabi_attribute" | ".arch_extension" => {
                cur.set_pos(cur.all().len());
                true
            }
            _ => false,
        }
    }
}

/// True if `name` is an ARM register, for callers that need to avoid treating
/// register names as symbols.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}
