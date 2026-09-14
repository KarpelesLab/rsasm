//! Motorola 68000 family. `EM_68K`.
//!
//! One backend covers the 68000, 68010 and 68020 instruction sets, chosen by
//! name: `m68k` is the 68020, which is what GNU as assumes by default, and
//! `68000` and `68010` reject what those CPUs lack — scaled indexes, 32-bit
//! branches, `extb`, `mulu.l`, bit fields — with a message naming the CPU.
//!
//! Motorola syntax is the default dialect, since that is what Amiga and Atari
//! source is written in; GNU syntax (`movew #1,%d0`) is the other. The core
//! lexes both and aligns code for the Motorola one; the backend parses
//! operands ([`operand`]), encodes effective addresses ([`encode`]) and
//! instructions ([`ops`], [`branch`]).
//!
//! Everything here was checked against `m68k-elf-as` 2.47, in both its native
//! and `--mri` modes, with vasm as a second opinion where the two differ. The
//! differences that remain are deliberate and listed where they are decided:
//! no instruction substitution ([`ops`]), and Motorola's word-sized default
//! index ([`operand`]).

pub mod branch;
pub mod encode;
pub mod insn;
pub mod operand;
pub mod ops;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, CommentSyntax, Endian, InsnRequest, Syntax};
use crate::dwarf::{CfiTarget, DwarfTarget, Flavor, cfi, numbered_register};
use crate::section::Variant;

pub const NAMES: &[&str] = &["m68k"];

/// The instruction set in force, in order of what each adds.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Cpu {
    M68000,
    M68010,
    M68020,
}

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let cpu = match name {
        "m68k" | "68020" | "68030" | "68040" | "mc68020" | "mc68030" | "mc68040" => Cpu::M68020,
        "68000" | "mc68000" => Cpu::M68000,
        "68010" | "mc68010" => Cpu::M68010,
        _ => return None,
    };
    Some(Box::new(M68k { cpu }))
}

pub struct M68k {
    cpu: Cpu,
}

impl Architecture for M68k {
    fn name(&self) -> &'static str {
        match self.cpu {
            Cpu::M68020 => "m68k",
            Cpu::M68010 => "68010",
            Cpu::M68000 => "68000",
        }
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[
            "68000", "68010", "68020", "68030", "68040", "mc68000", "mc68010", "mc68020",
            "mc68030", "mc68040",
        ]
    }

    fn endian(&self) -> Endian {
        Endian::Big
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        4
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: 32,
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
            used: 0,
        }
    }

    fn supports_syntax(&self, syntax: Syntax) -> bool {
        syntax == Syntax::Att
    }

    fn elf_machine(&self) -> u16 {
        4 // EM_68K
    }

    fn pcrel_number_is_address(&self) -> bool {
        true
    }

    /// GNU as for m68k treats only a weak symbol as one the linker may
    /// replace: a branch to a global symbol in the same section is resolved.
    fn defers_to_linker(&self, r: &crate::arch::SameSectionRef<'_>) -> bool {
        r.binding == crate::symbol::Binding::Weak
    }

    /// And a relocation against a global symbol names its section.
    fn relocates_globals_by_section(&self) -> bool {
        true
    }

    /// GNU as aligns the three standard sections to 4 bytes from the start,
    /// and no other.
    fn section_align(
        &self,
        _state: &ArchState,
        name: &str,
        _flags: &crate::section::SectionFlags,
    ) -> u64 {
        match name {
            ".text" | ".data" | ".bss" => 4,
            _ => 1,
        }
    }

    fn default_dialect(&self) -> crate::lexer::Dialect {
        crate::lexer::Dialect::Motorola
    }

    fn align_unit(&self) -> u64 {
        2
    }

    /// GNU as for m68k comments with `|`, and with `#` only at the start of a
    /// line, since `#` marks an immediate. `;` still separates statements.
    fn comments(&self) -> CommentSyntax {
        CommentSyntax {
            anywhere: &["|"],
            line_start: &["#"],
        }
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        reloc::data(size, pcrel)
    }

    /// GNU as's conventions, as for every m68k encoding: code counted in
    /// words, and a frame that starts with the return address just above the
    /// stack pointer.
    fn dwarf(&self, _state: &ArchState) -> DwarfTarget {
        DwarfTarget {
            cfi: Some(CfiTarget {
                data_align: -4,
                ra_column: 24,
                initial: vec![cfi::Insn::DefCfa(15, 4), cfi::Insn::Offset(24, -4)],
                fde_encoding: 0x1b,
                eh_frame_align: 4,
                cie_version: 1,
            }),
            ..DwarfTarget::lines_only(Flavor::Gnu, 2)
        }
    }

    /// GNU as's numbering, for the names it accepts, with or without `%`:
    /// `d0`-`d7`, `a0`-`a6` and `sp` from 8, `fp0`-`fp7` from 16, and `pc`
    /// as 24. It takes neither `a7` nor `fp` here.
    fn dwarf_register(&self, _state: &ArchState, name: &str) -> Option<u32> {
        let name = name.strip_prefix('%').unwrap_or(name);
        match name {
            "sp" => Some(15),
            "pc" => Some(24),
            _ => numbered_register(name, "d", 7)
                .or_else(|| numbered_register(name, "a", 6).map(|n| 8 + n))
                .or_else(|| numbered_register(name, "fp", 7).map(|n| 16 + n)),
        }
    }

    /// Zeroes, not `NOP`s: `m68k-elf-as` (in both syntaxes) and vasm pad code
    /// alignment with zero bytes, and matching them keeps the bytes identical.
    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        vec![0; len as usize]
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let name = cx.name(req.mnemonic).to_ascii_lowercase();
        let (def, size, _) = match insn::resolve(&name) {
            Ok(r) => r,
            Err(msg) => {
                cx.error(req.mnemonic_span, msg);
                return None;
            }
        };
        let before = cx.diags.error_count();
        let mut asm = ops::Asm {
            cx,
            cpu: self.cpu,
            name,
            span: req.span,
        };
        let out = asm.assemble(def, size, req);
        // Every failure path reports its own error. Should one ever not, the
        // statement must still not vanish without a word.
        if out.is_none() && cx.diags.error_count() == before {
            cx.error(req.span, "cannot assemble this instruction");
        }
        out
    }
}
