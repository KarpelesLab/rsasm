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
            private: 0,
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
