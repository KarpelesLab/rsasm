//! Motorola 68000 family. `EM_68K`. Defaults to Motorola syntax, which is what Amiga and Atari source is written in.
//!
//! Placeholder. The backend is registered so that `.arch` and `--arch` can
//! name it and report something useful, but it assembles nothing yet.

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::section::Variant;

pub const NAMES: &[&str] = &["m68k"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let canonical = match name {
        "m68k" => "m68k",
        "68000" | "68010" | "68020" | "68030" | "68040" | "mc68000" | "mc68020" => "m68k",
        _ => return None,
    };
    Some(Box::new(Stub { name: canonical }))
}

struct Stub {
    name: &'static str,
}

impl Architecture for Stub {
    fn name(&self) -> &'static str {
        self.name
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[
            "68000", "68010", "68020", "68030", "68040", "mc68000", "mc68020",
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
        }
    }

    fn supports_syntax(&self, _syntax: Syntax) -> bool {
        true
    }

    fn elf_machine(&self) -> u16 {
        4
    }

    fn default_dialect(&self) -> crate::lexer::Dialect {
        crate::lexer::Dialect::Motorola
    }

    fn align_unit(&self) -> u64 {
        2
    }

    fn data_reloc(&self, _size: u8, _pcrel: bool) -> Option<u32> {
        None
    }

    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        vec![0; len as usize]
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        cx.error(
            insn.span,
            format!("the `{}` backend is not implemented yet", self.name),
        );
        None
    }
}
