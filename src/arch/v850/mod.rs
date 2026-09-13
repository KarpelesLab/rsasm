//! NEC/Renesas V850 and its successor RH850 (the v850e3v5 instruction set). `EM_V850`.
//!
//! Placeholder. The backend is registered so that `.arch` and `--arch` can
//! name it and report something useful, but it assembles nothing yet.

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::section::Variant;

pub const NAMES: &[&str] = &["v850", "rh850"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let canonical = match name {
        "v850" => "v850",
        "rh850" => "rh850",
        "v850e" | "v850e2v3" | "v850e3v5" => "v850",
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
        &["v850e", "v850e2v3", "v850e3v5"]
    }

    fn endian(&self) -> Endian {
        Endian::Little
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
        87
    }

    fn default_dialect(&self) -> crate::lexer::Dialect {
        crate::lexer::Dialect::Gas
    }

    fn align_unit(&self) -> u64 {
        1
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
