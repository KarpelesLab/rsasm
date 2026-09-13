//! ARM 32-bit, both the A32 and T32 (Thumb) instruction sets. `EM_ARM`.
//!
//! Placeholder. The backend is registered so that `.arch` and `--arch` can
//! name it and report something useful, but it assembles nothing yet.

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::section::Variant;

pub const NAMES: &[&str] = &["arm", "thumb"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let canonical = match name {
        "arm" => "arm",
        "thumb" => "thumb",
        "armv7" | "armv7-a" | "thumbv7" | "arm32" => "arm",
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
        &["armv7", "armv7-a", "thumbv7", "arm32"]
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
        40
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
