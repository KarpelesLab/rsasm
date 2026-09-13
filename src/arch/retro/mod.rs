//! The 8-bit families: Zilog Z80, MOS 6502 and Intel 8080.
//!
//! Three backends share this module because they share a problem shape: byte
//! streams with 8-bit opcodes and little-endian 16-bit operands, no fixed
//! instruction width, and a 64 KiB address space. The Z80 and the 8080 also
//! share their *opcode* values — the 8080 set is the Z80 main page minus the
//! `EX AF,AF'`/`DJNZ`/`JR` corners — so [`i8080`] builds Intel mnemonics on top
//! of the tables in [`z80`] rather than repeating the bytes.
//!
//! **Flat binary is the intended output.** These machines predate ELF and have
//! no `EM_*` number, so [`Architecture::elf_machine`] returns 0 and
//! [`Architecture::data_reloc`] returns `None`; assemble with `-f bin`. An
//! unresolved external reference is therefore an error rather than a
//! relocation, which is the right answer for a target with no linker.
//!
//! ## Syntax, and where the lexer forces a deviation
//!
//! The GAS lexer this crate shares treats `#` as a line comment and `$` as the
//! start of an immediate, and it has no `$`-prefixed hexadecimal. The
//! traditional 6502 spelling `lda #$12` is therefore unwritable here: `#`
//! swallows the rest of the line. Until the core grows a per-architecture
//! lexer hook, the 6502 backend accepts `$` *or* `#` as the immediate marker
//! (`lda $12` in the GAS dialect, `lda #0x12` in the NASM dialect, where `#`
//! is not a comment) and hexadecimal is written `0x12`. See
//! [`mos6502`] for the details.

pub mod common;
pub mod i8080;
pub mod mos6502;
pub mod z80;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::section::Variant;

pub const NAMES: &[&str] = &["z80", "6502", "i8080"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    Some(match name {
        "z80" | "zilog-z80" => Box::new(Retro::Z80) as Box<dyn Architecture>,
        "6502" | "mos6502" | "m6502" => Box::new(Retro::Mos6502),
        "i8080" | "8080" | "intel-8080" => Box::new(Retro::I8080),
        _ => return None,
    })
}

/// The three backends, distinguished only by which instruction table they
/// consult: everything else about them (byte order, pointer width, output
/// format) is identical.
pub enum Retro {
    Z80,
    Mos6502,
    I8080,
}

impl Architecture for Retro {
    fn name(&self) -> &'static str {
        match self {
            Retro::Z80 => "z80",
            Retro::Mos6502 => "6502",
            Retro::I8080 => "i8080",
        }
    }

    fn aliases(&self) -> &'static [&'static str] {
        match self {
            Retro::Z80 => &["zilog-z80"],
            Retro::Mos6502 => &["mos6502", "m6502"],
            Retro::I8080 => &["8080", "intel-8080"],
        }
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        2
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: 16,
            // These assemblers never had two operand syntaxes to choose
            // between; `Att` is simply the default the core starts from.
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
            used: 0,
        }
    }

    fn supports_syntax(&self, syntax: Syntax) -> bool {
        // Only one operand grammar exists per machine, so a `.intel_syntax`
        // carried over from an x86 part of the file must not silently change
        // how these operands are read.
        syntax == Syntax::Att
    }

    fn elf_machine(&self) -> u16 {
        // No `EM_*` value was ever assigned to any of these. Returning 0
        // (`EM_NONE`) keeps the ELF writer honest; it refuses a non-64-bit
        // target anyway, and `-f bin` is what these backends are for.
        0
    }

    fn data_reloc(&self, _size: u8, _pcrel: bool) -> Option<u32> {
        // No relocation format exists for a flat 16-bit binary: everything
        // must be resolved by the time the assembler finishes.
        None
    }

    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        // Padding inside a code section has to be executable, so it is the
        // machine's real no-op rather than zero. On the 6502 zero is `BRK`.
        let nop = match self {
            Retro::Z80 | Retro::I8080 => 0x00,
            Retro::Mos6502 => 0xea,
        };
        vec![nop; len as usize]
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(insn.mnemonic).to_ascii_lowercase();
        match self {
            Retro::Z80 => z80::assemble(cx, insn, &mnemonic),
            Retro::Mos6502 => mos6502::assemble(cx, insn, &mnemonic),
            Retro::I8080 => i8080::assemble(cx, insn, &mnemonic),
        }
    }
}
