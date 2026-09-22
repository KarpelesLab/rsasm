//! ELF relocation numbers.
//!
//! PPC32 and PPC64 share the low end of the table — `R_PPC_ADDR32` and
//! `R_PPC64_ADDR32` are both 1, and so on up through `REL32` — which is why
//! one set of constants serves both, and why the ones that exist for only one
//! of the two say so. The numbers here were read back from objects produced
//! by `llvm-mc` and by `powerpc64-linux-gnu-as`, not from memory.

pub const ADDR32: u32 = 1;
pub const ADDR24: u32 = 2;
pub const ADDR16: u32 = 3;
pub const ADDR16_LO: u32 = 4;
pub const ADDR16_HI: u32 = 5;
pub const ADDR16_HA: u32 = 6;
pub const ADDR14: u32 = 7;
pub const REL24: u32 = 10;
pub const REL14: u32 = 11;
pub const GOT16: u32 = 14;
pub const GOT16_LO: u32 = 15;
pub const GOT16_HI: u32 = 16;
pub const GOT16_HA: u32 = 17;
pub const REL32: u32 = 26;

/// 32-bit only: a call that the linker routes through the PLT (`@plt`), and
/// one it is told to keep direct (`@local`). PowerPC64 has neither; see
/// [`super::encode::Encoder::branch`].
pub const PLTREL24: u32 = 18;
pub const LOCAL24PC: u32 = 23;

/// 64-bit only.
pub const ADDR64: u32 = 38;
/// The halves above bit 31 of a 64-bit address, which only a 64-bit object
/// can name: `@higher` and `@highest` take bits 32:47 and 48:63, and the `a`
/// spellings pre-compensate for a sign-extended low half the way `@ha` does.
pub const ADDR16_HIGHER: u32 = 39;
pub const ADDR16_HIGHERA: u32 = 40;
pub const ADDR16_HIGHEST: u32 = 41;
pub const ADDR16_HIGHESTA: u32 = 42;
pub const REL64: u32 = 44;
/// 64-bit only: an offset into the TOC, the ELFv1 and ELFv2 register-2
/// window onto a program's addresses.
pub const TOC16: u32 = 47;
pub const TOC16_LO: u32 = 48;
pub const TOC16_HI: u32 = 49;
pub const TOC16_HA: u32 = 50;
/// The DS-form variants, whose low two bits belong to the opcode.
pub const ADDR16_DS: u32 = 56;
pub const ADDR16_LO_DS: u32 = 57;
pub const GOT16_DS: u32 = 58;
pub const GOT16_LO_DS: u32 = 59;
pub const TOC16_DS: u32 = 63;
pub const TOC16_LO_DS: u32 = 64;
/// 64-bit only: `@high` and `@higha` take the same halfword as `@h` and
/// `@ha` but are not checked for overflow, which is what a `lis`/`ori`
/// sequence building a full 64-bit address needs.
pub const ADDR16_HIGH: u32 = 110;
pub const ADDR16_HIGHA: u32 = 111;

/// The 34-bit field of a POWER10 prefixed instruction: absolute, relative to
/// the instruction (`@pcrel`), and the address of a GOT entry relative to the
/// instruction (`@got@pcrel`).
pub const D34: u32 = 128;
pub const PCREL34: u32 = 132;
pub const GOT_PCREL34: u32 = 133;

/// The relocation for a `size`-byte data reference, or `None` where the ABI
/// has none.
pub fn data(size: u8, pcrel: bool, bits64: bool) -> Option<u32> {
    Some(match (size, pcrel) {
        (8, false) if bits64 => ADDR64,
        (8, true) if bits64 => REL64,
        (4, false) => ADDR32,
        (4, true) => REL32,
        (2, false) => ADDR16,
        _ => return None,
    })
}
