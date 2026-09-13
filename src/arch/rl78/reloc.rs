//! `R_RL78_*` relocation numbers, and the fixup kinds that carry them.
//!
//! Every number here was read with `rl78-elf-readelf -r` from an object that
//! `rl78-elf-as` (binutils 2.47) produced for the operand in question, not
//! copied from a header. The pairing of operand to relocation is also the
//! reference's: an 8-bit immediate is `DIR8S` even though RL78 immediates are
//! as often unsigned, and a short direct address gets the Red Hat
//! `RH_SADDR` rather than a plain 8-bit relocation.

use crate::section::FixupKind;

/// `.long sym`.
pub const R_RL78_DIR32: u32 = 0x01;
/// `.3byte sym`, and the 20-bit `!!addr` operand.
pub const R_RL78_DIR24S: u32 = 0x02;
/// `.short sym`, `#imm16`, and the 16-bit `!addr` and `addr[b]` operands.
pub const R_RL78_DIR16S: u32 = 0x05;
/// `.byte sym`, `#imm8`, and the displacement in `[hl+d]`.
pub const R_RL78_DIR8S: u32 = 0x08;
/// A short direct address (`saddr`), which the linker reduces to one byte.
pub const R_RL78_RH_SADDR: u32 = 0x2f;

/// An 8-bit immediate or based-addressing displacement.
pub fn imm8() -> FixupKind {
    FixupKind::data(1).with_reloc(R_RL78_DIR8S)
}

/// A 16-bit immediate, or the 16-bit base of `addr[b]`.
pub fn imm16() -> FixupKind {
    FixupKind::data(2).with_reloc(R_RL78_DIR16S)
}

/// The 16-bit `!addr` of a symbolic address.
///
/// The field is two bytes but the address space is 20 bits, and a 16-bit
/// address means the top 64 KiB, `0xF0000`–`0xFFFFF`, when `ES` is not
/// involved: RL78 SFRs and RAM live there. The value is therefore checked as a
/// 20-bit address and its low 16 bits are written, which is also what the GNU
/// linker does for `R_RL78_DIR16S` when the top nibble is `F`.
pub fn addr16() -> FixupKind {
    FixupKind::data(2)
        .with_field(20, 1)
        .with_reloc(R_RL78_DIR16S)
}

/// The 20-bit `!!addr` of `br`, `call`: three bytes, 20 bits of address.
pub fn addr20() -> FixupKind {
    FixupKind::data(3)
        .with_field(20, 1)
        .with_reloc(R_RL78_DIR24S)
}

/// A symbolic short direct address. One byte holds the low eight bits of an
/// address in `0xFFE20`–`0xFFF1F`, so the value is checked as a 20-bit address
/// and truncated as it is written, just as it is for a constant.
pub fn saddr() -> FixupKind {
    FixupKind::data(1)
        .with_field(20, 1)
        .with_reloc(R_RL78_RH_SADDR)
}

/// An 8-bit branch displacement, counted from the end of the instruction.
///
/// Every RL78 relative field is the last thing in its instruction, so the
/// adjustment is simply the field width.
///
/// No relocation is attached, deliberately. The GNU linker computes
/// `R_RL78_DIR8S_PCREL` and `R_RL78_DIR16S_PCREL` as `S + A - (P + size)`
/// (`bfd/elf32-rl78.c`, `rl78_elf_relocate_section`), so the reference writes
/// an addend of 0 for `$sym`. The core writes `addend - adjust`, the x86
/// convention, which would land every such branch `size` bytes early. A
/// target in the same section never needs a relocation; one in another
/// section is reported as unrelocatable rather than silently mislinked.
pub fn rel8() -> FixupKind {
    FixupKind::pcrel(1, 1)
}

/// The 16-bit displacement of `br $!addr` and `call $!addr`. See [`rel8`] for
/// why it has no relocation.
pub fn rel16() -> FixupKind {
    FixupKind::pcrel(2, 2)
}

/// The relocation for a data directive of `size` bytes.
///
/// PC-relative data has none: the reference expresses `.short sym - .` as a
/// stack of `R_RL78_SYM`/`R_RL78_OPsub`/`R_RL78_ABS16` operations, which the
/// core's one-relocation-per-fixup model cannot produce.
pub fn data(size: u8, pcrel: bool) -> Option<u32> {
    if pcrel {
        return None;
    }
    match size {
        1 => Some(R_RL78_DIR8S),
        2 => Some(R_RL78_DIR16S),
        3 => Some(R_RL78_DIR24S),
        4 => Some(R_RL78_DIR32),
        _ => None,
    }
}
