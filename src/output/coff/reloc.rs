//! The relocation mapping layer: ELF numbers in, COFF numbers out.
//!
//! Backends choose relocations as ELF numbers ([`Architecture::data_reloc`],
//! [`Architecture::modifier_reloc`], [`FixupKind::reloc`]), which is the one
//! numbering every one of them already has. COFF needs its own, so the
//! translation lives here rather than in the backends: nothing about x86 or
//! AArch64 changes when an object comes out as PE/COFF, and the ELF writer
//! never sees this file.
//!
//! Two things differ per relocation and both are answered here:
//!
//! - **Which number.** A COFF type is not always one-to-one with an ELF one:
//!   `R_X86_64_PC32`, `PLT32` and `GOTPCREL` all become
//!   `IMAGE_REL_AMD64_REL32`, since a Windows object has no PLT and no GOT
//!   for the assembler to name.
//! - **Where "here" is.** COFF's PC-relative relocations on x86 and for
//!   AArch64's `REL32` measure from the byte *after* the four-byte field,
//!   while AArch64's branches and `adrp` measure from the instruction. ELF
//!   measures from the field on all of them. [`pc_base`] is the difference,
//!   and it is what the in-place addend has to carry.
//!
//! [`Architecture::data_reloc`]: crate::arch::Architecture::data_reloc
//! [`Architecture::modifier_reloc`]: crate::arch::Architecture::modifier_reloc
//! [`FixupKind::reloc`]: crate::section::FixupKind::reloc

use super::{MACHINE_AMD64, MACHINE_ARM64, MACHINE_I386};
use crate::arch::Endian;
use crate::section::FixupKind;

/// COFF-only relocations, in the space the backends' ELF numbers leave free.
///
/// `@IMGREL`, `.rva`, `.secrel32` and `.secidx` name relocations no psABI
/// has, so there is no ELF number to carry them through the core. These
/// stand in, out of reach of any real `R_*` value, and are only ever produced
/// by the COFF-only directives and modifiers, which refuse to appear in any
/// other output format.
pub(crate) mod pseudo {
    /// The address of the target relative to the image base: `@IMGREL`,
    /// `.rva`, NASM's `wrt ..imagebase`.
    pub(crate) const IMGREL: u32 = 0x8000_0001;
    /// The offset of the target within its own section: `.secrel32`,
    /// `@SECREL32`.
    pub(crate) const SECREL: u32 = 0x8000_0002;
    /// The one-based index of the target's section: `.secidx`.
    pub(crate) const SECIDX: u32 = 0x8000_0003;
}

// ---- IMAGE_REL_AMD64_* ------------------------------------------------------
const AMD64_ADDR64: u16 = 0x0001;
const AMD64_ADDR32: u16 = 0x0002;
const AMD64_ADDR32NB: u16 = 0x0003;
const AMD64_REL32: u16 = 0x0004;
const AMD64_SECTION: u16 = 0x000a;
const AMD64_SECREL: u16 = 0x000b;

// ---- IMAGE_REL_I386_* -------------------------------------------------------
const I386_DIR32: u16 = 0x0006;
const I386_DIR32NB: u16 = 0x0007;
const I386_SECTION: u16 = 0x000a;
const I386_SECREL: u16 = 0x000b;
const I386_REL32: u16 = 0x0014;

// ---- IMAGE_REL_ARM64_* ------------------------------------------------------
const ARM64_ADDR32: u16 = 0x0001;
const ARM64_ADDR32NB: u16 = 0x0002;
const ARM64_BRANCH26: u16 = 0x0003;
const ARM64_PAGEBASE_REL21: u16 = 0x0004;
const ARM64_REL21: u16 = 0x0005;
const ARM64_PAGEOFFSET_12A: u16 = 0x0006;
const ARM64_PAGEOFFSET_12L: u16 = 0x0007;
const ARM64_SECREL: u16 = 0x0008;
const ARM64_SECTION: u16 = 0x000d;
const ARM64_ADDR64: u16 = 0x000e;
const ARM64_BRANCH19: u16 = 0x000f;
const ARM64_BRANCH14: u16 = 0x0010;
const ARM64_REL32: u16 = 0x0011;

/// The COFF relocation an ELF-numbered one becomes, or `None` where COFF has
/// none: a byte or word PC-relative field, or anything naming a GOT, a PLT
/// entry or a thread-local block, which a Windows object cannot describe.
pub(crate) fn map(machine: u16, elf: u32) -> Option<u16> {
    match machine {
        MACHINE_AMD64 => Some(match elf {
            pseudo::IMGREL => AMD64_ADDR32NB,
            pseudo::SECREL => AMD64_SECREL,
            pseudo::SECIDX => AMD64_SECTION,
            // R_X86_64_64
            1 => AMD64_ADDR64,
            // R_X86_64_32 and _32S; the linker writes the same 32 bits, and
            // COFF has no separate sign-extending form.
            10 | 11 => AMD64_ADDR32,
            // R_X86_64_PC32, _PLT32 and _GOTPCREL: a call, a jump and a
            // RIP-relative load are all plain PC-relative references here.
            2 | 4 | 9 => AMD64_REL32,
            _ => return None,
        }),
        MACHINE_I386 => Some(match elf {
            pseudo::IMGREL => I386_DIR32NB,
            pseudo::SECREL => I386_SECREL,
            pseudo::SECIDX => I386_SECTION,
            // R_386_32; COFF's `DIR16` exists, but llvm-mc refuses a 16-bit
            // field, and so does this.
            1 => I386_DIR32,
            // R_386_PC32 and _PLT32
            2 | 4 => I386_REL32,
            _ => return None,
        }),
        MACHINE_ARM64 => Some(match elf {
            pseudo::IMGREL => ARM64_ADDR32NB,
            pseudo::SECREL => ARM64_SECREL,
            pseudo::SECIDX => ARM64_SECTION,
            // R_AARCH64_ABS64 / ABS32 / PREL32
            257 => ARM64_ADDR64,
            258 => ARM64_ADDR32,
            261 => ARM64_REL32,
            // R_AARCH64_ADR_PREL_LO21 (`adr`) and ADR_PREL_PG_HI21 (`adrp`)
            274 => ARM64_REL21,
            275 => ARM64_PAGEBASE_REL21,
            // R_AARCH64_ADD_ABS_LO12_NC and the `ldr`/`str` `:lo12:` forms,
            // which COFF distinguishes only as "add" and "load/store".
            277 => ARM64_PAGEOFFSET_12A,
            278 | 284 | 285 | 286 | 299 => ARM64_PAGEOFFSET_12L,
            // R_AARCH64_TSTBR14, CONDBR19, JUMP26, CALL26
            279 => ARM64_BRANCH14,
            280 => ARM64_BRANCH19,
            282 | 283 => ARM64_BRANCH26,
            _ => return None,
        }),
        _ => None,
    }
}

/// How far past the start of the relocated field a COFF relocation of this
/// type measures its PC, which is what the in-place addend has to make up
/// for: the field of a `call` holds nothing extra, because `REL32` already
/// measures from the end of the instruction, while a `mov $0, sym(%rip)`
/// whose four-byte displacement is followed by a four-byte immediate holds
/// `-4`.
///
/// Zero for everything absolute, and for the AArch64 branches and `adrp`,
/// whose displacement is measured from the instruction itself.
pub(crate) fn pc_base(machine: u16, coff: u16) -> i64 {
    match (machine, coff) {
        (MACHINE_AMD64, AMD64_REL32) => 4,
        (MACHINE_I386, I386_REL32) => 4,
        (MACHINE_ARM64, ARM64_REL32) => 4,
        _ => 0,
    }
}

/// Writes a relocation's addend into the field it relocates, which is where
/// COFF keeps it.
///
/// Normally that is the field's own encoding — the same bits the resolved
/// value would have gone through, so an AArch64 `:lo12:` addend lands scaled
/// by the access size, as the linker reads it back. `adrp` is the exception:
/// its field holds a page count once resolved, but its addend is a plain byte
/// offset that the linker adds to the symbol before taking the page, so it
/// goes into the 21-bit immediate unshifted.
pub(crate) fn write_addend(
    machine: u16,
    coff: u16,
    kind: &FixupKind,
    endian: Endian,
    dst: &mut [u8],
    addend: i64,
) {
    if machine == MACHINE_ARM64 && coff == ARM64_PAGEBASE_REL21 {
        let w = endian.read(dst);
        let v = addend as u64;
        endian.write(
            dst,
            (w & !0x60ff_ffe0) | ((v & 3) << 29) | (((v >> 2) & 0x7_ffff) << 5),
        );
        return;
    }
    kind.write(endian, dst, addend);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_x86_pc_relative_forms_all_become_rel32() {
        // PC32, PLT32 and GOTPCREL: a Windows object has no PLT or GOT for
        // the assembler to name, so the three collapse into one.
        for elf in [2, 4, 9] {
            assert_eq!(map(MACHINE_AMD64, elf), Some(AMD64_REL32));
        }
        assert_eq!(pc_base(MACHINE_AMD64, AMD64_REL32), 4);
    }

    #[test]
    fn a_field_coff_cannot_describe_has_no_mapping() {
        // R_X86_64_PC8 and PC16: COFF has no byte or word PC-relative type.
        assert_eq!(map(MACHINE_AMD64, 15), None);
        assert_eq!(map(MACHINE_AMD64, 13), None);
        // R_AARCH64_LD_PREL_LO19, the `ldr x0, label` literal load.
        assert_eq!(map(MACHINE_ARM64, 273), None);
    }

    #[test]
    fn only_the_x86_and_arm64_rel32_forms_measure_past_the_field() {
        assert_eq!(pc_base(MACHINE_ARM64, ARM64_REL32), 4);
        assert_eq!(pc_base(MACHINE_ARM64, ARM64_BRANCH26), 0);
        assert_eq!(pc_base(MACHINE_ARM64, ARM64_PAGEBASE_REL21), 0);
    }
}
