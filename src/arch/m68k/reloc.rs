//! ELF relocation numbers for `EM_68K`, as `m68k-elf-objdump -r` names them.
//!
//! The absolute and PC-relative widths are all this backend writes: the
//! relocation suffixes GNU as reads are not assembled yet, and are refused
//! rather than relocated as a plain reference would be. For a `%a0`-relative
//! operand GNU as writes `R_68K_GOT32O` for `x@GOT` and `R_68K_PLT32O` for
//! `x@PLT`, `R_68K_PLT32` for `x@PLTPC` and `R_68K_GOT32` for `x@GOTPC`, and
//! for the thread-local suffixes `R_68K_TLS_GD32`, `R_68K_TLS_LDM32`,
//! `R_68K_TLS_LDO32`, `R_68K_TLS_IE32` and `R_68K_TLS_LE32`. It reads none of
//! them in a data directive.

pub const R_68K_32: u32 = 1;
pub const R_68K_16: u32 = 2;
pub const R_68K_8: u32 = 3;
pub const R_68K_PC32: u32 = 4;
pub const R_68K_PC16: u32 = 5;
pub const R_68K_PC8: u32 = 6;

/// The relocation for a `size`-byte reference.
pub fn data(size: u8, pcrel: bool) -> Option<u32> {
    Some(match (size, pcrel) {
        (4, false) => R_68K_32,
        (2, false) => R_68K_16,
        (1, false) => R_68K_8,
        (4, true) => R_68K_PC32,
        (2, true) => R_68K_PC16,
        (1, true) => R_68K_PC8,
        _ => return None,
    })
}
