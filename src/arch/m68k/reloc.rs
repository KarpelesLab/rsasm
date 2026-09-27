//! ELF relocation numbers for `EM_68K`, as `m68k-elf-objdump -r` names them.
//!
//! The widths here and the thread-local models are all this backend writes:
//! the position-independent suffixes are not assembled yet, and are refused
//! rather than relocated as a plain reference would be. For a `%a0`-relative
//! operand GNU as writes `R_68K_GOT32O` for `x@GOT` and `R_68K_PLT32O` for
//! `x@PLT`, `R_68K_PLT32` for `x@PLTPC` and `R_68K_GOT32` for `x@GOTPC`; it
//! reads none of the four in a data directive.

pub const R_68K_32: u32 = 1;
pub const R_68K_16: u32 = 2;
pub const R_68K_8: u32 = 3;
pub const R_68K_PC32: u32 = 4;
pub const R_68K_PC16: u32 = 5;
pub const R_68K_PC8: u32 = 6;

pub const R_68K_TLS_GD32: u32 = 25;
pub const R_68K_TLS_GD16: u32 = 26;
pub const R_68K_TLS_GD8: u32 = 27;
pub const R_68K_TLS_LDM32: u32 = 28;
pub const R_68K_TLS_LDM16: u32 = 29;
pub const R_68K_TLS_LDM8: u32 = 30;
pub const R_68K_TLS_LDO32: u32 = 31;
pub const R_68K_TLS_LDO16: u32 = 32;
pub const R_68K_TLS_LDO8: u32 = 33;
pub const R_68K_TLS_IE32: u32 = 34;
pub const R_68K_TLS_IE16: u32 = 35;
pub const R_68K_TLS_IE8: u32 = 36;
pub const R_68K_TLS_LE32: u32 = 37;
pub const R_68K_TLS_LE16: u32 = 38;
pub const R_68K_TLS_LE8: u32 = 39;

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

/// The five thread-local access models, spelled as the `@` suffix that names
/// one, with the relocation each takes in a four-, two- and one-byte field.
/// These are GNU as's `enum pic_relocation` and the widths its
/// `get_reloc_code` has a relocation for, which is all three for every model.
const TLS_MODELS: [(&str, [u32; 3]); 5] = [
    ("tlsgd", [R_68K_TLS_GD32, R_68K_TLS_GD16, R_68K_TLS_GD8]),
    ("tlsldm", [R_68K_TLS_LDM32, R_68K_TLS_LDM16, R_68K_TLS_LDM8]),
    ("tlsldo", [R_68K_TLS_LDO32, R_68K_TLS_LDO16, R_68K_TLS_LDO8]),
    ("tlsie", [R_68K_TLS_IE32, R_68K_TLS_IE16, R_68K_TLS_IE8]),
    ("tlsle", [R_68K_TLS_LE32, R_68K_TLS_LE16, R_68K_TLS_LE8]),
];

/// Whether `name` is one of the thread-local access models.
pub fn is_tls(name: &str) -> bool {
    TLS_MODELS.iter().any(|&(m, _)| m == name)
}

/// The relocation a thread-local access model takes in a `size`-byte field.
/// A model has no PC-relative relocation of its own: what the linker computes
/// is the same either way, and GNU as writes the same number for a field it
/// measures from the instruction.
pub fn tls(name: &str, size: u8) -> Option<u32> {
    let i = match size {
        4 => 0,
        2 => 1,
        1 => 2,
        _ => return None,
    };
    TLS_MODELS
        .iter()
        .find(|&&(m, _)| m == name)
        .map(|&(_, r)| r[i])
}
