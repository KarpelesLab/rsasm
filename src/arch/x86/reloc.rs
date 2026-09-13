//! ELF relocation types for x86-64 (`R_X86_64_*`).

pub const NONE: u32 = 0;
pub const ABS64: u32 = 1;
pub const PC32: u32 = 2;
pub const GOT32: u32 = 3;
pub const PLT32: u32 = 4;
pub const GOTPCREL: u32 = 9;
pub const ABS32: u32 = 10;
pub const ABS32S: u32 = 11;
pub const ABS16: u32 = 12;
pub const PC16: u32 = 13;
pub const ABS8: u32 = 14;
pub const PC8: u32 = 15;
pub const PC64: u32 = 24;

/// The absolute relocation for an `n`-byte field.
pub fn abs(n: u8) -> Option<u32> {
    Some(match n {
        1 => ABS8,
        2 => ABS16,
        4 => ABS32,
        8 => ABS64,
        _ => return None,
    })
}

/// The PC-relative relocation for an `n`-byte field.
pub fn pcrel(n: u8) -> Option<u32> {
    Some(match n {
        1 => PC8,
        2 => PC16,
        4 => PC32,
        8 => PC64,
        _ => return None,
    })
}

/// Maps a source-level `@` modifier to a relocation type.
pub fn from_modifier(name: &str, size: u8, pcrel_field: bool) -> Option<u32> {
    Some(match name {
        "plt" => PLT32,
        "gotpcrel" => GOTPCREL,
        "got" => GOT32,
        _ => return if pcrel_field { pcrel(size) } else { abs(size) },
    })
}
