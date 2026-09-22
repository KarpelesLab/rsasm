//! `R_ARM_*` relocation numbers, from the ARM ELF ABI.

pub const ABS32: u32 = 2;
pub const REL32: u32 = 3;
pub const ABS16: u32 = 5;
pub const ABS8: u32 = 8;
pub const PREL31: u32 = 42;
pub const THM_CALL: u32 = 10;
pub const CALL: u32 = 28;
pub const JUMP24: u32 = 29;
pub const THM_JUMP24: u32 = 30;
pub const THM_JUMP19: u32 = 51;

/// `sym(GOTOFF)`: the symbol's distance from the GOT, `S + A - GOT_ORG`.
/// `readelf` prints it as `R_ARM_GOTOFF32`.
pub const GOTOFF32: u32 = 24;
/// A reference to `_GLOBAL_OFFSET_TABLE_`: the distance from the field to the
/// GOT, `B(S) + A - P`. `readelf` prints it as `R_ARM_GOTPC`.
pub const BASE_PREL: u32 = 25;
/// `sym(GOT)`: the offset of the symbol's GOT entry from the GOT,
/// `GOT(S) + A - GOT_ORG`. `readelf` prints it as `R_ARM_GOT32`.
pub const GOT_BREL: u32 = 26;
/// `sym(GOT_PREL)`: the symbol's GOT entry measured from the field,
/// `GOT(S) + A - P`, which reaches a GOT entry without first loading the
/// GOT's own address.
pub const GOT_PREL: u32 = 96;

/// `movw rd, #:lower16:sym`.
pub const MOVW_ABS_NC: u32 = 43;
/// `movt rd, #:upper16:sym`.
pub const MOVT_ABS: u32 = 44;
/// `movw rd, #:lower16:(sym - label)`.
pub const MOVW_PREL_NC: u32 = 45;
/// `movt rd, #:upper16:(sym - label)`.
pub const MOVT_PREL: u32 = 46;
/// The Thumb encodings of the same four.
pub const THM_MOVW_ABS_NC: u32 = 47;
pub const THM_MOVT_ABS: u32 = 48;
pub const THM_MOVW_PREL_NC: u32 = 49;
pub const THM_MOVT_PREL: u32 = 50;

/// Relocation for a data reference of `size` bytes.
pub fn data(size: u8, pcrel: bool) -> Option<u32> {
    Some(match (size, pcrel) {
        (4, false) => ABS32,
        (4, true) => REL32,
        (2, false) => ABS16,
        (1, false) => ABS8,
        _ => return None,
    })
}

/// The relocation a `sym(NAME)` suffix selects in a `size`-byte data field.
///
/// GNU as reads the suffix in `s_arm_elf_cons`, which only `.word` and
/// `.long` go through, so every one of these is a four-byte relocation.
/// `(PLT)` is the exception: there the suffix names a branch target and
/// `s_arm_elf_cons` emits the symbol itself, so `.word sym(PLT)` is
/// `.word sym`.
pub fn modifier(name: &str, size: u8, pcrel: bool) -> Option<u32> {
    if size != 4 || pcrel {
        return None;
    }
    Some(match name {
        "got" => GOT_BREL,
        "got_prel" => GOT_PREL,
        "gotoff" => GOTOFF32,
        "plt" => ABS32,
        _ => return None,
    })
}

/// The PC-relative counterpart of a `movw`/`movt` half, which is what
/// `:lower16:(sym - label)` asks for; see
/// [`Architecture::pcrel_reloc`](crate::arch::Architecture::pcrel_reloc).
pub fn half_pcrel(reloc: u32) -> Option<u32> {
    Some(match reloc {
        MOVW_ABS_NC => MOVW_PREL_NC,
        MOVT_ABS => MOVT_PREL,
        THM_MOVW_ABS_NC => THM_MOVW_PREL_NC,
        THM_MOVT_ABS => THM_MOVT_PREL,
        _ => return None,
    })
}
