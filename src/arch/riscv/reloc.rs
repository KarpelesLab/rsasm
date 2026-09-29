//! ELF relocation types for RISC-V (`R_RISCV_*`).

pub const ABS32: u32 = 1;
pub const ABS64: u32 = 2;
pub const BRANCH: u32 = 16;
pub const JAL: u32 = 17;
pub const CALL_PLT: u32 = 19;
pub const GOT_HI20: u32 = 20;
pub const TLS_GOT_HI20: u32 = 21;
pub const TLS_GD_HI20: u32 = 22;
pub const PCREL_HI20: u32 = 23;
pub const PCREL_LO12_I: u32 = 24;
pub const PCREL_LO12_S: u32 = 25;
pub const HI20: u32 = 26;
pub const LO12_I: u32 = 27;
pub const LO12_S: u32 = 28;
pub const TPREL_HI20: u32 = 29;
pub const TPREL_LO12_I: u32 = 30;
pub const TPREL_LO12_S: u32 = 31;
pub const TPREL_ADD: u32 = 32;
pub const ALIGN: u32 = 43;
pub const RVC_BRANCH: u32 = 44;
pub const RVC_JUMP: u32 = 45;
pub const RELAX: u32 = 51;
pub const PCREL32: u32 = 57;
pub const TLSDESC_HI20: u32 = 62;
pub const TLSDESC_LOAD_LO12: u32 = 63;
pub const TLSDESC_ADD_LO12: u32 = 64;
pub const TLSDESC_CALL: u32 = 65;

/// Whether a linker that relaxes knows how to rewrite the sequence this
/// relocation belongs to, and so whether an `R_RISCV_RELAX` goes beside it.
///
/// The set is GNU as's, from the `relaxable` arm of `md_apply_fix` in
/// `tc-riscv.c`: the two halves of an absolute or PC-relative address, the
/// `call` pair, and the local-exec and descriptor thread-local sequences.
/// Left out are the relocations that name a slot a linker lays out rather
/// than an instruction it can shorten — `R_RISCV_GOT_HI20`,
/// `R_RISCV_TLS_GOT_HI20` and `R_RISCV_TLS_GD_HI20` — every branch and jump
/// displacement, and data.
pub fn relaxable(reloc: u32) -> bool {
    matches!(
        reloc,
        CALL_PLT
            | PCREL_HI20
            | PCREL_LO12_I
            | PCREL_LO12_S
            | HI20
            | LO12_I
            | LO12_S
            | TPREL_HI20
            | TPREL_LO12_I
            | TPREL_LO12_S
            | TPREL_ADD
            | TLSDESC_HI20
            | TLSDESC_LOAD_LO12
            | TLSDESC_ADD_LO12
            | TLSDESC_CALL
    )
}

/// Whether a reference to a symbol in the fixup's own section is left to the
/// linker once relaxation is on, and whether the instruction is still sized
/// by the distance as it stands.
///
/// A relaxing linker deletes instructions, so a distance measured here can be
/// wrong by the time the program runs; GNU as therefore stops marking these
/// fixups done in `md_apply_fix` while `riscv_opts.relax` holds, and llvm-mc
/// under `+relax` does the same. It is every branch and jump displacement,
/// the `call` pair, and both halves of a PC-relative address. Nothing else
/// resolves here anyway: an absolute address is one no relaxation moves, and
/// a GOT slot or a thread-local offset is the linker's to begin with.
///
/// A branch and a jump are the ones with more than one form, and both
/// references still choose it by the distance as written; the rest are one
/// shape whatever the distance, so nothing needs the value at all
/// (`FixupKind::object_reloc` is enough for those). The field itself is
/// left empty either way, as llvm-mc leaves it; GNU as writes the distance
/// into a branch or jump anyway, by its own comment "to improve objdump
/// readability", which no linker reads.
pub fn deferred_when_relaxed(reloc: u32) -> Option<bool> {
    match reloc {
        BRANCH | JAL | RVC_BRANCH | RVC_JUMP => Some(true),
        CALL_PLT | PCREL_HI20 | PCREL_LO12_I | PCREL_LO12_S => Some(false),
        _ => None,
    }
}

/// `R_RISCV_ADD8` to `R_RISCV_ADD64`, and the matching `SUB`s: a field that
/// holds one symbol minus another, in two relocations at the same offset.
pub fn difference(size: u8) -> Option<(u32, u32)> {
    Some(match size {
        1 => (33, 37),
        2 => (34, 38),
        4 => (35, 39),
        8 => (36, 40),
        _ => return None,
    })
}

/// The relocation for an `n`-byte data reference.
///
/// RISC-V has no absolute one- or two-byte relocation, so `.byte foo` can only
/// be assembled when `foo` is already known.
pub fn data(size: u8, pcrel: bool) -> Option<u32> {
    Some(match (size, pcrel) {
        (4, false) => ABS32,
        (8, false) => ABS64,
        (4, true) => PCREL32,
        _ => return None,
    })
}
