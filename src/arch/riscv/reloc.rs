//! ELF relocation types for RISC-V (`R_RISCV_*`).

pub const ABS32: u32 = 1;
pub const ABS64: u32 = 2;
pub const BRANCH: u32 = 16;
pub const JAL: u32 = 17;
pub const CALL_PLT: u32 = 19;
pub const GOT_HI20: u32 = 20;
pub const PCREL_HI20: u32 = 23;
pub const PCREL_LO12_I: u32 = 24;
pub const PCREL_LO12_S: u32 = 25;
pub const HI20: u32 = 26;
pub const LO12_I: u32 = 27;
pub const LO12_S: u32 = 28;
pub const RVC_BRANCH: u32 = 44;
pub const RVC_JUMP: u32 = 45;
pub const PCREL32: u32 = 57;

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
