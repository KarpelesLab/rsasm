//! ELF relocation types for MIPS (`R_MIPS_*`).
//!
//! The numbers come from the MIPS psABI. Only the handful this backend can
//! actually produce are listed.

pub const R16: u32 = 1;
pub const R32: u32 = 2;
/// The 26-bit field of `j` / `jal`, holding a word index into the current
/// 256 MB region rather than a displacement.
pub const R26: u32 = 4;
/// High half of a 32-bit address, biased so that a sign-extended `LO16`
/// added to it lands on the right value.
pub const HI16: u32 = 5;
pub const LO16: u32 = 6;
/// The 16-bit word displacement of a conditional branch.
pub const PC16: u32 = 10;
pub const R64: u32 = 18;
pub const PC32: u32 = 248;

/// The thread-local access models, which are the same numbers in all three
/// ABIs: n64 packs three relocation types into one `r_info`, but every
/// thread-local operator fills only the first and leaves the other two
/// `R_MIPS_NONE`, as both references do.
///
/// `TLS_GD` and `TLS_LDM` name the two-word GOT entry `__tls_get_addr` is
/// given, for general dynamic and for local dynamic; `TLS_GOTTPREL` the
/// one-word entry initial exec reads. The `DTPREL` halves are a variable's
/// offset within its module's block, which local dynamic adds to what the
/// call returned, and the `TPREL` halves its offset from the thread pointer,
/// which only local exec knows without asking.
pub const TLS_GD: u32 = 42;
pub const TLS_LDM: u32 = 43;
pub const TLS_DTPREL_HI16: u32 = 44;
pub const TLS_DTPREL_LO16: u32 = 45;
pub const TLS_GOTTPREL: u32 = 46;
pub const TLS_TPREL_HI16: u32 = 49;
pub const TLS_TPREL_LO16: u32 = 50;

/// The absolute relocation for an `n`-byte data reference.
pub fn abs(n: u8) -> Option<u32> {
    Some(match n {
        2 => R16,
        4 => R32,
        8 => R64,
        _ => return None,
    })
}

/// The PC-relative relocation for an `n`-byte data reference. MIPS has no
/// PC-relative data relocation narrower than 32 bits.
pub fn pcrel(n: u8) -> Option<u32> {
    match n {
        4 => Some(PC32),
        _ => None,
    }
}
