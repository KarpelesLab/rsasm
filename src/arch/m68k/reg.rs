//! 68000-family register names.
//!
//! The same names serve both syntaxes. What differs is the spelling around
//! them: GNU as requires the `%` sigil (without it `d0` is an ordinary symbol,
//! checked against `m68k-elf-as`), while Motorola source writes registers bare
//! and GNU as `--mri` also tolerates the sigil. That decision belongs to the
//! operand parser; this module only answers "is this name a register".

/// A register an operand can name.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Reg {
    /// `d0`-`d7`.
    D(u8),
    /// `a0`-`a7`, including `sp` (and `fp`, in GNU syntax).
    A(u8),
    /// The program counter, only meaningful as a base register.
    Pc,
    Sr,
    Ccr,
    Usp,
}

impl Reg {
    /// The 4-bit number an index or `MOVEC` field uses: data registers are
    /// 0-7 and address registers 8-15.
    pub fn index_bits(self) -> Option<u8> {
        match self {
            Reg::D(n) => Some(n),
            Reg::A(n) => Some(8 | n),
            _ => None,
        }
    }
}

/// Looks up a general register by its lower-case name.
///
/// `fp` is GNU as's name for `a6`; Motorola assemblers have no such register,
/// and a symbol called `fp` is plausible there, so the caller says whether it
/// counts.
pub fn lookup(name: &str, gnu: bool) -> Option<Reg> {
    let b = name.as_bytes();
    if b.len() == 2 && (b'0'..=b'7').contains(&b[1]) {
        let n = b[1] - b'0';
        match b[0] {
            b'd' => return Some(Reg::D(n)),
            b'a' => return Some(Reg::A(n)),
            _ => {}
        }
    }
    Some(match name {
        "sp" => Reg::A(7),
        "fp" if gnu => Reg::A(6),
        "pc" => Reg::Pc,
        "sr" => Reg::Sr,
        "ccr" => Reg::Ccr,
        "usp" => Reg::Usp,
        _ => return None,
    })
}

/// The 12-bit `MOVEC` code of a control register, and the lowest CPU that has
/// it.
///
/// These are recognised only as `MOVEC` operands. Elsewhere `vbr` is just a
/// name, and a program with a variable called `cacr` should keep it.
pub fn control(name: &str) -> Option<(u16, super::Cpu)> {
    use super::Cpu::{M68010, M68020};
    Some(match name {
        "sfc" => (0x000, M68010),
        "dfc" => (0x001, M68010),
        "usp" => (0x800, M68010),
        "vbr" => (0x801, M68010),
        "cacr" => (0x002, M68020),
        "caar" => (0x802, M68020),
        "msp" => (0x803, M68020),
        "isp" => (0x804, M68020),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(lookup("d0", false), Some(Reg::D(0)));
        assert_eq!(lookup("a7", false), Some(Reg::A(7)));
        assert_eq!(lookup("sp", false), Some(Reg::A(7)));
        assert_eq!(lookup("fp", true), Some(Reg::A(6)));
        assert_eq!(lookup("fp", false), None);
        assert_eq!(lookup("d8", false), None);
        assert_eq!(lookup("a", false), None);
        assert_eq!(Reg::A(3).index_bits(), Some(11));
    }
}
