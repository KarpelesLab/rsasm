//! The x86 instruction table.
//!
//! Operand patterns are written in **Intel order** (destination first). The
//! AT&T front end reverses its operands before matching, so there is only one
//! table.
//!
//! The tables themselves live in submodules, one per instruction-set family,
//! each contributing its entries through an `install` function. Splitting them
//! keeps any one file readable: the SIMD families alone outnumber the base
//! integer instruction set several times over.

pub mod base;

use std::collections::HashMap;
use std::sync::OnceLock;

/// What an operand slot accepts. Widths are in bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Op {
    /// Register or memory of the given width.
    Rm(u8),
    /// Register only.
    R(u8),
    /// Memory only; width 0 means "any, size irrelevant" (as for `lea`).
    M(u8),
    /// Immediate encoded in this many bytes.
    Imm(u8),
    /// One immediate byte, sign-extended to the operation width.
    Imm8s,
    /// Branch displacement of this many bytes.
    Rel(u8),
    /// A specific register, by name.
    Fixed(&'static str),
    /// The literal constant 1, as in `shl $1, %eax`.
    One,
    /// Register or memory operand used indirectly (`jmp *%rax`).
    IndirectRm(u8),
}

impl Op {
    pub fn width(self) -> u8 {
        match self {
            Op::Rm(w) | Op::R(w) | Op::M(w) | Op::Imm(w) | Op::IndirectRm(w) => w,
            Op::Imm8s => 1,
            Op::Rel(w) => w,
            Op::One => 0,
            Op::Fixed(_) => 0,
        }
    }
}

/// How ModRM is formed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ModRm {
    /// No ModRM byte.
    None,
    /// `/r`: the reg field holds a register operand.
    Reg,
    /// `/digit`: the reg field is a fixed opcode extension.
    Ext(u8),
}

pub const PLUSREG: u16 = 1 << 0;
/// Operand size defaults to 64 bits in long mode (push, pop, jmp, call, ret).
pub const DEF64: u16 = 1 << 1;
/// Only encodable in 64-bit mode.
pub const ONLY64: u16 = 1 << 2;
/// Not encodable in 64-bit mode.
pub const NO64: u16 = 1 << 3;
/// The immediate is an absolute 64-bit value (`movabs`).
pub const IMM64: u16 = 1 << 4;
/// Not usable when every register operand is the accumulator. `xchg` needs
/// this: `xchg eax, eax` must not encode as `90`, which is `nop` and does not
/// clear the upper half of `rax`.
pub const NOTACC: u16 = 1 << 5;
/// A 64-bit form that needs no REX.W, because the plain opcode already means
/// what the source asked for. `xchg rax, rax` is the one case: it is spelled
/// `90`, the canonical `nop`.
pub const NO_REX_W: u16 = 1 << 6;

#[derive(Clone, Debug)]
pub struct Def {
    pub ops: Vec<Op>,
    /// Mandatory prefix emitted before REX: 0x66, 0xF2 or 0xF3.
    pub pfx: u8,
    pub opcode: Vec<u8>,
    pub modrm: ModRm,
    /// Operation width in bits: 0 (irrelevant), 8, 16, 32 or 64. Drives the
    /// 0x66 prefix and REX.W.
    pub opsize: u8,
    pub flags: u16,
}

impl Def {
    pub fn new(ops: Vec<Op>, opcode: Vec<u8>, modrm: ModRm, opsize: u8) -> Def {
        Def {
            ops,
            pfx: 0,
            opcode,
            modrm,
            opsize,
            flags: 0,
        }
    }

    pub fn flags(mut self, f: u16) -> Def {
        self.flags |= f;
        self
    }
}

pub fn d(ops: Vec<Op>, opcode: &[u8], modrm: ModRm, opsize: u8) -> Def {
    Def::new(ops, opcode.to_vec(), modrm, opsize)
}

/// The 16 condition codes, in `tttn` order, with every accepted spelling.
#[rustfmt::skip]
pub const CONDITIONS: &[(&str, u8)] = &[
    ("o", 0x0),
    ("no", 0x1),
    ("b", 0x2), ("c", 0x2), ("nae", 0x2),
    ("ae", 0x3), ("nb", 0x3), ("nc", 0x3),
    ("e", 0x4), ("z", 0x4),
    ("ne", 0x5), ("nz", 0x5),
    ("be", 0x6), ("na", 0x6),
    ("a", 0x7), ("nbe", 0x7),
    ("s", 0x8),
    ("ns", 0x9),
    ("p", 0xa), ("pe", 0xa),
    ("np", 0xb), ("po", 0xb),
    ("l", 0xc), ("nge", 0xc),
    ("ge", 0xd), ("nl", 0xd),
    ("le", 0xe), ("ng", 0xe),
    ("g", 0xf), ("nle", 0xf),
];

/// Widths that the generic "r/m, r" style patterns are generated for.
pub const WIDTHS: [u8; 3] = [2, 4, 8];

pub fn opsize_bits(w: u8) -> u8 {
    w * 8
}

fn build() -> HashMap<&'static str, Vec<Def>> {
    let mut t: HashMap<&'static str, Vec<Def>> = HashMap::new();
    base::install(&mut t);
    t
}

pub fn table() -> &'static HashMap<&'static str, Vec<Def>> {
    static TABLE: OnceLock<HashMap<&'static str, Vec<Def>>> = OnceLock::new();
    TABLE.get_or_init(build)
}

pub fn lookup(mnemonic: &str) -> Option<&'static [Def]> {
    table().get(mnemonic).map(|v| v.as_slice())
}

/// True if `name` names an instruction, ignoring AT&T size suffixes.
pub fn is_mnemonic(name: &str) -> bool {
    table().contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_covers_the_expected_groups() {
        for m in [
            "add", "sub", "mov", "lea", "jmp", "je", "setne", "cmovg", "imul", "shl", "ret",
        ] {
            assert!(is_mnemonic(m), "missing `{m}`");
        }
        assert!(!is_mnemonic("nosuchinsn"));
    }

    #[test]
    fn jmp_offers_a_short_and_a_near_form() {
        let defs = lookup("jmp").unwrap();
        assert!(defs.iter().any(|x| x.ops == [Op::Rel(1)]));
        assert!(defs.iter().any(|x| x.ops == [Op::Rel(4)]));
    }

    #[test]
    fn alu_prefers_sign_extended_imm8() {
        let defs = lookup("add").unwrap();
        let i8_pos = defs
            .iter()
            .position(|x| x.ops == [Op::Rm(4), Op::Imm8s])
            .unwrap();
        let i32_pos = defs
            .iter()
            .position(|x| x.ops == [Op::Rm(4), Op::Imm(4)])
            .unwrap();
        assert!(i8_pos < i32_pos, "imm8 form must be matched first");
    }
}
