//! The SuperH opcode table.
//!
//! Every instruction is one 16-bit word. An entry gives the word with its
//! operand fields zero and says, operand by operand, what is accepted and
//! which bits it fills. A mnemonic has as many entries as it has addressing
//! modes; they are tried in order and the first whose operands all match
//! wins, which is how GNU as picks among them too.
//!
//! Field positions are named by where they go, not by the source/destination
//! role: `n` is bits 11-8 and `m` is bits 7-4. That is how the manuals draw
//! the words (`0110nnnnmmmm0011` is `mov rm,rn`), but it means `lds rm,fpul`
//! uses an `N` argument, since its register sits in bits 11-8.

use super::reg::Ctl;

/// Instruction-set levels, as bits in [`crate::arch::ArchState::features`].
pub mod isa {
    /// SH-2: delayed conditional branches, `dt`, the 32-bit multiplies,
    /// `braf` / `bsrf`.
    pub const SH2: u64 = 1 << 0;
    /// SH-3: `ssr`, `spc` and the banked registers, `clrs` / `sets`,
    /// `ldtlb`, and the dynamic shifts `shad` / `shld`.
    pub const SH3: u64 = 1 << 1;
    /// SH-4 without its FPU: `sgr`, `dbr`, `movca.l` and the cache hints.
    pub const SH4: u64 = 1 << 2;
    /// SH-4A: `movli.l` / `movco.l`, `movua.l`, `icbi`, `prefi`, `synco`.
    pub const SH4A: u64 = 1 << 3;
    /// The SH-2E/SH-3E single-precision FPU.
    pub const FPU: u64 = 1 << 4;
    /// The SH-4 double-precision FPU and its vector instructions.
    pub const DFPU: u64 = 1 << 5;

    pub const ALL: u64 = SH2 | SH3 | SH4 | SH4A | FPU | DFPU;

    /// Describes the lowest level that provides `bits`.
    pub fn describe(bits: u64) -> &'static str {
        if bits & DFPU != 0 {
            "the SH-4 double-precision FPU"
        } else if bits & FPU != 0 {
            "an SH-2E, SH-3E or SH-4 FPU"
        } else if bits & SH4A != 0 {
            "SH-4A"
        } else if bits & SH4 != 0 {
            "SH-4"
        } else if bits & SH3 != 0 {
            "SH-3"
        } else {
            "SH-2"
        }
    }
}

/// What one operand slot accepts, and where it goes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Arg {
    /// `rn`, bits 11-8.
    RegN,
    /// `rm`, bits 7-4.
    RegM,
    /// Exactly `r0`; no bits.
    R0,
    /// `#imm`, bits 7-0.
    Imm8,
    /// `@rn` / `@rm`.
    IndN,
    IndM,
    /// `@rn+` / `@rm+`.
    IncN,
    IncM,
    /// `@-rn` / `@-rm`.
    DecN,
    DecM,
    /// `@(r0,rn)` / `@(r0,rm)`.
    R0IdxN,
    R0IdxM,
    /// `@(disp,rn)` / `@(disp,rm)`: register plus a four-bit displacement in
    /// bits 3-0, counted in units of the operand size.
    DispN(u8),
    DispM(u8),
    /// `@(disp,gbr)`: an eight-bit displacement in bits 7-0, scaled likewise.
    GbrDisp(u8),
    /// `@(r0,gbr)`.
    R0Gbr,
    /// A PC-relative data address, bits 7-0, scaled by the operand size.
    PcRel(u8),
    /// A branch target: eight or twelve bits of signed word displacement.
    Branch8,
    Branch12,
    /// A named control register; no bits.
    Ctl(Ctl),
    /// `rN_bank`, bits 7-4 as `1nnn`.
    BankM,
    /// `frn` / `frm`.
    FrN,
    FrM,
    /// Exactly `fr0`, as `fmac` takes it.
    Fr0,
    /// `drn` / `drm`, written with the number of their first `fr` register.
    DrN,
    DrM,
    /// `fvn` in bits 11-8 as `nn00`, `fvm` as `00mm`: `fipr` packs both
    /// vectors into one nibble.
    FvN,
    FvM,
    Xmtrx,
}

impl Arg {
    /// How the operand is written, for listing an instruction's forms.
    pub fn spelling(self) -> String {
        match self {
            Arg::RegN => "rn".into(),
            Arg::RegM => "rm".into(),
            Arg::R0 => "r0".into(),
            Arg::Imm8 => "#imm".into(),
            Arg::IndN => "@rn".into(),
            Arg::IndM => "@rm".into(),
            Arg::IncN => "@rn+".into(),
            Arg::IncM => "@rm+".into(),
            Arg::DecN => "@-rn".into(),
            Arg::DecM => "@-rm".into(),
            Arg::R0IdxN => "@(r0,rn)".into(),
            Arg::R0IdxM => "@(r0,rm)".into(),
            Arg::DispN(_) => "@(disp,rn)".into(),
            Arg::DispM(_) => "@(disp,rm)".into(),
            Arg::GbrDisp(_) => "@(disp,gbr)".into(),
            Arg::R0Gbr => "@(r0,gbr)".into(),
            Arg::PcRel(_) => "label".into(),
            Arg::Branch8 | Arg::Branch12 => "label".into(),
            Arg::Ctl(c) => c.name().into(),
            Arg::BankM => "rN_bank".into(),
            Arg::FrN => "frn".into(),
            Arg::FrM => "frm".into(),
            Arg::Fr0 => "fr0".into(),
            Arg::DrN => "drn".into(),
            Arg::DrM => "drm".into(),
            Arg::FvN => "fvn".into(),
            Arg::FvM => "fvm".into(),
            Arg::Xmtrx => "xmtrx".into(),
        }
    }
}

pub struct Entry {
    pub name: &'static str,
    pub args: &'static [Arg],
    pub word: u16,
    /// Required [`isa`] bits; 0 for the SH-1 base set.
    pub isa: u64,
}

use Arg::*;
use Ctl::{Dbr, Fpscr, Fpul, Gbr, Mach, Macl, Pr, Sgr, Spc, Sr, Ssr, Vbr};
use isa::{DFPU, FPU, SH2, SH3, SH4, SH4A};

const fn e(name: &'static str, args: &'static [Arg], word: u16, isa: u64) -> Entry {
    Entry {
        name,
        args,
        word,
        isa,
    }
}

/// Every instruction this backend assembles, grouped by mnemonic.
///
/// The order within a mnemonic matters only where two entries could accept
/// the same operands, and none here can. Across mnemonics it does not matter.
#[rustfmt::skip]
pub static TABLE: &[Entry] = &[
    // ---- data transfer ----------------------------------------------------
    e("mov", &[Imm8, RegN], 0xe000, 0),
    e("mov", &[RegM, RegN], 0x6003, 0),

    e("mov.b", &[RegM, IndN], 0x2000, 0),
    e("mov.b", &[RegM, DecN], 0x2004, 0),
    e("mov.b", &[RegM, R0IdxN], 0x0004, 0),
    e("mov.b", &[R0, DispM(1)], 0x8000, 0),
    e("mov.b", &[R0, GbrDisp(1)], 0xc000, 0),
    e("mov.b", &[IndM, RegN], 0x6000, 0),
    e("mov.b", &[IncM, RegN], 0x6004, 0),
    e("mov.b", &[R0IdxM, RegN], 0x000c, 0),
    e("mov.b", &[DispM(1), R0], 0x8400, 0),
    e("mov.b", &[GbrDisp(1), R0], 0xc400, 0),

    e("mov.w", &[RegM, IndN], 0x2001, 0),
    e("mov.w", &[RegM, DecN], 0x2005, 0),
    e("mov.w", &[RegM, R0IdxN], 0x0005, 0),
    e("mov.w", &[R0, DispM(2)], 0x8100, 0),
    e("mov.w", &[R0, GbrDisp(2)], 0xc100, 0),
    e("mov.w", &[IndM, RegN], 0x6001, 0),
    e("mov.w", &[IncM, RegN], 0x6005, 0),
    e("mov.w", &[R0IdxM, RegN], 0x000d, 0),
    e("mov.w", &[DispM(2), R0], 0x8500, 0),
    e("mov.w", &[GbrDisp(2), R0], 0xc500, 0),
    e("mov.w", &[PcRel(2), RegN], 0x9000, 0),

    e("mov.l", &[RegM, IndN], 0x2002, 0),
    e("mov.l", &[RegM, DecN], 0x2006, 0),
    e("mov.l", &[RegM, R0IdxN], 0x0006, 0),
    e("mov.l", &[RegM, DispN(4)], 0x1000, 0),
    e("mov.l", &[R0, GbrDisp(4)], 0xc200, 0),
    e("mov.l", &[IndM, RegN], 0x6002, 0),
    e("mov.l", &[IncM, RegN], 0x6006, 0),
    e("mov.l", &[R0IdxM, RegN], 0x000e, 0),
    e("mov.l", &[DispM(4), RegN], 0x5000, 0),
    e("mov.l", &[GbrDisp(4), R0], 0xc600, 0),
    e("mov.l", &[PcRel(4), RegN], 0xd000, 0),

    e("mova", &[PcRel(4), R0], 0xc700, 0),
    e("movt", &[RegN], 0x0029, 0),
    e("swap.b", &[RegM, RegN], 0x6008, 0),
    e("swap.w", &[RegM, RegN], 0x6009, 0),
    e("xtrct", &[RegM, RegN], 0x200d, 0),
    e("movca.l", &[R0, IndN], 0x00c3, SH4),
    e("movli.l", &[IndN, R0], 0x0063, SH4A),
    e("movco.l", &[R0, IndN], 0x0073, SH4A),
    e("movua.l", &[IndN, R0], 0x40a9, SH4A),
    e("movua.l", &[IncN, R0], 0x40e9, SH4A),

    // ---- arithmetic ---------------------------------------------------------
    e("add", &[Imm8, RegN], 0x7000, 0),
    e("add", &[RegM, RegN], 0x300c, 0),
    e("addc", &[RegM, RegN], 0x300e, 0),
    e("addv", &[RegM, RegN], 0x300f, 0),
    e("sub", &[RegM, RegN], 0x3008, 0),
    e("subc", &[RegM, RegN], 0x300a, 0),
    e("subv", &[RegM, RegN], 0x300b, 0),
    e("cmp/eq", &[Imm8, R0], 0x8800, 0),
    e("cmp/eq", &[RegM, RegN], 0x3000, 0),
    e("cmp/hs", &[RegM, RegN], 0x3002, 0),
    e("cmp/ge", &[RegM, RegN], 0x3003, 0),
    e("cmp/hi", &[RegM, RegN], 0x3006, 0),
    e("cmp/gt", &[RegM, RegN], 0x3007, 0),
    e("cmp/pz", &[RegN], 0x4011, 0),
    e("cmp/pl", &[RegN], 0x4015, 0),
    e("cmp/str", &[RegM, RegN], 0x200c, 0),
    e("div0s", &[RegM, RegN], 0x2007, 0),
    e("div0u", &[], 0x0019, 0),
    e("div1", &[RegM, RegN], 0x3004, 0),
    e("dmuls.l", &[RegM, RegN], 0x300d, SH2),
    e("dmulu.l", &[RegM, RegN], 0x3005, SH2),
    e("mul.l", &[RegM, RegN], 0x0007, SH2),
    e("muls.w", &[RegM, RegN], 0x200f, 0),
    e("muls", &[RegM, RegN], 0x200f, 0),
    e("mulu.w", &[RegM, RegN], 0x200e, 0),
    e("mulu", &[RegM, RegN], 0x200e, 0),
    e("mac.w", &[IncM, IncN], 0x400f, 0),
    e("mac.l", &[IncM, IncN], 0x000f, SH2),
    e("neg", &[RegM, RegN], 0x600b, 0),
    e("negc", &[RegM, RegN], 0x600a, 0),
    e("dt", &[RegN], 0x4010, SH2),
    e("exts.b", &[RegM, RegN], 0x600e, 0),
    e("exts.w", &[RegM, RegN], 0x600f, 0),
    e("extu.b", &[RegM, RegN], 0x600c, 0),
    e("extu.w", &[RegM, RegN], 0x600d, 0),

    // ---- logic --------------------------------------------------------------
    e("and", &[Imm8, R0], 0xc900, 0),
    e("and", &[RegM, RegN], 0x2009, 0),
    e("and.b", &[Imm8, R0Gbr], 0xcd00, 0),
    e("or", &[Imm8, R0], 0xcb00, 0),
    e("or", &[RegM, RegN], 0x200b, 0),
    e("or.b", &[Imm8, R0Gbr], 0xcf00, 0),
    e("xor", &[Imm8, R0], 0xca00, 0),
    e("xor", &[RegM, RegN], 0x200a, 0),
    e("xor.b", &[Imm8, R0Gbr], 0xce00, 0),
    e("tst", &[Imm8, R0], 0xc800, 0),
    e("tst", &[RegM, RegN], 0x2008, 0),
    e("tst.b", &[Imm8, R0Gbr], 0xcc00, 0),
    e("not", &[RegM, RegN], 0x6007, 0),
    e("tas.b", &[IndN], 0x401b, 0),

    // ---- shifts -------------------------------------------------------------
    e("shal", &[RegN], 0x4020, 0),
    e("shar", &[RegN], 0x4021, 0),
    e("shll", &[RegN], 0x4000, 0),
    e("shlr", &[RegN], 0x4001, 0),
    e("shll2", &[RegN], 0x4008, 0),
    e("shlr2", &[RegN], 0x4009, 0),
    e("shll8", &[RegN], 0x4018, 0),
    e("shlr8", &[RegN], 0x4019, 0),
    e("shll16", &[RegN], 0x4028, 0),
    e("shlr16", &[RegN], 0x4029, 0),
    e("rotl", &[RegN], 0x4004, 0),
    e("rotr", &[RegN], 0x4005, 0),
    e("rotcl", &[RegN], 0x4024, 0),
    e("rotcr", &[RegN], 0x4025, 0),
    e("shad", &[RegM, RegN], 0x400c, SH3),
    e("shld", &[RegM, RegN], 0x400d, SH3),

    // ---- branches -----------------------------------------------------------
    // The conditional branches are handled before the table is consulted,
    // since they may relax; their entries are here for the words and levels.
    e("bt", &[Branch8], 0x8900, 0),
    e("bf", &[Branch8], 0x8b00, 0),
    e("bt/s", &[Branch8], 0x8d00, SH2),
    e("bt.s", &[Branch8], 0x8d00, SH2),
    e("bf/s", &[Branch8], 0x8f00, SH2),
    e("bf.s", &[Branch8], 0x8f00, SH2),
    e("bra", &[Branch12], 0xa000, 0),
    e("bsr", &[Branch12], 0xb000, 0),
    e("braf", &[RegN], 0x0023, SH2),
    e("bsrf", &[RegN], 0x0003, SH2),
    e("jmp", &[IndN], 0x402b, 0),
    e("jsr", &[IndN], 0x400b, 0),
    e("rts", &[], 0x000b, 0),
    e("rte", &[], 0x002b, 0),
    e("trapa", &[Imm8], 0xc300, 0),

    // ---- system -------------------------------------------------------------
    e("nop", &[], 0x0009, 0),
    e("sleep", &[], 0x001b, 0),
    e("clrmac", &[], 0x0028, 0),
    e("clrt", &[], 0x0008, 0),
    e("sett", &[], 0x0018, 0),
    e("clrs", &[], 0x0048, SH3),
    e("sets", &[], 0x0058, SH3),
    e("ldtlb", &[], 0x0038, SH3),
    e("pref", &[IndN], 0x0083, SH3),
    e("ocbi", &[IndN], 0x0093, SH4),
    e("ocbp", &[IndN], 0x00a3, SH4),
    e("ocbwb", &[IndN], 0x00b3, SH4),
    e("icbi", &[IndN], 0x00e3, SH4A),
    e("prefi", &[IndN], 0x00d3, SH4A),
    e("synco", &[], 0x00ab, SH4A),

    e("ldc", &[RegN, Ctl(Sr)], 0x400e, 0),
    e("ldc", &[RegN, Ctl(Gbr)], 0x401e, 0),
    e("ldc", &[RegN, Ctl(Vbr)], 0x402e, 0),
    e("ldc", &[RegN, Ctl(Ssr)], 0x403e, SH3),
    e("ldc", &[RegN, Ctl(Spc)], 0x404e, SH3),
    e("ldc", &[RegN, Ctl(Sgr)], 0x403a, SH4),
    e("ldc", &[RegN, Ctl(Dbr)], 0x40fa, SH4),
    e("ldc", &[RegN, BankM], 0x408e, SH3),
    e("ldc.l", &[IncN, Ctl(Sr)], 0x4007, 0),
    e("ldc.l", &[IncN, Ctl(Gbr)], 0x4017, 0),
    e("ldc.l", &[IncN, Ctl(Vbr)], 0x4027, 0),
    e("ldc.l", &[IncN, Ctl(Ssr)], 0x4037, SH3),
    e("ldc.l", &[IncN, Ctl(Spc)], 0x4047, SH3),
    e("ldc.l", &[IncN, Ctl(Sgr)], 0x4036, SH4),
    e("ldc.l", &[IncN, Ctl(Dbr)], 0x40f6, SH4),
    e("ldc.l", &[IncN, BankM], 0x4087, SH3),
    e("stc", &[Ctl(Sr), RegN], 0x0002, 0),
    e("stc", &[Ctl(Gbr), RegN], 0x0012, 0),
    e("stc", &[Ctl(Vbr), RegN], 0x0022, 0),
    e("stc", &[Ctl(Ssr), RegN], 0x0032, SH3),
    e("stc", &[Ctl(Spc), RegN], 0x0042, SH3),
    e("stc", &[Ctl(Sgr), RegN], 0x003a, SH4),
    e("stc", &[Ctl(Dbr), RegN], 0x00fa, SH4),
    e("stc", &[BankM, RegN], 0x0082, SH3),
    e("stc.l", &[Ctl(Sr), DecN], 0x4003, 0),
    e("stc.l", &[Ctl(Gbr), DecN], 0x4013, 0),
    e("stc.l", &[Ctl(Vbr), DecN], 0x4023, 0),
    e("stc.l", &[Ctl(Ssr), DecN], 0x4033, SH3),
    e("stc.l", &[Ctl(Spc), DecN], 0x4043, SH3),
    e("stc.l", &[Ctl(Sgr), DecN], 0x4032, SH4),
    e("stc.l", &[Ctl(Dbr), DecN], 0x40f2, SH4),
    e("stc.l", &[BankM, DecN], 0x4083, SH3),
    e("lds", &[RegN, Ctl(Mach)], 0x400a, 0),
    e("lds", &[RegN, Ctl(Macl)], 0x401a, 0),
    e("lds", &[RegN, Ctl(Pr)], 0x402a, 0),
    e("lds", &[RegN, Ctl(Fpul)], 0x405a, FPU),
    e("lds", &[RegN, Ctl(Fpscr)], 0x406a, FPU),
    e("lds.l", &[IncN, Ctl(Mach)], 0x4006, 0),
    e("lds.l", &[IncN, Ctl(Macl)], 0x4016, 0),
    e("lds.l", &[IncN, Ctl(Pr)], 0x4026, 0),
    e("lds.l", &[IncN, Ctl(Fpul)], 0x4056, FPU),
    e("lds.l", &[IncN, Ctl(Fpscr)], 0x4066, FPU),
    e("sts", &[Ctl(Mach), RegN], 0x000a, 0),
    e("sts", &[Ctl(Macl), RegN], 0x001a, 0),
    e("sts", &[Ctl(Pr), RegN], 0x002a, 0),
    e("sts", &[Ctl(Fpul), RegN], 0x005a, FPU),
    e("sts", &[Ctl(Fpscr), RegN], 0x006a, FPU),
    e("sts.l", &[Ctl(Mach), DecN], 0x4002, 0),
    e("sts.l", &[Ctl(Macl), DecN], 0x4012, 0),
    e("sts.l", &[Ctl(Pr), DecN], 0x4022, 0),
    e("sts.l", &[Ctl(Fpul), DecN], 0x4052, FPU),
    e("sts.l", &[Ctl(Fpscr), DecN], 0x4062, FPU),

    // ---- floating point -----------------------------------------------------
    // A `dr` operand is written with the number of its first `fr` register,
    // so `fadd dr2,dr4` is the same word as `fadd fr2,fr4`; which one the
    // hardware does depends on FPSCR.PR, not on the opcode.
    e("fabs", &[FrN], 0xf05d, FPU),
    e("fabs", &[DrN], 0xf05d, DFPU),
    e("fadd", &[FrM, FrN], 0xf000, FPU),
    e("fadd", &[DrM, DrN], 0xf000, DFPU),
    e("fsub", &[FrM, FrN], 0xf001, FPU),
    e("fsub", &[DrM, DrN], 0xf001, DFPU),
    e("fmul", &[FrM, FrN], 0xf002, FPU),
    e("fmul", &[DrM, DrN], 0xf002, DFPU),
    e("fdiv", &[FrM, FrN], 0xf003, FPU),
    e("fdiv", &[DrM, DrN], 0xf003, DFPU),
    e("fcmp/eq", &[FrM, FrN], 0xf004, FPU),
    e("fcmp/eq", &[DrM, DrN], 0xf004, DFPU),
    e("fcmp/gt", &[FrM, FrN], 0xf005, FPU),
    e("fcmp/gt", &[DrM, DrN], 0xf005, DFPU),
    e("fneg", &[FrN], 0xf04d, FPU),
    e("fneg", &[DrN], 0xf04d, DFPU),
    e("fsqrt", &[FrN], 0xf06d, FPU),
    e("fsqrt", &[DrN], 0xf06d, DFPU),
    e("fldi0", &[FrN], 0xf08d, FPU),
    e("fldi1", &[FrN], 0xf09d, FPU),
    e("flds", &[FrN, Ctl(Fpul)], 0xf01d, FPU),
    e("fsts", &[Ctl(Fpul), FrN], 0xf00d, FPU),
    e("float", &[Ctl(Fpul), FrN], 0xf02d, FPU),
    e("float", &[Ctl(Fpul), DrN], 0xf02d, DFPU),
    e("ftrc", &[FrN, Ctl(Fpul)], 0xf03d, FPU),
    e("ftrc", &[DrN, Ctl(Fpul)], 0xf03d, DFPU),
    e("fcnvds", &[DrN, Ctl(Fpul)], 0xf0bd, DFPU),
    e("fcnvsd", &[Ctl(Fpul), DrN], 0xf0ad, DFPU),
    e("fmac", &[Fr0, FrM, FrN], 0xf00e, FPU),
    e("fsca", &[Ctl(Fpul), DrN], 0xf0fd, DFPU),
    e("fsrra", &[FrN], 0xf07d, DFPU),
    e("fipr", &[FvM, FvN], 0xf0ed, DFPU),
    e("ftrv", &[Xmtrx, FvN], 0xf1fd, DFPU),
    e("frchg", &[], 0xfbfd, DFPU),
    e("fschg", &[], 0xf3fd, DFPU),
    e("fpchg", &[], 0xf7fd, DFPU | SH4A),

    e("fmov", &[FrM, FrN], 0xf00c, FPU),
    e("fmov", &[IndM, FrN], 0xf008, FPU),
    e("fmov", &[FrM, IndN], 0xf00a, FPU),
    e("fmov", &[IncM, FrN], 0xf009, FPU),
    e("fmov", &[FrM, DecN], 0xf00b, FPU),
    e("fmov", &[R0IdxM, FrN], 0xf006, FPU),
    e("fmov", &[FrM, R0IdxN], 0xf007, FPU),
    e("fmov", &[DrM, DrN], 0xf00c, DFPU),
    e("fmov", &[IndM, DrN], 0xf008, DFPU),
    e("fmov", &[DrM, IndN], 0xf00a, DFPU),
    e("fmov", &[IncM, DrN], 0xf009, DFPU),
    e("fmov", &[DrM, DecN], 0xf00b, DFPU),
    e("fmov", &[R0IdxM, DrN], 0xf006, DFPU),
    e("fmov", &[DrM, R0IdxN], 0xf007, DFPU),
    e("fmov.s", &[IndM, FrN], 0xf008, FPU),
    e("fmov.s", &[FrM, IndN], 0xf00a, FPU),
    e("fmov.s", &[IncM, FrN], 0xf009, FPU),
    e("fmov.s", &[FrM, DecN], 0xf00b, FPU),
    e("fmov.s", &[R0IdxM, FrN], 0xf006, FPU),
    e("fmov.s", &[FrM, R0IdxN], 0xf007, FPU),
    e("fmov.d", &[IndM, DrN], 0xf008, DFPU),
    e("fmov.d", &[DrM, IndN], 0xf00a, DFPU),
    e("fmov.d", &[IncM, DrN], 0xf009, DFPU),
    e("fmov.d", &[DrM, DecN], 0xf00b, DFPU),
    e("fmov.d", &[R0IdxM, DrN], 0xf006, DFPU),
    e("fmov.d", &[DrM, R0IdxN], 0xf007, DFPU),
];

/// The entries for `name`, in table order. Empty if it is not an instruction.
pub fn lookup(name: &str) -> impl Iterator<Item = &'static Entry> + '_ {
    TABLE.iter().filter(move |e| e.name == name)
}

pub fn exists(name: &str) -> bool {
    lookup(name).next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_two_entries_of_a_mnemonic_take_the_same_operands() {
        for (i, a) in TABLE.iter().enumerate() {
            for b in &TABLE[i + 1..] {
                assert!(
                    !(a.name == b.name && a.args == b.args),
                    "`{}` has two entries for the same operands",
                    a.name
                );
            }
        }
    }

    #[test]
    fn operand_fields_are_zero_in_the_base_word() {
        // A nonzero field bit in the table would be ORed into every use.
        for e in TABLE {
            let mut mask = 0u16;
            for a in e.args {
                mask |= match a {
                    RegN | IndN | IncN | DecN | R0IdxN | DispN(_) | FrN | DrN => 0x0f00,
                    FvN => 0x0c00,
                    RegM | IndM | IncM | DecM | R0IdxM | DispM(_) | FrM | DrM => 0x00f0,
                    BankM => 0x0070,
                    FvM => 0x0300,
                    Imm8 | GbrDisp(_) | PcRel(_) | Branch8 => 0x00ff,
                    Branch12 => 0x0fff,
                    _ => 0,
                };
                if let DispN(_) | DispM(_) = a {
                    mask |= 0x000f;
                }
            }
            assert_eq!(e.word & mask, 0, "`{}` word {:#06x}", e.name, e.word);
        }
    }
}
