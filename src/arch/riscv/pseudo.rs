//! Pseudo-instructions.
//!
//! Most real RISC-V assembly is written in these: the base ISA has no move,
//! no negate and no branch-against-zero, because each is an existing
//! instruction with `x0` in one operand. They are expanded here, before the
//! instruction table is consulted, and the result goes through the same
//! compression step as anything else — which is why `mv a0, a1` comes out as
//! two bytes.

use super::asm::Asm;
use super::encode;
use super::matint;
use super::operand::Operands;
use super::reg::{self, Reg};
use super::reloc;

// Base words the expansions build on.
const ADDI: u32 = 0x0000_0013;
const ADDIW: u32 = 0x0000_001b;
const SLTI_U: u32 = 0x0000_3013;
const XORI: u32 = 0x0000_4013;
const SLLI: u32 = 0x0000_1013;
const SRLI: u32 = 0x0000_5013;
const SLT: u32 = 0x0000_2033;
const SLTU: u32 = 0x0000_3033;
const SUB: u32 = 0x4000_0033;
const SUBW: u32 = 0x4000_003b;
const BEQ: u32 = 0x0000_0063;
const BNE: u32 = 0x0000_1063;
const BLT: u32 = 0x0000_4063;
const BGE: u32 = 0x0000_5063;
const BLTU: u32 = 0x0000_6063;
const BGEU: u32 = 0x0000_7063;
const JALR: u32 = 0x0000_0067;
const AUIPC: u32 = 0x0000_0017;
const LUI: u32 = 0x0000_0037;
const CSRRW: u32 = 0x0000_1073;
const CSRRS: u32 = 0x0000_2073;
const CSRRC: u32 = 0x0000_3073;
const CSRRWI: u32 = 0x0000_5073;
const CSRRSI: u32 = 0x0000_6073;
const CSRRCI: u32 = 0x0000_7073;
const FSGNJ_S: u32 = 0x2000_0053;
const FSGNJN_S: u32 = 0x2000_1053;
const FSGNJX_S: u32 = 0x2000_2053;
const FSGNJ_D: u32 = 0x2200_0053;
const FSGNJN_D: u32 = 0x2200_1053;
const FSGNJX_D: u32 = 0x2200_2053;

pub enum Handled {
    /// Not a pseudo-instruction; try the table.
    No,
    Done,
    Failed,
}

/// Which expansion a mnemonic names, and the pieces that differ between the
/// members of a family.
#[derive(Copy, Clone)]
enum P {
    Nop,
    Ret,
    /// `op rd, rs, imm` with a fixed immediate.
    RegImm(u32, i64),
    /// `op rd, x0, rs`
    ZeroThenReg(u32),
    /// `op rd, rs, x0`
    RegThenZero(u32),
    /// A branch with `x0` as the other operand; the flag says which side the
    /// written register goes on, since `blez a, t` is `bge x0, a, t`.
    BranchZero(u32, bool),
    /// A branch whose two registers are written the other way round.
    BranchSwap(u32),
    Jump,
    JumpReg,
    /// `call` and, when the flag is set, `tail`, which links into `x0` and
    /// scratches `t1` instead of `ra`.
    Call(bool),
    Li,
    LoadAddress,
    /// `fmv`, `fneg` and `fabs`, all of which are a sign-injection with the
    /// source used twice.
    FloatSign(u32),
    /// `csrr rd, csr`
    CsrRead,
    /// `csrw csr, rs` and friends.
    CsrWrite(u32),
    /// `csrwi csr, imm` and friends.
    CsrWriteImm(u32),
    /// `rdcycle rd` and friends: a read of one fixed counter.
    ReadCounter(u32),
    /// RV64-only spellings, which are worth their own diagnostic.
    Rv64(&'static P),
}

fn classify(name: &str) -> Option<P> {
    Some(match name {
        "nop" => P::Nop,
        "ret" => P::Ret,
        "mv" => P::RegImm(ADDI, 0),
        "not" => P::RegImm(XORI, -1),
        "seqz" => P::RegImm(SLTI_U, 1),
        "sext.w" => P::Rv64(&P::RegImm(ADDIW, 0)),
        "neg" => P::ZeroThenReg(SUB),
        "negw" => P::Rv64(&P::ZeroThenReg(SUBW)),
        "snez" => P::ZeroThenReg(SLTU),
        "sgtz" => P::ZeroThenReg(SLT),
        "sltz" => P::RegThenZero(SLT),
        "beqz" => P::BranchZero(BEQ, true),
        "bnez" => P::BranchZero(BNE, true),
        "bgez" => P::BranchZero(BGE, true),
        "bltz" => P::BranchZero(BLT, true),
        "blez" => P::BranchZero(BGE, false),
        "bgtz" => P::BranchZero(BLT, false),
        "bgt" => P::BranchSwap(BLT),
        "ble" => P::BranchSwap(BGE),
        "bgtu" => P::BranchSwap(BLTU),
        "bleu" => P::BranchSwap(BGEU),
        "j" => P::Jump,
        "jr" => P::JumpReg,
        "call" => P::Call(false),
        "tail" => P::Call(true),
        "li" => P::Li,
        "la" | "lla" => P::LoadAddress,
        "fmv.s" => P::FloatSign(FSGNJ_S),
        "fneg.s" => P::FloatSign(FSGNJN_S),
        "fabs.s" => P::FloatSign(FSGNJX_S),
        "fmv.d" => P::FloatSign(FSGNJ_D),
        "fneg.d" => P::FloatSign(FSGNJN_D),
        "fabs.d" => P::FloatSign(FSGNJX_D),
        "csrr" => P::CsrRead,
        "csrw" => P::CsrWrite(CSRRW),
        "csrs" => P::CsrWrite(CSRRS),
        "csrc" => P::CsrWrite(CSRRC),
        "csrwi" => P::CsrWriteImm(CSRRWI),
        "csrsi" => P::CsrWriteImm(CSRRSI),
        "csrci" => P::CsrWriteImm(CSRRCI),
        "rdcycle" => P::ReadCounter(0xc00),
        "rdtime" => P::ReadCounter(0xc01),
        "rdinstret" => P::ReadCounter(0xc02),
        _ => return None,
    })
}

pub fn expand(a: &mut Asm<'_, '_>, name: &str, ops: &Operands<'_>) -> Handled {
    let Some(p) = classify(name) else {
        return Handled::No;
    };
    match emit(a, p, name, ops) {
        Some(()) => Handled::Done,
        None => Handled::Failed,
    }
}

fn emit(a: &mut Asm<'_, '_>, p: P, name: &str, ops: &Operands<'_>) -> Option<()> {
    match p {
        P::Rv64(inner) => {
            if !a.rv64() {
                a.error(
                    a.span,
                    format!("`{name}` is an RV64 instruction, but the target is RV32"),
                );
                return None;
            }
            return emit(a, *inner, name, ops);
        }
        P::Nop => {
            ops.arity(a.cx, name, &[0])?;
            a.i_const(ADDI, reg::ZERO, reg::ZERO, 0);
        }
        P::Ret => {
            ops.arity(a.cx, name, &[0])?;
            a.i_const(JALR, reg::ZERO, reg::RA, 0);
        }
        P::RegImm(base, imm) => {
            ops.arity(a.cx, name, &[2])?;
            let (rd, rs) = (ops.xreg(a.cx, 0)?, ops.xreg(a.cx, 1)?);
            a.i_const(base, rd, rs, imm);
        }
        P::ZeroThenReg(base) => {
            ops.arity(a.cx, name, &[2])?;
            let (rd, rs) = (ops.xreg(a.cx, 0)?, ops.xreg(a.cx, 1)?);
            a.r_type(base, rd, reg::ZERO, rs);
        }
        P::RegThenZero(base) => {
            ops.arity(a.cx, name, &[2])?;
            let (rd, rs) = (ops.xreg(a.cx, 0)?, ops.xreg(a.cx, 1)?);
            a.r_type(base, rd, rs, reg::ZERO);
        }
        P::BranchZero(base, reg_first) => {
            ops.arity(a.cx, name, &[2])?;
            let rs = ops.xreg(a.cx, 0)?;
            let target = ops.imm(a.cx, 1)?;
            let (rs1, rs2) = if reg_first {
                (rs, reg::ZERO)
            } else {
                (reg::ZERO, rs)
            };
            a.branch(base, rs1, rs2, &target)?;
        }
        P::BranchSwap(base) => {
            ops.arity(a.cx, name, &[3])?;
            let (rs, rt) = (ops.xreg(a.cx, 0)?, ops.xreg(a.cx, 1)?);
            let target = ops.imm(a.cx, 2)?;
            a.branch(base, rt, rs, &target)?;
        }
        P::Jump => {
            ops.arity(a.cx, name, &[1])?;
            let target = ops.imm(a.cx, 0)?;
            a.jal(reg::ZERO, &target)?;
        }
        P::JumpReg => {
            ops.arity(a.cx, name, &[1])?;
            let rs = ops.xreg(a.cx, 0)?;
            a.i_const(JALR, reg::ZERO, rs, 0);
        }
        P::Call(tail) => {
            let (link, target) = if tail {
                ops.arity(a.cx, name, &[1])?;
                (reg::T1, ops.imm(a.cx, 0)?)
            } else {
                ops.arity(a.cx, name, &[1, 2])?;
                if ops.len() == 2 {
                    (ops.xreg(a.cx, 0)?, ops.imm(a.cx, 1)?)
                } else {
                    (reg::RA, ops.imm(a.cx, 0)?)
                }
            };
            // The pair is patched as one field, because the linker's
            // `R_RISCV_CALL` covers both halves as well.
            let auipc = encode::rd(AUIPC, link.bits());
            let jump = encode::rs1(
                encode::rd(JALR, if tail { 0 } else { link.bits() }),
                link.bits(),
            );
            a.auipc_pair(auipc, jump, &target, encode::kind_pair(reloc::CALL));
        }
        P::Li => {
            ops.arity(a.cx, name, &[2])?;
            let rd = ops.xreg(a.cx, 0)?;
            let imm = ops.imm(a.cx, 1)?;
            // `li rd, %lo(sym)` is accepted, and is simply an add from zero.
            if imm.modifier.is_some() {
                return a.i_expr(ADDI, rd, reg::ZERO, &imm);
            }
            let Some(v) = a.cx.constant(imm.expr) else {
                a.error(imm.span, "`li` needs a value known at assembly time");
                return None;
            };
            let v = if a.rv64() {
                v
            } else {
                // On RV32 the constant is 32 bits, written either way round.
                if !(-(1i64 << 31)..(1i64 << 32)).contains(&v) {
                    a.error(imm.span, format!("value {v} does not fit in 32 bits"));
                    return None;
                }
                v as i32 as i64
            };
            load_immediate(a, rd, v);
        }
        P::LoadAddress => {
            ops.arity(a.cx, name, &[2])?;
            let rd = ops.xreg(a.cx, 0)?;
            let target = ops.imm(a.cx, 1)?;
            let auipc = encode::rd(AUIPC, rd.bits());
            let addi = encode::rs1(encode::rd(ADDI, rd.bits()), rd.bits());
            a.auipc_pair(auipc, addi, &target, encode::kind_pair(reloc::PCREL_HI20));
        }
        P::FloatSign(base) => {
            ops.arity(a.cx, name, &[2])?;
            let (rd, rs) = (ops.freg(a.cx, 0)?, ops.freg(a.cx, 1)?);
            let w = encode::rs2(
                encode::rs1(encode::rd(base, rd.bits()), rs.bits()),
                rs.bits(),
            );
            a.emit(w);
        }
        P::CsrRead => {
            ops.arity(a.cx, name, &[2])?;
            let rd = ops.xreg(a.cx, 0)?;
            let csr = a.csr(ops, 1)?;
            a.emit(encode::rd(CSRRS, rd.bits()) | (csr << 20));
        }
        P::CsrWrite(base) => {
            ops.arity(a.cx, name, &[2])?;
            let csr = a.csr(ops, 0)?;
            let rs = ops.xreg(a.cx, 1)?;
            a.emit(encode::rs1(base, rs.bits()) | (csr << 20));
        }
        P::CsrWriteImm(base) => {
            ops.arity(a.cx, name, &[2])?;
            let csr = a.csr(ops, 0)?;
            let imm = ops.imm(a.cx, 1)?;
            let v = a.constant(&imm, 0, 31, "a CSR immediate")?;
            a.emit(encode::rs1(base, v as u32) | (csr << 20));
        }
        P::ReadCounter(csr) => {
            ops.arity(a.cx, name, &[1])?;
            let rd = ops.xreg(a.cx, 0)?;
            a.emit(encode::rd(CSRRS, rd.bits()) | (csr << 20));
        }
    }
    Some(())
}

/// Emits the sequence that puts `v` in `rd`.
fn load_immediate(a: &mut Asm<'_, '_>, rd: Reg, v: i64) {
    let mut src = reg::ZERO;
    for op in matint::generate(v, a.xlen) {
        match op {
            matint::Op::Lui(imm) => {
                let w = encode::rd(LUI, rd.bits());
                a.emit(encode::u_imm(w as u64, imm) as u32);
            }
            matint::Op::Addi(imm) => a.i_const(ADDI, rd, src, imm),
            matint::Op::Addiw(imm) => a.i_const(ADDIW, rd, src, imm),
            matint::Op::Slli(n) => a.i_const(SLLI, rd, src, n as i64),
            matint::Op::Srli(n) => a.i_const(SRLI, rd, src, n as i64),
            matint::Op::Not => a.i_const(XORI, rd, src, -1),
        }
        // Only the first step reads `x0`; the rest build on what is there.
        src = rd;
    }
}
