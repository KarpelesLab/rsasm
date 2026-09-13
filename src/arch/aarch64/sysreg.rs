//! System registers for `mrs` and `msr`.
//!
//! A system register is really five numbers — `op0:op1:CRn:CRm:op2` — and the
//! architecture keeps adding names for combinations of them. Rather than carry
//! the whole ever-growing list, this table holds the registers ordinary code
//! touches and the generic `S<op0>_<op1>_C<n>_C<m>_<op2>` spelling reaches the
//! rest, exactly as GNU as does.

use super::operand::Operand;
use crate::arch::AsmCtx;

/// `(name, op0, op1, CRn, CRm, op2)`.
#[rustfmt::skip]
static REGS: &[(&str, u32, u32, u32, u32, u32)] = &[
    ("nzcv",         3, 3,  4, 2, 0),
    ("daif",         3, 3,  4, 2, 1),
    ("fpcr",         3, 3,  4, 4, 0),
    ("fpsr",         3, 3,  4, 4, 1),
    ("currentel",    3, 0,  4, 2, 2),
    ("spsel",        3, 0,  4, 2, 0),
    ("sp_el0",       3, 0,  4, 1, 0),
    ("tpidr_el0",    3, 3, 13, 0, 2),
    ("tpidrro_el0",  3, 3, 13, 0, 3),
    ("tpidr_el1",    3, 0, 13, 0, 4),
    ("ctr_el0",      3, 3,  0, 0, 1),
    ("dczid_el0",    3, 3,  0, 0, 7),
    ("midr_el1",     3, 0,  0, 0, 0),
    ("mpidr_el1",    3, 0,  0, 0, 5),
    ("cntfrq_el0",   3, 3, 14, 0, 0),
    ("cntvct_el0",   3, 3, 14, 0, 2),
    ("cntpct_el0",   3, 3, 14, 0, 1),
    ("elr_el1",      3, 0,  4, 0, 1),
    ("spsr_el1",     3, 0,  4, 0, 0),
    ("sctlr_el1",    3, 0,  1, 0, 0),
    ("vbar_el1",     3, 0, 12, 0, 0),
    ("esr_el1",      3, 0,  5, 2, 0),
    ("far_el1",      3, 0,  6, 0, 0),
    ("ttbr0_el1",    3, 0,  2, 0, 0),
    ("ttbr1_el1",    3, 0,  2, 0, 1),
    ("tcr_el1",      3, 0,  2, 0, 2),
    ("mair_el1",     3, 0, 10, 2, 0),
];

/// The `o0:op1:CRn:CRm:op2` bits of an `mrs`/`msr` word, already shifted into
/// place. `op0` contributes only its low bit: the two high bits are fixed by
/// the opcode.
fn pack(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    ((op0 & 1) << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5)
}

/// Parses a named system register.
pub fn by_name(name: &str) -> Option<u32> {
    if let Some((_, op0, op1, crn, crm, op2)) = REGS.iter().find(|e| e.0 == name) {
        return Some(pack(*op0, *op1, *crn, *crm, *op2));
    }
    generic(name)
}

/// The `S<op0>_<op1>_C<CRn>_C<CRm>_<op2>` escape hatch.
fn generic(name: &str) -> Option<u32> {
    let rest = name.strip_prefix('s')?;
    let mut parts = rest.split('_');
    let op0: u32 = parts.next()?.parse().ok()?;
    let op1: u32 = parts.next()?.parse().ok()?;
    let crn: u32 = parts.next()?.strip_prefix('c')?.parse().ok()?;
    let crm: u32 = parts.next()?.strip_prefix('c')?.parse().ok()?;
    let op2: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    // Only op0 2 and 3 are reachable: the opcode fixes the top two bits.
    if !(2..=3).contains(&op0) || op1 > 7 || crn > 15 || crm > 15 || op2 > 7 {
        return None;
    }
    Some(pack(op0, op1, crn, crm, op2))
}

/// Reads a system-register operand, reporting a diagnostic if it is not one.
pub fn operand(cx: &mut AsmCtx<'_>, op: &Operand<'_>) -> Option<u32> {
    let Some(n) = op.word() else {
        cx.error(op.span, "expected a system register name");
        return None;
    };
    let text = cx.name(n).to_ascii_lowercase();
    match by_name(&text) {
        Some(e) => Some(e),
        None => {
            cx.error(
                op.span,
                format!(
                    "unknown system register `{text}`; \
                     write it as `s<op0>_<op1>_c<CRn>_c<CRm>_<op2>` if it has no name here"
                ),
            );
            None
        }
    }
}

/// The `op1`/`op2` pair of a PSTATE field, which `msr` writes with an
/// immediate rather than a register.
pub fn pstate(name: &str) -> Option<(u32, u32)> {
    Some(match name {
        "spsel" => (0, 5),
        "daifset" => (3, 6),
        "daifclr" => (3, 7),
        "uao" => (0, 3),
        "pan" => (0, 4),
        "dit" => (3, 2),
        "ssbs" => (3, 1),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_and_generic_spellings_agree() {
        // TPIDRRO_EL0 is op0=3, op1=3, CRn=13, CRm=0, op2=3.
        assert_eq!(by_name("tpidrro_el0"), by_name("s3_3_c13_c0_3"));
        assert!(by_name("s3_3_c13_c0").is_none());
        assert!(by_name("s9_3_c13_c0_3").is_none());
        assert!(by_name("nosuchreg").is_none());
    }
}
