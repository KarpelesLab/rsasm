//! x86 register names and properties.

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegClass {
    /// General purpose, addressed through ModRM/SIB.
    Gpr,
    /// `ah`/`ch`/`dh`/`bh`: encoded as GPR numbers 4-7 but unusable with REX.
    GprHigh,
    Segment,
    /// The `rip` pseudo-register, only valid as a memory base.
    Rip,
    Xmm,
    Mmx,
    Control,
    Debug,
    /// x87 stack registers.
    St,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Reg {
    pub class: RegClass,
    /// Encoding number, 0-15.
    pub num: u8,
    /// Width in bytes.
    pub size: u8,
    /// True for `spl`/`bpl`/`sil`/`dil`, which only exist when a REX prefix is
    /// present. Without REX those encodings mean `ah`/`ch`/`dh`/`bh`.
    pub rex_required: bool,
}

impl Reg {
    pub fn is_gpr(&self) -> bool {
        matches!(self.class, RegClass::Gpr | RegClass::GprHigh)
    }

    /// True if the register number needs the extension bit in REX.
    pub fn needs_rex_ext(&self) -> bool {
        self.num >= 8
    }

    /// x86 forbids `rsp`/`esp` as a SIB index.
    pub fn valid_index(&self) -> bool {
        self.class == RegClass::Gpr && !(self.num == 4 && self.size >= 4)
    }
}

struct Entry {
    name: &'static str,
    class: RegClass,
    num: u8,
    size: u8,
    rex_required: bool,
}

/// Every register this backend understands, keyed by lowercase name.
///
/// Laid out one line per group so it reads the way the manuals tabulate it.
#[rustfmt::skip]
static REGS: &[Entry] = &{
    // Built as a literal list rather than generated, so the table reads the
    // way the manuals do.
    const fn e(name: &'static str, class: RegClass, num: u8, size: u8, rex_required: bool) -> Entry {
        Entry { name, class, num, size, rex_required }
    }
    use RegClass::*;
    [
        // 64-bit
        e("rax", Gpr, 0, 8, false), e("rcx", Gpr, 1, 8, false),
        e("rdx", Gpr, 2, 8, false), e("rbx", Gpr, 3, 8, false),
        e("rsp", Gpr, 4, 8, false), e("rbp", Gpr, 5, 8, false),
        e("rsi", Gpr, 6, 8, false), e("rdi", Gpr, 7, 8, false),
        e("r8", Gpr, 8, 8, false), e("r9", Gpr, 9, 8, false),
        e("r10", Gpr, 10, 8, false), e("r11", Gpr, 11, 8, false),
        e("r12", Gpr, 12, 8, false), e("r13", Gpr, 13, 8, false),
        e("r14", Gpr, 14, 8, false), e("r15", Gpr, 15, 8, false),
        // 32-bit
        e("eax", Gpr, 0, 4, false), e("ecx", Gpr, 1, 4, false),
        e("edx", Gpr, 2, 4, false), e("ebx", Gpr, 3, 4, false),
        e("esp", Gpr, 4, 4, false), e("ebp", Gpr, 5, 4, false),
        e("esi", Gpr, 6, 4, false), e("edi", Gpr, 7, 4, false),
        e("r8d", Gpr, 8, 4, false), e("r9d", Gpr, 9, 4, false),
        e("r10d", Gpr, 10, 4, false), e("r11d", Gpr, 11, 4, false),
        e("r12d", Gpr, 12, 4, false), e("r13d", Gpr, 13, 4, false),
        e("r14d", Gpr, 14, 4, false), e("r15d", Gpr, 15, 4, false),
        // 16-bit
        e("ax", Gpr, 0, 2, false), e("cx", Gpr, 1, 2, false),
        e("dx", Gpr, 2, 2, false), e("bx", Gpr, 3, 2, false),
        e("sp", Gpr, 4, 2, false), e("bp", Gpr, 5, 2, false),
        e("si", Gpr, 6, 2, false), e("di", Gpr, 7, 2, false),
        e("r8w", Gpr, 8, 2, false), e("r9w", Gpr, 9, 2, false),
        e("r10w", Gpr, 10, 2, false), e("r11w", Gpr, 11, 2, false),
        e("r12w", Gpr, 12, 2, false), e("r13w", Gpr, 13, 2, false),
        e("r14w", Gpr, 14, 2, false), e("r15w", Gpr, 15, 2, false),
        // 8-bit, low
        e("al", Gpr, 0, 1, false), e("cl", Gpr, 1, 1, false),
        e("dl", Gpr, 2, 1, false), e("bl", Gpr, 3, 1, false),
        // These four require REX; without it the same encodings mean ah..bh.
        e("spl", Gpr, 4, 1, true), e("bpl", Gpr, 5, 1, true),
        e("sil", Gpr, 6, 1, true), e("dil", Gpr, 7, 1, true),
        e("r8b", Gpr, 8, 1, false), e("r9b", Gpr, 9, 1, false),
        e("r10b", Gpr, 10, 1, false), e("r11b", Gpr, 11, 1, false),
        e("r12b", Gpr, 12, 1, false), e("r13b", Gpr, 13, 1, false),
        e("r14b", Gpr, 14, 1, false), e("r15b", Gpr, 15, 1, false),
        // 8-bit, high halves of the legacy registers
        e("ah", GprHigh, 4, 1, false), e("ch", GprHigh, 5, 1, false),
        e("dh", GprHigh, 6, 1, false), e("bh", GprHigh, 7, 1, false),
        // Segments
        e("es", Segment, 0, 2, false), e("cs", Segment, 1, 2, false),
        e("ss", Segment, 2, 2, false), e("ds", Segment, 3, 2, false),
        e("fs", Segment, 4, 2, false), e("gs", Segment, 5, 2, false),
        // Instruction pointer, usable only as a memory base.
        e("rip", Rip, 0, 8, false), e("eip", Rip, 0, 4, false),
        // SSE
        e("xmm0", Xmm, 0, 16, false), e("xmm1", Xmm, 1, 16, false),
        e("xmm2", Xmm, 2, 16, false), e("xmm3", Xmm, 3, 16, false),
        e("xmm4", Xmm, 4, 16, false), e("xmm5", Xmm, 5, 16, false),
        e("xmm6", Xmm, 6, 16, false), e("xmm7", Xmm, 7, 16, false),
        e("xmm8", Xmm, 8, 16, false), e("xmm9", Xmm, 9, 16, false),
        e("xmm10", Xmm, 10, 16, false), e("xmm11", Xmm, 11, 16, false),
        e("xmm12", Xmm, 12, 16, false), e("xmm13", Xmm, 13, 16, false),
        e("xmm14", Xmm, 14, 16, false), e("xmm15", Xmm, 15, 16, false),
    ]
};

fn index() -> &'static HashMap<&'static str, Reg> {
    static INDEX: OnceLock<HashMap<&'static str, Reg>> = OnceLock::new();
    INDEX.get_or_init(|| {
        REGS.iter()
            .map(|e| {
                (
                    e.name,
                    Reg {
                        class: e.class,
                        num: e.num,
                        size: e.size,
                        rex_required: e.rex_required,
                    },
                )
            })
            .collect()
    })
}

/// Looks up a register by its lowercase name.
pub fn lookup(name: &str) -> Option<Reg> {
    index().get(name).copied()
}

/// The canonical name of a register, for diagnostics.
pub fn name_of(r: Reg) -> &'static str {
    REGS.iter()
        .find(|e| e.class == r.class && e.num == r.num && e.size == r.size)
        .map(|e| e.name)
        .unwrap_or("?")
}

/// True if `name` is a register in this architecture.
pub fn is_register(name: &str) -> bool {
    lookup(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_by_size() {
        assert_eq!(
            lookup("rax").unwrap(),
            Reg {
                class: RegClass::Gpr,
                num: 0,
                size: 8,
                rex_required: false
            }
        );
        assert_eq!(lookup("eax").unwrap().size, 4);
        assert_eq!(lookup("ax").unwrap().size, 2);
        assert_eq!(lookup("al").unwrap().size, 1);
        assert_eq!(lookup("r15b").unwrap().num, 15);
    }

    #[test]
    fn high_byte_registers_are_distinct() {
        let ah = lookup("ah").unwrap();
        assert_eq!(ah.class, RegClass::GprHigh);
        assert_eq!(ah.num, 4);
        // spl shares ah's number but is a normal GPR needing REX.
        let spl = lookup("spl").unwrap();
        assert_eq!(spl.class, RegClass::Gpr);
        assert_eq!(spl.num, 4);
        assert!(spl.rex_required);
    }

    #[test]
    fn rsp_cannot_be_an_index() {
        assert!(!lookup("rsp").unwrap().valid_index());
        assert!(lookup("rbp").unwrap().valid_index());
        assert!(lookup("r12").unwrap().valid_index());
    }

    #[test]
    fn names_round_trip() {
        for n in ["rax", "r13d", "sil", "ah", "xmm7", "gs"] {
            assert_eq!(name_of(lookup(n).unwrap()), n);
        }
    }
}
