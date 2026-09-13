//! MIPS, 32- and 64-bit, big and little endian. `EM_MIPS`.
//!
//! Four targets share one backend, differing only in byte order and register
//! width: `mips` and `mipsel` are 32-bit, `mips64` and `mips64el` 64-bit. The
//! instruction words are identical; only how they are laid down in memory and
//! which doubleword instructions are legal change.
//!
//! **Delay slots are the programmer's problem.** GNU as defaults to
//! `.set reorder`, in which the assembler may move an instruction into the
//! slot after a branch or insert a `nop` there. This backend behaves as
//! `.set noreorder` always: it emits exactly the instructions written, in the
//! order written, and never invents a `nop`. Multi-instruction *macros* such
//! as `li` and `la` are still expanded, since almost no real source avoids
//! them.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod pseudo;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::section::Variant;
use encode::Args;
use operand::{Operand, OperandParser};

pub const NAMES: &[&str] = &["mips", "mipsel", "mips64", "mips64el"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let (canonical, endian, bits) = match name {
        "mips" | "mips32" => ("mips", Endian::Big, 32),
        "mipsel" | "mips32el" | "mipsle" => ("mipsel", Endian::Little, 32),
        "mips64" => ("mips64", Endian::Big, 64),
        "mips64el" | "mips64le" => ("mips64el", Endian::Little, 64),
        _ => return None,
    };
    Some(Box::new(Mips {
        name: canonical,
        endian,
        bits,
    }))
}

pub struct Mips {
    name: &'static str,
    endian: Endian,
    bits: u8,
}

impl Architecture for Mips {
    fn name(&self) -> &'static str {
        self.name
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["mips32", "mips32el", "mipsle", "mips64le"]
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        self.bits / 8
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: self.bits,
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
        }
    }

    fn supports_syntax(&self, syntax: Syntax) -> bool {
        // MIPS assembly has only ever had one operand order.
        syntax == Syntax::Att
    }

    fn elf_machine(&self) -> u16 {
        8 // EM_MIPS
    }

    fn word_bytes(&self) -> u8 {
        4
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        if pcrel {
            reloc::pcrel(size)
        } else {
            reloc::abs(size)
        }
    }

    /// MIPS `nop` is `sll $zero, $zero, 0`, whose encoding is the all-zero
    /// word. Zero fill therefore *is* nop fill here, which is why this looks
    /// like the unimplemented default and is not.
    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        vec![0; len as usize]
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(req.mnemonic).to_ascii_lowercase();

        let cur = req.cursor();
        let pieces = cur.split_commas();
        let mut ops: Vec<Operand> = Vec::with_capacity(pieces.len());
        for piece in &pieces {
            let mut p = OperandParser { cx };
            ops.push(p.parse_all(piece, req.span)?);
        }

        let args = Args {
            mnemonic: &mnemonic,
            ops: &ops,
            span: req.span,
        };

        // Macros are tried first: `b` and `move` are not real opcodes, so
        // there is nothing in the table for them to shadow.
        if pseudo::is_pseudo(&mnemonic) {
            return pseudo::expand(cx, &mnemonic, &args, self.endian, self.bits == 64)
                .map(|v| vec![v]);
        }

        let Some(def) = insn::lookup(&mnemonic) else {
            cx.error(
                req.mnemonic_span,
                format!("unknown instruction `{mnemonic}`"),
            );
            return None;
        };
        // Every MIPS instruction is one word wide, so there is never more than
        // one candidate for the layout pass to choose between.
        encode::encode(cx, &def, &args, self.endian, self.bits == 64).map(|v| vec![v])
    }
}
