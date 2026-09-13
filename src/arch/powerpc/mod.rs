//! PowerPC, 32- and 64-bit, big and little endian. `EM_PPC` / `EM_PPC64`.
//!
//! Three targets share one backend, differing only in pointer width and byte
//! order: `powerpc` (32-bit big endian), `powerpc64` (64-bit big endian) and
//! `powerpc64le`. The instruction encodings are identical in all three — a
//! PowerPC instruction word is the same 32 bits whichever way round it is
//! written to memory — so the only thing byte order changes is [`Endian`], and
//! everything the core writes goes through that.
//!
//! Two things about PowerPC assembly shape the code here. First, register
//! operands are conventionally bare numbers: nothing in `add 3, 4, 5` says
//! which `3` is a register, so operands are parsed without classification and
//! read as whatever field the instruction form asks for (see
//! [`operand`]). Second, a large fraction of real PowerPC assembly is written
//! in extended mnemonics — `li`, `mr`, `slwi`, `beq` — that are aliases for
//! awkward base instructions. Those are table entries in their own right
//! rather than a rewriting pass, so a bad operand is reported against the
//! mnemonic the programmer actually wrote.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, Endian, InsnRequest, Syntax};
use crate::lexer::Punct;
use crate::section::Variant;

pub const NAMES: &[&str] = &["powerpc", "powerpc64", "powerpc64le"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let target = match name {
        "powerpc" | "ppc" | "powerpc32" | "ppc32" => Target::Ppc32,
        "powerpc64" | "ppc64" => Target::Ppc64,
        "powerpc64le" | "ppc64le" | "powerpcle" => Target::Ppc64Le,
        _ => return None,
    };
    Some(Box::new(PowerPc { target }))
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Target {
    Ppc32,
    Ppc64,
    Ppc64Le,
}

pub struct PowerPc {
    target: Target,
}

impl PowerPc {
    fn bits(&self) -> u8 {
        match self.target {
            Target::Ppc32 => 32,
            _ => 64,
        }
    }
}

impl Architecture for PowerPc {
    fn name(&self) -> &'static str {
        match self.target {
            Target::Ppc32 => "powerpc",
            Target::Ppc64 => "powerpc64",
            Target::Ppc64Le => "powerpc64le",
        }
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["ppc", "ppc32", "ppc64", "ppc64le", "powerpc32", "powerpcle"]
    }

    fn endian(&self) -> Endian {
        match self.target {
            Target::Ppc64Le => Endian::Little,
            _ => Endian::Big,
        }
    }

    fn pointer_bytes(&self, state: &ArchState) -> u8 {
        state.bits / 8
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: self.bits(),
            syntax: Syntax::Att,
            features: 0,
            intel_register_prefix: false,
        }
    }

    /// PowerPC has one operand syntax. Refusing Intel here keeps an
    /// `.intel_syntax` left over from an x86 section from carrying across a
    /// `.arch` switch.
    fn supports_syntax(&self, syntax: Syntax) -> bool {
        syntax == Syntax::Att
    }

    fn elf_machine(&self) -> u16 {
        match self.target {
            Target::Ppc32 => 20, // EM_PPC
            _ => 21,             // EM_PPC64
        }
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        reloc::data(size, pcrel, self.bits() == 64)
    }

    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        encode::nop_bytes(self.endian(), len as usize)
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mnemonic = cx.name(req.mnemonic).to_ascii_lowercase();
        let Some(resolved) = insn::lookup(&mnemonic) else {
            cx.error(
                req.mnemonic_span,
                format!("unknown instruction `{mnemonic}`"),
            );
            return None;
        };

        // `beq+`/`bne-` are static branch hints. The lexer splits the sign off
        // the mnemonic, where it would otherwise be read as a unary plus on
        // the first operand and silently ignored.
        let cur = req.cursor();
        let head = cur.peek();
        if !head.preceded_by_space
            && (head.is_punct(Punct::Plus) || head.is_punct(Punct::Minus))
            && mnemonic.starts_with('b')
        {
            cx.error(
                req.mnemonic_span.to(head.span),
                "static branch prediction hints (`+`/`-`) are not supported",
            );
            return None;
        }

        if resolved.def.flags & insn::P64 != 0 && cx.state.bits < 64 {
            cx.error(
                req.mnemonic_span,
                format!("`{mnemonic}` is a 64-bit instruction, but this is 32-bit code"),
            );
            return None;
        }

        let ops = operand::parse_list(cx, &cur)?;
        let variant = encode::Encoder::new(cx, self.endian()).encode(&resolved, &ops, req.span)?;
        Some(vec![variant])
    }
}

/// True if `name` is a register in this architecture.
pub fn is_register(name: &str) -> bool {
    reg::is_register(name)
}
