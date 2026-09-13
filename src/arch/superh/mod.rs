//! Hitachi/Renesas SuperH, big-endian (`sh`) and little-endian (`shl`). `EM_SH`.
//!
//! Every instruction is one 16-bit word; the two targets differ only in the
//! order its two bytes are laid down. The operand syntax is GNU as's: bare
//! register names, `#` immediates, `@`-prefixed memory operands, and `!` for
//! comments (with `#` a comment only at the start of a line, since it is the
//! immediate prefix everywhere else).
//!
//! The pieces: [`reg`] names the registers, [`operand`] parses the addressing
//! modes, [`insn`] is the opcode table, [`encode`] matches operands against it
//! and fills in the fields, and [`pcrel`] handles branches and PC-relative
//! loads, whose displacement is measured from the instruction plus four.
//!
//! `sh` and `shl` accept the whole SH-1 to SH-4A instruction set with the FPU,
//! which is what GNU as does by default. The aliases `sh1`, `sh2`, `sh2e`,
//! `sh3`, `sh3e`, `sh4` and `sh4a` select a big-endian `sh` restricted to that
//! CPU's instructions, so `.arch sh2` rejects an FPU instruction. SH-2A's
//! 32-bit instructions and the SH-DSP extensions are not assembled.

pub mod encode;
pub mod insn;
pub mod operand;
pub mod pcrel;
pub mod reg;
pub mod reloc;

use crate::arch::{ArchState, Architecture, AsmCtx, CommentSyntax, Endian, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::lexer::{Punct, TokKind};
use crate::section::Variant;
use insn::isa;
use operand::OperandParser;

pub const NAMES: &[&str] = &["sh", "shl"];

pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    use isa::{DFPU, FPU, SH2, SH3, SH4};
    let (canonical, endian, features) = match name {
        "sh" | "superh" => ("sh", Endian::Big, isa::ALL),
        "shl" => ("shl", Endian::Little, isa::ALL),
        "sh1" => ("sh", Endian::Big, 0),
        "sh2" => ("sh", Endian::Big, SH2),
        "sh2e" => ("sh", Endian::Big, SH2 | FPU),
        "sh3" => ("sh", Endian::Big, SH2 | SH3),
        "sh3e" => ("sh", Endian::Big, SH2 | SH3 | FPU),
        "sh4" => ("sh", Endian::Big, SH2 | SH3 | SH4 | FPU | DFPU),
        "sh4a" => ("sh", Endian::Big, isa::ALL),
        _ => return None,
    };
    Some(Box::new(SuperH {
        name: canonical,
        endian,
        features,
    }))
}

pub struct SuperH {
    name: &'static str,
    endian: Endian,
    /// The [`insn::isa`] bits this target accepts.
    features: u64,
}

impl Architecture for SuperH {
    fn name(&self) -> &'static str {
        self.name
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["superh", "sh1", "sh2", "sh2e", "sh3", "sh3e", "sh4", "sh4a"]
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn pointer_bytes(&self, _state: &ArchState) -> u8 {
        4
    }

    fn initial_state(&self) -> ArchState {
        ArchState {
            bits: 32,
            syntax: Syntax::Att,
            features: self.features,
            intel_register_prefix: false,
            used: 0,
        }
    }

    /// There is only the one operand syntax.
    fn supports_syntax(&self, syntax: Syntax) -> bool {
        syntax == Syntax::Att
    }

    /// `EM_SH`, as `sh-elf-readelf -h` reports for both byte orders.
    fn elf_machine(&self) -> u16 {
        42
    }

    fn align_is_log2(&self) -> bool {
        true
    }

    fn pads_section_tail(&self, flags: &crate::section::SectionFlags) -> bool {
        flags.exec
    }

    /// `sh-elf-as` writes every addend into the field and zero into the
    /// entry, except for `R_SH_DIR16`, the one data relocation BFD does not
    /// mark `partial_inplace`.
    fn addend_in_field(&self, reloc: u32, _rela: bool) -> bool {
        reloc != reloc::DIR16
    }

    /// GNU as for SH comments with `!` anywhere, and with `#` only at the
    /// start of a line, where it cannot be confused with an immediate.
    /// `//` is not a comment: `mov r1,r2 // x` is an error there.
    fn comments(&self) -> CommentSyntax {
        CommentSyntax {
            anywhere: &["!"],
            line_start: &["#"],
        }
    }

    /// `.word` is 16 bits, matching the instruction width.
    fn word_bytes(&self) -> u8 {
        2
    }

    /// One byte, although SH instructions must sit on even addresses: GNU as
    /// does not align code for you. `.byte 1` followed by `nop` puts the
    /// `nop` at offset 1 (checked against `sh-elf-as`), and so does rsasm.
    fn align_unit(&self) -> u64 {
        1
    }

    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32> {
        reloc::data(size, pcrel)
    }

    fn modifier_reloc(&self, name: &str, size: u8, _pcrel: bool) -> Option<u32> {
        reloc::modifier(name, size)
    }

    /// `nop` is `0009`. An odd pad gets a zero byte first, which is what
    /// GNU as's SH alignment handler writes, so the `nop`s after it land on
    /// the same boundaries.
    fn nop_fill(&self, _state: &ArchState, len: u64) -> Vec<u8> {
        let len = len as usize;
        let mut out = Vec::with_capacity(len);
        if len % 2 == 1 {
            out.push(0);
        }
        while out.len() < len {
            out.extend_from_slice(&self.endian.bytes(0x0009, 2));
        }
        out
    }

    fn assemble(&self, cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>) -> Option<Vec<Variant>> {
        let mut cur = req.cursor();
        let mnemonic = mnemonic(cx, req, &mut cur)?;
        let entries: Vec<&'static insn::Entry> = insn::lookup(&mnemonic).collect();
        if entries.is_empty() {
            cx.error(
                req.mnemonic_span,
                format!("unknown instruction `{mnemonic}`"),
            );
            return None;
        }
        let ops = OperandParser { cx }.parse_list(&cur)?;
        encode::encode(cx, &mnemonic, &entries, &ops, req.span, self.endian)
    }
}

/// The full mnemonic, with the cursor moved past any part of it the lexer
/// split off.
///
/// Several SH mnemonics contain a `/`: `cmp/eq`, `cmp/hs`, `bt/s`,
/// `fcmp/gt`. The shared lexer stops an identifier at `/` (it is division
/// everywhere else), so `cmp/eq r1,r2` arrives as the mnemonic `cmp` followed
/// by the tokens `/`, `eq`, `r1`, and so on. The pieces are joined back here,
/// but only when nothing separates them: GNU as reads a mnemonic up to the
/// first space, so `cmp / eq` and `cmp /eq` are not `cmp/eq` there either.
fn mnemonic(cx: &mut AsmCtx<'_>, req: &InsnRequest<'_>, cur: &mut Cursor<'_>) -> Option<String> {
    let mut m = cx.name(req.mnemonic).to_ascii_lowercase();
    let slash = cur.peek();
    if !slash.is_punct(Punct::Slash) || slash.preceded_by_space {
        return Some(m);
    }
    let suffix = cur.nth(1);
    match suffix.kind {
        TokKind::Ident(n) if !suffix.preceded_by_space => {
            m.push('/');
            m.push_str(&cx.name(n).to_ascii_lowercase());
            cur.advance();
            cur.advance();
            Some(m)
        }
        _ => {
            cx.error(
                req.mnemonic_span.to(slash.span),
                format!("expected the rest of a mnemonic such as `{m}/eq` after `/`"),
            );
            None
        }
    }
}
