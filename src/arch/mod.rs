//! Architecture backends.
//!
//! Every CPU architecture implements [`Architecture`]. Backends are compiled
//! in behind cargo features and looked up by name, so a single source file can
//! switch between them with `.arch` and emit, say, x86 and ARM code into
//! different sections of the same object.

use crate::cursor::Cursor;
use crate::diag::DiagBag;
use crate::expr::{ExprArena, ExprParser};
use crate::intern::{Interner, Name};
use crate::lexer::{LitPool, Token};
use crate::section::Variant;
use crate::source::Span;
use crate::symbol::SymbolTable;

#[cfg(feature = "x86")]
pub mod x86;

#[cfg(feature = "aarch64")]
pub mod aarch64;

#[cfg(feature = "arm")]
pub mod arm;

#[cfg(feature = "riscv")]
pub mod riscv;

#[cfg(feature = "powerpc")]
pub mod powerpc;

#[cfg(feature = "mips")]
pub mod mips;

#[cfg(feature = "sparc")]
pub mod sparc;

#[cfg(feature = "retro")]
pub mod retro;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn write(self, out: &mut [u8], value: u64) {
        let n = out.len();
        for (i, slot) in out.iter_mut().enumerate() {
            let shift = match self {
                Endian::Little => i,
                Endian::Big => n - 1 - i,
            };
            *slot = (value >> (shift * 8)) as u8;
        }
    }

    /// Reads up to eight bytes back as an integer in this byte order.
    pub fn read(self, src: &[u8]) -> u64 {
        let n = src.len();
        let mut v = 0u64;
        for (i, b) in src.iter().enumerate() {
            let shift = match self {
                Endian::Little => i,
                Endian::Big => n - 1 - i,
            };
            v |= (*b as u64) << (shift * 8);
        }
        v
    }

    pub fn bytes(self, value: u64, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.write(&mut v, value);
        v
    }
}

/// Operand syntax flavour. Distinct from the [`crate::lexer::Dialect`]: GAS can
/// assemble Intel-syntax operands via `.intel_syntax`, keeping `#` comments.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Syntax {
    /// `mov %rbx, %rax` — source first, sigils on registers and immediates.
    Att,
    /// `mov rax, rbx` — destination first.
    Intel,
}

/// Which strings start a comment, for GNU-style source.
///
/// This is a per-target choice in GNU as, not a dialect-wide one, because the
/// characters it would otherwise use are taken: ARM, AArch64 and SPARC all
/// write immediates as `#1`, so on those targets `#` can only be a comment at
/// the start of a line.
#[derive(Copy, Clone, Debug)]
pub struct CommentSyntax {
    /// Start a comment anywhere on a line.
    pub anywhere: &'static [&'static str],
    /// Start a comment only in the first column (after leading whitespace).
    pub line_start: &'static [&'static str],
}

impl CommentSyntax {
    /// `#` and `//` everywhere: x86, RISC-V, MIPS and PowerPC.
    pub const HASH: CommentSyntax = CommentSyntax {
        anywhere: &["#", "//"],
        line_start: &[],
    };
}

/// Mutable, architecture-specific assembler state.
///
/// Kept outside the [`Architecture`] object so backends stay `&self` and can be
/// shared, while `.code64`, `.arch` extensions and similar directives still
/// have somewhere to record what they changed.
#[derive(Clone, Debug)]
pub struct ArchState {
    /// Operating mode width in bits (x86: 16, 32 or 64).
    pub bits: u8,
    pub syntax: Syntax,
    /// Bitset of optional instruction-set extensions the backend defines.
    pub features: u64,
    /// Set by `.intel_syntax noprefix` / `prefix`.
    pub intel_register_prefix: bool,
}

/// One instruction to assemble, as the generic parser saw it.
pub struct InsnRequest<'t> {
    pub mnemonic: Name,
    pub mnemonic_span: Span,
    /// Every token after the mnemonic, up to the end of the statement. The
    /// backend splits these itself, since operand grammar is arch-specific
    /// (x86 memory operands, ARM register lists, and so on).
    pub operands: &'t [Token],
    /// Span of the whole statement.
    pub span: Span,
}

impl InsnRequest<'_> {
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor::new(self.operands)
    }
}

/// The slice of assembler state a backend may touch.
pub struct AsmCtx<'a> {
    pub interner: &'a mut Interner,
    pub exprs: &'a mut ExprArena,
    pub diags: &'a mut DiagBag,
    pub pool: &'a LitPool,
    /// Read-only: backends resolve named constants, never define them.
    pub symbols: &'a SymbolTable,
    pub state: &'a mut ArchState,
    /// The source dialect, which decides operand spelling as much as lexing:
    /// the same m68k register is `%d0` to GNU as and `d0` in Motorola source.
    pub dialect: crate::lexer::Dialect,
}

impl AsmCtx<'_> {
    pub fn expr_parser(&mut self) -> ExprParser<'_> {
        ExprParser {
            arena: self.exprs,
            interner: self.interner,
            diags: self.diags,
            // `$` is an immediate marker in AT&T, not the location counter.
            dollar_is_here: self.dialect.dollar_is_here(),
            star_is_here: self.dialect.star_is_here(),
        }
    }

    pub fn name(&self, n: Name) -> &str {
        self.interner.get(n)
    }

    /// The constant value of an expression, following `.set` definitions.
    ///
    /// Backends use this to choose an encoding width, so `.set n, 1` followed
    /// by `add $n, %rax` gets the same short form as `add $1, %rax`.
    pub fn constant(&self, e: crate::expr::ExprRef) -> Option<i64> {
        crate::expr::SymbolEnv::new(self.exprs, self.symbols).constant(e)
    }

    pub fn error(&mut self, span: Span, msg: impl Into<String>) {
        self.diags.error(span, msg);
    }
}

pub trait Architecture {
    /// Canonical name, as accepted by `--arch` and `.arch`.
    fn name(&self) -> &'static str;

    /// Alternative spellings accepted by `.arch`.
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn endian(&self) -> Endian;

    /// Width of a pointer in bytes, in the current mode.
    fn pointer_bytes(&self, state: &ArchState) -> u8;

    fn initial_state(&self) -> ArchState;

    fn supports_syntax(&self, syntax: Syntax) -> bool;

    /// `EM_*` value for ELF output.
    fn elf_machine(&self) -> u16;

    /// ELF relocation type for an `size`-byte data reference, or `None` if the
    /// architecture has no such relocation (which makes an unresolved
    /// reference of that width an error).
    fn data_reloc(&self, size: u8, pcrel: bool) -> Option<u32>;

    /// Relocation type selected by a source-level `@` modifier such as
    /// `foo@PLT`. `None` means the modifier is not recognised.
    fn modifier_reloc(&self, _name: &str, _size: u8, _pcrel: bool) -> Option<u32> {
        None
    }

    /// Comment characters in GNU-style source. Ignored for the NASM dialect,
    /// which uses `;` on every target.
    fn comments(&self) -> CommentSyntax {
        CommentSyntax::HASH
    }

    /// The alignment unit instructions and multi-byte data need, in bytes.
    ///
    /// The 68000 raises an address error on a word or long at an odd address,
    /// so its unit is 2. Dialects that align automatically — Motorola does,
    /// GNU as does not — use this to decide how far; everyone else needs 1.
    fn align_unit(&self) -> u64 {
        1
    }

    /// The dialect a source is assumed to be in when none is named.
    ///
    /// Amiga and Atari m68k source is overwhelmingly Motorola syntax, and
    /// nobody has written 78K0 source in anything but Renesas's own; for those
    /// targets defaulting to GNU as would reject the source people have.
    fn default_dialect(&self) -> crate::lexer::Dialect {
        crate::lexer::Dialect::Gas
    }

    /// Adjusts GNU-dialect lexing beyond comment characters, for targets whose
    /// GNU as port differs: RL78's accepts `10H`, m68k's comments with `|`.
    /// Only called for the GNU dialect; the vendor dialects are fixed.
    fn tune_lexer(&self, _cfg: &mut crate::lexer::LexConfig) {}

    /// Width of `.word` in bytes.
    ///
    /// Not derivable from anything else: it is an assembler convention per
    /// target rather than a property of the instruction set. x86 keeps the
    /// 16-bit word of its 8086 origins, and so — less obviously — does
    /// PowerPC, while ARM, AArch64, RISC-V, MIPS and SPARC use 4. The default
    /// is 2 because that is the value for x86 and for every 8-bit target.
    fn word_bytes(&self) -> u8 {
        2
    }

    /// Padding for `.align` in an executable section: real no-ops where the
    /// architecture has them, so padding stays executable.
    fn nop_fill(&self, state: &ArchState, len: u64) -> Vec<u8>;

    /// Assembles one instruction. Returns the candidate encodings, smallest
    /// first; layout picks among them. Returns `None` after reporting a
    /// diagnostic.
    fn assemble(&self, cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>) -> Option<Vec<Variant>>;

    /// Handles an architecture-specific directive such as `.code64`. Returns
    /// false if the name is not one of this backend's directives.
    fn directive(&self, _cx: &mut AsmCtx<'_>, _name: &str, _cur: &mut Cursor<'_>) -> bool {
        false
    }
}

/// Looks up a backend by canonical name or alias.
pub fn lookup(name: &str) -> Option<Box<dyn Architecture>> {
    let lower = name.to_ascii_lowercase();
    #[cfg(feature = "x86")]
    if let Some(a) = x86::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "aarch64")]
    if let Some(a) = aarch64::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "arm")]
    if let Some(a) = arm::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "riscv")]
    if let Some(a) = riscv::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "powerpc")]
    if let Some(a) = powerpc::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "mips")]
    if let Some(a) = mips::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "sparc")]
    if let Some(a) = sparc::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "retro")]
    if let Some(a) = retro::lookup(&lower) {
        return Some(a);
    }
    let _ = lower;
    None
}

/// Every architecture name this build can assemble, for `--list-arch` and for
/// the "unknown architecture" diagnostic.
pub fn available() -> Vec<&'static str> {
    // `mut` is only needed when at least one backend feature is on.
    #[allow(unused_mut)]
    let mut v = Vec::new();
    #[cfg(feature = "x86")]
    v.extend_from_slice(x86::NAMES);
    #[cfg(feature = "aarch64")]
    v.extend_from_slice(aarch64::NAMES);
    #[cfg(feature = "arm")]
    v.extend_from_slice(arm::NAMES);
    #[cfg(feature = "riscv")]
    v.extend_from_slice(riscv::NAMES);
    #[cfg(feature = "powerpc")]
    v.extend_from_slice(powerpc::NAMES);
    #[cfg(feature = "mips")]
    v.extend_from_slice(mips::NAMES);
    #[cfg(feature = "sparc")]
    v.extend_from_slice(sparc::NAMES);
    #[cfg(feature = "retro")]
    v.extend_from_slice(retro::NAMES);
    v
}

/// The backend used when nothing is specified: the host architecture if this
/// build supports it, else the first available one.
pub fn default_arch() -> Option<Box<dyn Architecture>> {
    #[cfg(all(feature = "x86", target_arch = "x86_64"))]
    if let Some(a) = lookup("x86-64") {
        return Some(a);
    }
    available().first().and_then(|n| lookup(n))
}
