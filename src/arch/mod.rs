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
}

impl AsmCtx<'_> {
    pub fn expr_parser(&mut self) -> ExprParser<'_> {
        ExprParser {
            arena: self.exprs,
            interner: self.interner,
            diags: self.diags,
            // `$` is an immediate marker in AT&T, not the location counter.
            dollar_is_here: false,
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
