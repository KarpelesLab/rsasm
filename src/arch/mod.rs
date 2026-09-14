//! Architecture backends.
//!
//! Every CPU architecture implements [`Architecture`]. Backends are compiled
//! in behind cargo features and looked up by name, so a single source file can
//! switch between them with `.arch` and emit, say, x86 and ARM code into
//! different sections of the same object.

use crate::cursor::Cursor;
use crate::diag::DiagBag;
use crate::expr::{ExprArena, ExprParser, ExprRef};
use crate::intern::{Interner, Name};
use crate::lexer::{LitPool, Token};
use crate::section::{FragKind, SectionId, Variant};
use crate::source::Span;
use crate::symbol::{Binding, SymbolId, SymbolTable, SymbolValue};

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

#[cfg(feature = "m68k")]
pub mod m68k;

#[cfg(feature = "v850")]
pub mod v850;

#[cfg(feature = "rl78")]
pub mod rl78;

#[cfg(feature = "rx")]
pub mod rx;

#[cfg(feature = "superh")]
pub mod superh;

#[cfg(feature = "k78")]
pub mod k78;

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

/// A bit of [`ArchState::features`] set by NASM's `default rel`: a memory
/// operand with no register in it is RIP-relative. Only x86 reads it.
pub const FEATURE_DEFAULT_REL: u64 = 1 << 63;

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

/// What a relocation modifier makes of a value in a flat binary; see
/// [`Architecture::flat_modifier`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FlatModifier {
    /// The value itself. `call foo@PLT` in an image with no PLT calls `foo`.
    Plain,
    /// The value relative to the field, even in a field that is otherwise
    /// absolute: x86-64's `R_X86_64_PLT32` is `L + A - P`, so `.long foo@PLT`
    /// in a static image is the distance to `foo`.
    PcRelative,
    /// Something only a linker creates, such as a GOT entry; refused.
    LinkerOnly,
}

/// Something a backend asks the core to do to the section, which it cannot do
/// itself because sections belong to the core. Queued on
/// [`AsmCtx::requests`] and carried out once the statement is assembled.
#[derive(Clone, Debug)]
pub enum Request {
    /// Pads to a multiple of `align` bytes with zeros, even in code: GNU as's
    /// `frag_align (n, 0, 0)`, which ARM's `.arm` and literal pools use.
    AlignZero(u64),
    /// Raises the section's alignment to at least this many bytes, without
    /// padding anything: GNU as's `record_alignment`.
    RecordAlign(u64),
    /// A value the instruction loads from the section's literal pool; see
    /// [`AsmCtx::literal`].
    Literal(LiteralRequest),
    /// Writes out the section's literal pool here: `.ltorg`.
    FlushLiterals,
}

/// One use of a literal pool entry.
#[derive(Clone, Debug)]
pub struct LiteralRequest {
    /// The label the instruction refers to, defined where the entry lands.
    pub label: Name,
    pub value: Literal,
    /// Entry width in bytes.
    pub size: u8,
    pub span: Span,
}

/// A literal pool entry's value.
#[derive(Copy, Clone, Debug)]
pub enum Literal {
    /// A number, as it was when the instruction was read.
    Const(i64),
    /// Anything else, which the entry relocates if it has to.
    Expr(ExprRef),
}

/// A PC-relative reference to a symbol defined in the fixup's own section,
/// as [`Architecture::defers_to_linker`] is asked about it.
#[derive(Copy, Clone, Debug)]
pub struct SameSectionRef<'a> {
    /// The binding of the symbol as written: `alias` in `call alias` after
    /// `.set alias, target`, not `target`.
    pub binding: Binding,
    /// The relocation the reference would get, after any `@` modifier.
    pub reloc: u32,
    /// The `@` modifier, lowercased, if the reference was written with one.
    pub modifier: Option<&'a str>,
    /// Whether the instruction has more than one size to relax between.
    pub relaxable: bool,
}

/// How relaxation picks instruction sizes, as each reference assembler does;
/// see [`Architecture::relaxation`]. Where a file uses backends that relax
/// differently, the one listed last here wins for the whole file, since each
/// is a refinement of the ones before it.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Relaxation {
    /// Every size is chosen at once from the previous pass's addresses, and
    /// only grows. Layout starts each instruction at its smallest candidate,
    /// which finds the smallest layout whenever a form that reaches a target
    /// also reaches every nearer one.
    FromLastPass,
    /// Sizes are chosen walking each section in order, as GNU as's generic
    /// `relax_frag` chooses them, and only grow. The two can settle on
    /// different layouts: a branch that was out of reach at the previous
    /// pass's addresses, and is back in reach once an alignment has absorbed
    /// an earlier branch's growth, stays short when sized in order and grows
    /// when not. SuperH's GNU as works this way.
    InOrder,
    /// Sizes are picked afresh on every pass, walking each section in order,
    /// the way GNU as's ARM port picks them (`arm_relax_frag`). A target in a
    /// fragment the walk has yet to reach is taken to have moved by the
    /// growth so far, less what each alignment in between would absorb of it
    /// (GNU's `relaxed_symbol_addr`), which can let a fragment shrink back. A
    /// fragment that takes a larger candidate on a pass where nothing before
    /// it grew keeps that size for good, which is how GNU as stops the walk
    /// from cycling.
    EachPass,
    /// Every size is re-picked on each pass, and may shrink, with a target
    /// ahead moved by the growth so far as decided by its last-pass address.
    /// RX needs it: `bra.s` reaches 3 to 10 bytes forward, not 0 to 10, so a
    /// branch that was too close early on can come within reach once the code
    /// around it grows. GNU as's RX port re-picks every size for this reason,
    /// under a limit on how often one fragment may flip.
    Shrinking,
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
    /// Bitset of what the source has used so far, in the backend's own terms,
    /// for header fields that describe the object's contents rather than the
    /// options it was assembled with: GNU as for SuperH derives `e_flags` from
    /// the least capable CPU that has every instruction in the file.
    pub used: u64,
    /// What one statement leaves for the next in the backend's own terms:
    /// ARM's open `it` block, and a `.thumb_func` waiting for its label.
    pub private: u64,
}

/// What a PC-relative reference's target is, for
/// [`Architecture::interwork`].
#[derive(Copy, Clone, Debug)]
pub struct InterworkTarget {
    /// The bits [`Architecture::label_flags`] gave the target's label.
    pub flags: u8,
    pub ty: crate::symbol::SymType,
    /// Defined in the section the reference is in.
    pub same_section: bool,
    /// Global or weak, or not defined here at all: another definition may
    /// take its place at link time.
    pub global: bool,
    /// Global with default visibility, weak, or undefined: another object's
    /// definition can take its place even within one link.
    pub preemptible: bool,
    /// Whether the output is an object, with a linker still to come.
    pub relocatable: bool,
}

/// What a branch becomes once its target is known; see
/// [`Architecture::interwork`].
#[derive(Copy, Clone, Debug)]
pub enum Interwork {
    /// Resolved, or relocated, as written.
    AsWritten,
    /// Left to the linker, however near the target is.
    Relocate,
    /// Something only a linker builds, described for the diagnostic.
    LinkerOnly(&'static str),
    /// Another instruction: the word, read in the target's byte order, put
    /// through `patch`, and the field written as `kind` describes.
    Becomes {
        patch: fn(u64) -> u64,
        kind: crate::section::FixupKind,
    },
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
    /// Read-only: what has been emitted so far, for
    /// [`AsmCtx::fixed_distance`].
    pub sections: &'a [crate::section::Section],
    /// The section the statement is assembled into.
    pub section: crate::section::SectionId,
    /// Set by a backend whose reference assembler would give this instruction
    /// a fragment that relaxation revisits, though it has one encoding here;
    /// see [`crate::section::Fragment::relaxable`].
    pub relaxable: bool,
    /// What the statement needs done to the section beyond its own bytes;
    /// see [`Request`].
    pub requests: Vec<Request>,
}

impl AsmCtx<'_> {
    /// Places `value` in the current section's literal pool and returns an
    /// expression for the address of its entry.
    ///
    /// The pool is written out at the next `.ltorg`, or at the end of the
    /// section, and equal entries are shared the way GNU as shares them: the
    /// same number, or the same symbol plus the same addend. Until then the
    /// entry's address is a label with a name no source can spell.
    pub fn literal(&mut self, value: Literal, size: u8, span: Span) -> ExprRef {
        // The arena only grows, and grows below, so its length names each
        // entry once.
        let n = self.exprs.len();
        let label = self.interner.intern(&format!(".L\u{0}lit.{n}"));
        self.requests.push(Request::Literal(LiteralRequest {
            label,
            value,
            size,
            span,
        }));
        self.exprs.alloc(crate::expr::ExprKind::Sym(label), span)
    }

    pub fn expr_parser(&mut self) -> ExprParser<'_> {
        ExprParser {
            arena: self.exprs,
            interner: self.interner,
            diags: self.diags,
            // `$` is an immediate marker in AT&T, not the location counter.
            dollar_is_here: self.dialect.dollar_is_here(),
            star_is_here: self.dialect.star_is_here(),
            dialect: self.dialect,
            strings: Some(self.pool),
        }
    }

    pub fn name(&self, n: Name) -> &str {
        self.interner.get(n)
    }

    /// The first relocation modifier (`foo wrt ..got`, `foo@PLT`) in an
    /// expression, if any.
    pub fn find_modifier_for(&self, e: crate::expr::ExprRef) -> Option<Name> {
        use crate::expr::ExprKind::*;
        match &self.exprs.get(e).kind {
            Modifier(n, _) => Some(*n),
            Unary(_, a) => self.find_modifier_for(*a),
            Binary(_, a, b) => self
                .find_modifier_for(*a)
                .or_else(|| self.find_modifier_for(*b)),
            _ => None,
        }
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

    /// The address `e` has now, in a flat image: a constant, or a label whose
    /// section starts at an address the source gave it (the 8-bit dialect's
    /// `ORG`) with nothing between that start and the label that could change
    /// size.
    ///
    /// ca65 reads a label after `.org` as the number it is, so it can choose
    /// zero-page addressing for one defined earlier, just as it does for a
    /// constant; this is what lets the 6502 backend do the same.
    pub fn address_now(&self, e: crate::expr::ExprRef) -> Option<i64> {
        let v = crate::expr::SymbolEnv::new(self.exprs, self.symbols).value(e)?;
        let at = |id: SymbolId| -> Option<i64> {
            let (section, frag) = self.label_position(id)?;
            let origin = self.sections[section.0 as usize].origin?;
            let d = self.fixed_distance((section, 0), (section, frag))?;
            Some(origin as i64 + d)
        };
        let plus = match v.plus {
            Some(p) => at(p)?,
            None => 0,
        };
        let minus = match v.minus {
            Some(m) => at(m)?,
            None => 0,
        };
        Some(v.addend + plus - minus)
    }

    /// Where a label was defined: its section, and the index of the fragment
    /// it starts.
    pub fn label_position(&self, id: SymbolId) -> Option<(SectionId, u32)> {
        match self.symbols.get(id).value {
            SymbolValue::Label { section, frag } => Some((section, frag)),
            _ => None,
        }
    }

    /// Where the statement being assembled starts, in the terms of
    /// [`AsmCtx::label_position`]; this is where its `.` is.
    pub fn here(&self) -> (SectionId, u32) {
        let s = &self.sections[self.section.0 as usize];
        (self.section, s.next_frag_index())
    }

    /// The distance from `from` to `to`, if nothing emitted between them can
    /// change size.
    ///
    /// This is when GNU as's expression parser folds a difference of labels
    /// to a constant as it reads it (`frag_offset_fixed_p`), which decides
    /// the encoding on targets whose backend chooses one by whether an operand
    /// is constant. An alignment, a `.org`, a `.space` or LEB128 value that is
    /// not a constant, or an instruction relaxation may resize between the
    /// two breaks it, even where layout later finds nothing to change.
    pub fn fixed_distance(&self, from: (SectionId, u32), to: (SectionId, u32)) -> Option<i64> {
        if from.0 != to.0 {
            return None;
        }
        let (lo, hi, sign) = if from.1 <= to.1 {
            (from.1, to.1, 1)
        } else {
            (to.1, from.1, -1)
        };
        let frags = &self.sections[from.0.0 as usize].frags;
        let mut total = 0i64;
        for f in frags.get(lo as usize..hi as usize)? {
            if f.relaxable {
                return None;
            }
            total += match &f.kind {
                FragKind::Bytes { variants, .. } if variants.len() == 1 => {
                    variants[0].bytes.len() as i64
                }
                FragKind::Space { size, .. } => self.constant(*size).filter(|n| *n >= 0)?,
                FragKind::Leb128 { value, signed, .. } => {
                    let v = self.constant(*value)?;
                    let n = if *signed {
                        crate::layout::sleb128(v).len()
                    } else {
                        crate::layout::uleb128(v as u64).len()
                    };
                    n as i64
                }
                FragKind::Align { align, .. } if *align <= 1 => 0,
                _ => return None,
            };
        }
        Some(sign * total)
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

    /// What a source-level `@` modifier means in a flat binary, where there is
    /// no relocation for it to choose and no linker to build what it names.
    /// Only asked about modifiers on fixups whose [`FixupKind::link`] is
    /// plain; the default refuses them all.
    ///
    /// [`FixupKind::link`]: crate::section::FixupKind::link
    fn flat_modifier(&self, _name: &str) -> FlatModifier {
        FlatModifier::LinkerOnly
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

    /// Recognises this backend's mnemonics, lowercased, for the 8-bit dialect,
    /// in which a word in the first column is a label unless it names an
    /// instruction or a directive. `None`, the default, makes every such word
    /// that is not a directive a label.
    fn mnemonics(&self) -> Option<fn(&str) -> bool> {
        None
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

    /// How relaxation picks the sizes of instructions with more than one
    /// encoding; see [`Relaxation`].
    fn relaxation(&self) -> Relaxation {
        Relaxation::FromLastPass
    }

    /// Whether `.short`, `.word`, `.int`, `.long` and `.quad` must each start
    /// on a boundary of their own width.
    ///
    /// SuperH's GNU as raises the section's alignment to the data's width,
    /// pads up to the boundary, and refuses the data as misaligned if that
    /// took any padding; the padding still moves everything after it while
    /// branches are sized. `.2byte`, `.4byte` and `.8byte` stay unaligned,
    /// and so do the SuperH spellings `.uaword`, `.ualong` and `.uaquad`,
    /// which a target returning true also accepts.
    fn aligns_data(&self) -> bool {
        false
    }

    /// Whether a plain number as a PC-relative target (`call 0x1000`) is an
    /// absolute address, which relocatable output must relocate against no
    /// symbol, rather than an offset into the current section.
    ///
    /// The references split on this. GNU as on x86, m68k, RL78 and RX takes
    /// the address; GNU as on SuperH and V850, and llvm-mc everywhere except
    /// x86, measure from the start of the section.
    fn pcrel_number_is_address(&self) -> bool {
        false
    }

    /// Whether a PC-relative reference to a symbol in the fixup's own section
    /// is left to the linker in relocatable output, rather than resolved.
    ///
    /// A global or weak symbol can be preempted: the linker may bind the name
    /// to a definition in another object, whether from a shared library or,
    /// for a weak one, a strong definition elsewhere. So on AArch64, ARM,
    /// PowerPC, MIPS, SPARC, RX and V850, and for calls on x86 and RISC-V, both
    /// references relocate a reference to a global or weak symbol, whatever
    /// its visibility, and resolve one to a local symbol, including a local
    /// `.set` alias of a global one; that is the default. A difference of two
    /// labels in one section is never affected: both references fold `.long
    /// weak - .` to a constant. A field no relocation can describe is
    /// resolved, unless the instruction has a larger form that one can.
    ///
    /// The ports whose reference differs override this, and every binding is
    /// checked in the `*-relocs.txt` corpora of `tools/gas-diff`,
    /// `tools/mc-diff` and `tools/xas-diff`.
    fn defers_to_linker(&self, r: &SameSectionRef<'_>) -> bool {
        r.binding != Binding::Local
    }

    /// What goes in the field of a PC-relative fixup at section offset `pc`
    /// that is relocated against a `binding` symbol in its own section, where
    /// that is not zero. A linker overwrites the field, so this only matters
    /// for matching the reference byte for byte: GNU as for V850 measures
    /// such a reference from the fixup as if the symbol were at 0, and writes
    /// `-pc`.
    fn relocated_pcrel_field(&self, _binding: Binding, _pc: u64) -> Option<i64> {
        None
    }

    /// The relocation pair, adding one symbol and subtracting another, that
    /// a `size`-byte data field holding a difference the file cannot fold is
    /// written as, if the target has one.
    ///
    /// Without one, only `sym - label` with the label in the field's own
    /// section can be relocated, as `sym` relative to the field. RISC-V's
    /// linker relaxation needs every difference it cannot see through kept as
    /// its two symbols, so llvm-mc writes `R_RISCV_ADD32`/`R_RISCV_SUB32` for
    /// that one too, and for a difference across sections.
    fn difference_relocs(&self, _size: u8) -> Option<(u32, u32)> {
        None
    }

    /// Whether a relocation against a global symbol defined in this object
    /// names the symbol's section plus an offset, as one against a local
    /// label does, rather than the symbol. GNU as for m68k does this for all
    /// but weak symbols.
    fn relocates_globals_by_section(&self) -> bool {
        false
    }

    /// The relocation to write for a PC-relative `reloc` that names a local
    /// label's section. GNU as for x86 writes a `call` to a local label as
    /// `PC32` rather than `PLT32`, there being no PLT entry to go through.
    fn section_relative_reloc(&self, reloc: u32) -> u32 {
        reloc
    }

    /// The alignment a section is given when it is created, before anything
    /// in it asks for more.
    ///
    /// This shows as `sh_addralign` in an object, and as where the section
    /// starts in a flat image. The references decide it mostly by name, and
    /// not all of them agree: llvm-mc aligns `.text` on every target, every
    /// executable section on AArch64, and `.data` and `.bss` too on MIPS,
    /// while GNU as aligns `.text`, `.data` and `.bss` on m68k, `.text` alone
    /// on MIPS and RISC-V, and on ARM and AArch64 whatever section an
    /// instruction is assembled into. Where both references exist, the one
    /// whose harness checks the target wins; each override says which.
    fn section_align(
        &self,
        _state: &ArchState,
        _name: &str,
        _flags: &crate::section::SectionFlags,
    ) -> u64 {
        1
    }

    /// `e_flags` for ELF output, given the state at the end of the source.
    fn elf_flags(&self, _state: &ArchState) -> u32 {
        0
    }

    /// Whether a relocation of type `reloc` keeps its addend in the relocated
    /// field, given whether the object's relocation sections are `RELA`.
    ///
    /// Under `REL` there is nowhere else to put it. A `RELA` target normally
    /// writes it into the entry and leaves the field zero, but the SuperH
    /// relocations are `partial_inplace` in BFD, whose linker then reads the
    /// field and ignores the entry's addend; GNU as writes both accordingly.
    fn addend_in_field(&self, _reloc: u32, rela: bool) -> bool {
        !rela
    }

    /// Whether `.align n` means 2^n bytes rather than n.
    ///
    /// GNU as decides this per target, for historical reasons only: x86 ELF,
    /// SPARC, m68k and RX count bytes, while ARM, AArch64, RISC-V, MIPS,
    /// PowerPC, RL78, V850 and SuperH count low-order zero bits. `.balign` and
    /// `.p2align` mean the same everywhere.
    fn align_is_log2(&self) -> bool {
        false
    }

    /// Whether GNU as rounds the end of a section with these flags up to the
    /// section's alignment.
    ///
    /// The Renesas ports (RL78, RX, V850) round every section, SuperH only
    /// code sections; the padding counts towards the section's size, so a
    /// linker placing the next object's section sees it.
    fn pads_section_tail(&self, _flags: &crate::section::SectionFlags) -> bool {
        false
    }

    /// The most a section tail is padded to, where
    /// [`Architecture::pads_section_tail`] pads it at all. ARM's GNU as pads
    /// code to its alignment only up to a word.
    fn section_tail_align_limit(&self) -> u64 {
        u64::MAX
    }

    /// Whether no-op padding is for the state the last instruction before it
    /// was assembled in, rather than the state in force where the padding is
    /// written. GNU as's ARM port pads so (its PR 9814), so that padding
    /// after Thumb code is Thumb no-ops even once `.arm` has been seen; its
    /// x86 port pads for the mode in force. See `Section::nop_state`.
    fn pads_as_last_instruction(&self) -> bool {
        false
    }

    /// The mapping symbol that marks code this backend emits in `state`, and
    /// the alignment in bytes such code gives its section, for a target whose
    /// ELF objects mark code and data apart: ARM's `$a` and `$t`. `None`, the
    /// default, for a target that does not.
    ///
    /// Where the marks go follows GNU as's ARM port; see
    /// `Assembler::map_code`.
    fn code_mapping(&self, _state: &ArchState) -> Option<(&'static str, u64)> {
        None
    }

    /// The mapping symbol that marks data, for a target with
    /// [`Architecture::code_mapping`].
    fn data_mapping(&self) -> &'static str {
        "$d"
    }

    /// Bits to record on a label as it is defined, in the backend's own
    /// terms, from the state it is defined in: ARM marks a label in Thumb
    /// code, and the one a `.thumb_func` names. `name` is the label's, and
    /// `in_code` whether its section is executable.
    fn label_flags(&self, _state: &mut ArchState, _name: &str, _in_code: bool) -> u8 {
        0
    }

    /// The type and value an ELF symbol table gives a symbol with these
    /// label flags: an ARM Thumb function is `STT_FUNC` with its low bit set.
    fn elf_symbol(
        &self,
        _flags: u8,
        ty: crate::symbol::SymType,
        _defined: bool,
        value: u64,
    ) -> (crate::symbol::SymType, u64) {
        (ty, value)
    }

    /// Whether a relocation against this local label names the label rather
    /// than its section: an ARM linker needs to see a function symbol, to
    /// know which instruction set it is in.
    fn keeps_reloc_symbol(&self, _flags: u8, _ty: crate::symbol::SymType) -> bool {
        false
    }

    /// What an ARM linker adds to a symbol's value in a field of relocation
    /// type `reloc`, which a flat binary has to add itself: the low bit of a
    /// Thumb function's address.
    fn link_bias(&self, _reloc: u32, _flags: u8, _ty: crate::symbol::SymType) -> i64 {
        0
    }

    /// For a fixup whose [`LinkValue`](crate::section::LinkValue) is
    /// `Interwork(class)`, what the instruction becomes given its target:
    /// an ARM `bl` to a Thumb function is a `blx`, and a branch to a function
    /// in the other instruction set, which only a linker can make reach,
    /// keeps its relocation. `class` is the backend's own.
    fn interwork(&self, _class: u8, _target: &InterworkTarget) -> Interwork {
        Interwork::AsWritten
    }

    /// Padding for `.align` in an executable section: real no-ops where the
    /// architecture has them, so padding stays executable.
    fn nop_fill(&self, state: &ArchState, len: u64) -> Vec<u8>;

    /// Assembles one instruction. Returns the candidate encodings, smallest
    /// first; layout picks among them. Returns `None` after reporting a
    /// diagnostic.
    fn assemble(&self, cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>) -> Option<Vec<Variant>>;

    /// Whether an instruction's operands refer to the instruction's own
    /// address without spelling it `.`, so that [`Architecture::assemble`]
    /// may build [`ExprKind::Here`](crate::expr::ExprKind::Here) nodes for
    /// it. SuperH's `@(8,pc)` means `. + 8`.
    fn operands_use_location(&self, _interner: &Interner, _operands: &[Token]) -> bool {
        false
    }

    /// Whether `name` (lowercased) could be one of this backend's
    /// instructions. NASM source may write a label without a colon, and a
    /// first word that is not an instruction is taken as one; a backend that
    /// cannot tell says yes, which makes the colon required.
    fn is_mnemonic(&self, _name: &str) -> bool {
        true
    }

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
    #[cfg(feature = "m68k")]
    if let Some(a) = m68k::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "v850")]
    if let Some(a) = v850::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "rl78")]
    if let Some(a) = rl78::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "rx")]
    if let Some(a) = rx::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "superh")]
    if let Some(a) = superh::lookup(&lower) {
        return Some(a);
    }
    #[cfg(feature = "k78")]
    if let Some(a) = k78::lookup(&lower) {
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
    #[cfg(feature = "m68k")]
    v.extend_from_slice(m68k::NAMES);
    #[cfg(feature = "v850")]
    v.extend_from_slice(v850::NAMES);
    #[cfg(feature = "rl78")]
    v.extend_from_slice(rl78::NAMES);
    #[cfg(feature = "rx")]
    v.extend_from_slice(rx::NAMES);
    #[cfg(feature = "superh")]
    v.extend_from_slice(superh::NAMES);
    #[cfg(feature = "k78")]
    v.extend_from_slice(k78::NAMES);
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
