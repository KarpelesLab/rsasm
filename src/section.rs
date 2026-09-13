//! Sections, fragments and fixups.
//!
//! Output is built as a list of *fragments* per section. A fragment whose size
//! is not yet known (an alignment, or a branch that may need a longer
//! displacement) keeps enough information for the layout loop to re-decide its
//! size until everything is stable.

use crate::expr::ExprRef;
use crate::intern::Name;
use crate::source::Span;
use crate::symbol::SymbolId;

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SectionId(pub u32);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SectionKind {
    /// Occupies space in the output file.
    Progbits,
    /// Zero-filled at load time (`.bss`).
    Nobits,
    Note,
}

#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct SectionFlags {
    pub alloc: bool,
    pub write: bool,
    pub exec: bool,
    pub merge: bool,
    pub strings: bool,
    pub tls: bool,
    pub group: bool,
}

impl SectionFlags {
    pub fn text() -> SectionFlags {
        SectionFlags { alloc: true, exec: true, ..Default::default() }
    }
    pub fn data() -> SectionFlags {
        SectionFlags { alloc: true, write: true, ..Default::default() }
    }
    pub fn rodata() -> SectionFlags {
        SectionFlags { alloc: true, ..Default::default() }
    }
    pub fn bss() -> SectionFlags {
        SectionFlags { alloc: true, write: true, ..Default::default() }
    }
}

/// How a fixup's value is written into the output.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FixupKind {
    /// Field width in bytes: 1, 2, 4 or 8.
    pub size: u8,
    /// The value is relative to the address of the fixup itself (plus
    /// `adjust`), rather than absolute.
    pub pcrel: bool,
    /// Range-check the result as signed rather than allowing either sign.
    pub signed: bool,
    /// Added to the fixup's own address before subtracting, for PC-relative
    /// fields that are not at the end of their instruction. For x86 a `rel32`
    /// four bytes before the end of the instruction uses `adjust = 4`.
    pub adjust: i8,
    /// Relocation to emit if the value cannot be resolved at assembly time.
    /// `0` means "no relocation available"; an unresolved fixup is then an
    /// error.
    pub reloc: u32,
}

impl FixupKind {
    pub fn data(size: u8) -> FixupKind {
        FixupKind { size, pcrel: false, signed: false, adjust: 0, reloc: 0 }
    }

    pub fn pcrel(size: u8, adjust: i8) -> FixupKind {
        FixupKind { size, pcrel: true, signed: true, adjust, reloc: 0 }
    }

    pub fn with_reloc(mut self, reloc: u32) -> FixupKind {
        self.reloc = reloc;
        self
    }

    pub fn signed(mut self) -> FixupKind {
        self.signed = true;
        self
    }

    /// Inclusive range of values this field can hold.
    pub fn range(&self) -> (i128, i128) {
        let bits = self.size as u32 * 8;
        if self.signed {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            // Accept both the unsigned and the sign-extended reading, which is
            // what assemblers do for `.byte -1` as well as `.byte 255`.
            (-(1i128 << (bits - 1)), (1i128 << bits) - 1)
        }
    }

    pub fn fits(&self, v: i128) -> bool {
        if self.size >= 8 {
            return true;
        }
        let (lo, hi) = self.range();
        v >= lo && v <= hi
    }
}

#[derive(Clone, Debug)]
pub struct Fixup {
    /// Byte offset within the fragment's bytes.
    pub offset: u32,
    pub expr: ExprRef,
    pub kind: FixupKind,
    pub span: Span,
}

/// One possible encoding of a fragment.
#[derive(Clone, Debug, Default)]
pub struct Variant {
    pub bytes: Vec<u8>,
    pub fixups: Vec<Fixup>,
}

impl Variant {
    pub fn new(bytes: Vec<u8>) -> Variant {
        Variant { bytes, fixups: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub enum FragKind {
    /// Literal bytes. Instructions that can be encoded several ways list all
    /// candidates smallest-first; layout raises `chosen` until every fixup
    /// fits, and never lowers it, so the loop terminates.
    Bytes { variants: Vec<Variant>, chosen: usize },
    /// Pad to a multiple of `align`, at most `max_skip` bytes.
    Align { align: u64, fill: Vec<u8>, max_skip: Option<u64>, /* filled by layout */ pad: u64 },
    /// Advance the location counter to an absolute offset within the section.
    Org { target: ExprRef, fill: u8, size: u64 },
    /// `.space` / `.skip`: `size` bytes of `fill`.
    Space { size: ExprRef, fill: ExprRef, resolved: u64 },
    /// A variable-length integer whose width depends on its value.
    Leb128 { value: ExprRef, signed: bool, encoded: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Fragment {
    pub kind: FragKind,
    pub span: Span,
    /// Offset from the start of the section, assigned by layout.
    pub offset: u64,
}

impl Fragment {
    pub fn new(kind: FragKind, span: Span) -> Fragment {
        Fragment { kind, span, offset: 0 }
    }

    /// Current size in bytes, based on the last layout decision.
    pub fn size(&self) -> u64 {
        match &self.kind {
            FragKind::Bytes { variants, chosen } => {
                variants.get(*chosen).map_or(0, |v| v.bytes.len() as u64)
            }
            FragKind::Align { pad, .. } => *pad,
            FragKind::Org { size, .. } => *size,
            FragKind::Space { resolved, .. } => *resolved,
            FragKind::Leb128 { encoded, .. } => encoded.len() as u64,
        }
    }

    pub fn is_plain_data(&self) -> bool {
        matches!(&self.kind, FragKind::Bytes { variants, .. } if variants.len() == 1)
    }
}

pub struct Section {
    pub id: SectionId,
    pub name: Name,
    pub kind: SectionKind,
    pub flags: SectionFlags,
    /// Required alignment of the section itself.
    pub align: u64,
    /// Entry size for mergeable sections; 0 otherwise.
    pub entsize: u64,
    pub frags: Vec<Fragment>,
    /// Total size after the last layout pass.
    pub size: u64,
    /// Base address, for absolute output formats.
    pub addr: u64,
    /// The section symbol, created lazily when a relocation needs it.
    pub sym: Option<SymbolId>,
    /// Index of the trailing fragment that new data may be appended to, if
    /// any. Cleared by anything that must not be merged across, such as a
    /// label definition.
    open_data: Option<usize>,
    /// The `.subsection`-style saved location counter is not modelled yet;
    /// this records the section's declared group name if it has one.
    pub group: Option<Name>,
}

impl Section {
    pub fn new(id: SectionId, name: Name, kind: SectionKind, flags: SectionFlags) -> Section {
        Section {
            id,
            name,
            kind,
            flags,
            align: 1,
            entsize: 0,
            frags: Vec::new(),
            size: 0,
            addr: 0,
            sym: None,
            open_data: None,
            group: None,
        }
    }

    /// Index the next fragment will get. Labels record this to name a position.
    pub fn next_frag_index(&self) -> u32 {
        self.frags.len() as u32
    }

    /// Prevents further merging into the current data fragment, so that the
    /// next fragment index refers to a real position.
    pub fn seal(&mut self) {
        self.open_data = None;
    }

    pub fn push(&mut self, frag: Fragment) -> u32 {
        self.open_data = None;
        let idx = self.frags.len() as u32;
        self.frags.push(frag);
        idx
    }

    /// Appends raw bytes, merging into the previous data fragment when that is
    /// safe. Merging keeps fragment counts (and therefore layout cost) low for
    /// data-heavy files.
    pub fn emit_bytes(&mut self, bytes: &[u8], span: Span) {
        if let Some(i) = self.open_data
            && let FragKind::Bytes { variants, .. } = &mut self.frags[i].kind {
                variants[0].bytes.extend_from_slice(bytes);
                self.frags[i].span = self.frags[i].span.to(span);
                return;
            }
        let idx = self.frags.len();
        self.frags.push(Fragment::new(
            FragKind::Bytes { variants: vec![Variant::new(bytes.to_vec())], chosen: 0 },
            span,
        ));
        self.open_data = Some(idx);
    }

    /// Appends `size` bytes to be filled in later from `expr`.
    pub fn emit_fixup(&mut self, size: u8, expr: ExprRef, kind: FixupKind, span: Span) {
        let placeholder = vec![0u8; size as usize];
        let (idx, base) = match self.open_data {
            Some(i) => {
                let FragKind::Bytes { variants, .. } = &self.frags[i].kind else {
                    unreachable!("open_data always points at a Bytes fragment")
                };
                (i, variants[0].bytes.len() as u32)
            }
            None => {
                let i = self.frags.len();
                self.frags.push(Fragment::new(
                    FragKind::Bytes { variants: vec![Variant::default()], chosen: 0 },
                    span,
                ));
                self.open_data = Some(i);
                (i, 0)
            }
        };
        let FragKind::Bytes { variants, .. } = &mut self.frags[idx].kind else { unreachable!() };
        variants[0].bytes.extend_from_slice(&placeholder);
        variants[0].fixups.push(Fixup { offset: base, expr, kind, span });
        self.frags[idx].span = self.frags[idx].span.to(span);
    }

    /// Appends a pre-encoded instruction with one or more size variants.
    pub fn emit_variants(&mut self, variants: Vec<Variant>, span: Span) -> u32 {
        debug_assert!(!variants.is_empty(), "an instruction needs at least one encoding");
        self.push(Fragment::new(FragKind::Bytes { variants, chosen: 0 }, span))
    }

    pub fn is_empty(&self) -> bool {
        self.frags.iter().all(|f| f.size() == 0)
    }
}
