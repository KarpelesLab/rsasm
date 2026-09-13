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
        SectionFlags {
            alloc: true,
            exec: true,
            ..Default::default()
        }
    }
    pub fn data() -> SectionFlags {
        SectionFlags {
            alloc: true,
            write: true,
            ..Default::default()
        }
    }
    pub fn rodata() -> SectionFlags {
        SectionFlags {
            alloc: true,
            ..Default::default()
        }
    }
    pub fn bss() -> SectionFlags {
        SectionFlags {
            alloc: true,
            write: true,
            ..Default::default()
        }
    }
}

/// How a resolved value is placed into the bytes a fixup covers.
///
/// Not comparable: the `Scatter` variant holds a function pointer, and
/// comparing those says nothing useful.
#[derive(Copy, Clone, Debug, Default)]
pub enum FieldEncoding {
    /// The value fills the field: it is written as an integer of `size` bytes
    /// in the target's byte order. This is what byte-oriented architectures
    /// need, and what every data directive uses.
    #[default]
    Whole,
    /// The architecture scatters the value through an instruction word.
    ///
    /// Fixed-width RISC encodings rarely have a contiguous displacement field:
    /// a RISC-V B-type immediate arrives in four pieces, and AArch64 branch
    /// offsets are pre-shifted. The function is handed the bytes already
    /// emitted, read as an integer in the target's byte order, plus the
    /// resolved value, and returns the patched word.
    ///
    /// A plain `fn` pointer keeps [`FixupKind`] `Copy` and lets each backend
    /// keep its bit-placement next to the instruction it belongs to.
    Scatter(fn(u64, i64) -> u64),
}

/// How a fixup's value is written into the output.
#[derive(Copy, Clone, Debug)]
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
    /// How many bits of the value the field can hold. `0` means the whole
    /// field, `size * 8`.
    ///
    /// A 4-byte AArch64 instruction word carrying a 26-bit branch offset has
    /// `size: 4` but `value_bits: 28` — 26 encoded bits plus the two that the
    /// alignment supplies.
    pub value_bits: u8,
    /// The value must be a multiple of this. `1` means no constraint.
    ///
    /// Branch displacements on fixed-width architectures are counted in
    /// instructions, so a misaligned target is an error rather than something
    /// to round.
    pub value_align: u8,
    pub encoding: FieldEncoding,
    /// Whether a PC-relative relocation's addend carries the `adjust` bias.
    ///
    /// Relocations disagree about where "here" is. x86-64's `PC32` is
    /// `S + A - P` with `P` the field itself, so a field four bytes short of
    /// the end of its instruction needs `A = -4`, and GNU as writes that. The
    /// Renesas-lineage targets — RL78, RX, V850 — define theirs from the
    /// instruction, and GNU as writes `A = 0`. Same-section resolution is
    /// unaffected either way; this only decides what the linker is handed.
    pub bias_reloc_addend: bool,
    /// Narrower bounds than the field's width allows, where a reference
    /// assembler picks a form by a range that is not a power of two.
    pub limits: Option<(i64, i64)>,
    /// Relaxation sizes this field the way GNU as's RX port sizes a symbolic
    /// immediate, rather than by whether the value fits.
    ///
    /// `rx_relax_frag` only knows a value for a difference of two local
    /// labels in the fixup's own section, and takes the smallest field whose
    /// signed range holds it. It does not move labels ahead of the
    /// instruction by the growth so far, as it does for a branch target:
    /// it adds that growth to the whole difference, and only when the
    /// difference, read as an unsigned address, lies past the instruction.
    /// Anything it cannot evaluate gets the widest field. `range` still
    /// decides whether the value that is finally written is accepted.
    pub relax_difference: bool,
}

impl FixupKind {
    pub fn data(size: u8) -> FixupKind {
        FixupKind {
            size,
            pcrel: false,
            signed: false,
            adjust: 0,
            reloc: 0,
            value_bits: 0,
            value_align: 1,
            encoding: FieldEncoding::Whole,
            bias_reloc_addend: true,
            limits: None,
            relax_difference: false,
        }
    }

    pub fn pcrel(size: u8, adjust: i8) -> FixupKind {
        FixupKind {
            pcrel: true,
            signed: true,
            adjust,
            ..FixupKind::data(size)
        }
    }

    pub fn with_reloc(mut self, reloc: u32) -> FixupKind {
        self.reloc = reloc;
        self
    }

    pub fn signed(mut self) -> FixupKind {
        self.signed = true;
        self
    }

    /// Constrains the field to `bits` bits of value, requiring the value to be
    /// a multiple of `align`.
    pub fn with_field(mut self, bits: u8, align: u8) -> FixupKind {
        self.value_bits = bits;
        self.value_align = align.max(1);
        self
    }

    /// Leaves the `adjust` bias out of the relocation addend; see
    /// [`FixupKind::bias_reloc_addend`].
    pub fn unbiased_reloc(mut self) -> FixupKind {
        self.bias_reloc_addend = false;
        self
    }

    /// Accepts only values from `lo` to `hi`, within what the field holds.
    pub fn with_limits(mut self, lo: i64, hi: i64) -> FixupKind {
        self.limits = Some((lo, hi));
        self
    }

    /// Sizes the field during relaxation as GNU as's RX port does; see
    /// [`FixupKind::relax_difference`].
    pub fn relaxed_as_difference(mut self) -> FixupKind {
        self.relax_difference = true;
        self
    }

    /// Sets the function that scatters the value through the instruction word.
    pub fn scatter(mut self, f: fn(u64, i64) -> u64) -> FixupKind {
        self.encoding = FieldEncoding::Scatter(f);
        self
    }

    /// How many bits of value the field holds.
    pub fn bits(&self) -> u32 {
        if self.value_bits > 0 {
            self.value_bits as u32
        } else {
            self.size as u32 * 8
        }
    }

    /// Inclusive range of values this field can hold.
    pub fn range(&self) -> (i128, i128) {
        let (lo, hi) = self.field_range();
        match self.limits {
            Some((l, h)) => (lo.max(l as i128), hi.min(h as i128)),
            None => (lo, hi),
        }
    }

    fn field_range(&self) -> (i128, i128) {
        let bits = self.bits();
        if bits >= 128 {
            return (i128::MIN, i128::MAX);
        }
        if self.signed {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            // Accept both the unsigned and the sign-extended reading, which is
            // what assemblers do for `.byte -1` as well as `.byte 255`.
            (-(1i128 << (bits - 1)), (1i128 << bits) - 1)
        }
    }

    pub fn fits(&self, v: i128) -> bool {
        if self.value_align > 1 && v % self.value_align as i128 != 0 {
            return false;
        }
        if self.bits() >= 64 && self.limits.is_none() {
            return true;
        }
        let (lo, hi) = self.range();
        v >= lo && v <= hi
    }

    /// Applies `value` to the `size` bytes at `dst`, in the target's byte
    /// order.
    pub fn write(&self, endian: crate::arch::Endian, dst: &mut [u8], value: i64) {
        let word = match self.encoding {
            FieldEncoding::Whole => value as u64,
            FieldEncoding::Scatter(f) => f(endian.read(dst), value),
        };
        endian.write(dst, word);
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
        Variant {
            bytes,
            fixups: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum FragKind {
    /// Literal bytes. Instructions that can be encoded several ways list all
    /// candidates smallest-first; layout raises `chosen` until every fixup
    /// fits, and never lowers it, so the loop terminates.
    Bytes {
        variants: Vec<Variant>,
        chosen: usize,
    },
    /// Pad to a multiple of `align`, at most `max_skip` bytes.
    Align {
        align: u64,
        fill: Vec<u8>,
        max_skip: Option<u64>,
        /* filled by layout */ pad: u64,
    },
    /// Advance the location counter to an absolute offset within the section.
    Org {
        target: ExprRef,
        fill: u8,
        size: u64,
    },
    /// `.space` / `.skip`: `size` bytes of `fill`.
    Space {
        size: ExprRef,
        fill: ExprRef,
        resolved: u64,
    },
    /// A variable-length integer whose width depends on its value.
    Leb128 {
        value: ExprRef,
        signed: bool,
        encoded: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct Fragment {
    pub kind: FragKind,
    pub span: Span,
    /// Offset from the start of the section, assigned by layout.
    pub offset: u64,
    /// The reference assembler gives this instruction a fragment that its
    /// relaxation revisits, even though it has only one encoding here. A
    /// difference of labels on either side of it is then not a constant
    /// while the file is read; see [`crate::arch::AsmCtx::fixed_distance`].
    pub relaxable: bool,
}

impl Fragment {
    pub fn new(kind: FragKind, span: Span) -> Fragment {
        Fragment {
            kind,
            span,
            offset: 0,
            relaxable: false,
        }
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
            && let FragKind::Bytes { variants, .. } = &mut self.frags[i].kind
        {
            variants[0].bytes.extend_from_slice(bytes);
            self.frags[i].span = self.frags[i].span.to(span);
            return;
        }
        let idx = self.frags.len();
        self.frags.push(Fragment::new(
            FragKind::Bytes {
                variants: vec![Variant::new(bytes.to_vec())],
                chosen: 0,
            },
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
                    FragKind::Bytes {
                        variants: vec![Variant::default()],
                        chosen: 0,
                    },
                    span,
                ));
                self.open_data = Some(i);
                (i, 0)
            }
        };
        let FragKind::Bytes { variants, .. } = &mut self.frags[idx].kind else {
            unreachable!()
        };
        variants[0].bytes.extend_from_slice(&placeholder);
        variants[0].fixups.push(Fixup {
            offset: base,
            expr,
            kind,
            span,
        });
        self.frags[idx].span = self.frags[idx].span.to(span);
    }

    /// Appends a pre-encoded instruction with one or more size variants.
    pub fn emit_variants(&mut self, variants: Vec<Variant>, span: Span) -> u32 {
        debug_assert!(
            !variants.is_empty(),
            "an instruction needs at least one encoding"
        );
        self.push(Fragment::new(
            FragKind::Bytes {
                variants,
                chosen: 0,
            },
            span,
        ))
    }

    pub fn is_empty(&self) -> bool {
        self.frags.iter().all(|f| f.size() == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Endian;

    #[test]
    fn whole_fields_are_written_in_target_byte_order() {
        let k = FixupKind::data(4);
        let mut buf = [0u8; 4];
        k.write(Endian::Little, &mut buf, 0x1122_3344);
        assert_eq!(buf, [0x44, 0x33, 0x22, 0x11]);
        k.write(Endian::Big, &mut buf, 0x1122_3344);
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn scattered_fields_merge_into_the_instruction_word() {
        // The shape every fixed-width RISC branch needs: keep the opcode bits
        // already emitted, drop the value's low zero bits, and mask it into
        // the field. This is AArch64's `b` — a 26-bit field of word offsets.
        fn aarch64_b(word: u64, value: i64) -> u64 {
            (word & !0x03ff_ffff) | (((value >> 2) as u64) & 0x03ff_ffff)
        }
        let k = FixupKind::pcrel(4, 0).with_field(28, 4).scatter(aarch64_b);

        // `b .+8` starting from the opcode word 0x1400_0000.
        let mut buf = 0x1400_0000u32.to_le_bytes();
        k.write(Endian::Little, &mut buf, 8);
        assert_eq!(u32::from_le_bytes(buf), 0x1400_0002);

        // A negative offset must not corrupt the opcode bits above the field.
        let mut buf = 0x1400_0000u32.to_le_bytes();
        k.write(Endian::Little, &mut buf, -8);
        assert_eq!(u32::from_le_bytes(buf), 0x17ff_fffe);
    }

    #[test]
    fn field_width_and_alignment_are_checked_separately_from_size() {
        // A 4-byte field that only carries 28 bits of value.
        let k = FixupKind::pcrel(4, 0).with_field(28, 4);
        assert!(k.fits(128 * 1024 * 1024 - 4));
        assert!(!k.fits(128 * 1024 * 1024), "out of range must not fit");
        assert!(k.fits(-(128 * 1024 * 1024)));
        // Misaligned targets are rejected rather than rounded.
        assert!(!k.fits(2));
        assert!(k.fits(4));
    }

    #[test]
    fn the_relocation_bias_is_on_by_default_and_can_be_dropped() {
        // Every existing backend relies on the x86-style bias, so it must stay
        // the default; the Renesas-lineage targets opt out.
        assert!(FixupKind::pcrel(4, 4).bias_reloc_addend);
        assert!(!FixupKind::pcrel(1, 1).unbiased_reloc().bias_reloc_addend);
        // Dropping the bias does not touch how the field resolves locally.
        let k = FixupKind::pcrel(1, 1).unbiased_reloc();
        assert_eq!(k.adjust, 1);
    }

    #[test]
    fn byte_fields_accept_both_signed_and_unsigned_spellings() {
        let k = FixupKind::data(1);
        assert!(k.fits(255));
        assert!(k.fits(-1));
        assert!(!k.fits(256));
        assert!(!k.fits(-129));
    }
}
