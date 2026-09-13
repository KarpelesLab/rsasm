//! Layout, relaxation and fixup resolution.
//!
//! Fragment sizes and symbol addresses depend on each other: an alignment's
//! padding depends on where it lands, and where it lands depends on how long
//! the branches before it turned out to be. The pass below iterates to a fixed
//! point. Instruction sizes only ever grow — `chosen` never decreases — so the
//! branch half of the loop always terminates; the whole loop is bounded as
//! well, since a `.org` or `.space` whose size depends on a later symbol can
//! be written to oscillate.

use crate::assembler::{Assembler, Relocation};
use crate::expr::{ExprKind, ExprRef, Value};
use crate::section::{FixupKind, FragKind, SectionId, SectionKind};
use crate::source::Span;
use crate::symbol::{Binding, SymbolId, SymbolValue};

/// Enough passes for any realistic file; hitting the limit means the input is
/// self-referential in a way that cannot settle.
const MAX_PASSES: u32 = 32;

/// What a fragment's size depends on, extracted so the size computation can
/// call back into the assembler without holding a borrow on the fragment.
enum Task {
    Fixed(u64),
    Align {
        align: u64,
        max_skip: Option<u64>,
    },
    Org {
        target: ExprRef,
        span: Span,
    },
    Space {
        size: ExprRef,
        span: Span,
    },
    Leb {
        value: ExprRef,
        signed: bool,
        span: Span,
    },
}

impl Assembler {
    /// Resolves everything and prepares the sections for output. Returns false
    /// if errors were reported.
    pub fn finish(&mut self) -> bool {
        self.report_undefined_locals();

        let mut settled = false;
        for _ in 0..MAX_PASSES {
            // Addresses are assigned from the previous pass's sizes before
            // this pass computes new ones. For relocatable output every
            // section sits at zero and this changes nothing; for a flat image
            // it is what lets `.space start + 4 - 0x8000`, or a zero-page
            // choice on the 6502, see where a label really is rather than its
            // offset within the section. The loop only ends on a pass where no
            // size changed, and addresses are a function of sizes, so the
            // addresses that pass used are the final ones.
            self.assign_addresses();
            let sizes_changed = self.assign_offsets();
            let relaxed = self.relax();
            if !sizes_changed && !relaxed {
                settled = true;
                break;
            }
        }
        if !settled {
            self.diags.error(
                Span::DUMMY,
                "could not settle section layout; a `.org`, `.space` or `.align` \
                 probably depends on a symbol that it also moves",
            );
            return false;
        }

        self.assign_addresses();
        self.apply_fixups();
        self.materialize();
        !self.diags.has_errors()
    }

    /// Walks every section assigning fragment offsets, recomputing the sizes
    /// that depend on them. Returns true if any size changed.
    fn assign_offsets(&mut self) -> bool {
        let mut changed = false;
        for si in 0..self.sections.len() {
            let mut off: u64 = 0;
            for fi in 0..self.sections[si].frags.len() {
                self.sections[si].frags[fi].offset = off;
                let prev = self.sections[si].frags[fi].size();
                let task = self.task_for(si, fi);
                let (size, encoded) = self.compute_size(si, off, task);
                // Cache the result on the fragment so `Fragment::size` stays
                // cheap and consistent between passes.
                match &mut self.sections[si].frags[fi].kind {
                    FragKind::Align { pad, .. } => *pad = size,
                    FragKind::Org { size: slot, .. } => *slot = size,
                    FragKind::Space { resolved, .. } => *resolved = size,
                    FragKind::Leb128 { encoded: slot, .. } => {
                        if let Some(e) = encoded {
                            *slot = e;
                        }
                    }
                    FragKind::Bytes { .. } => {}
                }
                if prev != size {
                    changed = true;
                }
                off = off.saturating_add(size);
            }
            if self.sections[si].size != off {
                self.sections[si].size = off;
                changed = true;
            }
        }
        changed
    }

    fn task_for(&self, si: usize, fi: usize) -> Task {
        let f = &self.sections[si].frags[fi];
        match &f.kind {
            FragKind::Bytes { variants, chosen } => {
                Task::Fixed(variants[*chosen].bytes.len() as u64)
            }
            FragKind::Align {
                align, max_skip, ..
            } => Task::Align {
                align: *align,
                max_skip: *max_skip,
            },
            FragKind::Org { target, .. } => Task::Org {
                target: *target,
                span: f.span,
            },
            FragKind::Space { size, .. } => Task::Space {
                size: *size,
                span: f.span,
            },
            FragKind::Leb128 { value, signed, .. } => Task::Leb {
                value: *value,
                signed: *signed,
                span: f.span,
            },
        }
    }

    /// Computes a fragment's size, plus the encoded bytes for LEB128.
    fn compute_size(&mut self, si: usize, off: u64, task: Task) -> (u64, Option<Vec<u8>>) {
        match task {
            Task::Fixed(n) => (n, None),
            Task::Align { align, max_skip } => {
                let pad = if align <= 1 {
                    0
                } else {
                    off.next_multiple_of(align) - off
                };
                // `.align n,,max` skips the padding entirely when it would
                // cost more than `max` bytes.
                match max_skip {
                    Some(m) if pad > m => (0, None),
                    _ => (pad, None),
                }
            }
            Task::Org { target, span } => {
                let id = SectionId(si as u32);
                let Some(t) = self.resolve_section_relative(target, id) else {
                    self.diags
                        .error(span, "`.org` target must resolve to a fixed offset");
                    return (0, None);
                };
                if t < off as i64 {
                    self.diags.error(
                        span,
                        format!("`.org` cannot move backwards, from offset {off} to {t}"),
                    );
                    return (0, None);
                }
                ((t as u64) - off, None)
            }
            Task::Space { size, span } => {
                let Some(n) = self.eval_absolute_quiet(size) else {
                    self.diags
                        .error(span, "`.space` size must be an absolute value");
                    return (0, None);
                };
                if n < 0 {
                    self.diags.error(span, "`.space` size must not be negative");
                    return (0, None);
                }
                (n as u64, None)
            }
            Task::Leb {
                value,
                signed,
                span,
            } => {
                let v = match self.eval_absolute_quiet(value) {
                    Some(v) => v,
                    None => {
                        self.diags
                            .error(span, "LEB128 value must be an absolute value");
                        0
                    }
                };
                let encoded = if signed {
                    sleb128(v)
                } else {
                    uleb128(v as u64)
                };
                (encoded.len() as u64, Some(encoded))
            }
        }
    }

    fn relax(&mut self) -> bool {
        let mut changed = false;
        for si in 0..self.sections.len() {
            for fi in 0..self.sections[si].frags.len() {
                let (nvariants, chosen, frag_off) = match &self.sections[si].frags[fi].kind {
                    FragKind::Bytes { variants, chosen } => {
                        (variants.len(), *chosen, self.sections[si].frags[fi].offset)
                    }
                    _ => continue,
                };
                if nvariants <= 1 || chosen + 1 >= nvariants {
                    continue;
                }
                let fixups: Vec<(u32, ExprRef, FixupKind)> = match &self.sections[si].frags[fi].kind
                {
                    FragKind::Bytes { variants, .. } => variants[chosen]
                        .fixups
                        .iter()
                        .map(|f| (f.offset, f.expr, f.kind))
                        .collect(),
                    _ => continue,
                };
                let id = SectionId(si as u32);
                let all_fit = fixups.iter().all(|(off, e, kind)| {
                    let at = frag_off + *off as u64;
                    match self.fixup_value(*e, kind, id, at) {
                        Some(v) => kind.fits(v as i128),
                        // An unresolved reference takes the widest form on
                        // offer. Nothing is known about how far away its
                        // target will be, so any shorter form is a guess the
                        // linker may not be able to honour: a RISC-V `c.j`
                        // carries a relocation, but reaches only ±2 KiB.
                        // llvm-mc makes the same choice (checked: `j sym` to
                        // an undefined `sym` is a full `R_RISCV_JAL`). The
                        // widest variant is never bumped past, since `relax`
                        // stops at the last one.
                        None => false,
                    }
                });
                if !all_fit {
                    if let FragKind::Bytes { chosen, .. } = &mut self.sections[si].frags[fi].kind {
                        *chosen += 1;
                    }
                    changed = true;
                }
            }
        }
        changed
    }

    /// Gives each section a base address. Relocatable output leaves them all
    /// at zero; absolute output lays them out end to end.
    fn assign_addresses(&mut self) {
        if self.options.relocatable {
            for s in &mut self.sections {
                s.addr = 0;
            }
            return;
        }
        let mut addr = self.options.base_addr;
        for s in &mut self.sections {
            addr = addr.next_multiple_of(s.align.max(1));
            s.addr = addr;
            addr += s.size;
        }
    }

    // ---- value resolution -------------------------------------------------

    /// The address a symbol resolves to, if it has one yet.
    pub(crate) fn symbol_addr(&self, id: SymbolId) -> Option<i64> {
        match self.symbols.get(id).value {
            SymbolValue::Label { section, frag } => {
                let s = self.section(section);
                let off = match s.frags.get(frag as usize) {
                    Some(f) => f.offset,
                    // A label at the very end of a section has no fragment of
                    // its own; it sits at the section's current size.
                    None => s.size,
                };
                Some((s.addr + off) as i64)
            }
            _ => None,
        }
    }

    fn symbol_section(&self, id: SymbolId) -> Option<SectionId> {
        match self.symbols.get(id).value {
            SymbolValue::Label { section, .. } => Some(section),
            _ => None,
        }
    }

    /// Reduces a [`Value`] to a number, if every symbol in it has an address.
    pub(crate) fn resolve_value(&self, v: Value) -> Option<i64> {
        let mut n = v.addend;
        if let Some(p) = v.plus {
            n = n.wrapping_add(self.symbol_addr(p)?);
        }
        if let Some(m) = v.minus {
            n = n.wrapping_sub(self.symbol_addr(m)?);
        }
        Some(n)
    }

    /// Evaluates an expression, ignoring errors (the caller reports its own).
    fn eval_absolute_quiet(&mut self, e: ExprRef) -> Option<i64> {
        let v = self.eval(e).ok()?;
        self.resolve_value(v)
    }

    /// Resolves an expression to an offset within `section`.
    ///
    /// `.org 64` gives a plain number, which is already section-relative,
    /// while `. = . + 16` gives an address, which has to have the section base
    /// taken off it.
    fn resolve_section_relative(&mut self, e: ExprRef, section: SectionId) -> Option<i64> {
        let v = self.eval(e).ok()?;
        if v.is_absolute() {
            return Some(v.addend);
        }
        if v.plus
            .is_some_and(|p| self.symbol_section(p) == Some(section))
            && v.minus.is_none()
        {
            let addr = self.resolve_value(v)?;
            return Some(addr - self.section(section).addr as i64);
        }
        None
    }

    /// The number a fixup should write, or `None` if it needs a relocation.
    fn fixup_value(
        &mut self,
        e: ExprRef,
        kind: &FixupKind,
        section: SectionId,
        at: u64,
    ) -> Option<i64> {
        let v = self.eval(e).ok()?;
        // Within one section the two section bases cancel, so a PC-relative
        // reference resolves even in relocatable output. Across sections it
        // resolves only once the sections have real addresses.
        if kind.pcrel {
            if self.options.relocatable
                && v.plus
                    .is_some_and(|p| self.symbol_section(p) != Some(section))
            {
                return None;
            }
            let target = self.resolve_value(v)?;
            let here = (self.section(section).addr + at) as i64 + kind.adjust as i64;
            return Some(target - here);
        }
        // The distance between two labels in one section is fixed no matter
        // where the linker puts that section, so it resolves even in
        // relocatable output.
        if let (Some(p), Some(m)) = (v.plus, v.minus) {
            let (ps, ms) = (self.symbol_section(p), self.symbol_section(m));
            if ps.is_some() && ps == ms {
                return self.resolve_value(v);
            }
            return None;
        }
        // An absolute reference to a section-relative symbol can only be
        // resolved here when the output is not going to be relocated.
        if !v.is_absolute() && self.options.relocatable {
            return None;
        }
        self.resolve_value(v)
    }

    // ---- writing ----------------------------------------------------------

    fn apply_fixups(&mut self) {
        let mut relocs = Vec::new();
        // Under a REL psABI the addend lives in the field being relocated
        // rather than in the relocation entry, so it has to be written here
        // while the field is still reachable. Relocation numbering is ELF's
        // throughout, so asking the ELF writer which convention the target
        // uses is consistent rather than a layering slip.
        let addend_in_field = !crate::output::elf::uses_rela(self.arch.elf_machine());
        for si in 0..self.sections.len() {
            let id = SectionId(si as u32);
            for fi in 0..self.sections[si].frags.len() {
                let frag_off = self.sections[si].frags[fi].offset;
                let list: Vec<(u32, ExprRef, FixupKind, Span)> =
                    match &self.sections[si].frags[fi].kind {
                        FragKind::Bytes { variants, chosen } => variants[*chosen]
                            .fixups
                            .iter()
                            .map(|f| (f.offset, f.expr, f.kind, f.span))
                            .collect(),
                        _ => continue,
                    };
                for (off, e, kind, span) in list {
                    let at = frag_off + off as u64;
                    match self.fixup_value(e, &kind, id, at) {
                        Some(v) => {
                            if !kind.fits(v as i128) {
                                self.diags.error(span, range_message(&kind, v));
                                continue;
                            }
                            let endian = self.arch.endian();
                            if let FragKind::Bytes { variants, chosen } =
                                &mut self.sections[si].frags[fi].kind
                            {
                                let dst = &mut variants[*chosen].bytes
                                    [off as usize..off as usize + kind.size as usize];
                                kind.write(endian, dst, v);
                            }
                        }
                        None => {
                            if let Some(r) = self.build_relocation(e, &kind, id, at, span) {
                                if addend_in_field && r.addend != 0 {
                                    let endian = self.arch.endian();
                                    if let FragKind::Bytes { variants, chosen } =
                                        &mut self.sections[si].frags[fi].kind
                                    {
                                        let dst = &mut variants[*chosen].bytes
                                            [off as usize..off as usize + kind.size as usize];
                                        kind.write(endian, dst, r.addend);
                                    }
                                }
                                relocs.push(r);
                            }
                        }
                    }
                }
            }
        }
        self.relocs = relocs;
    }

    fn build_relocation(
        &mut self,
        e: ExprRef,
        kind: &FixupKind,
        section: SectionId,
        at: u64,
        span: Span,
    ) -> Option<Relocation> {
        let v = match self.eval(e) {
            Ok(v) => v,
            Err(err) => {
                self.diags.emit(err.into_diagnostic());
                return None;
            }
        };
        if v.minus.is_some() {
            self.diags.error(
                span,
                "the difference of two symbols in different sections cannot be relocated",
            );
            return None;
        }
        let Some(target) = v.plus else {
            self.diags.error(span, "cannot resolve this value");
            return None;
        };
        if !self.options.relocatable {
            let name = self.display_name(target);
            self.diags.error(span, format!("undefined symbol `{name}`"));
            return None;
        }

        // A modifier anywhere in the expression selects the relocation.
        let reloc = self
            .find_modifier(e)
            .and_then(|m| {
                let name = self.interner.get(m).to_string();
                self.arch.modifier_reloc(&name, kind.size, kind.pcrel)
            })
            .unwrap_or(kind.reloc);
        if reloc == 0 {
            self.diags.error(
                span,
                format!(
                    "no relocation exists for a {}-byte {}reference",
                    kind.size,
                    if kind.pcrel { "PC-relative " } else { "" }
                ),
            );
            return None;
        }

        let mut addend = v.addend - if kind.pcrel { kind.adjust as i64 } else { 0 };

        // Local symbols are relocated against their section, which is what
        // linkers expect and what keeps local labels out of the symbol table.
        let sym = self.symbols.get(target);
        let symbol =
            if sym.binding == Binding::Local && matches!(sym.value, SymbolValue::Label { .. }) {
                let sec = self.symbol_section(target).expect("label has a section");
                addend += self.symbol_addr(target).unwrap_or(0) - self.section(sec).addr as i64;
                self.section_symbol(sec)
            } else {
                self.symbols.get_mut(target).used = true;
                target
            };

        Some(Relocation {
            section,
            offset: at,
            symbol,
            addend,
            kind: reloc,
        })
    }

    /// The first `@`-modifier appearing in an expression, if any.
    pub(crate) fn find_modifier(&self, e: ExprRef) -> Option<crate::intern::Name> {
        match &self.exprs.get(e).kind {
            ExprKind::Modifier(n, _) => Some(*n),
            ExprKind::Unary(_, a) => self.find_modifier(*a),
            ExprKind::Binary(_, a, b) => self.find_modifier(*a).or_else(|| self.find_modifier(*b)),
            _ => None,
        }
    }

    /// The symbol standing for a whole section, created on first use.
    pub(crate) fn section_symbol(&mut self, id: SectionId) -> SymbolId {
        if let Some(s) = self.section(id).sym {
            return s;
        }
        let name = self.section(id).name;
        let sym = self.symbols.intern_section(name, id);
        self.section_mut(id).sym = Some(sym);
        sym
    }

    /// Turns alignment, `.org` and `.space` fragments into real bytes so the
    /// output writers only ever see byte runs.
    fn materialize(&mut self) {
        for si in 0..self.sections.len() {
            if self.sections[si].kind == SectionKind::Nobits {
                continue;
            }
            let exec = self.sections[si].flags.exec;
            for fi in 0..self.sections[si].frags.len() {
                let size = self.sections[si].frags[fi].size() as usize;
                let bytes = match &self.sections[si].frags[fi].kind {
                    FragKind::Bytes { .. } => continue,
                    FragKind::Align { fill, .. } => {
                        if fill.is_empty() && exec {
                            self.arch.nop_fill(&self.arch_state, size as u64)
                        } else {
                            let pattern: &[u8] = if fill.is_empty() { &[0] } else { fill };
                            pattern.iter().copied().cycle().take(size).collect()
                        }
                    }
                    FragKind::Org { fill, .. } => vec![*fill; size],
                    FragKind::Space { fill, .. } => {
                        let byte = self.eval_absolute_quiet(*fill).unwrap_or(0) as u8;
                        vec![byte; size]
                    }
                    FragKind::Leb128 { encoded, .. } => encoded.clone(),
                };
                debug_assert_eq!(bytes.len(), size, "materialized fragment changed size");
                self.sections[si].frags[fi].kind = FragKind::Bytes {
                    variants: vec![crate::section::Variant::new(bytes)],
                    chosen: 0,
                };
            }
        }
    }

    /// The final bytes of a section, in order.
    pub fn section_bytes(&self, id: SectionId) -> Vec<u8> {
        let s = self.section(id);
        if s.kind == SectionKind::Nobits {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(s.size as usize);
        for f in &s.frags {
            match &f.kind {
                FragKind::Bytes { variants, chosen } => {
                    out.extend_from_slice(&variants[*chosen].bytes)
                }
                _ => out.resize(out.len() + f.size() as usize, 0),
            }
        }
        out
    }
}

/// Explains why a value does not fit its field, naming the actual limit.
///
/// A field's byte width is rarely the constraint that matters: a MIPS branch
/// lives in a four-byte word but holds ±128 KiB in steps of four. Saying
/// "out of range for a 4-byte field" sends the reader to the wrong limit, and
/// calling a misaligned target "out of range" sends them to the wrong problem.
fn range_message(kind: &FixupKind, v: i64) -> String {
    let what = if kind.pcrel { "offset" } else { "value" };
    let align = kind.value_align as i128;
    if align > 1 && (v as i128) % align != 0 {
        return format!("{what} {v} is not a multiple of {align}");
    }
    let (lo, hi) = kind.range();
    format!("{what} {v} is out of range ({} to {})", show(lo), show(hi))
}

/// Prints a bound in whichever base reads better: small limits in decimal,
/// the large ones as the power-of-two-ish hex they really are.
fn show(n: i128) -> String {
    if n.unsigned_abs() < 0x1_0000 {
        n.to_string()
    } else if n < 0 {
        format!("-{:#x}", n.unsigned_abs())
    } else {
        format!("{n:#x}")
    }
}

pub fn uleb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

pub fn sleb128(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        // Stop once the remaining bits are all copies of the sign bit that the
        // last emitted byte already carries.
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb_matches_the_dwarf_examples() {
        assert_eq!(uleb128(0), vec![0]);
        assert_eq!(uleb128(2), vec![2]);
        assert_eq!(uleb128(127), vec![127]);
        assert_eq!(uleb128(128), vec![0x80, 1]);
        assert_eq!(uleb128(624485), vec![0xe5, 0x8e, 0x26]);
    }

    #[test]
    fn sleb_matches_the_dwarf_examples() {
        assert_eq!(sleb128(2), vec![2]);
        assert_eq!(sleb128(-2), vec![0x7e]);
        assert_eq!(sleb128(127), vec![0xff, 0]);
        assert_eq!(sleb128(-127), vec![0x81, 0x7f]);
        assert_eq!(sleb128(128), vec![0x80, 1]);
        assert_eq!(sleb128(-128), vec![0x80, 0x7f]);
    }
}
