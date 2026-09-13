//! ELF64 relocatable object output.
//!
//! Only `ET_REL` is produced: rsasm is an assembler, so linking is somebody
//! else's job. ELF32 is not implemented yet, and the writer says so rather
//! than emitting something a linker would misread.

use super::OutputError;
use crate::assembler::Assembler;
use crate::section::{SectionId, SectionKind};
use crate::symbol::{Binding, SymType, SymbolId, SymbolValue, Visibility};
use std::collections::HashMap;

const EI_NIDENT: usize = 16;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const EV_CURRENT: u8 = 1;
const ET_REL: u16 = 1;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_NOTE: u32 = 7;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_MERGE: u64 = 0x10;
const SHF_STRINGS: u64 = 0x20;
const SHF_TLS: u64 = 0x400;

const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_TLS: u8 = 6;

const SYM_SIZE: u64 = 24;
const RELA_SIZE: u64 = 24;
const SHDR_SIZE: u64 = 64;
const EHDR_SIZE: u64 = 64;

/// A growable string table with deduplication of whole strings.
#[derive(Default)]
struct StrTab {
    bytes: Vec<u8>,
    seen: HashMap<String, u32>,
}

impl StrTab {
    fn new() -> StrTab {
        StrTab { bytes: vec![0], seen: HashMap::new() }
    }

    fn add(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&o) = self.seen.get(s) {
            return o;
        }
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.seen.insert(s.to_string(), off);
        off
    }
}

/// Little-endian byte sink. ELF is written in the target's byte order, which
/// for every architecture here is the same order as the data it describes.
struct Buf {
    out: Vec<u8>,
    big_endian: bool,
}

impl Buf {
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    fn u16(&mut self, v: u16) {
        if self.big_endian {
            self.out.extend_from_slice(&v.to_be_bytes());
        } else {
            self.out.extend_from_slice(&v.to_le_bytes());
        }
    }
    fn u32(&mut self, v: u32) {
        if self.big_endian {
            self.out.extend_from_slice(&v.to_be_bytes());
        } else {
            self.out.extend_from_slice(&v.to_le_bytes());
        }
    }
    fn u64(&mut self, v: u64) {
        if self.big_endian {
            self.out.extend_from_slice(&v.to_be_bytes());
        } else {
            self.out.extend_from_slice(&v.to_le_bytes());
        }
    }
    fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }
    fn pad_to(&mut self, align: u64) {
        while self.out.len() as u64 % align != 0 {
            self.out.push(0);
        }
    }
    fn len(&self) -> u64 {
        self.out.len() as u64
    }
}

/// One section header, filled in as the layout is decided.
#[derive(Default, Clone)]
struct Shdr {
    name: u32,
    ty: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

/// An assembler symbol that made it into the ELF symbol table.
struct OutSym {
    id: SymbolId,
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

pub fn build(asm: &Assembler) -> Result<Vec<u8>, OutputError> {
    if asm.arch.pointer_bytes(&asm.arch_state) != 8 {
        return Err(OutputError::Unsupported(
            "ELF32 output is not implemented yet; only 64-bit targets can be written as ELF"
                .into(),
        ));
    }

    let mut shstrtab = StrTab::new();
    let mut strtab = StrTab::new();

    // ---- decide which ELF sections exist ---------------------------------
    // Index 0 is the null header; then one per assembler section that has
    // content, then a .rela for each of those with relocations, then the
    // symbol and string tables.
    let mut shdrs: Vec<Shdr> = vec![Shdr { ty: SHT_NULL, ..Shdr::default() }];
    let mut sec_index: HashMap<SectionId, u16> = HashMap::new();
    let mut emitted: Vec<SectionId> = Vec::new();

    for s in &asm.sections {
        if s.size == 0 && s.frags.is_empty() {
            continue;
        }
        let idx = shdrs.len() as u16;
        sec_index.insert(s.id, idx);
        emitted.push(s.id);
        let name = asm.interner.get(s.name).to_string();
        shdrs.push(Shdr {
            name: shstrtab.add(&name),
            ty: match s.kind {
                SectionKind::Nobits => SHT_NOBITS,
                SectionKind::Note => SHT_NOTE,
                SectionKind::Progbits => SHT_PROGBITS,
            },
            flags: elf_flags(&s.flags),
            addr: 0,
            offset: 0,
            size: s.size,
            link: 0,
            info: 0,
            addralign: s.align.max(1),
            entsize: s.entsize,
        });
    }

    // ---- build the symbol table ------------------------------------------
    let (syms, first_global) = collect_symbols(asm, &sec_index, &mut strtab);
    let sym_index: HashMap<SymbolId, u32> = syms
        .iter()
        .enumerate()
        // +1 for the reserved null entry.
        .map(|(i, s)| (s.id, i as u32 + 1))
        .collect();

    // Relocation sections, one per section that needs them.
    let mut relocs_by_section: HashMap<SectionId, Vec<&crate::assembler::Relocation>> =
        HashMap::new();
    for r in &asm.relocs {
        relocs_by_section.entry(r.section).or_default().push(r);
    }
    let mut rela_for: Vec<(SectionId, u16)> = Vec::new();
    for &sid in &emitted {
        let Some(list) = relocs_by_section.get(&sid) else { continue };
        if list.is_empty() {
            continue;
        }
        let target = sec_index[&sid];
        let name = format!(".rela{}", asm.interner.get(asm.section(sid).name));
        let idx = shdrs.len() as u16;
        rela_for.push((sid, idx));
        shdrs.push(Shdr {
            name: shstrtab.add(&name),
            ty: SHT_RELA,
            flags: 0,
            addr: 0,
            offset: 0,
            size: list.len() as u64 * RELA_SIZE,
            // Patched below once the symtab index is known.
            link: 0,
            info: target as u32,
            addralign: 8,
            entsize: RELA_SIZE,
        });
    }

    let symtab_idx = shdrs.len() as u16;
    shdrs.push(Shdr {
        name: shstrtab.add(".symtab"),
        ty: SHT_SYMTAB,
        flags: 0,
        addr: 0,
        offset: 0,
        size: (syms.len() as u64 + 1) * SYM_SIZE,
        link: 0, // patched: .strtab
        info: first_global + 1,
        addralign: 8,
        entsize: SYM_SIZE,
    });
    let strtab_idx = shdrs.len() as u16;
    shdrs.push(Shdr {
        name: shstrtab.add(".strtab"),
        ty: SHT_STRTAB,
        flags: 0,
        addr: 0,
        offset: 0,
        size: 0, // patched
        link: 0,
        info: 0,
        addralign: 1,
        entsize: 0,
    });
    let shstrtab_idx = shdrs.len() as u16;
    shdrs.push(Shdr {
        name: shstrtab.add(".shstrtab"),
        ty: SHT_STRTAB,
        flags: 0,
        addr: 0,
        offset: 0,
        size: 0, // patched
        link: 0,
        info: 0,
        addralign: 1,
        entsize: 0,
    });

    shdrs[symtab_idx as usize].link = strtab_idx as u32;
    for (_, idx) in &rela_for {
        shdrs[*idx as usize].link = symtab_idx as u32;
    }

    // ---- lay the file out -------------------------------------------------
    let big_endian = asm.arch.endian() == crate::arch::Endian::Big;
    let mut buf = Buf { out: Vec::new(), big_endian };
    buf.out.resize(EHDR_SIZE as usize, 0);

    for &sid in &emitted {
        let i = sec_index[&sid] as usize;
        let s = asm.section(sid);
        if s.kind == SectionKind::Nobits {
            // No file space, but the offset still has to look plausible.
            shdrs[i].offset = buf.len();
            continue;
        }
        buf.pad_to(shdrs[i].addralign.max(1));
        shdrs[i].offset = buf.len();
        let bytes = asm.section_bytes(sid);
        debug_assert_eq!(bytes.len() as u64, s.size, "section bytes disagree with layout");
        buf.out.extend_from_slice(&bytes);
    }

    for (sid, idx) in &rela_for {
        buf.pad_to(8);
        shdrs[*idx as usize].offset = buf.len();
        for r in &relocs_by_section[sid] {
            let sym = sym_index.get(&r.symbol).copied().unwrap_or(0);
            buf.u64(r.offset);
            buf.u64(((sym as u64) << 32) | r.kind as u64);
            buf.i64(r.addend);
        }
    }

    buf.pad_to(8);
    shdrs[symtab_idx as usize].offset = buf.len();
    // The reserved null symbol.
    for _ in 0..SYM_SIZE {
        buf.u8(0);
    }
    for s in &syms {
        buf.u32(s.name);
        buf.u8(s.info);
        buf.u8(s.other);
        buf.u16(s.shndx);
        buf.u64(s.value);
        buf.u64(s.size);
    }

    shdrs[strtab_idx as usize].offset = buf.len();
    shdrs[strtab_idx as usize].size = strtab.bytes.len() as u64;
    buf.out.extend_from_slice(&strtab.bytes);

    shdrs[shstrtab_idx as usize].offset = buf.len();
    shdrs[shstrtab_idx as usize].size = shstrtab.bytes.len() as u64;
    buf.out.extend_from_slice(&shstrtab.bytes);

    buf.pad_to(8);
    let shoff = buf.len();
    for sh in &shdrs {
        buf.u32(sh.name);
        buf.u32(sh.ty);
        buf.u64(sh.flags);
        buf.u64(sh.addr);
        buf.u64(sh.offset);
        buf.u64(sh.size);
        buf.u32(sh.link);
        buf.u32(sh.info);
        buf.u64(sh.addralign);
        buf.u64(sh.entsize);
    }

    // ---- header -----------------------------------------------------------
    let mut hdr = Buf { out: Vec::new(), big_endian };
    let mut ident = [0u8; EI_NIDENT];
    ident[0..4].copy_from_slice(b"\x7fELF");
    ident[4] = ELFCLASS64;
    ident[5] = if big_endian { ELFDATA2MSB } else { ELFDATA2LSB };
    ident[6] = EV_CURRENT;
    hdr.out.extend_from_slice(&ident);
    hdr.u16(ET_REL);
    hdr.u16(asm.arch.elf_machine());
    hdr.u32(EV_CURRENT as u32);
    hdr.u64(0); // e_entry
    hdr.u64(0); // e_phoff
    hdr.u64(shoff);
    hdr.u32(0); // e_flags
    hdr.u16(EHDR_SIZE as u16);
    hdr.u16(0); // e_phentsize
    hdr.u16(0); // e_phnum
    hdr.u16(SHDR_SIZE as u16);
    hdr.u16(shdrs.len() as u16);
    hdr.u16(shstrtab_idx);
    buf.out[..EHDR_SIZE as usize].copy_from_slice(&hdr.out);

    Ok(buf.out)
}

fn elf_flags(f: &crate::section::SectionFlags) -> u64 {
    let mut v = 0;
    if f.alloc {
        v |= SHF_ALLOC;
    }
    if f.write {
        v |= SHF_WRITE;
    }
    if f.exec {
        v |= SHF_EXECINSTR;
    }
    if f.merge {
        v |= SHF_MERGE;
    }
    if f.strings {
        v |= SHF_STRINGS;
    }
    if f.tls {
        v |= SHF_TLS;
    }
    v
}

/// Collects the symbols worth writing, locals first as ELF requires.
///
/// Returns the symbols and the index of the last local, which becomes the
/// symbol table's `sh_info`.
fn collect_symbols(
    asm: &Assembler,
    sec_index: &HashMap<SectionId, u16>,
    strtab: &mut StrTab,
) -> (Vec<OutSym>, u32) {
    let mut locals = Vec::new();
    let mut globals = Vec::new();

    for (id, sym) in asm.symbols.iter() {
        // Numeric local labels and the anonymous labels standing in for `.`
        // are assembler bookkeeping; they never reach the object file.
        if sym.local_number.is_some() {
            continue;
        }
        let raw = asm.interner.get(sym.name);
        let is_synthetic = raw.contains('\u{0}');
        if is_synthetic && sym.ty != SymType::Section {
            continue;
        }
        if !sym.is_defined() && !sym.used {
            continue;
        }

        let (shndx, value) = match &sym.value {
            SymbolValue::Label { section, .. } => {
                let Some(&idx) = sec_index.get(section) else { continue };
                (idx, asm.symbol_addr(id).unwrap_or(0) as u64)
            }
            SymbolValue::Common { align, .. } => (SHN_COMMON, *align),
            // An `.equ` naming a label belongs to that label's section, the
            // way GNU as places it; anything else is absolute.
            SymbolValue::Expr(_) => match asm.symbol_target_section(id) {
                Some((section, off)) => match sec_index.get(&section) {
                    Some(&idx) => (idx, off),
                    None => continue,
                },
                None => (SHN_ABS, asm.symbol_number(id).unwrap_or(0) as u64),
            },
            SymbolValue::Undefined => (SHN_UNDEF, 0),
        };

        let bind = match sym.binding {
            Binding::Local => STB_LOCAL,
            Binding::Global => STB_GLOBAL,
            Binding::Weak => STB_WEAK,
        };
        let ty = match sym.ty {
            SymType::NoType => STT_NOTYPE,
            SymType::Object => STT_OBJECT,
            SymType::Func => STT_FUNC,
            SymType::Section => STT_SECTION,
            SymType::File => STT_FILE,
            SymType::Tls => STT_TLS,
        };
        let other = match sym.visibility {
            Visibility::Default => 0,
            Visibility::Internal => 1,
            Visibility::Hidden => 2,
            Visibility::Protected => 3,
        };
        let size = match &sym.value {
            SymbolValue::Common { size, .. } => *size,
            _ => sym.size.and_then(|e| asm.eval_const(e)).unwrap_or(0) as u64,
        };

        // A section symbol is named by its section, not by a string of its own.
        let name = if sym.ty == SymType::Section { 0 } else { strtab.add(raw) };

        let out = OutSym { id, name, info: (bind << 4) | ty, other, shndx, value, size };
        // An undefined symbol is always global: the linker has to find it.
        if bind == STB_LOCAL && sym.is_defined() {
            locals.push(out);
        } else {
            globals.push(out);
        }
    }

    // Section symbols sort first among locals, which is what linkers expect
    // and what makes `.rela` entries against them readable.
    locals.sort_by_key(|s| (s.info & 0xf) != STT_SECTION);

    let first_global = locals.len() as u32;
    locals.extend(globals);
    (locals, first_global)
}
