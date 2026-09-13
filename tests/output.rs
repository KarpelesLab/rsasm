//! Object and flat-binary output.

mod common;
use common::*;

use rsasm::output;

fn elf(src: &str) -> Vec<u8> {
    let asm = assemble(src);
    assert!(!asm.diags.has_errors(), "{}", asm.diags.render(&asm.sm, false));
    output::elf::build(&asm).expect("ELF output")
}

fn u16at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Section headers as (name, type, flags, size).
fn sections_of(b: &[u8]) -> Vec<(String, u32, u64, u64)> {
    let shoff = u64at(b, 0x28) as usize;
    let shnum = u16at(b, 0x3c) as usize;
    let shstrndx = u16at(b, 0x3e) as usize;
    let strtab_off = u64at(b, shoff + shstrndx * 64 + 0x18) as usize;
    (0..shnum)
        .map(|i| {
            let sh = shoff + i * 64;
            let name_off = strtab_off + u32at(b, sh) as usize;
            let end = b[name_off..].iter().position(|&c| c == 0).unwrap() + name_off;
            (
                String::from_utf8_lossy(&b[name_off..end]).into_owned(),
                u32at(b, sh + 4),
                u64at(b, sh + 8),
                u64at(b, sh + 0x20),
            )
        })
        .collect()
}

#[test]
fn elf_header_is_well_formed() {
    let b = elf("nop\n");
    assert_eq!(&b[..4], b"\x7fELF");
    assert_eq!(b[4], 2, "ELFCLASS64");
    assert_eq!(b[5], 1, "little endian");
    assert_eq!(b[6], 1, "version");
    assert_eq!(u16at(&b, 0x10), 1, "ET_REL");
    assert_eq!(u16at(&b, 0x12), 62, "EM_X86_64");
    assert_eq!(u16at(&b, 0x34), 64, "e_ehsize");
    assert_eq!(u16at(&b, 0x3a), 64, "e_shentsize");
    // Section headers must lie inside the file.
    let shoff = u64at(&b, 0x28) as usize;
    let shnum = u16at(&b, 0x3c) as usize;
    assert_eq!(shoff + shnum * 64, b.len());
}

#[test]
fn sections_carry_the_right_types_and_flags() {
    let b = elf(".text\nnop\n.data\n.byte 1\n.bss\n.space 8\n.section .note.x,\"\",@note\n.byte 0\n");
    let secs = sections_of(&b);
    let find = |n: &str| secs.iter().find(|s| s.0 == n).unwrap_or_else(|| panic!("no {n}"));

    // SHT_PROGBITS = 1, SHT_NOBITS = 8, SHT_NOTE = 7.
    // SHF_ALLOC = 2, SHF_EXECINSTR = 4, SHF_WRITE = 1.
    assert_eq!(find(".text").1, 1);
    assert_eq!(find(".text").2, 2 | 4);
    assert_eq!(find(".data").2, 2 | 1);
    assert_eq!(find(".bss").1, 8);
    assert_eq!(find(".bss").3, 8, ".bss has a size but no file content");
    assert_eq!(find(".note.x").1, 7);
    assert!(secs.iter().any(|s| s.0 == ".symtab"));
    assert!(secs.iter().any(|s| s.0 == ".strtab"));
    assert!(secs.iter().any(|s| s.0 == ".shstrtab"));
    // The null header comes first and stays empty.
    assert_eq!(secs[0].0, "");
    assert_eq!(secs[0].1, 0);
}

#[test]
fn relocations_are_emitted_for_unresolved_references() {
    let asm = assemble("call printf@PLT\nmovq gvar(%rip), %rax\n.quad gvar\n");
    assert!(!asm.diags.has_errors(), "{}", asm.diags.render(&asm.sm, false));
    assert_eq!(asm.relocs.len(), 3);
    // R_X86_64_PLT32 = 4, PC32 = 2, 64 = 1.
    let kinds: Vec<u32> = asm.relocs.iter().map(|r| r.kind).collect();
    assert_eq!(kinds, vec![4, 2, 1]);
    // A PC-relative field is biased by its own width.
    assert_eq!(asm.relocs[0].addend, -4);
    assert_eq!(asm.relocs[1].addend, -4);
    assert_eq!(asm.relocs[2].addend, 0);
    // The object must actually contain a .rela.text.
    let b = output::elf::build(&asm).unwrap();
    assert!(sections_of(&b).iter().any(|s| s.0 == ".rela.text" && s.1 == 4));
}

#[test]
fn local_references_relocate_against_their_section() {
    // A reference to a local label in another section goes through that
    // section's symbol, with the label's offset folded into the addend.
    let asm = assemble(".data\n.byte 0\nlocal: .byte 0\n.text\n.quad local\n");
    assert_eq!(asm.relocs.len(), 1);
    let r = &asm.relocs[0];
    assert_eq!(r.addend, 1, "the label's offset becomes the addend");
    assert_eq!(rsasm::symbol::SymType::Section, asm.symbols.get(r.symbol).ty);
}

#[test]
fn same_section_references_need_no_relocation() {
    let asm = assemble("target: nop\njmp target\ncall target\n");
    assert!(asm.relocs.is_empty(), "{:?}", asm.relocs);
}

#[test]
fn flat_binary_places_sections_at_their_addresses() {
    let asm = assemble_flat(".text\nnop\n.data\n.byte 0xaa\n", 0x1000);
    let out = output::raw::build(&asm).unwrap();
    // .text is one byte, .data follows it.
    assert_eq!(out, vec![0x90, 0xaa]);

    // A flat image resolves absolute references rather than deferring them.
    let asm = assemble_flat(".text\nfoo:\n.quad foo\n", 0x1000);
    let out = output::raw::build(&asm).unwrap();
    assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0x1000);
    assert!(asm.relocs.is_empty());
}

#[test]
fn flat_binary_reports_undefined_symbols() {
    let arch = rsasm::arch::lookup("x86-64").unwrap();
    let options = rsasm::assembler::Options {
        relocatable: false,
        ..rsasm::assembler::Options::default()
    };
    let mut asm = rsasm::assembler::Assembler::new(arch, options);
    asm.assemble_str("t.s", ".quad nosuch\n");
    asm.finish();
    let e = asm.diags.render(&asm.sm, false);
    assert!(e.contains("undefined symbol `nosuch`"), "{e}");
}

#[test]
fn empty_input_produces_a_valid_object() {
    let b = elf("");
    assert_eq!(&b[..4], b"\x7fELF");
    // Even with nothing in it, the tables are present and consistent.
    let secs = sections_of(&b);
    assert!(secs.iter().any(|s| s.0 == ".symtab"));
}
