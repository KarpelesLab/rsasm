//! Shared helpers for the integration tests.
//!
//! The `*_for` functions take an architecture name, so a backend's tests need
//! nothing added here.

#![allow(dead_code)]

use rsasm::arch;
use rsasm::assembler::{Assembler, Options};
use rsasm::section::SectionId;

/// Assembles `src` for `arch` and returns the bytes of its first section.
pub fn text_for(arch: &str, src: &str) -> Vec<u8> {
    match try_text_for(arch, src) {
        Ok(b) => b,
        Err(e) => panic!("assembly failed for `{arch}`:\n{e}\nsource:\n{src}"),
    }
}

pub fn try_text_for(arch: &str, src: &str) -> Result<Vec<u8>, String> {
    let asm = assemble_for(arch, src);
    if asm.diags.has_errors() {
        return Err(asm.diags.render(&asm.sm, false));
    }
    Ok(asm.section_bytes(SectionId(0)))
}

/// Assembles `src` for `arch`, expecting failure, and returns the rendered
/// diagnostics.
pub fn errors_for(arch: &str, src: &str) -> String {
    match try_text_for(arch, src) {
        Ok(_) => panic!("expected an error, but assembly succeeded:\n{src}"),
        Err(e) => e,
    }
}

/// Assembles `src` and hands the finished assembler back for inspection.
pub fn assemble_for(arch: &str, src: &str) -> Assembler {
    let arch = arch::lookup(arch).unwrap_or_else(|| panic!("no `{arch}` backend in this build"));
    let mut asm = Assembler::new(arch, Options::default());
    asm.assemble_str("test.s", src);
    asm.finish();
    asm
}

/// Assembles `src` for flat binary output based at `base`.
pub fn assemble_flat_for(arch: &str, src: &str, base: u64) -> Assembler {
    let arch = arch::lookup(arch).unwrap_or_else(|| panic!("no `{arch}` backend in this build"));
    let options = Options {
        relocatable: false,
        base_addr: base,
        ..Options::default()
    };
    let mut asm = Assembler::new(arch, options);
    asm.assemble_str("test.s", src);
    asm.finish();
    asm
}

/// The bytes of a section, looked up by name.
pub fn section(asm: &Assembler, name: &str) -> Vec<u8> {
    let id = asm
        .sections
        .iter()
        .find(|s| asm.interner.get(s.name) == name)
        .unwrap_or_else(|| panic!("no section named `{name}`"))
        .id;
    asm.section_bytes(id)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---- x86 shorthands, kept so the existing tests read unchanged ------------

pub fn text(src: &str) -> Vec<u8> {
    text_for("x86-64", src)
}

pub fn try_text(src: &str) -> Result<Vec<u8>, String> {
    try_text_for("x86-64", src)
}

pub fn errors(src: &str) -> String {
    errors_for("x86-64", src)
}

pub fn assemble(src: &str) -> Assembler {
    assemble_for("x86-64", src)
}

pub fn assemble_flat(src: &str, base: u64) -> Assembler {
    assemble_flat_for("x86-64", src, base)
}
