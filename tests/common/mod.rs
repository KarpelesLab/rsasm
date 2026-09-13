//! Shared helpers for the integration tests.

#![allow(dead_code)]

use rsasm::arch;
use rsasm::assembler::{Assembler, Options};
use rsasm::section::SectionId;

/// Assembles `src` and returns the bytes of its `.text` section.
pub fn text(src: &str) -> Vec<u8> {
    match try_text(src) {
        Ok(b) => b,
        Err(e) => panic!("assembly failed:\n{e}\nsource:\n{src}"),
    }
}

pub fn try_text(src: &str) -> Result<Vec<u8>, String> {
    let arch = arch::lookup("x86-64").expect("x86 backend is enabled");
    let mut asm = Assembler::new(arch, Options::default());
    asm.assemble_str("test.s", src);
    let ok = asm.finish();
    if !ok || asm.diags.has_errors() {
        return Err(asm.diags.render(&asm.sm, false));
    }
    Ok(asm.section_bytes(SectionId(0)))
}

/// Assembles `src` expecting failure, returning the rendered diagnostics.
pub fn errors(src: &str) -> String {
    match try_text(src) {
        Ok(_) => panic!("expected an error, but assembly succeeded:\n{src}"),
        Err(e) => e,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}
