//! Linking assembled objects into a program with qld.

#![cfg(all(feature = "link", feature = "x86"))]

mod common;
use common::*;

use rsasm::diag::DiagBag;
use rsasm::link::{self, Kind, Options};
use rsasm::output::{self, Format};

/// The example from the README: a freestanding Linux program that writes a
/// line and exits, with an entry point and no dependency on a runtime.
const HELLO: &str = r#"
        .section .rodata
msg:    .ascii  "Hello from rsasm!\n"
msglen = . - msg

        .text
        .globl  _start
_start:
        movq    $1, %rax
        movq    $1, %rdi
        leaq    msg(%rip), %rsi
        movq    $msglen, %rdx
        syscall

        movq    $60, %rax
        xorq    %rdi, %rdi
        syscall
"#;

/// Assembles `src` for x86-64 and returns the ELF object bytes.
fn object(src: &str) -> Vec<u8> {
    let asm = assemble_for("x86-64", src);
    assert!(
        !asm.diags.has_errors(),
        "{}",
        asm.diags.render(&asm.sm, false)
    );
    output::elf::build(&asm).expect("ELF output")
}

fn u16at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Checks the ELF header of a 64-bit little-endian executable and returns
/// its entry address. The field offsets and the constants are the ones in
/// the ELF specification, not bytes read out of a particular image.
fn executable_header(image: &[u8], e_type: u16) -> u64 {
    assert!(image.len() > 64, "an ELF header is 64 bytes");
    assert_eq!(&image[..4], b"\x7fELF");
    assert_eq!(image[4], 2, "ELFCLASS64");
    assert_eq!(image[5], 1, "ELFDATA2LSB");
    assert_eq!(u16at(image, 16), e_type, "e_type");
    assert_eq!(u16at(image, 18), 62, "e_machine is EM_X86_64");
    let entry = u64at(image, 24);
    let phoff = u64at(image, 32) as usize;
    let phentsize = u16at(image, 54) as usize;
    let phnum = u16at(image, 56) as usize;
    assert!(phnum > 0, "an executable has program headers");
    // PT_LOAD is 1: without one there is nothing for a loader to map.
    let loads = (0..phnum)
        .map(|i| u32at(image, phoff + i * phentsize))
        .filter(|&p_type| p_type == 1)
        .count();
    assert!(loads > 0, "at least one PT_LOAD");
    entry
}

/// The program header of type `p_type`, if the image has one.
fn segment(image: &[u8], p_type: u32) -> Option<usize> {
    let phoff = u64at(image, 32) as usize;
    let phentsize = u16at(image, 54) as usize;
    let phnum = u16at(image, 56) as usize;
    (0..phnum)
        .map(|i| phoff + i * phentsize)
        .find(|&at| u32at(image, at) == p_type)
}

#[test]
fn links_a_freestanding_program_in_memory() {
    let mut diags = DiagBag::new();
    let image = link::link(
        vec![("hello.o".to_string(), object(HELLO))],
        &Options::new(),
        &mut diags,
    )
    .expect("the link succeeds");
    assert!(!diags.has_errors(), "{}", diags.len());

    // ET_EXEC is 2: a static executable is linked at a fixed address.
    let entry = executable_header(&image, 2);
    assert_ne!(entry, 0, "the entry point is `_start`, which is defined");
    // Nothing completes a static executable, so it names no interpreter.
    // PT_INTERP is 3.
    assert!(segment(&image, 3).is_none(), "no PT_INTERP");
}

#[test]
fn a_named_entry_symbol_is_used() {
    let src = "\
        .text\n\
        .globl begin\n\
begin:  movq $60, %rax\n\
        xorq %rdi, %rdi\n\
        syscall\n";
    let mut diags = DiagBag::new();
    let image = link::link(
        vec![("begin.o".to_string(), object(src))],
        &Options::new().with_entry("begin"),
        &mut diags,
    )
    .expect("the link succeeds");
    assert_ne!(executable_header(&image, 2), 0);
}

#[test]
fn a_position_independent_executable_is_et_dyn() {
    let mut diags = DiagBag::new();
    let image = link::link(
        vec![("hello.o".to_string(), object(HELLO))],
        &Options::new().with_kind(Kind::Pie),
        &mut diags,
    )
    .expect("the link succeeds");
    // ET_DYN is 3, which is what both a PIE and a shared library are.
    executable_header(&image, 3);
}

#[test]
fn an_undefined_symbol_is_an_rsasm_diagnostic() {
    let src = "\
        .text\n\
        .globl _start\n\
_start: callq nowhere\n";
    let mut diags = DiagBag::new();
    let error = link::link(
        vec![("undef.o".to_string(), object(src))],
        &Options::new(),
        &mut diags,
    )
    .expect_err("the link fails");
    assert!(diags.has_errors(), "the failure reached the diag bag");
    let rendered = diags.render(&rsasm::source::SourceMap::new(), false);
    assert!(rendered.contains("nowhere"), "{rendered}");
    assert!(rendered.starts_with("error: "), "{rendered}");
    assert!(!error.to_string().is_empty());
}

#[test]
fn qld_does_not_link_every_machine_rsasm_assembles() {
    // EM_X86_64 and EM_AARCH64 in ELF and PE32+; nothing else, and no flat
    // image, which has no relocations left to resolve anyway.
    assert!(link::supports(Format::Elf, 62));
    assert!(link::supports(Format::Coff, 62));
    assert!(link::supports(Format::Elf, 183));
    // EM_386 is 3, EM_RISCV is 243.
    assert!(!link::supports(Format::Elf, 3));
    assert!(!link::supports(Format::Elf, 243));
    assert!(!link::supports(Format::Binary, 62));
    assert!(!link::supports(Format::MachO, 62));
}

/// A PE/COFF object links into a PE32+ image, which is the other container
/// qld writes. Nothing here can run it — this host is not Windows — so the
/// check is that the bytes are the image the PE specification describes.
#[test]
fn links_a_pe32_plus_image() {
    let arch = rsasm::arch::lookup("x86-64").expect("the x86 backend");
    let options = rsasm::assembler::Options::new().with_format(Format::Coff);
    let mut asm = rsasm::assembler::Assembler::new(arch, options);
    asm.assemble_str(
        "start.s",
        ".text\n.globl mainCRTStartup\nmainCRTStartup:\n xorl %eax, %eax\n ret\n",
    );
    assert!(asm.finish(), "{}", asm.diags.render(&asm.sm, false));
    let obj = output::coff::build(&asm).expect("COFF output");

    let mut diags = DiagBag::new();
    let image = link::link(
        vec![("start.o".to_string(), obj)],
        &Options::new().with_target(Format::Coff, 62),
        &mut diags,
    )
    .expect("the link succeeds");

    // The DOS stub, then the PE signature it points at, then the optional
    // header: all offsets and constants from the PE specification.
    assert_eq!(&image[..2], b"MZ");
    let pe = u32at(&image, 0x3c) as usize;
    assert_eq!(&image[pe..pe + 4], b"PE\0\0");
    assert_eq!(u16at(&image, pe + 4), 0x8664, "IMAGE_FILE_MACHINE_AMD64");
    let optional = pe + 24;
    assert_eq!(u16at(&image, optional), 0x20b, "PE32+");
    assert_ne!(u32at(&image, optional + 16), 0, "AddressOfEntryPoint");
}

/// Writes `image` somewhere runnable and makes it executable.
#[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
fn runnable(name: &str, image: &[u8]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!("rsasm-link-{}-{name}", std::process::id()));
    std::fs::write(&path, image).expect("write the image");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("make it executable");
    path
}

/// The same program the `cli_smoke` CI job assembles, links and runs, with
/// the link done in this process instead of by GNU ld. The bytes being a
/// well-formed ELF image is one thing; the kernel agreeing to run it, and
/// the program printing what it was written to print, is another.
#[test]
#[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
fn the_linked_program_runs() {
    let mut diags = DiagBag::new();
    let image = link::link(
        vec![("hello.o".to_string(), object(HELLO))],
        &Options::new(),
        &mut diags,
    )
    .expect("the link succeeds");
    let path = runnable("hello", &image);
    let out = std::process::Command::new(&path)
        .output()
        .expect("run the linked program");
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "{:?}", out.status);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "Hello from rsasm!\n");
}

/// A directory holding glibc's startup files and `libc.so`, if the host has
/// one where this test knows to look.
#[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
fn glibc_dir() -> Option<std::path::PathBuf> {
    [
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib",
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .find(|dir| dir.join("crt1.o").is_file() && dir.join("libc.so").exists())
}

/// A dynamic link against the system libc. Unlike every other test here it
/// reads files the host may not have — the startup objects, `libc.so` and
/// the program interpreter belong to glibc, not to rsasm — so it skips
/// rather than fails when they are missing.
#[test]
#[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
fn links_against_the_system_libc() {
    const INTERPRETER: &str = "/lib64/ld-linux-x86-64.so.2";
    let Some(dir) = glibc_dir() else {
        eprintln!("skipping: no glibc startup files on this host");
        return;
    };
    if !std::path::Path::new(INTERPRETER).exists() {
        eprintln!("skipping: no {INTERPRETER} on this host");
        return;
    }
    let src = "\
        .section .rodata\n\
msg:    .asciz \"Hello from rsasm and libc!\"\n\
        .text\n\
        .globl main\n\
main:   subq $8, %rsp\n\
        leaq msg(%rip), %rdi\n\
        call puts@PLT\n\
        xorl %eax, %eax\n\
        addq $8, %rsp\n\
        ret\n";
    // The startup files bracket the program: `crt1.o` defines `_start` and
    // calls `main`, and `crti.o` and `crtn.o` are the two halves of the
    // `.init` and `.fini` sections glibc expects around it.
    let options = Options::new()
        .with_kind(Kind::Executable)
        .with_dynamic_linker(INTERPRETER)
        .with_search_path(&dir)
        .with_library(":crt1.o")
        .with_library(":crti.o")
        .with_library("c")
        .with_library(":crtn.o");
    let mut diags = DiagBag::new();
    let image = match link::link(
        vec![("main.o".to_string(), object(src))],
        &options,
        &mut diags,
    ) {
        Ok(image) => image,
        Err(error) => {
            let rendered = diags.render(&rsasm::source::SourceMap::new(), false);
            panic!("the dynamic link failed: {error}\n{rendered}");
        }
    };
    // ET_EXEC, with an interpreter for the loader to hand it to. PT_INTERP
    // is 3.
    executable_header(&image, 2);
    assert!(segment(&image, 3).is_some(), "PT_INTERP");

    let path = runnable("libc", &image);
    let out = std::process::Command::new(&path)
        .output()
        .expect("run the linked program");
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "{:?}", out.status);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Hello from rsasm and libc!\n"
    );
}
