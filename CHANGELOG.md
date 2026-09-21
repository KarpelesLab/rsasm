# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The public API is now a small, documented surface: `Assembler` and the
  methods that drive it, `Options` and its `with_*` builders, `output::Format`
  and the writers' `build`, `arch::lookup` with the `Architecture` trait,
  `section::SectionId`, the diagnostics types and `lexer::Dialect`. The
  backends, the lexer internals, the expression arena, the interner, the
  parser, the macro engine, the layout and the relocation classes are no
  longer reachable, or are marked `Not API.` and hidden from the docs.
- `Options` is `#[non_exhaustive]` and its fields are private; build it with
  `Options::new()` and `with_relocatable`, `with_base_addr`,
  `with_include_path`, `with_dialect`, `with_syntax`, `with_dwarf_version`,
  `with_debug_source` and `with_format`, and read it back with the matching
  getters.
- The public enums and structs that will keep growing are `#[non_exhaustive]`,
  so matching on `Format`, `Dialect`, `SectionKind`, `Severity` and the rest
  needs a wildcard arm outside the crate.

## [0.1.1](https://github.com/KarpelesLab/rsasm/compare/v0.1.0...v0.1.1) - 2026-09-14

### Other

- Tidy the 8051 backend, and cache AS's headers in CI
- Add Intel HEX output, and document and test the 8051
- Add an Intel 8051 (MCS-51) backend
- Merge master: ARM literal pools and mapping symbols, x86 32- and 16-bit coverage
- Describe the assembly source with -g, and check the compilation units
- Merge master: per-fragment backends, NASM, symbol preemption, section alignment
- Write GNU as's version 2 line tables with its opcode base of 10
- Share CIEs as GNU as 2.47 does, and place RX rows where its port does
- Check DWARF from GCC and Clang output for every target Clang assembles
- Assemble GCC's debug-info output for x86: .value, dashed section names, short inc/dec
- Accept 32-bit push and pop outside long mode
- Match the references' frame alignment, CIE sharing and relocated fields
- Write .debug_line and .eh_frame/.debug_frame from .loc and .cfi_* directives
- Update the cross-assembler case count
- Merge RX label-difference immediates folded and relaxed as GNU as does
- Merge re-lexing after a mid-file .arch, with per-fragment targets
- Merge SuperH PC-relative load ranges, data alignment and in-order relaxation
- Run the flat-binary link comparison in CI
- Merge flat-binary resolution of page, split and paired fixups
- Resolve page, split and paired relocations in flat binaries
- Relax RX branches the way GNU as does, shrinking included
- Keep the macro expander on Rust 1.89, and the CC-RL include test on Windows
- Merge the CC-RL, CC-RH and CC-RX dialects
- Read Renesas CC-RX source with -d ccrx
- Read Renesas CC-RL and CC-RH source with -d ccrl and -d ccrh
- Bring the README up to date with fourteen backends and the cross harness
- Write e_flags the way each target's reference assembler does
- Put SuperH addends in the field, and give MIPS n64 RELA relocations
- Relocate sym - label as PC-relative when the label is in the field's section
- Read quoted strings the Motorola and Renesas way
- Add the m68k backend: 68000/68010/68020, Motorola and GNU syntax
- Let the cross-assembler harness share one oracle build
- Scaffold six backends and a cross-assembler differential harness
- Remove a stray a.out, and ignore it
- Add the Motorola and Renesas dialects
- Pin the llvm-mc oracle to LLVM 22, and fix the docs build
- Give i386 objects i386 relocation numbers, and keep the ELF class fixed
- Let the lexer classify malformed numbers instead of reporting them
- Add SIMD to the x86 backend: MMX through AVX-512
- Split the x86 instruction table into one module per family
- Make the test helpers architecture-generic
- Let a fixup scatter its value through an instruction word
- Add an llvm-mc differential harness and scaffold seven new backends
- Add CI, crates.io, docs.rs and license badges to the README
