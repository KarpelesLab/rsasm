# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/KarpelesLab/rsasm/compare/v0.1.3...v0.1.4) - 2026-09-26

### Other

- Merge the RISC-V thread-local operands and descriptors
- Merge master's ARM coprocessor loads into the RISC-V thread-local operands
- Merge master's AArch64 and m68k work into the RISC-V thread-local operands
- Merge master's MIPS and SPARC thread-local operators into the RISC-V ones
- Assemble RISC-V's thread-local operands, in RV32 and RV64
- Recompute the counts after the ARM thread-local merge
- Merge the ARM thread-local suffixes and marks
- Recompute the counts after the thread-local and common-symbol merges
- Merge the common-symbol alignment and directive-only symbols
- Merge the PowerPC thread-local modifiers
- Give PowerPC its thread-local access models, in both word sizes
- Bring the Mach-O count up to the thread-local cases
- Merge ARM loads that name a label
- Recount the ARM row and the harness totals after the PC-relative loads
- Merge remote-tracking branch 'origin/master' into worktree-agent-ac8c8e5ff29ea168b
- Assemble ARM loads that name a label instead of a pool entry
- Merge the ARM relocation suffixes and the halves of an address
- Merge the SPARC floating-point families
- Merge the AArch64 address-group operators and the pmov index
- Merge the PowerPC branch and halfword relocation modifiers
- Merge the MIPS condition flags, conditional moves and jalx
- Merge master into the condition-flag work
- Name the floating-point condition flags, and assemble jalx
- Say why the not-generated list starts at 2
- Write down the flat-binary branch width NASM and rsasm disagree on
- List the pmov spelling among what AArch64's fuzzer drops
- Record the `pmov` index the AArch64 table does not have
- Say what the branch-over-a-gap cases are for, and what they found
- Say what the RISC-V program cases reach, and what they found
- Mention FUZZ_TIMEOUT in the runner's documentation
- Account for what other seeds turn up
- Say in the RISC-V fuzzer's docstring what the program cases are for
- Kill a fuzzer that hangs, and say which one it was
- Check for llvm-readobj before the fuzz job runs
- Describe the three whole-program fuzzers in the README
- Say how much the fuzz job runs and how long it takes
- Merge master: one long branch candidate, the shorter of the two
- Fold an index with no base in the NASM dialect
- Give CI three times the cases: 745,000 in under two minutes
- Record the `adr` expression GNU as refuses
- Account for what a heavier run turns up
- Fuzz the NASM dialect against NASM
- Narrow the RL78 truncation rule to branches
- cargo fmt
- Fuzz whole branches over a gap, not only single instructions
- List the new fuzzers in both READMEs
- Merge branch 'master' into worktree-agent-aacdb62e96c7282d5
- Fuzz the 6502 and the 8080, and expand a RISC-V branch that cannot reach
- cargo fmt
- Run the fuzzers in CI, and say how to repeat a failure
- Fuzz SuperH, RX, RL78, V850 and the Z80
- Fuzz SPARC, and read the forms its disassembler prints
- Fuzz RISC-V and MIPS, and read the aliases both references read
- Give every fuzzer one summary line and a runner to drive them from
- Refuse a wide pool entry that is not a number in the engine too
- Say what the pools hold in the README, and keep an overflow quiet
- Test the wider and narrower pool entries
- Put the pool layouts in the ARM and Thumb corpora
- Share a pool entry by what the source wrote, not by its i64
- Assemble the VFP and halfword literal loads
- Give the literal pool a per-backend layout policy
- Merge the release commit
- Reconcile the ARM pool findings with the DWARF comparison
- ARM whole-program pool fuzzer, and fixes it found

## [0.1.3](https://github.com/KarpelesLab/rsasm/compare/v0.1.2...v0.1.3) - 2026-09-21

### Other

- Merge the v0.1.2 release commit
- Assemble bic, bics, orn and eon with an immediate

## [0.1.2](https://github.com/KarpelesLab/rsasm/compare/v0.1.1...v0.1.2) - 2026-09-21

### Other

- Have the hexdump example read diagnostics through the accessors
- Cut the public API down to the surface that is actually supported
- keep the vector operand types out of the public API
- Document the ARM vector instructions and how their table is derived
- Merge master into the ARM vector work
- corpora and tests for the vector instructions
- fuzz the vector instructions, and what that turned up
- the NEON structure loads and stores
- the VFP and NEON data-processing instructions
- corpora and tests for the rest of the instruction set
- fuzz both instruction sets against GNU as and llvm-mc
- the user-mode and exception-return block transfers
- the Thumb-2 forms, ldrd/strd, the preloads, cbz and banked msr
- derive the instruction table from GNU's own
- Merge the x86 AVX-512 subsets, VEX extensions and AVX10
- Merge the 680x0 FPU, MMU and ColdFire instruction sets
- keep the new tables and CPU model out of the crate's public API
- Merge master: the Intel 8051 backend and PowerPC's vector instructions
- note the ColdFire check in generic's module docs
- the rest of the 680x0 family
- check the hand-written encoders' output against GNU's ColdFire forms
- m68k fuzzer: vasm mode with GNU as as tie-breaker; READMEs for the fuzzer and xas-diff keys
- tests for the FPU, MMU, CPU models, float formats, e_flags and relaxation
- keep FPU and MMU addresses absolute, as the integer instructions do
- e_flags as GNU as writes them, PC-relative stand-ins only within a section, .arch in multiarch-diff
- hand-written corpora for the FPU, MMU, relaxation and .arch
- corpora covering every form of GNU's table, one key per CPU model
- fuzz against GNU as; emulate far DBcc, jump to numbers, ColdFire index rules
- generate GNU's opcode table and encode the rest of the 680x0 family from it

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
