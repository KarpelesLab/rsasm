# rsasm

[![CI](https://github.com/KarpelesLab/rsasm/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/rsasm/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rsasm.svg)](https://crates.io/crates/rsasm)
[![docs.rs](https://img.shields.io/docsrs/rsasm)](https://docs.rs/rsasm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An assembler written in Rust, aiming at three things at once: accept the asm
text people actually have, target many CPUs, and let one source file emit code
for more than one of them.

```console
$ cat hello.s
        .section .rodata
msg:    .ascii  "Hello from rsasm!\n"
msglen = . - msg

        .text
        .globl  _start
_start:
        movq    $1, %rax                # write
        movq    $1, %rdi                # stdout
        leaq    msg(%rip), %rsi
        movq    $msglen, %rdx
        syscall
        movq    $60, %rax               # exit
        xorq    %rdi, %rdi
        syscall

$ rsasm -o hello.o hello.s && ld -o hello hello.o && ./hello
Hello from rsasm!
```

## Install

```console
$ cargo install rsasm
```

Prebuilt binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/KarpelesLab/rsasm/releases).

## Status

Early, but broad. The pipeline is complete end to end — lex, parse, encode,
lay out, relax, relocate, write — with eight backends behind it.

### Architectures

Every encoding claimed below is checked byte for byte against an independent
assembler, not against rsasm's own idea of the manual. See
[Verification](#verification).

| Target | Names | Checked against | Cases |
|---|---|---|---|
| x86-64, i386, i8086 | `x86-64` `i386` `i8086` | GNU as | 118 |
| AArch64 | `aarch64` | llvm-mc | 475 |
| ARM A32 / Thumb | `arm` `thumb` | llvm-mc | 361 |
| RISC-V RV32/RV64 IMAFDC | `riscv32` `riscv64` | llvm-mc | 485 |
| PowerPC 32/64, both endians | `powerpc` `powerpc64` `powerpc64le` | llvm-mc | 1044 |
| MIPS 32/64, both endians | `mips` `mipsel` `mips64` `mips64el` | llvm-mc | 654 |
| SPARC V8 / V9 | `sparc` `sparcv9` | llvm-mc | 185 |
| Z80, 6502, 8080 | `z80` `6502` `i8080` | opcode tables | — |

The 8-bit targets have no llvm-mc support to check against, so they are
verified differently: tests walk the complete opcode space and assert that
exactly the documented encodings exist, and the Z80 tables were additionally
cross-checked against an independent disassembler (690 of 690 documented
sequences). They are for flat binaries; ELF has no class for a 16-bit target.

### Everything else

**Working**

- AT&T and Intel syntax on x86, switchable mid-file; `.code16`/`.code32`/`.code64`
- ELF relocatable objects, 32- and 64-bit, REL or RELA as each psABI requires,
  and flat binaries
- branch relaxation, alignment, `.org`, symbol arithmetic, conditionals
- macros: `.macro` with defaults, `:req` and `:vararg`, plus `.rept`, `.irp`,
  `.irpc`, `.exitm` and `.purgem`
- each target's own comment syntax, so ARM's `@`, AArch64's `//` and SPARC's
  `!` work, and `#` stays an immediate prefix where it is one
- diagnostics with source snippets that name the real limit, and assembly that
  continues past the first error

**Not yet**

- x86 SIMD: MMX, SSE, AVX and AVX-512 (in progress)
- the NASM dialect (its lexing rules are in place; its directives are not)
- Mach-O and PE/COFF
- DWARF line tables (`.loc` and `.cfi_*` parse and are ignored)
- ARM: `it` blocks, literal pools (`ldr r0, =x`), and `.thumb_func` interworking
- AArch64: most of NEON, SVE
- PowerPC: AltiVec/VSX
- 6502: the conventional `lda #$12` spelling, which needs `$`-prefixed hex

**Known wrong**

These produce incorrect output rather than an error, which is why they are
listed separately.

- RISC-V `la` of an external symbol emits only `R_RISCV_PCREL_HI20`, without
  its paired `LO12` relocation.
- In flat binaries only (relocatable output is correct): AArch64 `adrp`, and
  PowerPC `@ha`/`@l` on a label, are resolved without the page or split
  arithmetic they need.
- A mid-file `.arch` switch to a target with different comment characters does
  not re-lex the rest of that file, though it does apply to anything included
  or expanded after the switch.

## Usage

```
rsasm [options] <input.s>...

  -o <file>          write output to <file> (default: a.out)
  -a, --arch <name>  target architecture (default: the host, if supported)
  -f, --format <fmt> output format: elf (default) or bin
  -s, --syntax <s>   initial operand syntax: att (default) or intel
  -d, --dialect <d>  source dialect: gas (default) or nasm
  -I <dir>           add <dir> to the .include search path
  -D <sym>[=<val>]   define <sym> before assembling
      --base <addr>  base address for `bin` output
      --hex          print the output as hex instead of writing a file
      --list-arch    list the architectures this build supports
```

Architectures are cargo features, all on by default — `x86`, `aarch64`, `arm`,
`riscv`, `powerpc`, `mips`, `sparc` and `retro`:

```console
$ cargo build --no-default-features --features x86,aarch64
```

## Verification

Two differential harnesses assemble the same source with rsasm and with an
independent assembler, and compare the bytes:

- `tools/gas-diff/run.sh` against GNU as, for x86. 118 of 118 match.
- `tools/mc-diff/run.sh` against llvm-mc, which can assemble every other
  target. 3,210 of 3,210 match across thirteen target variants.

Both run in CI. The expected bytes in the hermetic tests under `tests/` were
taken from these runs rather than written by hand: a test that only checks
rsasm against rsasm can never find a wrong encoding.

Where rsasm and the reference legitimately differ, the corpus says so rather
than dropping the case. The standing example is alignment padding in
executable sections, where GNU as picks its no-op sequence by `-mtune`; only
the total length is fixed.

## Design

The interesting problems in an assembler are mostly about *when* things are
known, and the design is shaped around that.

**Lexing depends on the target, not just the dialect.** `;` separates
statements in GAS and starts a comment in NASM; `1b` is a local-label reference
in GAS and the binary constant `2` in NASM. Within GAS, `#` is a comment on x86
but the immediate prefix on ARM, AArch64 and SPARC, where it is a comment only
in the first column — which is also what C preprocessor line markers look like.
So each backend supplies its comment syntax, and the lexer is configured from
it when a file is read.

**The parser stops at the statement level.** It finds labels, directives and
mnemonics; it does not look inside operands. `disp(base,index,scale)` and
`[base + index*scale + disp]` are x86's problem, and register lists are ARM's,
so the architecture backend gets the raw token tail and parses it itself.

**Expressions evaluate to relocatable values,** not numbers: `plus - minus +
addend`. That is what lets `end - start` be a constant while `end` alone is
not, and it is the same representation whether the answer comes out as bytes
or as a relocation.

**Positional references are bound where they are written.** `.` and `1f` mean
different things depending on where in the file they appear, which is
information that no longer exists by the time an expression is evaluated. Both
are rewritten into ordinary symbol references as soon as the statement
containing them is parsed.

**Macro expansion is textual, and re-lexed.** Substituting tokens cannot
express what macro bodies rely on: `.L\@_loop:` has to paste the invocation
counter into the middle of an identifier, and there is no token meaning "join
these". Expanding into text and re-lexing gives that for free, and it is what
GNU as does, so bodies written for it behave the same way. The expansion
becomes a real entry in the source map, which turns out to be a feature — a
diagnostic inside a macro points at the expanded line and names the macro it
came from.

**A fragment that might change size carries every candidate.** An instruction
whose branch could be short or long is encoded *both* ways at parse time; the
layout pass picks an index into that list. Since the index only ever
increases, the loop terminates. This costs a little memory and buys a
relaxation pass with no re-entry into the parser.

### Adding an architecture

Implement `arch::Architecture` and register it in `arch::lookup`. The trait is
the whole seam:

```rust
fn assemble(&self, cx: &mut AsmCtx<'_>, insn: &InsnRequest<'_>) -> Option<Vec<Variant>>;
```

The backend receives a mnemonic and the tokens after it, and returns the
candidate encodings with their fixups. It never touches sections, symbols or
addresses — those belong to the core, which is why two backends can write into
the same file. `.arch` switches between them at any point.

Fixed-width encodings rarely have a contiguous displacement field, so a fixup
can carry a function that scatters the value through the instruction word,
together with the field's real width and alignment. That is what lets a 26-bit
AArch64 branch offset be range-checked as 26 bits rather than as the 4 bytes
it lives in.

A few conventions really are per target and have trait methods with defaults:
`comments` (which characters start one) and `word_bytes` (how wide `.word` is —
2 on x86 and PowerPC, 4 on the other RISC targets).

Add a corpus under `tools/mc-diff/` for the new target and take the hermetic
tests' expected bytes from its runs.

## Building

```console
$ cargo build --release
$ cargo test
$ tools/gas-diff/run.sh     # needs binutils
$ tools/mc-diff/run.sh      # needs llvm-mc and llvm-objcopy
```

## License

MIT — see [LICENSE](LICENSE).
