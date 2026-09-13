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

Early. The pipeline is complete end to end — lex, parse, encode, lay out,
relax, relocate, write — and there is one real architecture behind it.

**Working**

- x86-64, in both AT&T and Intel syntax, switchable mid-file
- `.code16` / `.code32` / `.code64`
- ELF relocatable objects, 32- and 64-bit, and flat binaries
- branch relaxation, alignment, `.org`, symbol arithmetic, conditionals
- macros: `.macro` with defaults, `:req` and `:vararg`, plus `.rept`, `.irp`,
  `.irpc`, `.exitm` and `.purgem`
- diagnostics with source snippets, and assembly that continues past the
  first error

**Not yet**

- the NASM dialect (its lexing rules are in place; its directives are not)
- Mach-O and PE/COFF
- DWARF line tables (`.loc` and `.cfi_*` parse and are ignored)

**Known wrong**

- The i386 backend emits x86-64 relocation numbers. `R_386_PC32` and
  `R_386_PLT32` happen to share their values with the x86-64 ones, so branches
  and calls are right, but `R_386_32` is 1 where `R_X86_64_32` is 10 — so a
  32-bit object containing an absolute reference to a symbol will confuse a
  linker. 64-bit output is unaffected.

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

Architectures are cargo features, all on by default:

```console
$ cargo build --no-default-features --features x86
```

## Compatibility with GNU as

Where rsasm and GNU as both accept a program, they are meant to produce the
same bytes. `tools/gas-diff/run.sh` assembles a corpus with both and compares
`.text`; it currently reports 118 of 118 matching, and the expected encodings
in `tests/x86_encoding.rs` came from those runs.

One deliberate difference: alignment padding in executable sections uses a
different mix of multi-byte no-ops. GNU as picks its sequence by `-mtune`, so
the bytes differ between GNU as versions too; only the total length is fixed.

## Design

The interesting problems in an assembler are mostly about *when* things are
known, and the design is shaped around that.

**Lexing is pull-based, and its configuration is mutable.** `;` separates
statements in GAS and starts a comment in NASM. `1b` is a reference to a local
label in GAS and the binary constant `2` in NASM. A directive halfway down the
file can change which of those is true, so the lexer asks its configuration
again for every token rather than tokenizing the file up front.

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

## Building

```console
$ cargo build --release
$ cargo test
$ tools/gas-diff/run.sh     # needs binutils
```

## License

MIT — see [LICENSE](LICENSE).
