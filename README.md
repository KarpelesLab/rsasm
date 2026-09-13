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
lay out, relax, relocate, write — with fourteen backends behind it.

### Architectures

Every encoding claimed below is checked byte for byte against an independent
assembler, not against rsasm's own idea of the manual. See
[Verification](#verification).

| Target | Names | Checked against | Cases |
|---|---|---|---|
| x86-64, i386, i8086, with MMX, 3DNow!, SSE–SSE4.2, AVX, AVX2, AVX-512F | `x86-64` `i386` `i8086` | GNU as, llvm-mc | 1584 |
| AArch64 | `aarch64` | llvm-mc | 475 |
| ARM A32 / Thumb | `arm` `thumb` | llvm-mc | 361 |
| RISC-V RV32/RV64 IMAFDC | `riscv32` `riscv64` | llvm-mc | 518 |
| PowerPC 32/64, both endians | `powerpc` `powerpc64` `powerpc64le` | llvm-mc | 1047 |
| MIPS 32/64, both endians | `mips` `mipsel` `mips64` `mips64el` | llvm-mc | 654 |
| SPARC V8 / V9 | `sparc` `sparcv9` | llvm-mc | 185 |
| m68k (68000–68020), GNU and Motorola syntax | `m68k` `68000` `68010` | GNU as, vasm | 804 |
| SuperH SH-1 to SH-4A, both endians | `sh` `shl` | GNU as | 1248 |
| Renesas RX (RXv1), GNU and CC-RX syntax | `rx` | GNU as | 604 |
| Renesas RL78, GNU and CC-RL syntax | `rl78` | GNU as | 523 |
| NEC/Renesas V850 and RH850, GNU and CC-RH syntax | `v850` `rh850` | GNU as | 548 |
| NEC 78K0, in CA78K0 syntax | `78k0` | NEC code tables, MAME | — |
| Z80, 6502, 8080 | `z80` `6502` `i8080` | opcode tables | — |

The 8-bit targets have no llvm-mc support to check against, so they are
verified differently: tests walk the complete opcode space and assert that
exactly the documented encodings exist, and the Z80 tables were additionally
cross-checked against an independent disassembler (690 of 690 documented
sequences). They are for flat binaries; ELF has no class for a 16-bit target.
The 78K0 has no freely available assembler either: its table was extracted
from NEC's instruction manual, checked against the byte counts in a second NEC
manual, and cross-checked against MAME's disassembler, which agrees on all
but 18 forms where both manuals show MAME to be wrong.

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

- the NASM dialect (its lexing rules are in place; its directives are not)
- in CC-RL and CC-RH source: bit symbols, `$label`/`%label` gp- and
  ep-relative references, `STARTOF`/`SIZEOF`, and CC-RL's `HIGH`/`LOWW` of a
  relocatable label (all refused with the reason)
- in CC-RX source: `.FLOAT`/`.DOUBLE`, `.RVECTOR`, the `.LEN`/`.INSTR`/`.SUBSTR`
  string functions, `SIZEOF`/`TOPOF`, `__PID_REG`, big-endian sections, and
  bit length specifiers that ask for a longer form than the shortest (all
  refused with the reason)
- Mach-O and PE/COFF
- DWARF line tables (`.loc` and `.cfi_*` parse and are ignored)
- ARM: `it` blocks, literal pools (`ldr r0, =x`), and `.thumb_func` interworking
- AArch64: most of NEON, SVE
- PowerPC: AltiVec/VSX
- RISC-V: linker relaxation (`.option relax` is accepted, but objects come out
  as llvm-mc writes them without it, with no `R_RISCV_RELAX` or
  `R_RISCV_ALIGN`), and the TLS forms `la.tls.ie`, `la.tls.gd` and the
  `%tls_*` and `%got_pcrel_hi` modifiers
- 6502: the conventional `lda #$12` spelling, which needs `$`-prefixed hex

**Known wrong**

These produce incorrect output rather than an error, which is why they are
listed separately.

- A PC-relative reference to a weak symbol defined in the same section is
  resolved at assembly time. GNU as and llvm-mc leave it to the linker, which
  may choose another definition. (llvm-mc on RISC-V leaves references to
  global symbols to the linker too; rsasm resolves those as well.)
- Sections have no default alignment beyond what `.align` asks for, where GNU
  as and llvm-mc give them one: 4 for MIPS `.data` in GNU as, 16 in llvm-mc,
  and 4 for m68k. So in a flat binary a section that follows an odd-sized one
  can start at an address a linker would have rounded up. Explicit `.p2align`
  at the start of the section avoids it.
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
  -d, --dialect <d>  source dialect: gas, nasm, motorola, renesas (CA78K0),
                     ccrl (Renesas CC-RL), ccrh (Renesas CC-RH) or
                     ccrx (Renesas CC-RX)
                     (default: the architecture's usual one)
  -I <dir>           add <dir> to the .include search path
  -D <sym>[=<val>]   define <sym> before assembling
      --base <addr>  base address for `bin` output
      --hex          print the output as hex instead of writing a file
      --list-arch    list the architectures this build supports
```

Architectures are cargo features, all on by default — `x86`, `aarch64`, `arm`,
`riscv`, `powerpc`, `mips`, `sparc`, `retro`, `m68k`, `superh`, `rx`, `rl78`,
`v850` and `k78`:

```console
$ cargo build --no-default-features --features x86,aarch64
```

## Dialects

Source syntax is chosen with `-d`, or defaults to what each architecture's
source is normally written in.

| Dialect | Looks like | Default for |
|---|---|---|
| `gas` | `.byte 1`, `# comment`, `0x10` | most targets |
| `motorola` | `dc.b 1`, `; comment`, `$10`, `%1010` | m68k |
| `renesas` | `DB 'A',1`, `; comment`, `10H` | 78K0 |
| `ccrl` | `.DB "A",1`, `$IF`, `0x10` or `10H` (Renesas CC-RL) | — |
| `ccrh` | `.dw #label`, `$IF`, `0x10` (Renesas CC-RH) | — |
| `ccrx` | `.SECTION P,CODE`, `.LWORD 10H`, `#1:8` (Renesas CC-RX) | — |
| `nasm` | lexing only, so far | — |

```console
$ cat intena.s
        move.w  #$7fff,$DFF096          ; disable all Amiga interrupts
$ rsasm -a m68k -f bin --hex intena.s
33 fc 7f ff 00 df f0 96
```

Motorola covers vasm, Devpac and ASM-One source and was checked against both
vasm and GNU as `--mri`. Three rules in it catch people out:

- **A word in the first column is a label**, with or without a colon, so
  instructions have to be indented. `rts` written in column 0 assembles to no
  code at all — in both reference assemblers, not just here.
- **Word and long data, and instructions, are aligned to an even address.**
  vasm on its own defaults leaves a `dc.w` after a `dc.b` at an odd address;
  Devpac, GNU as and vasm's `-devpac` mode align it, and a 68000 faults on the
  alternative. GNU as's own m68k syntax aligns nothing, so this is a property of
  the dialect.
- **Instructions are assembled as written.** vasm's default optimizer turns
  `move.l #1,d0` into `moveq #1,d0`; rsasm, like GNU as, only chooses the
  shortest encoding of the instruction you wrote.

### Renesas CC-RL, CC-RH and CC-RX

`ccrl`, `ccrh` and `ccrx` read source written for the assemblers of Renesas's
RL78, RH850 and RX compiler packages. GNU as stays the default for those
targets, because
GNU-syntax source would not always be refused in the vendor dialects — it
would sometimes mean something else — so the dialect has to be asked for:

```console
$ cat start.asm
        .CSEG   TEXT
_start: MOVW    SP, #LOWW(0xFFE00)
        MOV     [HL], #0                ; CC-RL's shorthand for [HL+0]
        BR      !!_main
$ rsasm -a rl78 -d ccrl -o start.o start.asm
```

What is covered, from the *CC-RL Compiler User's Manual* (R20UT3123EJ0115)
and the *CC-RH Compiler User's Manual* (R20UT3516EJ0113):

- comments, both number notations (CC-RL), escapes in strings, `@` in symbols
- each assembler's own operator precedence, 32-bit `>>`, and the `HIGH`,
  `LOW`, `HIGHW`, `LOWW` and `HIGHW1` separators
- `.CSEG`/`.DSEG`/`.SECTION` with their relocation attributes, default names
  and alignments, `.ORG`, `.OFFSET`, `.ALIGN`, the `.DB` family, `.EQU` and a
  redefinable `.SET`, `.PUBLIC`/`.EXTERN`/`.WEAK`
- the `$IF`/`$IFDEF`/`$ELSEIFN` family, `$INCLUDE`, `$BINCLUDE`, and macros with
  named parameters, `.LOCAL`, `?`/`~` concatenation, `.REPT` and `.IRP`
- CC-RL's `[DE]`/`[HL]` zero-displacement shorthand
- CC-RH's instruction expansions — `mov 0x10, r10` is a `movea`, `add
  0x12345, r10` a load into `r1` — its `#label`/`!label` references, condition
  suffixes (`setfgt`, `cmovz`, `cmpfeq.s`), `jr22`/`ld23.w`-style width
  spellings, `push`/`pushm`, and byte-sized `prepare`/`dispose` frames

CC-RX has a directive set of its own, covered from the *CC-RX Compiler User's
Manual* (R20UT3248EJ0115): `B`/`O`/`H` number suffixes, names with `$` and
`.`, `$` as the location symbol, its operator precedence, `.SECTION` with
`CODE`/`ROMDATA`/`DATA` and `ALIGN=`, `.ORG` and `.OFFSET` with the NOP code
or `FILL` as padding, `.ALIGN`, `.BLKB` to `.BLKD`, `.BYTE`/`.WORD`/`.LWORD`,
`.EQU`, `.GLB`/`.WEAK`, `.INCLUDE`, `.END`, `.IF`/`.ELIF`, `.DEFINE`, `?:`
temporary labels, the `__PID_R0`-`__PID_R15` register names, and macros with
`..MACPARA`, `.MREPEAT`/`..MACREP`, `.LOCAL` and `@` concatenation.

```console
$ cat reset.src
        .SECTION P,CODE
        .GLB    _start
_start: MOV.L   #0FFH:8, R1
        ADD     400[R1], R2
        BRA     ?+
        NOP
?:      RTS
        .END
$ rsasm -a rx -d ccrx -o reset.o reset.src
```

CC-RX honours a bit length specifier such as `#1:8` even where a shorter form
fits; GNU as ignores it and rsasm, like GNU as, assembles the shortest form.
So a specifier is accepted where it names the width of that form, and refused
where CC-RX would have produced something else.

No Renesas assembler can be run here, so rsasm's reading of the manuals is
checked the only way it can be: each case in `tools/xas-diff/rl78-ccrl-pairs.txt`,
`rh850-ccrh-pairs.txt` and `rx-ccrx-pairs.txt` pairs vendor source with the
GNU-syntax program it means, and `tools/xas-diff/run.sh` requires rsasm's
bytes for the first to equal GNU as's for the second. Placement is the
linker's: an `AT` attribute or `.ORG` names the section (CC-RL, CC-RH) or pads
it (CC-RX) as the manual says, but the start address is not recorded.

## Verification

Four differential harnesses assemble the same source with rsasm and with an
independent assembler, and compare the bytes:

- `tools/gas-diff/run.sh` against the host's GNU as, for x86. 844 of 844 match.
- `tools/mc-diff/run.sh` against llvm-mc 22, for x86-64 and the targets LLVM
  supports. 3,980 of 3,980 match across fourteen target variants. For RISC-V
  it also compares whole objects, relocations included, since `la` and its
  relatives are only right if the linker is told the right things.
- `tools/xas-diff/run.sh` against cross GNU as 2.47 for m68k, SuperH, RX, RL78
  and V850/RH850, and vasm for Motorola syntax, plus CC-RL, CC-RH and CC-RX
  source paired with its GNU-syntax equivalent. `tools/oracles/build.sh` builds
  the references from checksum-pinned sources. 3,727 of 3,727 match across
  twelve variants.
- `tools/flat-diff/run.sh` against a link, for flat binaries: the reference
  assembler's object, linked by GNU ld 2.47 at the same base address with the
  sections laid end to end, against `rsasm -f bin`. That is what checks the
  arithmetic a linker would otherwise do — `adrp` pages, `@ha`, `%pcrel_lo`,
  distances between sections. 103 of 103 match across twenty-two variants.
  `tools/oracles/build.sh` builds the linkers alongside the assemblers.

All four run in CI. The expected bytes in the hermetic tests under `tests/` were
taken from these runs rather than written by hand: a test that only checks
rsasm against rsasm can never find a wrong encoding.

Where rsasm and the reference legitimately differ, the corpus says so rather
than dropping the case. The standing example is alignment padding in
executable sections, where GNU as picks its no-op sequence by `-mtune`; only
the total length is fixed. In flat binaries it is branches between sections:
a reference assembler cannot know how far away another section will be and
takes the longest form, while rsasm, which lays the image out itself, takes
the shortest that reaches; the flat corpora write those widths out.

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
$ tools/flat-diff/run.sh    # needs cross binutils with ld, and llvm-mc
```

## License

MIT — see [LICENSE](LICENSE).
