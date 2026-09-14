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
| x86-64, i386, i8086, with x87, MMX, 3DNow!, SSE–SSE4.2, AVX, AVX2, AVX-512F | `x86-64` `i386` `i8086` | GNU as, llvm-mc | 8100 |
| AArch64 | `aarch64` | llvm-mc | 480 |
| ARM A32 / Thumb | `arm` `thumb` | llvm-mc, GNU as | 446 |
| RISC-V RV32/RV64 IMAFDC | `riscv32` `riscv64` | llvm-mc | 530 |
| PowerPC 32/64, both endians | `powerpc` `powerpc64` `powerpc64le` | llvm-mc | 1062 |
| MIPS 32/64, both endians | `mips` `mipsel` `mips64` `mips64el` | llvm-mc | 669 |
| SPARC V8 / V9 | `sparc` `sparcv9` | llvm-mc | 190 |
| m68k (68000–68020), GNU and Motorola syntax | `m68k` `68000` `68010` | GNU as, vasm | 809 |
| SuperH SH-1 to SH-4A, both endians | `sh` `shl` | GNU as | 1280 |
| Renesas RX (RXv1), GNU and CC-RX syntax | `rx` | GNU as | 609 |
| Renesas RL78, GNU and CC-RL syntax | `rl78` | GNU as | 528 |
| NEC/Renesas V850 and RH850, GNU and CC-RH syntax | `v850` `rh850` | GNU as | 558 |
| NEC 78K0, in CA78K0 syntax | `78k0` | NEC code tables, MAME | — |
| Zilog Z80, with the undocumented `IXH`/`IXL` forms, Zilog and GNU syntax | `z80` | GNU as, vasm | 2572 |
| MOS 6502, in ca65 syntax | `6502` | ca65, vasm | 551 |
| Intel 8080, in Intel mnemonics | `i8080` | AS | 278 |

The 8-bit targets are checked against the assemblers their source is written
for: cc65's ca65 for the 6502, GNU as and vasm for the Z80, and the Macro
Assembler AS for the 8080 — GNU as has no Intel mnemonics, and vasm's `RST`
takes a Zilog address. Tests also walk each complete opcode space and assert
that exactly the documented encodings exist. They are for flat binaries; ELF
has no class for a 16-bit target. See [the 8-bit dialect](#the-8-bit-dialect).
The 78K0 has no freely available assembler: its table was extracted
from NEC's instruction manual, checked against the byte counts in a second NEC
manual, and cross-checked against MAME's disassembler, which agrees on all
but 18 forms where both manuals show MAME to be wrong.

### Everything else

**Working**

- AT&T and Intel syntax on x86, switchable mid-file; `.code16`/`.code32`/`.code64`
  and `.code16gcc`
- NASM source (`-d nasm`): its preprocessor (`%macro`, `%rep`, `%if`, `%define`,
  `%assign`, contexts, `%include`), `db`/`resb`/`times`/`equ`/`struc`, sections
  with attributes, `default rel`, and NASM's operand syntax and `wrt`
  relocations; see [Dialects](#dialects)
- several targets in one file, switched with `.arch`; see
  [Multi-architecture files](#multi-architecture-files)
- ELF relocatable objects, 32- and 64-bit, REL or RELA as each psABI requires,
  and flat binaries
- PE/COFF relocatable objects for x86-64, i386 and ARM64 (`-f coff`, or NASM's
  `-f win64` and `-f win32`): COMDAT sections, weak externals, `.def`, `.rva`,
  `.secrel32` and `@IMGREL`, and x86-64 unwind data from `.seh_*`; see
  [PE/COFF](#pecoff)
- branch relaxation, alignment, `.org`, symbol arithmetic, conditionals
- macros: `.macro` with defaults, `:req` and `:vararg`, plus `.rept`, `.irp`,
  `.irpc`, `.exitm` and `.purgem`
- DWARF: line tables from `.file` and `.loc`, versions 2 to 5, call frame
  information from `.cfi_*` in `.eh_frame` or `.debug_frame`, and `-g` to
  describe the assembly source itself; see [Debug information](#debug-information)
- each target's own comment syntax, so ARM's `@`, AArch64's `//` and SPARC's
  `!` work, and `#` stays an immediate prefix where it is one
- ARM and Thumb as GNU as assembles them: literal pools (`ldr r0, =x`,
  `.ltorg`), `adr` and `adrl`, `it` blocks, `.thumb_func` and calls between
  the two instruction sets, and `$a`/`$t`/`$d` mapping symbols
- diagnostics with source snippets that name the real limit, and assembly that
  continues past the first error

**Not yet**

- in NASM source: the multi-pass immediate-size optimizer for a value known
  only after layout, so `mov r64, len` where `len` is a label difference stays
  the sign-extending form rather than NASM's shorter 32-bit load (a constant or
  a symbol is optimized); x87, `enter`, far direct `jmp`/`call seg:off`, `[rip]`
  addressing (NASM uses `[rel]`), the `..gotpc`/`..gotoff`/`..tlsie` `wrt`
  targets and 16-bit object formats; `-f bin` follows NASM except that a
  trailing `.bss` is written as zeros rather than trimmed
- in CC-RL and CC-RH source: bit symbols, `$label`/`%label` gp- and
  ep-relative references, `STARTOF`/`SIZEOF`, and CC-RL's `HIGH`/`LOWW` of a
  relocatable label (all refused with the reason)
- in CC-RX source: `.FLOAT`/`.DOUBLE`, `.RVECTOR`, the `.LEN`/`.INSTR`/`.SUBSTR`
  string functions, `SIZEOF`/`TOPOF`, `__PID_REG`, big-endian sections, and
  bit length specifiers that ask for a longer form than the shortest (all
  refused with the reason)
- Mach-O
- PE/COFF: DWARF (`-g`, `.loc` and `.cfi_*` are refused with `-f coff`) and
  CodeView debug information, unwind data for ARM64 (its `.seh_*` directives
  are refused), i386 `.safeseh`, and associative COMDAT sections, so the
  unwind data of a function in a COMDAT section is not discarded with it
- DWARF: 64-bit DWARF, compressed debug sections, the `.cfi_*` directives
  beyond the common set (`.cfi_label`, `.cfi_val_encoded_addr`,
  `.cfi_inline_lsda`, `.cfi_fde_data` and llvm-mc's `.cfi_llvm_*`), and
  `.debug_macro`/`.debug_names`
- ARM: `-mimplicit-it`, so a conditional Thumb instruction needs an `it` block
  of its own, as with GNU as's default; `.thumb_set`; 8-byte (VFP) literal
  pool entries; and the divided Thumb syntax GNU as reads without
  `.syntax unified` (rsasm reads Thumb as unified syntax either way)
- AArch64: most of NEON, SVE
- PowerPC: AltiVec/VSX
- RISC-V: linker relaxation (`.option relax` is accepted, but objects come out
  as llvm-mc writes them without it, with no `R_RISCV_RELAX` or
  `R_RISCV_ALIGN`), and the TLS forms `la.tls.ie`, `la.tls.gd` and the
  `%tls_*` and `%got_pcrel_hi` modifiers
- 6502: the 65C02 and later instruction sets; in ca65 source, cheap local
  (`@loop`) and unnamed (`:`, `:-`) labels, `.proc`/`.scope`, `.struct`, and
  the `ZEROPAGE` segment's zero-page addressing for labels defined in it
- 8080: Intel's word operators (`AND`, `SHR`, `HIGH`, `MOD`), which AS does
  not read either
- Z80: the `DD CB d op,r` forms that also write a register, which vasm
  refuses; and in the GNU dialect, GNU as's `db`/`dw`/`ds` pseudo-ops (use
  `.byte`, `.word` and `.space`, or the 8-bit dialect)

**Known wrong**

Anything that produces incorrect output rather than an error is listed here,
separately. Nothing is, at the moment.

Where the references themselves disagree, rsasm follows the one whose harness
checks the target (see [Verification](#verification)) and says so in the
backend. Two such choices are worth knowing about:

- **Which references are left to the linker.** A PC-relative reference to a
  global or weak symbol is relocated even when the symbol is in the same
  section, since the linker may bind the name elsewhere; a local one, or a
  local `.set` alias of a global one, is resolved. That is what both
  references do on nearly every target. The exceptions follow GNU as for
  x86, m68k, SuperH and RL78 (a jump GNU as relaxes to a global symbol is
  resolved on x86; only weak symbols are left to the linker on m68k; nothing
  in the same section is on SuperH and RL78). On ARM GNU as is followed for
  whole objects: a `bl` to a local label is resolved, and made a `blx` where
  the label is a Thumb function, where llvm-mc relocates every `bl`.
- **Default section alignment.** Sections start with the alignment the
  reference gives them: 16 for MIPS `.text`, `.data` and `.bss` (llvm-mc; GNU
  as aligns only `.text`, to 4), 4 for `.text` on PowerPC and SPARC and for
  every executable section on AArch64 (llvm-mc; GNU as gives 1, or aligns
  once an instruction is assembled), on ARM what GNU as gives (a section is
  aligned by the first instruction in it, to 4 for ARM and 2 for Thumb), 2 or 4 for RISC-V `.text` depending on
  compressed instructions, 4 for m68k `.text`, `.data` and `.bss`, and 1
  otherwise, including on x86, where GNU as is followed and llvm-mc's `.text`
  is 4.

## Usage

```
rsasm [options] <input.s>...

  -o <file>          write output to <file> (default: a.out)
  -a, --arch <name>  target architecture (default: the host, if supported)
  -f, --format <fmt> output format: elf (default), elf32, elf64, coff,
                     win64, win32 or bin
  -s, --syntax <s>   initial operand syntax: att (default) or intel
  -d, --dialect <d>  source dialect: gas, nasm, motorola, renesas (CA78K0),
                     ccrl (Renesas CC-RL), ccrh (Renesas CC-RH),
                     ccrx (Renesas CC-RX) or 8bit (6502, Z80, 8080)
                     (default: the architecture's usual one)
  -I <dir>           add <dir> to the .include search path
  -D <sym>[=<val>]   define <sym> before assembling
      --base <addr>  base address for `bin` output
      --hex          print the output as hex instead of writing a file
  -g                 describe the assembly source in DWARF line information
      --gdwarf-<n>   the same, as DWARF version <n> (2 to 5); the version
                     also applies to `.loc` source
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
| `8bit` | `lda #$12`, `ld a,(ix+5)`, `MVI A,12H`, `DB 1`, `; comment` | 6502, Z80, 8080 |
| `nasm` | `db 1`, `; comment`, `mov eax, [rel x]`, `%macro`, `0FFh` | — |

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

### The 8-bit dialect

`8bit` reads the source people have for the 6502, the Z80 and the 8080:
ca65's for the 6502, Zilog's as GNU as and vasm read it, and Intel's as AS
reads it. Their spellings are one language — `$12`, `12H`, `%1010` and
`0x12` numbers, `$` and `*` for the location counter, `<`, `>` and `^` for
the bytes of an address, `DB`/`DEFB`/`.byte`, `DW`/`DEFW`/`.word`,
`DS`/`DEFS`/`.res`, `EQU`, `=`, `DEFL`/`SET`, `IF`/`ENDIF`, `MACRO`/`ENDM` or
`.macro`/`.endmacro`, ca65's `.segment` — and where the references disagree,
rsasm picks one and says so:

```console
$ cat hello.asm
bdos    equ 5
        org 100h                ; a CP/M program
start:  ld de,msg
        ld c,9
        call bdos
        ret
msg     db 'Hello$'
$ rsasm -a z80 -f bin --hex hello.asm
11 09 01 0e 09 cd 05 00 c9 48 65 6c 6c 6f 24
```

- **A word in the first column is a label, unless it is an instruction or a
  directive.** vasm and AS take any first-column word as a label; ca65 and
  GNU as want a colon and assemble `rts` written there. Both kinds of source
  work, except a colonless label spelled like a mnemonic, or a macro called
  from the first column.
- **`ORG` says where code is loaded.** The first `ORG` in a section is its
  address in the image, not padding: `ORG 100H` does not put 256 zeros in
  front of a CP/M program. A later `ORG` pads up to its address, as vasm and
  AS do; ca65 does not pad.
- **Zero page is chosen as ca65 chooses it:** for a constant or `ORG`-placed
  label known before its use, and for `<addr`; a forward reference is
  absolute, and `z:`/`a:` override either way. vasm, a multi-pass assembler,
  picks zero page for forward references too.
- **The location counter in a data list is each item's address**: `.word
  *, *` is two different values, as in ca65, vasm and GNU as. AS keeps the
  statement's address.
- A comparison is 1 when true, as in ca65 and AS; GNU as and vasm give -1.
  The operators have C's precedence, where ca65 binds `&` as tightly as `*`.

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

### NASM

`-d nasm` reads source written for NASM, the flat-binary and ELF assembler most
x86 hand-written code targets. The whole language people reach for is there:

- a preprocessor run a line at a time as NASM's is — `%define`/`%xdefine`/
  `%assign`/`%undef`, `%macro` with parameter ranges, defaults, greedy `+`
  params, `%0`, `%rotate`, `%%` labels and `%00` label capture, `%rep`/
  `%exitrep`, the `%if`/`%elif`/`%else` family (`%ifdef`, `%ifmacro`, `%ifidn`,
  `%ifnum`, `%ifstr`, `%ifctx` …), `%include`, `%strlen`/`%substr`/`%defstr`,
  `%push`/`%pop` contexts with `%$` locals, and `%error`/`%warning`
- `db`/`dw`/`dd`/`dq`/`dt` with single-, double- and backquoted strings, the
  `resb` family, `times n <stmt>` (including `times 510-($-$$) db 0`), `incbin`,
  `equ`, `struc`/`endstruc`/`istruc`/`at`/`iend`, `align`/`alignb`, and
  `absolute`
- `section`/`segment` with attributes (`progbits`, `nobits`, `alloc`, `exec`,
  `write`, `align=`), `bits 16/32/64`, `org`, `global`/`extern`/`common`/
  `static` with `:function`/`:data` and sizes, `default rel`/`abs`, `$`/`$$`
  and `.local`/`..@` labels
- NASM's operand syntax: the `byte`/`word`/`dword`/`qword` size keywords with
  no `ptr`, `[rel x]` and `[abs x]`, segment overrides `[es:di]`, the moffs
  accumulator forms, and 8086 16-bit addressing; and the `wrt ..plt`,
  `wrt ..got`, `wrt ..sym` and `wrt ..gotoff` ELF relocations

Much of what looks like NASM directive syntax — `section`, `global`, `struc`,
`align` — is macros in NASM's standard macro set wrapping a bracketed
primitive, `[section .data]`; rsasm defines the same macros, so `__SECT__` and
the rest behave as they do there.

```console
$ cat boot.asm
        org     0x7c00
        bits    16
start:  mov     ax, 0x1234
        jmp     start
        times   510-($-$$) db 0
        dw      0xaa55
$ rsasm -d nasm -f bin -o boot.bin boot.asm   # a 512-byte boot sector
```

`tools/nasm-diff/run.sh` assembles a corpus of whole programs with rsasm
`-d nasm` and with NASM 2.16.03 (built by `tools/oracles/build.sh`), and
compares the flat binaries byte for byte and the ELF objects section by
section, relocations and global symbols included. 373 of 373 match. Local
symbols are not compared: NASM writes every label into the symbol table, where
rsasm, like GNU as, keeps them to itself, and a linker never sees the
difference.

## Multi-architecture files

`.arch <name>` switches the target for everything after it, so one file can
hold, say, a boot stub for one CPU and the code it loads for another:

```console
$ cat two.s
        movl    $0x10000, %esp          # x86: `#` starts a comment
        .arch   m68k
        movew   #0x2700, %sr            | m68k: `#` is an immediate, `|` a comment
        .arch   sh
        mov     #1, r0                  ! SuperH: `!` is the comment
$ rsasm -a i386 -f bin --hex two.s
bc 00 00 01 00 46 fc 27 00 e0 01
```

- **Source is read as the target it is for.** The statement after an `.arch`
  is lexed by the new target's rules — its comment characters, and number
  spellings such as RL78's `10H` — whether the switch was in the file itself,
  in a macro expansion or in an included file. The rest of the `.arch` line,
  a trailing comment say, still belongs to the old target. The dialect (`-d`)
  does not change.
- **A macro body is read where it is expanded.** Only where it ends is found by
  the rules in force at `.macro`; the body is kept as text and lexed by the
  rules in force at each expansion, like an included file.
- **An `.arch` that is not assembled does nothing,** whether it is in a false
  conditional or in a macro that is never called.
- **Code keeps its target.** Byte order, branch displacements resolved at the
  end, and the no-ops that pad an alignment are those of the target the code
  was written for, not the one active at the end of the file.
- **The object is for the starting target.** The ELF class, machine and byte
  order are those of `-a`. Code for a different machine, byte order or word
  size can be in it, but cannot be relocated: a reference in that code has to
  resolve within the file.
  Switching to another CPU of the object's own machine (`.arch sh4` in an `sh`
  file) carries over what the ELF header records about the code so far.

Every case in `tools/multiarch-diff/programs.txt` is checked the only way it
can be: the file is split at its `.arch` lines, each part is assembled by its
own target's reference, and rsasm has to produce the concatenation.

## Debug information

`.file N "name"` (with a directory and `md5` in DWARF 5) and `.loc` with all of
its options, `view` included, write `.debug_line` and `.debug_line_str`; the
`.cfi_*` directives write `.eh_frame` or `.debug_frame`, as `.cfi_sections`
says. Where the source brings no `.debug_info`, the compilation unit an
assembler makes up for the table is written too. `-g` (or `--gdwarf-<n>`)
instead describes the assembly source: a row for each instruction, at its
line, and a unit naming the file.

The two references agree on the formats and disagree on nearly everything
inside them, so each target follows the one that checks its encodings: GNU as
for x86, m68k, SuperH, RX, RL78 and V850, and llvm-mc for the rest. That
decides, among other things, the default version (3 for GNU as, 4 for
llvm-mc, 5 for either once a `.file 0` appears), how a path splits into a
directory, whether a column carries over to the next `.loc`, which directives
end a pending `.loc`, how CIEs are shared, and how padding and relocations are
written. Each backend supplies its DWARF register numbers and names, return
address column, alignment factors, initial instructions and FDE encoding; RX,
RL78 and V850, whose GNU as has no CFI, refuse `.cfi_*` as it does. For `-g`,
GNU as places an instruction from a macro on the line that called it, one
from `.rept` or `.irp` on its line in the block, and one from an included file
on its line there; llvm-mc puts every instruction in the main file at the
outermost line that expanded it, and describes each label as well.

Three differences remain:

- GNU as gives a `view -0` row an address of its own wherever its frag
  obstack happened to start a new chunk, which depends on the host's memory
  allocation; rsasm does so only where the row is at the address of the one
  before, which is when the view count needs it.
- On RL78, GNU as leaves every distance in the line table to the linker as a
  stack of relocation operations; rsasm writes the distances, which are final
  since it lays out the section itself.
- For `-g` on llvm-mc's targets, llvm-mc numbers the last statement of an
  included file against the file that included it, reading past that file's
  buffer; rsasm gives its line in the included file.

The producer named in the unit is `rsasm` and its version, or the value of
`DEBUG_PRODUCER`, which llvm-mc also reads.

## Verification

Seven differential harnesses assemble the same source with rsasm and with an
independent assembler, and compare the bytes:

- `tools/gas-diff/run.sh` against GNU as 2.47, for x86 in 64-, 32- and
  16-bit mode, in AT&T and Intel syntax. 4,175 of 4,175 match.
- `tools/mc-diff/run.sh` against llvm-mc 22, for x86 and the targets LLVM
  supports. 7,230 of 7,230 match across eighteen target variants. For RISC-V
  it also compares whole objects, relocations included, since `la` and its
  relatives are only right if the linker is told the right things.
- `tools/xas-diff/run.sh` against cross GNU as 2.47 for m68k, SuperH, RX, RL78,
  V850/RH850 and the Z80, vasm for Motorola syntax and for the Z80 and the
  6502, cc65's ca65 for the 6502 and AS for the 8080, plus CC-RL, CC-RH and
  CC-RX source paired with its GNU-syntax equivalent. For ARM and Thumb it
  compares whole objects, local and mapping symbols included, against GNU as,
  the reference for literal pools and interworking. `tools/oracles/build.sh`
  builds the references from checksum-pinned sources. 7,294 of 7,294 match
  across twenty variants.
- `tools/flat-diff/run.sh` against a link, for flat binaries: the reference
  assembler's object, linked by GNU ld 2.47 at the same base address with the
  sections laid end to end, against `rsasm -f bin`. That is what checks the
  arithmetic a linker would otherwise do — `adrp` pages, `@ha`, `%pcrel_lo`,
  distances between sections. 120 of 120 match across twenty-four variants.
  `tools/oracles/build.sh` builds the linkers alongside the assemblers.
- `tools/nasm-diff/run.sh` against NASM 2.16.03, for the `nasm` dialect: whole
  programs compared as flat binaries and as ELF objects, relocations and global
  symbols included. 373 of 373 match. `tools/oracles/build.sh` builds NASM from
  a checksum-pinned source.
- `tools/multiarch-diff/run.sh` for files that switch targets with `.arch`,
  against the same references, one part at a time.
- `tools/dwarf-diff/run.sh` for [debug information](#debug-information),
  against GNU as 2.47 or llvm-mc 22, whichever the target follows: the line
  table, frame and compilation unit sections byte for byte with their
  relocations, from hand-written snippets, `-g` and whole files from GCC and
  Clang. 1,005 of 1,005 match across twenty-one target variants.

The x86 backend is also fuzzed: `tools/fuzz/x86.py` generates random
instructions from a table of forms written from the Intel manual, in all three
modes and both syntaxes, some of them deliberately invalid, and compares
rsasm's bytes, relocations and accept/reject decision with GNU as's and
llvm-mc's. Where the two references disagree, rsasm follows GNU as, apart
from the few cases the corpora note; a run of 600,000 instructions finds no
case where rsasm differs from both. See `tools/fuzz/README.md`.

The first three also compare whole objects for every ELF target, from the
`*-relocs.txt` corpora: each allocated section's type, flags, size, alignment
and bytes, the global, weak and undefined symbols, and every relocation, read
the way a linker reads it (`tools/mc-diff/canon.sh`). Bytes alone cannot show
a reference that should have been left to the linker, or one relocated
against the wrong symbol: the field is zero either way. Those corpora walk
each binding — local, global, weak, hidden and the other visibilities, `.set`
aliases either way round, `.globl` after use, another section, undefined —
through branches, calls, PC-relative loads and data.

All seven run in CI. The expected bytes in the hermetic tests under `tests/` were
taken from these runs rather than written by hand: a test that only checks
rsasm against rsasm can never find a wrong encoding.

Where rsasm and the reference legitimately differ, the corpus says so rather
than dropping the case. The standing example is alignment padding in
executable sections, where GNU as picks its no-op sequence by `-mtune`; only
the total length is fixed. In flat binaries it is branches between sections:
a reference assembler cannot know how far away another section will be and
takes the longest form, while rsasm, which lays the image out itself, takes
the shortest that reaches; the flat corpora write those widths out.

ARM has two references that disagree with each other. llvm-mc checks the
encodings; GNU as, which the source was written for, decides everything that
depends on more than one instruction: where literal pools go and what they
share, mapping symbols, which branches become `blx` and which are left to
the linker, how relaxation sizes Thumb instructions, and that a code
section's end is padded to a word. rsasm follows
GNU as there, and llvm-mc where the two only differ in spelling: Thumb
alignment padding uses 16-bit no-ops, and `adds r0, r0, #1` keeps the
three-operand form, where GNU as uses 32-bit no-ops and the 8-bit form. See
`tools/xas-diff/README.md`.

## Design

The interesting problems in an assembler are mostly about *when* things are
known, and the design is shaped around that.

**Lexing depends on the target, not just the dialect.** `;` separates
statements in GAS and starts a comment in NASM; `1b` is a local-label reference
in GAS and the binary constant `2` in NASM. Within GAS, `#` is a comment on x86
but the immediate prefix on ARM, AArch64 and SPARC, where it is a comment only
in the first column — which is also what C preprocessor line markers look like.
So each backend supplies its comment syntax, and the lexer is configured from
it. A file is read one statement at a time, each after the one before it has
been assembled, which is what lets an `.arch` switch change how the next line
is spelled without a second pass or a guess.

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
`comments` (which characters start one), `word_bytes` (how wide `.word` is —
2 on x86 and PowerPC, 4 on the other RISC targets), `section_align` (the
alignment a section starts with) and `defers_to_linker` (which references to
a symbol in their own section are still relocated).

Add a corpus under `tools/mc-diff/` for the new target and take the hermetic
tests' expected bytes from its runs.

## Building

```console
$ cargo build --release
$ cargo test
$ tools/gas-diff/run.sh     # needs binutils
$ tools/mc-diff/run.sh      # needs llvm-mc and llvm-objcopy
$ tools/flat-diff/run.sh    # needs cross binutils with ld, and llvm-mc
$ tools/xas-diff/run.sh     # needs tools/oracles/build.sh
$ tools/nasm-diff/run.sh    # needs NASM from tools/oracles/build.sh
$ tools/multiarch-diff/run.sh  # needs all of the above
$ tools/dwarf-diff/run.sh   # needs llvm-mc and tools/oracles/build.sh
$ tools/coff-diff/run.sh    # needs llvm-mc and tools/oracles/build.sh
```

## License

MIT — see [LICENSE](LICENSE).
