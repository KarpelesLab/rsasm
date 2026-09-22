# Differential fuzzing

A fuzzer per backend. Each generates programs or instructions, assembles
them with rsasm and with one or two independent references, and compares
the bytes, the relocations and whether each tool took the input at all.

## Running them all

```console
$ cargo build --all-features --bin rsasm
$ tools/oracles/build.sh                     # the cross assemblers
$ tools/fuzz/run.sh                          # every fuzzer, seed 1
$ tools/fuzz/run.sh --seed 20260922 --scale 10
$ tools/fuzz/run.sh --list                   # the set and its case counts
$ tools/fuzz/run.sh riscv mips               # only these
```

`run.sh` is what CI runs, and the one thing every fuzzer has to agree on:

* `fuzz --seed N --count M` generates the same cases for the same seed and
  count, and nothing else does.
* The exit status is 0 when nothing differed and non-zero when something
  did.
* The last line is `--- <name>: <n> case(s) compared, <k> finding(s)`.
  `run.sh` reads it, and a missing line or a zero count fails the run: a
  fuzzer that found nothing because it ran nothing must not read as a pass.

Each fuzzer's own command line is unchanged and is still the way to chase a
finding down; `run.sh` prints the exact one to repeat under any fuzzer that
differed.

`--scale` multiplies every count, which is how the nightly CI run covers ten
times the ground with a seed taken from the date.

## What each one fuzzes

| Fuzzer | Target | References | Cases from |
|---|---|---|---|
| `x86.py` | x86-64, i386, i8086 | GNU as, llvm-mc | the Intel SDM and GNU's expanded opcode table |
| `aarch64.py` | AArch64 | llvm-mc, GNU as | llvm-mc's or GNU objdump's disassembly |
| `arm.py` | A32, T32 | GNU as, llvm-mc | binutils' `arm-dis.c` syntax |
| `arm-programs.py` | A32, T32 | GNU as | whole random programs |
| `riscv.py` | RV32, RV64 | llvm-mc, GNU as | binutils' `riscv-opc.c` format strings |
| `powerpc.py` | PowerPC 32/64 | GNU as, llvm-mc | binutils' `ppc-opc.c` operand kinds |
| `mips.py` | MIPS 32/64, both endians | GNU as, llvm-mc | GNU objdump's disassembly |
| `sparc.py` | SPARC V8, V9 | GNU as, llvm-mc | GNU objdump's disassembly |
| `m68k.py` | 680x0, ColdFire | GNU as, vasm | GNU's opcode table |
| `sh.py` | SuperH | GNU as | GNU objdump's disassembly |
| `rx.py` | Renesas RX | GNU as | GNU objdump's disassembly |
| `rl78.py` | Renesas RL78 | GNU as | GNU objdump's disassembly |
| `v850.py` | V850, RH850 | GNU as | GNU objdump's disassembly |
| `msp430.py` | MSP430, 430X, 430Xv2 | GNU as | TI's user guides |
| `avr.py` | AVR, 21 cores | GNU as, GNU ld | whole random programs |
| `z80.py` | Zilog Z80 | GNU as | GNU objdump's disassembly |
| `mcs51.py` | Intel 8051 | AS, sdas8051 | whole random programs |

`gasfuzz.py` is the machinery the fuzzers added after the first few share:
the batch of cases in one object with a section each, the re-run without
whatever a tool rejected, a generic ELF reader that names a relocation the
way a linker computes it, and the report. `simd.py` and `gnutbl.py` belong
to `x86.py`.

## Cases from a disassembler

Several targets have no table of operand shapes to draw from -- RX and RL78
are parsed by a generated grammar, and the V850 and Z80 tables are the
assembler's own. For those, and for MIPS and SPARC where the table is large
and irregular, cases come from the other side of binutils: random bytes go
through the target's objdump, and every line that decodes becomes one case,
in the spelling GNU as reads. The disassembler's tables are not the parser's
and neither is rsasm's, so it is still an independent source, and it reaches
every operand value a form allows rather than the ones someone thought to
write down.

Two things have to be put right for a disassembled line to mean the same
thing again:

* **Where it sits.** A branch prints the address it lands on, so a case
  carries the `.skip` that puts it back at the offset it was read from. A
  target in the top half of the address space is written as the negative
  number it stands for, since an assembler asked for `0xffffd738` computes a
  displacement far out of range.
* **What the operand is.** GNU's V850 assembler reads a branch operand as a
  *displacement* where its own disassembler prints an *address*, so those
  lines do not read back as themselves; SPARC's `call` and branches become
  `.`-relative, which also keeps llvm-mc away from a fixup it crashes on.
  Each target says what its lines need in its own script.

What a backend does not implement is skipped by name, with the reason in the
script, so that a missing extension cannot read as thousands of identical
findings. Those lists are the honest record of what each backend leaves out.

## What is not fuzzed, and why

Everything here needs a second opinion. Two things in the crate cannot have
one, so neither is fuzzed:

* **The NEC 78K0.** There is no freely available CA78K0 assembler to compare
  against. Its table came out of NEC's instruction manual, was checked
  against the byte counts in a second NEC manual and cross-checked against
  MAME's disassembler; there is nothing to generate random programs for.
* **The Renesas CC-RL, CC-RH and CC-RX dialects.** No Renesas assembler can
  be run here either. What `tools/xas-diff` does instead is pair vendor
  source with the GNU-syntax program it means and require rsasm's bytes for
  the first to equal GNU as's for the second -- but the pairing is the thing
  under test, so a fuzzer would have to generate both halves, and generating
  the second half from the first is exactly the reading of the manual the
  test is meant to check. A fuzzer for these would need the manuals'
  expression grammar and number notation written out again, independently,
  as an oracle; the instruction encodings themselves are already covered by
  `rx.py`, `rl78.py` and `v850.py` through the GNU syntax.

The Motorola and 8-bit dialects do have one, because a second assembler
reads them: `m68k.py --syntax mot` and `--syntax vasm` fuzz Motorola syntax
against GNU as `--mri` and vasm, `mcs51.py` writes each program in both AS's
and sdas8051's spelling and compares all four ways, and `nasm.py` fuzzes
NASM source against NASM itself.

## x86

`x86.py` generates random x86 instructions in 16-, 32- and 64-bit mode, in
AT&T and Intel syntax, assembles them with GNU as, llvm-mc and rsasm, and
compares the bytes, the relocations and whether each assembler accepted the
line at all.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/x86.py fuzz --count 60000                 # all modes and syntaxes
$ tools/fuzz/x86.py fuzz --mode 16 --syntax intel --only '^(push|pop)$' --seed 3
$ tools/fuzz/x86.py fuzz --count 200000 --out findings.tsv --limit 50
$ tools/fuzz/x86.py check --mode 32 lines.txt          # one instruction per line
```

Instructions come from forms that are not rsasm's own tables. The
general-purpose set, system instructions, the x87 set and a slice of SSE/AVX
are written from the Intel SDM in `x86.py`. Operands are drawn per mode,
including 16-bit ModRM addressing, SIB forms, address-size overrides, segment
overrides, boundary immediates, external symbols and branches that need
relaxation. `--mutations` (default 0.25) is the fraction of cases deliberately
made invalid.

The SIMD and newer extensions — AVX-512 and every subset, FP16, AVX10.2, the
VEX additions, FMA4, XOP, BMI, TBM, AMX, CET, Key Locker and the system
instructions after them — are read from GNU binutils' expanded opcode table
(`opcodes/i386-tbl.h` in the source tree `tools/oracles/build.sh` unpacks),
which `gnutbl.py` decodes; `simd.py` turns each row into a form. Their cases
pick a vector length the row allows, the EVEX-only registers, a memory
operand whose displacement lands on and off every disp8\*N scale, and, where
the row takes them, a writemask, `{z}`, a `{1toN}` broadcast and embedded
rounding or `{sae}`; a mutated case gets a decorator that should be refused.
`--forms base|simd|all` (default `all`) chooses the set; `all` gives the two
halves of the cases.

`gnutbl.py` doubles as a way to look a row up:

```console
$ tools/fuzz/gnutbl.py 'vpdpbusd|vaddph'       # by mnemonic
$ tools/fuzz/gnutbl.py --cpu AVX512_FP16        # by CPU flag
```

`check.sh` assembles instructions from standard input one at a time with all
three assemblers and prints each result, which is handy for a handful of lines.

Every case goes in a section of its own, so one run of each assembler covers a
batch of 200; a batch with errors is reassembled without the rejected cases.
16-bit mode is `.code16` in 32-bit ELF for all three tools. Runs are seeded
(`--seed`) and spread over the CPUs (`--jobs`).

### Reading the report

- **rsasm**: GNU as and llvm-mc agree and rsasm does not. These are the
  findings. The exit status is 1 when there are any.
- **split**: the references disagree. Listed with the one rsasm follows, for a
  person to decide; a settled answer belongs in a corpus under `tools/gas-diff`
  or `tools/mc-diff`, with a comment.
- **convention**: the references disagree in a way a rule in `KNOWN_SPLITS`
  explains — prefix order, gas dropping a redundant segment override, gas
  reading an unknown register name as a symbol in Intel syntax — and rsasm
  follows one of them. **convention-other** is the same where rsasm follows
  the side the rule marks as the wrong one to copy; those are listed too.
- **ignored**: 64-bit lines both references encode as APX.

Findings are grouped by table row, mutation and prefix, most frequent first,
each with its shortest example.

rsasm follows GNU as where the references split. The splits it still follows
llvm-mc on are forms only GNU as accepts and nothing is written in: Intel
`jmp seg, off` with two operands and `callw` in Intel syntax, `arpl` with a
32-bit register, `fcoml %st(1)`, suffixed `loopel` and `cmpxchg8bq`, and
64-bit-mode quirks such as Intel `sysret` being ambiguous without a size.

In the SIMD forms the known splits are llvm-mc's: it ignores a `{z}` with no
writemask, takes an index-only VSIB address in 16-bit mode, rounds
`vp2intersectd`'s odd mask register down, refuses some AT&T length spellings
(`vcvtph2bf8y`) and the Xeon Phi prefetches in Intel syntax, assembles the
FP16 complex multiplications with a repeated register, reads an unsized
`vcvtsi2ss` memory operand outside long mode as ambiguous, and still takes
`{sae}` on some 256-bit AVX10.2 conversions. For the EVEX `vmovq` load and
store the two pick different, equally valid opcodes, and rsasm follows
llvm-mc, as the corpora note.

## ARM

`arm.py` generates random A32 and T32 instructions, assembles them with GNU
as, llvm-mc and rsasm, and compares bytes, relocations and accept/reject.
The forms come from the instruction tables in binutils'
`opcodes/arm-dis.c` — read at run time for their mnemonics and operand
*syntax* only, never their encodings, and independently of
`tools/tables/arm.py`, which writes the table rsasm encodes from. The
instructions whose syntax a format string does not spell out — the
data-processing second operand, the addressing modes, the register lists,
the branches, `msr`/`mrs`, the NEON modified immediate and the structure
transfers — are written out in `SHAPES`.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/arm.py fuzz --count 20000
$ tools/fuzz/arm.py fuzz --target thumb --only '^vld' --seed 7
$ tools/fuzz/arm.py check --target arm lines.txt        # one per line
```

The references run as ARMv7-A with the security, virtualization and divide
extensions and an FPU (`-march=armv7ve -mfpu=neon-vfpv4`, and llvm-mc with
the matching `-mattr`), which is what this backend claims. A quarter of the
cases are deliberately invalid.

Where the two references disagree the script names the rule and which side
rsasm follows (`KNOWN_SPLITS`): rsasm follows GNU as where llvm-mc is the
looser of the two — it takes a condition, a width suffix, an over-wide
immediate, an UNPREDICTABLE register or a two-operand shorthand with a shift
that GNU as refuses, relocates every branch, narrows a move it has
complemented, and loses the top register bit of `fldmiax` — and llvm-mc
where GNU as is: it refuses even an `al` condition on an instruction that
cannot be conditional, and rewrites a one-register `ldm sp`/`stm sp` into a
16-bit stack transfer the register may not reach. Two deviations are
rsasm's own and listed in `DEVIATIONS`: `ldc p9` is a plain coprocessor
transfer, not the half-precision `vldr` GNU as reads it as, and a condition
on `vaddl` or `vsubl` is refused, as it is on every other NEON instruction,
where GNU as alone takes it. Runs of 20,000 instructions find nothing else.

## MSP430

`msp430.py` does the same for the MSP430 backend against `msp430-elf-as`
from `tools/oracles/build.sh`, for the 430, 430X and 430Xv2 instruction sets:
random instructions in every addressing mode and size, MSP430X extension-word
and address instructions, `rpt`, jumps to numbers and labels, the polymorphic
branches, and a share of deliberately invalid cases. Each case refers to a
label of its own and to an undefined symbol, so relocations are compared as
well as bytes.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/msp430.py fuzz --count 100000 --seed 6
$ tools/fuzz/msp430.py fuzz --isa 430x --only '^(mova|calla)$'
$ tools/fuzz/msp430.py check --isa 430 lines.txt
```

There is one reference, so a finding is any case the two treat differently
that is not one of rsasm's recorded deviations (`DEVIATIONS` and `ACCEPTED`
in the script, and the backend's documentation). Runs of 100,000 cases with
seeds 6 and 7 find none.

## Environment

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `GAS` | `as` (must handle `--32` and `--64`) |
| `LLVM_MC` | `llvm-mc` (verified with LLVM 22) |
| `RSASM_ORACLES` | `target/oracles` under the repository root: the cross assemblers, and the binutils source some fuzzers read their forms from |

A reference that is not installed fails the fuzzer rather than being
skipped, so a machine that has lost one cannot read as a pass.

## AArch64

`aarch64.py` fuzzes the AArch64 backend, SIMD, floating point and SVE above
all, against llvm-mc and GNU as.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/aarch64.py fuzz --count 100000            # needs RSASM_ORACLES for GNU as
$ tools/fuzz/aarch64.py fuzz --only '^(ld|st)[1-4]' --mutations 0.6 --seed 3
$ tools/fuzz/aarch64.py fuzz --source gnu --count 50000  # GNU objdump's spellings
$ tools/fuzz/aarch64.py check --no-gas tools/mc-diff/aarch64-sve-words.txt
```

There is no table of forms here. Cases are llvm-mc's own disassembly of
random instruction words, weighted towards the AdvSIMD, floating-point and
SVE encoding groups, so every form llvm-mc prints is reachable with operands
of every value; the backend's table was measured from llvm-mc too, but by
assembling, so the disassembler's view is an independent one. `--mutations`
(default 0.25) is the fraction of cases then changed into likely-invalid ones:
a number moved past its range, an arrangement or register width swapped, an
operand dropped.

Each line is assembled by all three a batch at a time: every AArch64
instruction is one word, so a batch's output splits into lines, and a tool
that refuses one line of a batch is run again without it. The classes are
`rsasm` (the references agree and rsasm does not: the findings), `mc-only`
and `gas-only` (the references disagree and rsasm follows that one), and
`neither`. The AArch64 corpora follow llvm-mc, except that rsasm refuses the
out-of-range immediates llvm-mc truncates (`ext v0.8b, v1.8b, v2.8b, #8`),
as GNU as does. `--source gnu` takes the cases from GNU objdump's
disassembly instead, which is how the spellings GNU as source is written in
get tried. Lines for what the backend leaves out are dropped rather than
counted: SME's ZA array and lookup tables, predicates as counters, and the
multi-vector operands of SME2 (two register lists in one instruction).

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `RSASM_ORACLES` | `target/oracles`, for `bin/aarch64-elf-as` and `-objdump` |
| `GAS` | `$RSASM_ORACLES/bin/aarch64-elf-as` |
| `LLVM_MC` | `llvm-mc` (verified with LLVM 22) |

## PowerPC

`powerpc.py` generates random AltiVec, VSX, POWER8, POWER9 and POWER10
instructions for `powerpc64`, `powerpc64le` and `powerpc`, assembles them with
GNU as 2.47 (`-mfuture`), llvm-mc and rsasm, and compares the same way: bytes,
relocations and accept/reject decision, one section per case.

```console
$ cargo build --all-features --bin rsasm
$ tools/oracles/build.sh                              # GNU as and the binutils source
$ tools/fuzz/powerpc.py fuzz --count 120000 --seed 1   # all three targets
$ tools/fuzz/powerpc.py fuzz --target powerpc64le --only '^xx' --seed 3
$ tools/fuzz/powerpc.py check --target powerpc lines.txt
```

The forms come from binutils' `opcodes/ppc-opc.c`, read at run time for each
instruction's mnemonic and the kind and range of each operand, never for its
encoding, so the fuzzer shares nothing with rsasm but the list of
instructions. Operands are drawn per kind: register numbers written bare or
with their `%v`, `%vs`, `%r` or `%f` names, immediates at and near the ends of
their range, displacements at the multiple their form requires, the R bit,
and `sym@l` and `sym@pcrel` references. `--mutations` (default 0.25) makes a
fraction invalid: out-of-range or misaligned values, a register past its bank
or from another one, an odd VSX pair, an operand too many or too few, an R of
1 with a base register. The instructions README.md lists as not implemented
(the MMA accumulators, POWER11's AES instructions, the privileged set) are left
out of the table.

The classes are x86.py's, plus **deviation**: both references agree and rsasm
refuses on purpose. There are two: a doubleword instruction in 32-bit code,
and a register name from the wrong bank (`%vs3` where a GPR goes), which both
references read as its number, GNU as with a warning. The known splits
between the references are GNU as accepting more mnemonics, operands and
ranges than llvm-mc (rsasm accepts them too), llvm-mc accepting register
numbers and immediates past the end of their field (rsasm refuses them, as
GNU as does), the relocations llvm-mc writes for DS-form and `@pcrel`
references in 32-bit code (rsasm writes GNU as's), and `@pcrel` with an R of
0 (GNU as writes it, llvm-mc refuses or mis-encodes it, and rsasm refuses
it). A run of 600,000 instructions, 200,000 per target, finds no case where
rsasm differs from both references and no split outside those.

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `RSASM_ORACLES` | `target/oracles`, for `bin/powerpc64-linux-gnu-as` and `src/binutils-2.47` |
| `GAS` | `$RSASM_ORACLES/bin/powerpc64-linux-gnu-as` |
| `LLVM_MC` | `llvm-mc` (verified with LLVM 22) |

## The 8051

`mcs51.py` generates random whole 8051 programs from a table of forms written
from Intel's MCS-51 instruction set — labels with forward and backward
references, generic `JMP` and `CALL`, bit addresses, `DB`/`DW`/`DS`, and
code placed just short of a 2 KiB block boundary — and assembles each with
rsasm, with the Macro Assembler AS and with SDCC's sdas8051 and sdld, all
from `tools/oracles/build.sh`. A program both references can read is written
in both spellings and compared four ways; the rest, AS only.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/mcs51.py fuzz --count 20000
$ tools/fuzz/mcs51.py fuzz --count 20000 --as-only --seed 7
$ tools/fuzz/mcs51.py corpus as     # the one-line corpus for tools/xas-diff
```

`--mutations` (default 0.25) is the fraction of programs made invalid: an
operand out of range, reserved space that pushes a branch out of reach.
Programs are classified as in the module comment: **rsasm** findings, and
the known places where the references and rsasm part — **lenient** (sdas8051
truncates an operand AS and rsasm refuse), **strict** (sdld refuses an `LJMP`
below 0 that AS takes as a 16-bit value), **boundary** (an `AJMP` or `ACALL`
in the last two bytes of a block; see `tools/xas-diff/README.md`) and
**first-pass** (AS stops after a first pass in which it guessed a forward
`JMP` or `CALL` short). Two runs of 40,000 programs each, one mixed and one
AS-only, find no case where rsasm differs.

# m68k

`m68k.py` generates random 680x0 and ColdFire instructions for one CPU model
at a time (`--cpu 68030`, `--cpu 5475`, `--cpu all`), in GNU syntax, in
Motorola syntax against GNU as `--mri`, or in Motorola syntax against vasm,
and compares the bytes, the relocations and the accept/reject decisions.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/m68k.py fuzz --cpu all --syntax all --count 400000
$ tools/fuzz/m68k.py fuzz --cpu 68020,68040 --syntax vasm --count 50000
$ tools/fuzz/m68k.py fuzz --cpu 68040 --syntax mot --only '^fmove' --seed 3
$ tools/fuzz/m68k.py corpus --first --cpu 68040 --syntax gas
$ tools/fuzz/m68k.py check --cpu 68020 --syntax gas lines.txt
```

Its forms are GNU's own opcode table, read out of the binutils source by
`tools/tables/m68k.py` rather than from rsasm's generated copy, and its
operands are drawn per operand kind the way `tc-m68k.c` matches them: every
addressing mode a kind takes, 68020 full extension words where the CPU has
them, register lists, k-factors, float literals, MMU and control registers,
symbols, and branches whose targets move as the batch relaxes. By default
only the instructions rsasm encodes from that table are generated; `--all`
adds the 68000-68020 integer set, where rsasm deliberately assembles what is
written and GNU as substitutes (`addw #1` becomes `addq`), so expect findings.

Against vasm each case also goes to GNU as `--mri`, and one where vasm alone
differs from rsasm is a **split**, counted rather than listed (`--splits`
lists them): vasm and GNU as part ways by design (which names a 68000 takes as
registers, `movep` to `(An)`, one-operand `fsub.x`), and rsasm follows GNU as.
That mode is where extended and packed float immediates are checked, which GNU
as gets wrong or refuses.

What rsasm deliberately does differently from GNU as is not generated, since
one refused line moves every later label in its batch; `deviates` and
`mri_skips` in the script list each with its reason. A run of 400,000 cases
over every CPU in both syntaxes, and 100,000 against vasm, finds nothing.
## AVR

`avr.py` generates whole random AVR programs and compares what `avr-elf-as`
and rsasm make of them: labels in several sections, instructions from every
row of GNU binutils' opcode table (`include/opcode/avr.h`) with operands of
every shape, branches forward and back across `.skip`s that put some of them
out of reach, the `lo8()` family of modifiers on numbers, labels and
undefined symbols, data, alignment and `.org`, for one of twenty-one cores.

```console
$ cargo build --all-features --bin rsasm
$ tools/fuzz/avr.py fuzz --count 3000 --seed 1
$ tools/fuzz/avr.py fuzz --core avrtiny --count 500 --mutations 0.5
$ tools/fuzz/avr.py check --core avr5 prog.s
```

Both objects are read the way `tools/mc-diff/canon.sh` reads them, with
`e_flags` and `.avr.prop` too; symbols are declared at the top of each
program, so they come in the same order. A program with nothing undefined is
also linked by `avr-elf-ld` at address 0 with its sections end to end (and
`--no-stubs` for the cores with a 22-bit program counter) and compared with
`rsasm -f bin`, which checks every displacement and every relocated value.
`--mutations` (default 0.25) is the fraction of programs given one statement
meant to be refused.

A program is **agree** (the same object and image, or both refused),
**rsasm** (a finding, shown after removing every statement it does not need),
or **known**, where rsasm differs on purpose: it refuses an `ldi` constant
below -255, an AVR-tiny `lds`/`sts` address outside 0x40-0xbf, a `call` past
22 bits and `pm()` of an odd number, which GNU as keeps the low bits of with
at most a warning, and assembles `lo8(gs())` of a number, on which GNU as
stops with "unknown relocation type".

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `RSASM_ORACLES` | `target/oracles`, with `avr-elf-as`, `avr-elf-ld` and `avr-elf-objcopy` in `bin` |

## RISC-V

`riscv.py` generates RV32 and RV64 instructions from the opcode table in
binutils' `opcodes/riscv-opc.c`, read at run time for each row's mnemonic,
the XLEN it is for and its operand *format string* -- what `riscv_ip` in GNU
as reads to parse operands -- never for its encoding. What each letter of
that string means is written out in the script from the same source, and is
the only RISC-V knowledge in it; a row whose format uses a letter the script
does not generate is skipped rather than guessed at.

```console
$ tools/fuzz/riscv.py fuzz --count 20000
$ tools/fuzz/riscv.py fuzz --target riscv32 --only '^f' --seed 7
$ tools/fuzz/riscv.py check --target riscv64 lines.txt
```

GNU as runs with `-mno-relax`: it otherwise pairs every symbolic reference
with an `R_RISCV_RELAX` marker, which is a hint to the linker rather than
part of the encoding, and neither llvm-mc nor rsasm writes one.

The references part ways often enough to need rules: GNU as leaves a
reference to a label to the linker where llvm-mc resolves it, does not run
an alias through compression, and expands `li` into a longer sequence for
some values; llvm-mc truncates a value past the end of a field where GNU as
refuses it. rsasm follows llvm-mc, which is what README.md records RISC-V as
checked against. Three things rsasm does on purpose are listed as
deviations: it resolves a local label the way llvm-mc does, it takes a bare
symbol in a twelve-bit field where both references insist on `%lo`, and it
reads the twenty-bit field of `lui` and `auipc` as signed as well as
unsigned.

Running it found the aliases both references read and rsasm did not (`and
a0, a1, 4` for `andi` and the rest of that family, `csrw frm, 3`, `move`,
`sgt`, `zext.b`, the `sext`/`zext` shift pairs, `scall`, `sbreak`,
`fmv.s.x`, `jr off(rs)`), an `sext.b` whose second shift came out logical
instead of arithmetic, and a `csrrw x0, cycle, x0` compressed to `c.unimp`.

## MIPS, SPARC, SuperH, RX, RL78, V850 and the Z80

These take their cases from GNU objdump (see
[Cases from a disassembler](#cases-from-a-disassembler)). MIPS and SPARC
have llvm-mc as a second reference; the rest have GNU as alone, so a case is
`agree`, a named `deviation`, or a finding.

```console
$ tools/fuzz/mips.py fuzz --count 20000 --target mips64el
$ tools/fuzz/sparc.py fuzz --count 12000 --only '^f' --seed 7
$ tools/fuzz/z80.py check lines.txt
```

GNU as runs with `.set noreorder`, `.set nomacro` and `.set noat` for MIPS:
it otherwise moves instructions into branch delay slots and invents `nop`s,
and the backend does not.

ELF has no class for a 16-bit target, so the Z80's cases get a sixteen-byte
slot each with `.org` and are compared as images -- rsasm's `-f bin` against
the reference's object through `objcopy`. Relocations are not compared
there; `tools/xas-diff` covers the relocated forms.

Three deviations are shared, and each was checked by linking a differing
case with the target's own `ld` and comparing the image:

- **resolves-a-numeric-target** -- GNU as leaves a branch to a number to the
  linker, with the whole value as the addend, where rsasm computes the
  displacement. The linked images are identical.
- **fills-in-a-relocated-field** -- GNU as computes the value *and* emits
  the relocation for it; rsasm leaves those bits zero. With RELA the addend
  is what the linker uses.
- **relocates-an-absolute-target** -- the other way round: GNU as works the
  displacement out as if the section were at zero and emits nothing, where
  rsasm keeps the relocation and must therefore take the long form of a
  relaxable branch.

Two references failing are handled rather than counted: llvm-mc 22 crashes
on SPARC's `call` with an absolute value, and GNU as 2.47 gives up on some
RL78 branches with "Infinite loop encountered whilst attempting to compute
the addresses of symbols". The harness halves a batch a tool gave up on
until it finds the case, drops that reference for it, and counts it as
`skipped`.

Running them found, in SPARC: `mov<cc> %fccN` encoded with the integer
condition codes instead of the floating-point ones, `movre`/`movrne`, the
missing `swap`, `ldstub`, `taddcctv`, `tsubcctv`, `clrb`/`clrh`/`clrx` and
`b`, an address whose base register is the hardwired zero (`[ 0x66 ]`,
`jmpl -2347, %l2`), and the two-operand trap written as one address. MIPS,
SuperH, RX, RL78, V850 and the Z80 found nothing.
