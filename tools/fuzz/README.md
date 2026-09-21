# Differential fuzzing

Four fuzzers: one for x86, one for PowerPC's vector and POWER8-10
instructions (see [PowerPC](#powerpc)), one for whole 8051 programs (see
[The 8051](#the-8051)) and one for whole AVR programs (see [AVR](#avr)).

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

## Environment

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `GAS` | `as` (must handle `--32` and `--64`) |
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
