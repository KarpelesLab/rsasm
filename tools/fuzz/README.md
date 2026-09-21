# Differential fuzzing

Three fuzzers: one for x86, one for PowerPC's vector and POWER8-10
instructions (see [PowerPC](#powerpc)), and one for whole 8051 programs (see
[The 8051](#the-8051)).

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

Instructions come from a table of forms written from the Intel SDM, not from
rsasm's own tables: the general-purpose set, system instructions, the x87 set
and a slice of SSE/AVX. Operands are drawn per mode, including 16-bit ModRM
addressing, SIB forms, address-size overrides, segment overrides, boundary
immediates, external symbols and branches that need relaxation. `--mutations`
(default 0.25) is the fraction of cases deliberately made invalid.

Every case goes in a section of its own, so one run of each assembler covers a
batch of 200; a batch with errors is reassembled without the rejected cases.
16-bit mode is `.code16` in 32-bit ELF for all three tools. Runs are seeded
(`--seed`) and spread over the CPUs (`--jobs`).

## Reading the report

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

## Environment

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `GAS` | `as` (must handle `--32` and `--64`) |
| `LLVM_MC` | `llvm-mc` (verified with LLVM 22) |

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

# The 8051

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
