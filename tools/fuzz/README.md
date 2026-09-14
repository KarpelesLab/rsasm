# Differential fuzzing

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
`tools/m68k-opc/gen.py` rather than from rsasm's generated copy, and its
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
