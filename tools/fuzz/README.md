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

## Environment

| Variable | Default |
|---|---|
| `RSASM` | `target/debug/rsasm` under the repository root |
| `GAS` | `as` (must handle `--32` and `--64`) |
| `LLVM_MC` | `llvm-mc` (verified with LLVM 22) |
