# Differential testing against llvm-mc

`run.sh` assembles a corpus with rsasm and with `llvm-mc -filetype=obj`, then
compares the `.text` bytes. It is the only oracle that covers every
architecture in this crate — `tools/gas-diff` checks against GNU as, which is
usually only installed for the host.

```console
$ tools/mc-diff/run.sh            # every architecture that has a corpus
$ tools/mc-diff/run.sh aarch64    # just one
```

## Adding a corpus

`<arch>.txt` holds one instruction per line; `#` starts a comment. Optionally
`<arch>-programs.txt` holds multi-line snippets separated by `=== <name>`
lines, for anything that needs labels, branch relaxation or directives.

The `<arch>` key and its llvm triple are listed in the `ARCHES` table at the
top of `run.sh`.

## The oracle is pinned to LLVM 22

llvm-mc's answers change between releases, so the version is part of the
test, not a detail of the machine running it. Every corpus here was verified
against LLVM 22. `run.sh` prints the version it used and warns if it is not
22, and CI installs 22 explicitly and refuses to run against anything else.

This is not hypothetical. Against LLVM 18 — what the CI image shipped — 9 of
~3,900 cases disagree, and none are rsasm's fault:

- **LLVM 18 crashes** on a SPARC snippet mixing data and code ("unable to write
  nop sequence of 1 bytes … PLEASE submit a bug report").
- **LLVM 18 rejects valid input**: Intel-syntax AVX gathers such as
  `vgatherqps xmm3, dword ptr [rax+ymm1*4], xmm2`, which LLVM 22 and GNU as
  both accept.
- **LLVM changed its mind**: RISC-V `li` materializes constants with `addi`
  in 22 but `addiw` in 18. Both are correct; they are just different.

When moving to a newer LLVM, run the corpus under both versions first and read
every difference, as above, before deciding which side is right.

## What this is and is not

A matching byte string means rsasm agrees with LLVM about an encoding. It does
**not** mean the instruction is the best choice, and where two encodings are
equally valid the two assemblers may legitimately disagree — alignment padding
is the standing example. Record deliberate divergences as a comment in the
corpus rather than deleting the case.

Expectations in `tests/` should be *derived* from a run of this script, never
the other way round: a hermetic test can only confirm that rsasm still agrees
with what rsasm said last time.
