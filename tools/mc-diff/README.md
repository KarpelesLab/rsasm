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

## What this is and is not

A matching byte string means rsasm agrees with LLVM about an encoding. It does
**not** mean the instruction is the best choice, and where two encodings are
equally valid the two assemblers may legitimately disagree — alignment padding
is the standing example. Record deliberate divergences as a comment in the
corpus rather than deleting the case.

Expectations in `tests/` should be *derived* from a run of this script, never
the other way round: a hermetic test can only confirm that rsasm still agrees
with what rsasm said last time.
