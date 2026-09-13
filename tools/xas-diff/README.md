# Differential testing against cross assemblers

For targets that neither `tools/gas-diff` (the host's GNU as) nor
`tools/mc-diff` (llvm-mc) can assemble: m68k, V850/RH850, RL78, RX and SuperH.

```console
$ tools/oracles/build.sh          # once: builds the pinned references
$ tools/xas-diff/run.sh           # every target with a corpus
$ tools/xas-diff/run.sh m68k-mot  # just one
```

The references are GNU binutils 2.47 and vasm, built into `target/oracles/`.
See `tools/oracles/build.sh` for why the versions are pinned.

## Targets

| Key | rsasm | Reference |
|---|---|---|
| `m68k` | `m68k`, GNU syntax | `m68k-elf-as` |
| `m68k-mot` | `m68k`, Motorola syntax | `m68k-elf-as --mri` |
| `m68k-vasm` | `m68k`, Motorola syntax | `vasmm68k_mot -no-opt -devpac` |
| `v850` | `v850` | `v850-elf-as` |
| `rh850` | `rh850` | `v850-elf-as -mv850e3v5` |
| `rl78` | `rl78` | `rl78-elf-as` |
| `rx` | `rx` | `rx-elf-as` (code is in section `P`) |
| `sh` / `shl` | `sh` / `shl` | `sh-elf-as` / `sh-elf-as -little` |

## Which m68k reference to trust

GNU as `--mri` is the reference for Motorola *encodings*. vasm is a secondary
check, and only for cases with no size choice in them, because it disagrees
with GNU as for reasons that are not rsasm's to copy:

- By default vasm is an **optimizing** assembler. It rewrites instructions —
  `move.l #1,d0` becomes `moveq #1,d0` — and deletes a branch to the next
  instruction. GNU as and rsasm assemble what is written.
- With `-no-opt` it stops choosing absolute-short addressing, so `$0400`
  becomes a 32-bit address where GNU as uses the 16-bit form.

On *syntax* the two agree on every rule we checked, including the one that
surprises people: in Motorola source a word in the first column is a label,
so `rts` written in column 0 assembles to nothing.

## 78K0

No reference exists — CA78K0 is a proprietary Windows tool and neither GNU
binutils nor LLVM supports the 78K0 — so it has no corpus here. Its tables are
verified the way the Z80 and 6502 are, by tests that walk the whole opcode
space.
