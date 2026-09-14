# Differential testing against cross assemblers

For targets that neither `tools/gas-diff` (the host's GNU as) nor
`tools/mc-diff` (llvm-mc) can assemble: m68k, V850/RH850, RL78, RX, SuperH,
and the 8-bit Z80, 6502 and 8080.

```console
$ tools/oracles/build.sh          # once: builds the pinned references
$ tools/xas-diff/run.sh           # every target with a corpus
$ tools/xas-diff/run.sh m68k-mot  # just one
```

The references are GNU binutils 2.47, vasm, cc65 2.19's ca65 and the Macro
Assembler AS, built into `target/oracles/`,
or wherever `RSASM_ORACLES` points — useful for sharing one build between
worktrees, since binutils takes minutes per target.
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
| `rl78-ccrl` | `rl78`, CC-RL syntax | `rl78-elf-as`, on the GNU half of each pair |
| `rh850-ccrh` | `rh850`, CC-RH syntax | `v850-elf-as -mv850e3v5`, likewise |
| `rx-ccrx` | `rx`, CC-RX syntax | `rx-elf-as`, likewise |
| `6502` | `6502`, 8-bit syntax | `ca65`, laid out by `ld65` |
| `6502-vasm` | `6502`, 8-bit syntax | `vasm6502_oldstyle` |
| `z80` | `z80`, 8-bit syntax | `z80-elf-as`, linked at 0 by `z80-elf-ld` |
| `z80-gas` | `z80`, GNU syntax | `z80-elf-as`, on `z80.txt` |
| `z80-vasm` | `z80`, 8-bit syntax | `vasmz80_oldstyle`, on `z80.txt` and its own programs |
| `i8080` | `i8080`, 8-bit syntax | `asl -cpu 8080`, converted by `p2bin` |

## Vendor syntax no reference reads

No Renesas assembler can be run here, so CC-RL, CC-RH and CC-RX source cannot be
compared against the assembler it was written for. Their corpora,
`<key>-pairs.txt`, hold pairs instead:

```text
=== what the pair shows
	MOV	[DE], #1		; CC-RL, assembled by rsasm -d ccrl
--- gnu
	mov	[de+0], #1		; the same thing in GNU syntax, assembled by GNU as
```

The syntax rules come from the Renesas manuals, and the pairing — that the
GNU half means what the manual says the vendor half means — is the claim each
case makes; the bytes of both halves must then agree. A GNU half the
reference refuses counts as a failure, never a match. The pairs are also
the source of the expected bytes in `tests/rl78_ccrl.rs`,
`tests/rh850_ccrh.rs` and `tests/rx_ccrx.rs`.

The vendor half is assembled without a section directive, because only the
first section's bytes are compared; CC-RX's `.SECTION` and data-section
padding are tested in `tests/rx_ccrx.rs` instead.

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

## The 8-bit references

Each 8-bit target has the assembler its source is usually written for as its
reference, and a second where one reads the same syntax:

- **6502: ca65.** cc65's assembler is what most 6502 source today is written
  for. It assembles in one pass, so a forward reference is absolute, and its
  `.org` sets the location counter without padding; the corpus keeps to a
  leading `.org`. vasm is the second opinion, on programs only: it picks zero
  page for any address that turns out to fit, and has no `z:`/`a:` or dotted
  directives in oldstyle syntax.
- **Z80: GNU as.** Linked at address 0, since an unlinked object leaves
  absolute addresses to the linker. GNU as has no `org` directive of its own
  (`.org` pads), reads `add b` as something other than `add a,b`, and gives
  -1 for a true comparison; those cases are in the vasm programs or nowhere.
  vasm reads the whole one-line corpus identically.
- **8080: AS.** Neither GNU as nor vasm reads Intel's 8080 syntax faithfully,
  and AS does, with two gaps of its own: it has no `D` radix suffix or `AND`-
  style word operators, and its `$` in a data list is the statement's
  address rather than the item's.

A reference that refuses a case never matches, so the corpora hold only
source every reference for the key accepts.

## 78K0

No reference exists — CA78K0 is a proprietary Windows tool and neither GNU
binutils nor LLVM supports the 78K0 — so it has no corpus here. Its tables are
verified by tests that walk the whole opcode space.
