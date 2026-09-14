# Differential testing against cross assemblers

For targets that neither `tools/gas-diff` (the host's GNU as) nor
`tools/mc-diff` (llvm-mc) can assemble: m68k, V850/RH850, RL78, RX and SuperH.
And for ARM and Thumb where GNU as is the reference that matters and llvm-mc
answers differently; see [ARM](#arm).

```console
$ tools/oracles/build.sh          # once: builds the pinned references
$ tools/xas-diff/run.sh           # every target with a corpus
$ tools/xas-diff/run.sh m68k-mot  # just one
```

The references are GNU binutils 2.47 and vasm, built into `target/oracles/`,
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
| `arm` / `thumb` | `arm` / `thumb`, whole objects | `arm-none-eabi-as -march=armv7-a` (`-mthumb`) |

## ARM

llvm-mc checks ARM and Thumb encodings in `tools/mc-diff`, but the source
people write for ARM was written against GNU as, and for literal pools,
mapping symbols and interworking the two disagree. So the `arm` and `thumb`
corpora here compare whole objects against GNU as: `e_flags`; each allocated
section's size, alignment and bytes; every relocation, printed by
`tools/mc-diff/relocs.awk`; and the symbol table, mapping symbols included,
printed by `object.awk`. Sections, symbols and relocation sections are
sorted, since their order is each assembler's own. A snippet named
`refused: ...` matches when both assemblers reject it.

GNU as is run with `-march=armv7-a`: without it, it assumes a CPU with no
Thumb-2 and no `blx`. Every snippet starts with `.syntax unified`, because
GNU as reads Thumb in the older divided syntax unless told otherwise, and
rsasm only knows the unified one.

Where the two still differ, on purpose:

- **Alignment padding in Thumb code.** GNU as for ARMv7 pads with 32-bit
  `nop.w`, after one 16-bit `nop` if the count is odd; rsasm, like llvm-mc,
  uses 16-bit ones throughout. Snippets pad Thumb code with zeros, or not at
  all.
- **A three-operand Thumb immediate on one register.** GNU as assembles
  `adds r0, r0, #1` (and `suble r0, r0, #1` in an `it` block) with the 8-bit
  `adds r0, #1` form; rsasm, like llvm-mc, keeps the 3-bit form the spelling
  asks for, which `tools/mc-diff` checks. Snippets write the two-operand form.
- **`-mthumb-interwork`.** GNU as sets the low bit of a Thumb function's
  address in an ARM `adr` only with that option, which rsasm does not have;
  so the snippets, assembled without it, check that it does not.

Where GNU as and llvm-mc disagree and GNU as is followed, as seen in these
corpora: mapping symbols (llvm-mc marks neither alignment padding nor the
zeros that align a literal pool), padding the end of a code section to a
word (llvm-mc does not), and which branches are left to the linker (llvm-mc
relocates an ARM `bl` even to a label in the same section, and converts no
`bl` to `blx` itself).

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

## 78K0

No reference exists — CA78K0 is a proprietary Windows tool and neither GNU
binutils nor LLVM supports the 78K0 — so it has no corpus here. Its tables are
verified the way the Z80 and 6502 are, by tests that walk the whole opcode
space.
