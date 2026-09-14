#!/bin/bash
# Prints an ELF object in a form two assemblers can agree on.
#
#   tools/mc-diff/canon.sh o.o
#
# Three parts, each in the object's own order:
#
#   section .text SHT_PROGBITS flags=0x6 size=0x10 align=4
#     0000000013050000...
#   symbol foo Global Function STV_DEFAULT .text+0x4
#   .rela.text 0x4 R_RISCV_CALL_PLT foo+0x0
#
# A section is listed if it is allocated and not empty, with its bytes unless
# it is SHT_NOBITS. What a reference writes of its own accord is left out:
# the ABI and attribute sections (`.reginfo`, `.MIPS.abiflags`,
# `.riscv.attributes`, `.ARM.attributes`, `.note.*`, ...), and `.text`,
# `.data` and `.bss` while they are empty, which GNU as always creates.
#
# A symbol is listed if it is global, weak or undefined: which local labels
# reach the symbol table, and under what names, differs between assemblers
# without meaning anything to a linker. Relocations are read through
# relocs.awk, which names a local target by its section and offset for the
# same reason.
#
# Plain POSIX awk: no strtonum, so hex is converted by hand.
set -u
here=$(cd "$(dirname "$0")" && pwd)
obj=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

llvm-readobj --sections "$obj" | ${AWK:-awk} '
  function hex(h,    i, v) {
    sub(/^0x/, "", h); h = toupper(h); v = 0
    for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1
    return v
  }
  function flush() {
    if (name == "" || !alloc || size == 0) return
    if (name ~ /^\.(reginfo|pdr|comment|gnu\.attributes|riscv\.attributes|note)/ || name ~ /^\.(MIPS|ARM)\./) return
    printf "%s %s %s flags=%s size=0x%x align=%d\n", idx, name, type, flags, size, align
  }
  $1 == "Section" && $2 == "{" { name = ""; alloc = 0 }
  $1 == "Index:" { idx = $2 }
  $1 == "Name:" { name = $2 }
  $1 == "Type:" { type = $2 }
  $1 == "Flags" { f = $3; gsub(/[()]/, "", f); flags = f; alloc = int(hex(f) / 2) % 2 }
  $1 == "Size:" { size = $2 + 0 }
  $1 == "AddressAlignment:" { align = $2 }
  $1 == "}" { flush(); name = "" }
' > "$tmp/sections"

# By name: GNU as creates `.text`, `.data` and `.bss` before reading the
# source, and the others as the source names them, so the order of the
# section headers says nothing about the program.
sort -k2,2 "$tmp/sections" | while read -r idx name type flags size align; do
  echo "section $name $type $flags $size $align"
  [ "$type" = SHT_NOBITS ] && continue
  llvm-objcopy --dump-section "$name=$tmp/bytes" "$obj" "$tmp/copy" 2> /dev/null
  printf '  %s\n' "$(xxd -p "$tmp/bytes" | tr -d '\n')"
done

llvm-readobj --symbols "$obj" > "$tmp/syms"
${AWK:-awk} '
  function field(line,    s) { s = line; sub(/^[^:]*: ?/, "", s); sub(/ ?\([0-9a-fA-Fx]+\)$/, "", s); return s }
  $1 == "Symbol" && $2 == "{" { n++; other = "STV_DEFAULT"; inother = 0 }
  $1 == "Name:" { name = field($0) }
  $1 == "Value:" { value = $2 }
  $1 == "Binding:" { bind = $2 }
  $1 == "Type:" { type = $2 }
  $1 == "Other" && $2 == "[" { inother = 1 }
  inother && $1 ~ /^STV_/ { other = $1 }
  $1 == "]" { inother = 0 }
  $1 == "Section:" {
    sect = field($0)
    # GNU as for RL78 declares `__rl78_abs__` in every object, used or not.
    if (n > 1 && (bind != "Local" || sect == "Undefined") && name != "__rl78_abs__")
      printf "symbol %s %s %s %s %s+%s\n", name, bind, type, other, sect, value
  }
' "$tmp/syms"

# By section and offset, keeping the order of entries at one offset (a
# RISC-V ADD/SUB pair): GNU as writes the fixups of instructions it relaxed
# after the others.
llvm-readobj --relocs --expand-relocs "$obj" |
  ${AWK:-awk} -f "$here/relocs.awk" "$tmp/syms" - |
  ${AWK:-awk} '{ o = substr($2, 3); printf "%s\t%16s\t%s\n", $1, o, $0 }' |
  sort -s -t "$(printf '\t')" -k1,1 -k2,2 | cut -f3-
