#!/bin/bash
# Differential test of *linked* multi-object programs.
#
# Every other harness stops at the object file. Bytes alone cannot show a
# relocation that names the wrong symbol or carries the wrong addend -- the
# field a relocation covers is zero in both objects -- and `tools/flat-diff`
# only ever links one object, so nothing it does depends on a symbol being
# resolved across a file boundary. This one assembles a program split over
# two or three objects twice, with the reference assembler and with rsasm,
# links each set with the same GNU ld and the same script, and compares the
# linked image and the linked symbol table. A wrong symbol, addend or
# relocation type then shows up as different linked bytes.
#
#   tools/link-diff/run.sh              # every target with a corpus
#   tools/link-diff/run.sh x86-64 sh    # just these
#
# Corpora: tools/link-diff/<corpus>.txt. `=== <name>` starts a program and
# `--- <file>.s` starts an object inside it, so each program is at least two
# objects that reference each other. The corpora cover, per target, calls and
# branches between objects, absolute and PC-relative data references with
# addends, differences of symbols, weak symbols defined in one object and
# referenced in another, `.comm` and `.bss`, section-relative references, and
# whatever the target's own relocations are for (SuperH's in-field addends,
# AVR's `.avr.prop`, PE's `@IMGREL` and `.secrel32`). A program named
# `refused: ...` is one the reference will not assemble or link, and it
# matches when rsasm refuses it too.
#
# The linker is GNU ld 2.47 from the oracles directory, as in flat-diff. A
# target whose assembler or linker is missing is skipped. Where the target's
# linker relaxes, the same program is linked a second time with `--relax`:
# relaxation is what the difference records and `.avr.prop` exist for, and it
# is only exercised by a link.
#
# What the corpora do not reach, and why:
#
# * MIPS64 has no row: the MIPS GNU ld among the oracles emulates only o32,
#   so it cannot link an n64 object. The same is true in flat-diff.
# * The 8-bit targets (Z80, 6502, 8080, 8051) have no row: rsasm writes flat
#   binaries and Intel HEX for them, not ELF, so there is nothing to link.
# * The GOT and PLT modifiers only appear where the backend has them: x86-64
#   (`@GOTPCREL`, `@PLT`), i386 (`@GOT`, `@GOTOFF`, `@PLT`,
#   `_GLOBAL_OFFSET_TABLE_`), ARM (`sym(GOT)`, `sym(GOTOFF)`,
#   `sym(GOT_PREL)`, `sym(PLT)`, `_GLOBAL_OFFSET_TABLE_` and the
#   `:lower16:`/`:upper16:` halves), AArch64 (`:got:`, `:got_lo12:`, and
#   `:abs_g0_nc:` and its relatives) and PowerPC (`@plt`, `@local`, `@got`,
#   `@toc` and the halves of a 64-bit address). The thread-local models are
#   in the x86-64 and i386 rows, where the linker turns each of them into
#   local exec: `@TLSGD`, `@TLSLD` and `@TLSLDM`, `@DTPOFF`, `@GOTTPOFF`,
#   `@TPOFF` and `@NTPOFF`, and the descriptor pair `@TLSDESC`/`@TLSCALL`.
#   The other three still have none -- ARM's `(TLSGD)`, AArch64's
#   `:tprel_g0:`, PowerPC's `@tprel` and `@dtprel` -- but no longer for want
#   of `STT_TLS`, which a symbol in a thread-local section now has on every
#   target. What each lacks is its own: the relocations, the operand syntax
#   that selects them, and the marker relocations that cover no field but
#   tell the linker which instructions to rewrite (ARM's `(tlscall)` and
#   `.tlsdescseq`, AArch64's `.tlsdesccall`, PowerPC's `@tls` and
#   `bl __tls_get_addr(sym@tlsgd)`); each backend says where it refuses them.
# * A difference of two symbols in different sections is only in the corpora
#   of the targets that have a single relocation for it. RX and RL78 spell it
#   as a stack of `R_*_SYM`, `R_*_OPsub` and a store, which one fixup cannot
#   express; each backend's `reloc.rs` says it is refused rather than
#   approximated, and GNU as writes the stack.
# * Nothing here runs the linked program. There is no qemu user-mode
#   emulator on the machines this is developed on, and only x86-64 could run
#   natively; `cli_smoke` in the CI workflow does that for one program.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
bin="${RSASM_ORACLES:-$root/target/oracles}/bin"

# key | corpora | rsasm arch | assembler | assembler flags | linkers | linker flags | base | extra link variants
#
# The columns are flat-diff's, plus a last one: a semicolon-separated list of
# further linker flag sets, each of which links the same program again. That
# is where `--relax` goes.
#
# The assembler is a GNU as program name looked up in the oracles directory
# (or PATH), or `mc:<triple>` for llvm-mc. GNU as is preferred here: it is
# what rsasm follows for whole objects, so its local and mapping symbols are
# rsasm's, and the linker is its own ld. llvm-mc stands in for the targets
# rsasm follows it for -- MIPS, SPARC, PowerPC and RISC-V section alignment
# is llvm-mc's, and a GNU as reference would place the second object's
# `.text` differently for that reason alone.
#
# RISC-V is linked both ways: without relaxation, and with it, which is
# where a `call` pair that is really one instruction gets shortened.
#
# There is no MIPS64 row: the MIPS GNU ld among the oracles emulates only
# o32. There is no Z80 row: rsasm writes no ELF for the 8-bit targets.
#
# The last two rows are PE/COFF (`-f coff`), linked into an image by GNU ld
# for mingw. Their reference is llvm-mc rather than the mingw GNU as, which
# is what `tools/coff-diff` compares whole objects against: GNU as gives a
# COFF section a 16-byte alignment where llvm-mc and rsasm give it four, so
# a GNU as reference would place the second object's `.text` differently for
# that reason alone.
TARGETS="
x86-64|x86-64|x86-64|x86_64-elf-as|--64|x86_64-elf-ld|-m elf_x86_64|0x401000|
i386|i386|i386|x86_64-elf-as|--32|x86_64-elf-ld|-m elf_i386|0x8048000|
aarch64|aarch64|aarch64|aarch64-elf-as||aarch64-elf-ld||0x400000|
arm|arm|arm|arm-none-eabi-as|-march=armv7-a|arm-none-eabi-ld||0x8000|
thumb|thumb|thumb|arm-none-eabi-as|-march=armv7-a -mthumb|arm-none-eabi-ld||0x8000|
riscv32|riscv|riscv32|mc:riscv32|-mattr=+m,+a,+f,+d,+c|riscv64-elf-ld|-m elf32lriscv --no-relax|0x10000|-m elf32lriscv --relax
riscv64|riscv|riscv64|mc:riscv64|-mattr=+m,+a,+f,+d,+c|riscv64-elf-ld|-m elf64lriscv --no-relax|0x10000|-m elf64lriscv --relax
powerpc|powerpc|powerpc|mc:powerpc||powerpc64-linux-gnu-ld|-m elf32ppc|0x10000000|
powerpc64|powerpc64|powerpc64|mc:powerpc64||powerpc64-linux-gnu-ld|-m elf64ppc --no-toc-optimize|0x10000000|
powerpc64le|powerpc64|powerpc64le|mc:powerpc64le||powerpc64-linux-gnu-ld|-m elf64lppc --no-toc-optimize|0x10000000|
mips|mips|mips|mc:mips||mips64-elf-ld||0x400000|
mipsel|mips|mipsel|mc:mipsel||mips64-elf-ld|-EL|0x400000|
sparc|sparc|sparc|mc:sparc||sparc64-elf-ld|-b elf32-sparc OUTPUT_FORMAT(elf32-sparc) OUTPUT_ARCH(sparc)|0x100000|
sparcv9|sparc|sparcv9|mc:sparcv9||sparc64-elf-ld||0x100000|
m68k|m68k|m68k|m68k-elf-as||m68k-elf-ld||0x10000|
sh|sh|sh|sh-elf-as||sh-elf-ld||0x10000|--relax
shl|sh|shl|sh-elf-as|-little|sh-elf-ld|-EL|0x10000|-EL --relax
rx|rx|rx|rx-elf-as|-muse-conventional-section-names|rx-elf-ld||0x10000|--relax
rl78|rl78|rl78|rl78-elf-as||rl78-elf-ld||0x2000|--relax
msp430|msp430|msp430|msp430-elf-as|-mcpu=430 -mP|msp430-elf-ld|--no-relax|0x1000|--relax
msp430x|msp430,msp430x|msp430x|msp430-elf-as|-mcpu=430x -mP|msp430-elf-ld|--no-relax|0x4000|--relax
v850|v850|v850|v850-elf-as||v850-elf-ld||0x100000|--relax
rh850|v850|rh850|v850-elf-as|-mv850e3v5|v850-elf-ld||0x100000|--relax
avr5|avr5|avr5|avr-elf-as|-mmcu=avr5|avr-elf-ld|-m avr5|0x0|-m avr5 --relax
avr51|avr5|avr51|avr-elf-as|-mmcu=avr51|avr-elf-ld|-m avr51|0x0|-m avr51 --relax
avr6|avr5|avr6|avr-elf-as|-mmcu=avr6|avr-elf-ld|-m avr6 --no-stubs|0x0|-m avr6 --no-stubs --relax
avrtiny|avrtiny|avrtiny|avr-elf-as|-mmcu=avrtiny|avr-elf-ld|-m avrtiny|0x0|-m avrtiny --relax
win64|win64|x86-64|mc:x86_64-windows-msvc||pe:x86_64-w64-mingw32-ld||0|
win32|win32|i386|mc:i686-windows-msvc||pe:i686-w64-mingw32-ld||0|
"

command -v llvm-objcopy > /dev/null || { echo "llvm-objcopy not found; skipping" >&2; exit 0; }
command -v llvm-readelf > /dev/null || { echo "llvm-readelf not found; skipping" >&2; exit 0; }

cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --bin rsasm || exit 1
rsasm="$root/target/debug/rsasm"

pass=0
fail=0
skip=0

tool() { # name -> path, or nothing
  if [ -x "$bin/$1" ]; then echo "$bin/$1"; else command -v "$1"; fi
}

# Assembles $d/$1.s with the reference assembler into $d/$1.ref.o. Prints why
# and returns 1 if it cannot.
assemble_ref() { # stem as asflags
  local stem=$1 as=$2 asflags=$3 asm
  case "$as" in
    mc:*)
      llvm-mc -triple="${as#mc:}" $asflags -filetype=obj -o "$d/$stem.ref.o" "$d/$stem.s" \
        > "$d/log" 2>&1 || { echo "REF-ERROR: $stem: $(head -3 "$d/log" | tr '\n' ' ')"; return 1; } ;;
    *)
      asm=$(tool "$as") || { echo "REF-MISSING: $as"; return 1; }
      "$asm" $asflags -o "$d/$stem.ref.o" "$d/$stem.s" \
        > "$d/log" 2>&1 || { echo "REF-ERROR: $stem: $(head -3 "$d/log" | tr '\n' ' ')"; return 1; } ;;
  esac
}

# The allocated sections of every object, in the order they first appear:
# those with contents first, so that the image is contiguous, then the
# NOBITS ones. The linker would otherwise place what it makes itself -- the
# `.plt` the RL78 GNU ld writes whether or not anything needs it -- in the
# middle of the image.
#
# What a reference writes of its own accord is left out and lands in `.rest`
# after everything else, where it moves nothing: the ABI sections llvm-mc
# adds for MIPS (`.reginfo`, `.MIPS.abiflags`) are allocated, and counting
# them would shift every symbol in the reference's image and nothing in
# rsasm's. `tools/mc-diff/canon.sh` skips the same list.
section_list() { # kind objects...
  local kind=$1 want obj
  shift
  case "$kind" in
    bits) want='$2 != "NOBITS" && $7 ~ /A/' ;;
    nobits) want='$2 == "NOBITS" && $7 ~ /A/' ;;
  esac
  for obj in "$@"; do
    llvm-readelf -S --wide "$obj" | sed -n 's/^ *\[ *[0-9]*\] //p' | awk "$want { print \$1 }"
  done | grep -vE '^\.(reginfo|pdr|comment|gnu\.attributes|riscv\.attributes|note|MIPS\.|ARM\.)' |
    awk '!seen[$0]++'
}

# Writes $d/link.ld for the given section lists.
script() { # base script-commands bits nobits
  local base=$1 cmds=$2 s
  {
    [ -n "$cmds" ] && echo "$cmds"
    echo "SECTIONS {"
    echo "  . = $base;"
    for s in $3; do echo "  $s : { *($s) }"; done
    for s in $4; do
      if [ "$s" = .bss ]; then echo "  .bss : { *(.bss) *(COMMON) }"
      else echo "  $s : { *($s) }"; fi
    done
    case " $4 " in *" .bss "*) ;; *) echo "  .bss : { *(.bss) *(COMMON) }" ;; esac
    # The sections a reference adds of its own accord go nowhere: `.reginfo`
    # has to be merged rather than concatenated, and the MIPS linker refuses
    # an output one of the wrong size, which is what `*(*)` would make of two
    # objects' worth.
    echo "  /DISCARD/ : { *(.reginfo) *(.MIPS.*) *(.ARM.*) *(.comment) *(.pdr) }"
    echo "  .rest : { *(*) }"
    echo "}"
  } > "$d/link.ld"
}

# Links $2... into $1.elf and writes $1.bin, the bytes of the sections with
# contents. Prints why and returns 1 if the link fails.
link() { # out linkflags sections objects...
  local out=$1 sections=$3 s only=() ldflags=() cmds=""
  for s in $2; do
    case "$s" in OUTPUT_*) cmds="$cmds $s" ;; *) ldflags+=("$s") ;; esac
  done
  shift 3
  # A PE image lays itself out: there is no script, the entry is a symbol
  # rather than an address, and the timestamp the linker would otherwise
  # stamp into the header has to be turned off for two runs to agree. Its
  # sections and their contents come out of `llvm-objdump`, which reads the
  # loaded image without the header fields that are a function of when and
  # where it was linked.
  if [ -n "$pe" ]; then
    "$link_ld" "${ldflags[@]}" -e _start --no-insert-timestamp -o "$out.elf" "$@" \
      > "$d/log" 2>&1 ||
      { echo "LINK-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"; return 1; }
    llvm-objdump -h -s "$out.elf" > "$d/od" 2> "$d/log" ||
      { echo "LINK-ERROR: objdump: $(head -1 "$d/log")"; return 1; }
    # Past the first two lines, which name the file.
    tail -n +3 "$d/od" > "$out.bin"
    return 0
  fi
  "$link_ld" "${ldflags[@]}" -e "$base" -T "$d/link.ld" -o "$out.elf" "$@" > "$d/log" 2>&1 ||
    { echo "LINK-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"; return 1; }
  for s in $sections; do only+=(--only-section="$s"); done
  llvm-objcopy -O binary "${only[@]}" "$out.elf" "$out.bin" 2> "$d/log" ||
    { echo "LINK-ERROR: objcopy: $(head -1 "$d/log")"; return 1; }
}

# The linked symbol table, in a form two assemblers can agree on: every
# symbol that is not a section, a file or a mapping symbol, with the value
# the linker gave it. A relocation against the wrong symbol usually still
# links; a symbol that reached the object with the wrong binding, size or
# section does not survive this.
symbols() { # elf
  if [ -n "$pe" ]; then
    llvm-nm "$1" | LC_ALL=C sort
    return
  fi
  llvm-readelf --symbols --wide "$1" | awk '
    NR > 1 && $4 != "SECTION" && $4 != "FILE" && $8 != "" && $8 !~ /^\$/ {
      printf "%s %s %s %s %s %s\n", $8, $2, $3, $4, $5, $7
    }' | LC_ALL=C sort
}

compare() { # key arch as asflags ldflags variants name stems...
  local key=$1 arch=$2 as=$3 asflags=$4 ldflags=$5 variants=$6 name=$7 stem
  shift 7
  local m="" r="" bits nobits v vn=0
  for stem in "$@"; do
    m=$(assemble_ref "$stem" "$as" "$asflags") || break
  done
  case "$m" in
    REF-MISSING:*) skip=$((skip + 1)); return ;;
  esac
  local fmt=()
  [ -n "$pe" ] && fmt=(-f coff)
  for stem in "$@"; do
    "$rsasm" -a "$arch" "${fmt[@]}" -o "$d/$stem.rs.o" "$d/$stem.s" > "$d/rslog" 2>&1 ||
      { r="RSASM-ERROR: $stem: $(tr '\n' ' ' < "$d/rslog")"; break; }
  done
  # A program named `refused: ...` is one the reference will not assemble or
  # link, and it matches when rsasm refuses it too.
  if [ "${name#refused: }" != "$name" ] && [ -n "$m" ] && [ -n "$r" ]; then
    pass=$((pass + 1))
    return
  fi
  if [ -n "$m" ] || [ -n "$r" ]; then
    fail=$((fail + 1))
    echo "### [$key] $name"
    echo "  reference: ${m:-ok}"
    echo "  rsasm:     ${r:-ok}"
    return
  fi
  local refs=() rss=()
  for stem in "$@"; do refs+=("$d/$stem.ref.o"); rss+=("$d/$stem.rs.o"); done
  bits=$(section_list bits "${refs[@]}" "${rss[@]}" | tr '\n' ' ')
  nobits=$(section_list nobits "${refs[@]}" "${rss[@]}" | tr '\n' ' ')
  local cmds="" s
  for s in $ldflags; do case "$s" in OUTPUT_*) cmds="$cmds $s" ;; esac; done
  script "$base" "$cmds" "$bits" "$nobits"

  # The program is linked once per set of linker flags: plain, then each
  # extra variant (`--relax`, where the target's linker relaxes).
  local sets=("$ldflags") all old=$IFS
  IFS=';'
  for v in $variants; do [ -n "$v" ] && sets+=("$v"); done
  IFS=$old
  for all in "${sets[@]}"; do
    local label=$name
    [ "$vn" -gt 0 ] && label="$name [$all]"
    m=$(link "$d/ref$vn" "$all" "$bits" "${refs[@]}")
    r=$(link "$d/rs$vn" "$all" "$bits" "${rss[@]}")
    if [ -z "$m" ] && [ -z "$r" ] &&
      cmp -s "$d/ref$vn.bin" "$d/rs$vn.bin" &&
      diff -q <(symbols "$d/ref$vn.elf") <(symbols "$d/rs$vn.elf") > /dev/null; then
      pass=$((pass + 1))
    elif [ "${name#refused: }" != "$name" ] && [ -n "$m" ] && [ -n "$r" ]; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1))
      echo "### [$key] $label"
      if [ -n "$m" ] || [ -n "$r" ]; then
        echo "  reference: ${m:-ok}"
        echo "  rsasm:     ${r:-ok}"
      else
        diff <(dump "$d/ref$vn.bin") <(dump "$d/rs$vn.bin") |
          sed -n 's/^< /  reference: /p; s/^> /  rsasm:     /p' | head -40
        diff <(symbols "$d/ref$vn.elf") <(symbols "$d/rs$vn.elf") |
          sed -n 's/^< /  reference symbol: /p; s/^> /  rsasm symbol:     /p' | head -40
      fi
    fi
    vn=$((vn + 1))
  done
}

# Hex of a file, 16 bytes to a line, with the image address of each line. A
# PE image's is already `llvm-objdump`'s own listing.
dump() { # file
  if [ -n "$pe" ]; then cat "$1"; else xxd -g1 -o "$((base))" "$1" | cut -c1-58; fi
}

run_target() { # corpora key arch as asflags linkers ldflags base variants
  local corpora=$1 key=$2 arch=$3 as=$4 asflags=$5 linkers=$6 ldflags=$7 variants=$9
  local before=$((pass + fail)) name="" stems=() stem="" progs l
  base=$8
  link_ld=""
  # `pe:` on the linker marks a PE/COFF target: rsasm writes `-f coff`, the
  # linker lays the image out itself, and the two are compared as the loaded
  # image rather than as ELF sections.
  pe=""
  case "$linkers" in pe:*) pe=1; linkers=${linkers#pe:} ;; esac
  for l in ${linkers//,/ }; do
    link_ld=$(tool "$l") && break
  done
  [ -n "$link_ld" ] || { skip=$((skip + 1)); return 0; }
  d=$(mktemp -d)
  for progs in ${corpora//,/ }; do
    [ -f "$here/$progs.txt" ] || continue
    while IFS= read -r line; do
      case "$line" in
        "==="*)
          [ ${#stems[@]} -gt 0 ] && compare "$key" "$arch" "$as" "$asflags" "$ldflags" "$variants" "$name" "${stems[@]}"
          rm -f "$d"/*.s "$d"/*.o
          name="${line#=== }"; stems=(); stem="" ;;
        "---"*)
          stem="${line#--- }"; stem="${stem%.s}"; stems+=("$stem"); : > "$d/$stem.s" ;;
        *)
          [ -n "$stem" ] && printf '%s\n' "$line" >> "$d/$stem.s" ;;
      esac
    done < "$here/$progs.txt"
    [ ${#stems[@]} -gt 0 ] && compare "$key" "$arch" "$as" "$asflags" "$ldflags" "$variants" "$name" "${stems[@]}"
    rm -f "$d"/*.s "$d"/*.o
    name=""; stems=(); stem=""
  done
  rm -rf "$d"
  local n=$((pass + fail - before))
  [ "$n" -gt 0 ] && echo "[$key] $n links"
  return 0
}

wanted="${*:-}"
while IFS='|' read -r key corpus arch as asflags linkers ldflags base variants; do
  [ -z "$key" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $key "*) ;; *) continue ;; esac
  fi
  run_target "$corpus" "$key" "$arch" "$as" "$asflags" "$linkers" "$ldflags" "$base" "$variants"
done <<< "$TARGETS"

[ "$skip" -gt 0 ] && echo "($skip targets skipped: no reference assembler or linker)"
echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
