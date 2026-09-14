#!/bin/bash
# Differential test against cross assemblers built by tools/oracles/build.sh.
#
# For targets neither llvm-mc nor the host's GNU as can assemble: m68k (in
# GNU and Motorola syntax), V850/RH850, RL78, RX and SuperH. Assembles a corpus
# with rsasm and with the reference, and compares the code bytes. ARM and
# Thumb, which llvm-mc does assemble, are here too, for what GNU as decides
# differently and llvm-mc cannot check: literal pools, interworking and
# mapping symbols. Those are compared as whole objects.
#
#   tools/xas-diff/run.sh              # every target with a corpus
#   tools/xas-diff/run.sh m68k rx      # just these
#
# Corpora: tools/xas-diff/<key>.txt, one statement per line, and optionally
# <key>-programs.txt with multi-line snippets separated by `=== <name>`.
# Motorola source is column-sensitive, so indent instructions in those corpora.
#
# A vendor syntax no reference assembler reads (CC-RL, CC-RH, CC-RX) is checked in
# pairs instead: <key>-pairs.txt holds snippets separated by `=== <name>`, each
# split by a `--- gnu` line into the vendor source, which rsasm assembles in
# the key's dialect, and the GNU-syntax source that means the same thing,
# which the reference assembles. The pairing itself is what is under test.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# RSASM_ORACLES points somewhere else, so a worktree or a CI cache can share one
# build of the references instead of rebuilding binutils per checkout.
bin="${RSASM_ORACLES:-$root/target/oracles}/bin"

# key | rsasm arch | rsasm dialect | reference command | how to get the code
#
# The extraction is `elf:<section>` for an ELF object — RX keeps code in `P`,
# the Renesas name, not `.text` — `bin` for a flat binary, or `obj` for a
# whole object: `e_flags`, every allocated section's size, alignment and
# bytes, every relocation and the symbol table, as object.awk and
# ../mc-diff/relocs.awk print them. In an `obj` corpus a snippet named
# `refused: ...` matches when both assemblers reject it.
#
# ARM is checked against GNU as for ARMv7-A, whose Thumb-2 no-ops and
# interworking rules are what `-march=armv7-a` gives; without it GNU as
# assumes an ARMv4T-era CPU. Its corpora start with `.syntax unified`, GNU
# as's default being the older divided Thumb syntax, and rsasm knowing only
# the unified one.
#
# vasm is only a secondary reference, run with `-no-opt -devpac`. By default it
# is an optimizing assembler that rewrites instructions (`move.l #1,d0` becomes
# `moveq #1,d0`) and deletes branches, which is not what rsasm or GNU as do;
# with -no-opt it also stops choosing absolute-short addresses, which GNU as
# does. So GNU as `--mri` is the reference for Motorola encodings, and vasm
# corpora should hold only cases with no size choice in them.
TARGETS="
m68k|m68k|gas|m68k-elf-as|elf:.text
m68k-mot|m68k|motorola|m68k-elf-as --mri|elf:.text
m68k-vasm|m68k|motorola|vasmm68k_mot -quiet -no-opt -devpac -Fbin|bin
v850|v850|gas|v850-elf-as|elf:.text
rh850|rh850|gas|v850-elf-as -mv850e3v5|elf:.text
rl78|rl78|gas|rl78-elf-as|elf:.text
rx|rx|gas|rx-elf-as|elf:P
sh|sh|gas|sh-elf-as|elf:.text
shl|shl|gas|sh-elf-as -little|elf:.text
rl78-ccrl|rl78|ccrl|rl78-elf-as|elf:.text
rh850-ccrh|rh850|ccrh|v850-elf-as -mv850e3v5|elf:.text
rx-ccrx|rx|ccrx|rx-elf-as|elf:P
arm|arm|gas|arm-none-eabi-as -march=armv7-a|obj
thumb|thumb|gas|arm-none-eabi-as -march=armv7-a -mthumb|obj
"

[ -d "$bin" ] || { echo "no oracles in $bin; run tools/oracles/build.sh" >&2; exit 0; }
command -v llvm-objcopy > /dev/null || { echo "llvm-objcopy not found" >&2; exit 0; }
cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --example hexdump --bin rsasm ||
  exit 1
hexdump="$root/target/debug/examples/hexdump"
rsasm="$root/target/debug/rsasm"

pass=0
fail=0

reference() { # command, extraction; source on stdin
  local cmd=$1 extract=$2 d tool
  d=$(mktemp -d)
  cat > "$d/in.s"
  tool=${cmd%% *}
  if [ ! -x "$bin/$tool" ]; then
    echo "REF-MISSING: $tool"; rm -rf "$d"; return
  fi
  case "$extract" in
    bin)
      if ! (cd "$d" && "$bin/$tool" ${cmd#"$tool"} -o out.bin in.s > log 2>&1); then
        echo "REF-ERROR: $(grep -m2 -iE 'error|fatal' "$d/log" | tr '\n' ' ')"; rm -rf "$d"; return
      fi ;;
    elf:*)
      if ! (cd "$d" && "$bin/$tool" ${cmd#"$tool"} -o out.o in.s > log 2>&1); then
        echo "REF-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"; rm -rf "$d"; return
      fi
      llvm-objcopy -O binary --only-section="${extract#elf:}" "$d/out.o" "$d/out.bin" 2>/dev/null ;;
  esac
  [ -f "$d/out.bin" ] && xxd -p "$d/out.bin" | tr -d '\n' | sed 's/../& /g;s/ $//'
  echo
  rm -rf "$d"
}

# The canonical form of an object, for the `obj` extraction.
canon_obj() { # object
  local o=$1 name
  llvm-readobj --file-headers --sections --symbols "$o" | awk -f "$here/object.awk" > "$o.txt"
  cat "$o.txt"
  for name in $(awk '$1 == "section" && $3 == "SHT_PROGBITS" { print $2 }' "$o.txt"); do
    llvm-objcopy -O binary --only-section="$name" "$o" "$o.bin" 2>/dev/null
    # Sixteen to a line with offsets, so a difference shows as the lines it
    # is on rather than as one line the size of the section.
    xxd -g1 -c16 "$o.bin" | cut -c1-58 | sed "s/^/bytes $name /"
  done
  llvm-readobj --symbols "$o" > "$o.syms"
  # Relocations are sorted too: GNU as writes those of a relaxed instruction
  # after the others, and the order means nothing to a linker.
  llvm-readobj --relocs --expand-relocs "$o" |
    ${AWK:-awk} -f "$root/tools/mc-diff/relocs.awk" "$o.syms" - | LC_ALL=C sort
}

compare_obj() { # key arch cmd name source
  local d tool m r
  d=$(mktemp -d)
  printf '%s\n' "$5" > "$d/in.s"
  tool=${3%% *}
  if [ ! -x "$bin/$tool" ]; then
    m="REF-MISSING: $tool"
  elif (cd "$d" && "$bin/$tool" ${3#"$tool"} -o ref.o in.s > log 2>&1); then
    m=$(canon_obj "$d/ref.o")
  else
    m="REF-ERROR: $(grep -m2 -iE 'error' "$d/log" | tr '\n' ' ')"
  fi
  if "$rsasm" -a "$2" -o "$d/rs.o" "$d/in.s" > "$d/log" 2>&1; then
    r=$(canon_obj "$d/rs.o")
  else
    r="RSASM-ERROR: $(tr '\n' ' ' < "$d/log")"
  fi
  rm -rf "$d"
  if [ "${4#refused: }" != "$4" ]; then
    # Both have to refuse it; matching output would mean neither did.
    if [ "${m#REF-ERROR}" != "$m" ] && [ "${r#RSASM-ERROR}" != "$r" ]; then
      pass=$((pass + 1))
      return
    fi
  elif [ "$m" = "$r" ] && [ "${m#REF-}" = "$m" ]; then
    pass=$((pass + 1))
    return
  fi
  fail=$((fail + 1))
  echo "### [$1] $4"
  printf '%s\n' "$5" | sed 's/^/    |/'
  if [ "${m#REF-}" != "$m" ] || [ "${r#RSASM-}" != "$r" ] || [ "$m" = "$r" ]; then
    echo "  reference: ${m:0:300}"
    echo "  rsasm:     ${r:0:300}"
  else
    diff <(printf '%s\n' "$m") <(printf '%s\n' "$r") | sed -n 's/^< /  reference: /p; s/^> /  rsasm:     /p'
  fi
}

compare() { # key arch dialect cmd extract name source [reference-source]
  local r m gnu="${8-$7}"
  if [ "$5" = obj ]; then
    compare_obj "$1" "$2" "$4" "$6" "$7"
    return
  fi
  m=$(printf '%s\n' "$gnu" | reference "$4" "$5")
  r=$(printf '%s\n' "$7" | "$hexdump" "$2" "$3" "${5%%:*}" 2>&1)
  # A reference that fails is never a match: a pair whose GNU half does not
  # assemble proves nothing about the vendor half.
  if [ "$m" = "$r" ] && [ "${m#REF-}" = "$m" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$1] $6"
    printf '%s\n' "$7" | sed 's/^/    |/'
    if [ $# -ge 8 ]; then
      echo "  --- gnu"
      printf '%s\n' "$gnu" | sed 's/^/    |/'
    fi
    echo "  reference: $m"
    echo "  rsasm:     $r"
  fi
}

run_target() { # key arch dialect cmd extract
  local lines="$here/$1.txt" progs="$here/$1-programs.txt" before=$((pass + fail))
  if [ -f "$lines" ]; then
    while IFS= read -r line; do
      [ -z "${line// /}" ] && continue
      case "$line" in \#*) continue ;; esac
      compare "$1" "$2" "$3" "$4" "$5" "$line" "$line"
    done < "$lines"
  fi
  if [ -f "$progs" ]; then
    local snippet="" name=""
    while IFS= read -r line; do
      case "$line" in
        "==="*)
          [ -n "$snippet" ] && compare "$1" "$2" "$3" "$4" "$5" "$name" "$snippet"
          snippet=""; name="${line#=== }" ;;
        *) snippet="$snippet$line
" ;;
      esac
    done < "$progs"
    [ -n "$snippet" ] && compare "$1" "$2" "$3" "$4" "$5" "$name" "$snippet"
  fi
  local pairs="$here/$1-pairs.txt"
  if [ -f "$pairs" ]; then
    local vendor="" gnu="" side="" name=""
    flush_pair() {
      if [ -n "$name" ]; then
        if [ "$side" = gnu ]; then
          compare "$1" "$2" "$3" "$4" "$5" "$name" "$vendor" "$gnu"
        else
          fail=$((fail + 1))
          echo "### [$1] $name: no \`--- gnu\` half"
        fi
      fi
    }
    while IFS= read -r line; do
      case "$line" in
        "==="*)
          flush_pair "$@"
          vendor=""; gnu=""; side=""; name="${line#=== }" ;;
        "--- gnu") side=gnu ;;
        *)
          if [ "$side" = gnu ]; then
            gnu="$gnu$line
"
          else
            vendor="$vendor$line
"
          fi ;;
      esac
    done < "$pairs"
    flush_pair "$@"
  fi
  local n=$((pass + fail - before))
  [ "$n" -gt 0 ] && echo "[$1] $n cases"
  return 0
}

wanted="${*:-}"
while IFS='|' read -r key arch dialect cmd extract; do
  [ -z "$key" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $key "*) ;; *) continue ;; esac
  fi
  [ -f "$here/$key.txt" ] || [ -f "$here/$key-programs.txt" ] || [ -f "$here/$key-pairs.txt" ] ||
    continue
  run_target "$key" "$arch" "$dialect" "$cmd" "$extract"
done <<< "$TARGETS"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
