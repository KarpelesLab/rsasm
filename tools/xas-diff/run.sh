#!/bin/bash
# Differential test against cross assemblers built by tools/oracles/build.sh.
#
# For targets neither llvm-mc nor the host's GNU as can assemble: m68k (in
# GNU and Motorola syntax), V850/RH850, RL78, RX, SuperH, and the 8-bit Z80,
# 6502 and 8080. Assembles a corpus with rsasm and with the reference, and
# compares the code bytes.
#
#   tools/xas-diff/run.sh              # every target with a corpus
#   tools/xas-diff/run.sh m68k rx      # just these
#
# Corpora: tools/xas-diff/<key>.txt, one statement per line, and optionally
# <key>-programs.txt with multi-line snippets separated by `=== <name>`.
# Motorola source is column-sensitive, so indent instructions in those corpora.
#
# Snippets in <key>-relocs.txt, in the programs format, are compared as whole
# objects instead: every allocated section's header and bytes, the global,
# weak and undefined symbols, and the relocations, as tools/mc-diff/canon.sh
# prints them.
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
#     [| the key whose one-line corpus this one shares]
#
# The extraction is `elf:<section>` for an ELF object — RX keeps code in `P`,
# the Renesas name, not `.text` — or `bin` for a flat binary. The 8-bit
# references need a second tool to make one: `linked:<ld>` links the object at
# address 0 and takes `.text`, which resolves the absolute addresses an
# unlinked object leaves as relocations; `ld65` lays a ca65 object out with
# ld65; `p2bin` converts AS's code file. rsasm assembles a flat binary for all
# three, so a leading `org` is the image's load address on both sides.
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
6502|6502|8bit|ca65|ld65
6502-vasm|6502|8bit|vasm6502_oldstyle -quiet -Fbin|bin
z80|z80|8bit|z80-elf-as|linked:z80-elf-ld
z80-gas|z80|gas|z80-elf-as|linked:z80-elf-ld|z80
z80-vasm|z80|8bit|vasmz80_oldstyle -quiet -Fbin|bin|z80
i8080|i8080|8bit|asl -cpu 8080|p2bin
"

[ -d "$bin" ] || { echo "no oracles in $bin; run tools/oracles/build.sh" >&2; exit 0; }
command -v llvm-objcopy > /dev/null || { echo "llvm-objcopy not found" >&2; exit 0; }
command -v llvm-readobj > /dev/null || { echo "llvm-readobj not found" >&2; exit 0; }
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
    ld65)
      # One memory area from address 0, holding every segment ca65 names.
      printf '%s\n' 'MEMORY { M: start = 0, size = $10000, file = %O; }' \
        'SEGMENTS { CODE: load = M, type = rw; RODATA: load = M, type = rw, optional = yes;' \
        '  DATA: load = M, type = rw, optional = yes; ZEROPAGE: load = M, type = rw, optional = yes; }' \
        > "$d/flat.cfg"
      if ! (cd "$d" && "$bin/$tool" ${cmd#"$tool"} -o in.o in.s > log 2>&1 &&
        "$bin/ld65" -C flat.cfg -o out.bin in.o >> log 2>&1); then
        echo "REF-ERROR: $(grep -m2 -iE 'error' "$d/log" | tr '\n' ' ')"; rm -rf "$d"; return
      fi ;;
    p2bin)
      if ! (cd "$d" && "$bin/$tool" ${cmd#"$tool"} -q -o in.p in.s > log 2>&1 &&
        "$bin/p2bin" -q -l 0 in.p out.bin >> log 2>&1) || grep -q 'error' "$d/log"; then
        echo "REF-ERROR: $(grep -m2 -iE 'error' "$d/log" | tr '\n' ' ')"; rm -rf "$d"; return
      fi ;;
    linked:*)
      if ! (cd "$d" && "$bin/$tool" ${cmd#"$tool"} -o in.o in.s > log 2>&1 &&
        "$bin/${extract#linked:}" -e 0 -Ttext=0 -o out.elf in.o >> log 2>&1); then
        echo "REF-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"; rm -rf "$d"; return
      fi
      llvm-objcopy -O binary --only-section=.text "$d/out.elf" "$d/out.bin" 2>/dev/null ;;
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

compare() { # key arch dialect cmd extract name source [reference-source]
  local r m gnu="${8-$7}" format=bin
  m=$(printf '%s\n' "$gnu" | reference "$4" "$5")
  # Everything but an unlinked ELF object is compared as a flat image.
  [ "${5%%:*}" = elf ] && format=elf
  r=$(printf '%s\n' "$7" | "$hexdump" "$2" "$3" "$format" 2>&1)
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

compare_object() { # key arch dialect cmd name source
  local d m r tool=${4%% *} flags=""
  # GNU as for RX renames `.text`, `.data` and `.bss` to Renesas's `P`, `D_1`
  # and `B_1`, which rsasm does not; asked to keep the usual names, it does.
  case "$1" in rx*) flags=-muse-conventional-section-names ;; esac
  d=$(mktemp -d)
  printf '%s\n' "$6" > "$d/in.s"
  if [ ! -x "$bin/$tool" ]; then
    m="REF-MISSING: $tool"
  elif (cd "$d" && "$bin/$tool" ${4#"$tool"} $flags -o ref.o in.s > log 2>&1); then
    m=$("$root/tools/mc-diff/canon.sh" "$d/ref.o")
  else
    m="REF-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"
  fi
  if "$rsasm" -a "$2" -d "$3" -o "$d/rs.o" "$d/in.s" > "$d/log" 2>&1; then
    r=$("$root/tools/mc-diff/canon.sh" "$d/rs.o")
  else
    r="RSASM-ERROR: $(head -3 "$d/log" | tr '\n' ' ')"
  fi
  rm -rf "$d"
  if [ "$m" = "$r" ] && [ "${m#REF-}" = "$m" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$1] $5 (object)"
    printf '%s\n' "$6" | sed 's/^/    |/'
    echo "  reference:"
    printf '%s\n' "$m" | sed 's/^/    /'
    echo "  rsasm:"
    printf '%s\n' "$r" | sed 's/^/    /'
  fi
}

run_target() { # key arch dialect cmd extract corpus
  local lines="$here/$6.txt" progs="$here/$1-programs.txt" before=$((pass + fail))
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
  local objs="$here/$1-relocs.txt"
  if [ -f "$objs" ]; then
    local snippet="" name=""
    while IFS= read -r line; do
      case "$line" in
        "==="*)
          [ -n "$snippet" ] && compare_object "$1" "$2" "$3" "$4" "$name" "$snippet"
          snippet=""; name="${line#=== }" ;;
        *) snippet="$snippet$line
" ;;
      esac
    done < "$objs"
    [ -n "$snippet" ] && compare_object "$1" "$2" "$3" "$4" "$name" "$snippet"
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
while IFS='|' read -r key arch dialect cmd extract corpus; do
  [ -z "$key" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $key "*) ;; *) continue ;; esac
  fi
  corpus=${corpus:-$key}
  [ -f "$here/$corpus.txt" ] || [ -f "$here/$key-programs.txt" ] ||
    [ -f "$here/$key-pairs.txt" ] || [ -f "$here/$key-relocs.txt" ] || continue
  run_target "$key" "$arch" "$dialect" "$cmd" "$extract" "$corpus"
done <<< "$TARGETS"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
