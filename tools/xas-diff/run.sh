#!/bin/bash
# Differential test against cross assemblers built by tools/oracles/build.sh.
#
# For targets neither llvm-mc nor the host's GNU as can assemble: m68k (in
# GNU and Motorola syntax), V850/RH850, RL78, RX and SuperH. Assembles a corpus
# with rsasm and with the reference, and compares the code bytes.
#
#   tools/xas-diff/run.sh              # every target with a corpus
#   tools/xas-diff/run.sh m68k rx      # just these
#
# Corpora: tools/xas-diff/<key>.txt, one statement per line, and optionally
# <key>-programs.txt with multi-line snippets separated by `=== <name>`.
# Motorola source is column-sensitive, so indent instructions in those corpora.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# RSASM_ORACLES points somewhere else, so a worktree or a CI cache can share one
# build of the references instead of rebuilding binutils per checkout.
bin="${RSASM_ORACLES:-$root/target/oracles}/bin"

# key | rsasm arch | rsasm dialect | reference command | how to get the code
#
# The extraction is `elf:<section>` for an ELF object — RX keeps code in `P`,
# the Renesas name, not `.text` — or `bin` for a flat binary.
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
"

[ -d "$bin" ] || { echo "no oracles in $bin; run tools/oracles/build.sh" >&2; exit 0; }
command -v llvm-objcopy > /dev/null || { echo "llvm-objcopy not found" >&2; exit 0; }
cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --example hexdump || exit 1
hexdump="$root/target/debug/examples/hexdump"

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

compare() { # key arch dialect cmd extract name source
  local r m
  m=$(printf '%s\n' "$7" | reference "$4" "$5")
  r=$(printf '%s\n' "$7" | "$hexdump" "$2" "$3" "${5%%:*}" 2>&1)
  if [ "$m" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$1] $6"
    printf '%s\n' "$7" | sed 's/^/    |/'
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
  [ -f "$here/$key.txt" ] || [ -f "$here/$key-programs.txt" ] || continue
  run_target "$key" "$arch" "$dialect" "$cmd" "$extract"
done <<< "$TARGETS"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
