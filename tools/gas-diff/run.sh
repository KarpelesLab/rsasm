#!/bin/bash
# Differential test against GNU as.
#
# Assembles the same source with rsasm and with `as --64`, and compares the
# resulting .text bytes. Requires binutils; the hermetic expectations in
# tests/x86_encoding.rs were produced by running this.
#
#   tools/gas-diff/run.sh                 # both corpora
#   tools/gas-diff/run.sh <file>          # one corpus
#
# instructions.txt holds one instruction per line.
# programs.txt holds multi-line snippets separated by `=== <name>` lines.
# x86-64-relocs.txt and i386-relocs.txt hold snippets in the same format that
# are compared as whole objects, `as --64` and `as --32` against rsasm's
# x86-64 and i386: every allocated section's header and bytes, the global and
# undefined symbols, and the relocations, as tools/mc-diff/canon.sh prints
# them. That part needs llvm-readobj and llvm-objcopy, and is skipped without.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

command -v as >/dev/null || { echo "GNU as not found; skipping" >&2; exit 0; }
cargo build --quiet --manifest-path "$root/Cargo.toml" --example hexdump --bin rsasm || exit 1
hexdump="$root/target/debug/examples/hexdump"
rsasm="$root/target/debug/rsasm"

gas() {
  local d
  d=$(mktemp -d)
  cat > "$d/in.s"
  if ! as --64 -o "$d/out.o" "$d/in.s" 2> "$d/err"; then
    echo "GAS-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
    rm -rf "$d"; return
  fi
  objcopy -O binary --only-section=.text "$d/out.o" "$d/out.bin" 2>/dev/null
  xxd -p "$d/out.bin" | tr -d '\n' | sed 's/../& /g;s/ $//'
  echo
  rm -rf "$d"
}

pass=0; fail=0
compare() { # name, source
  local name=$1 src=$2 g r
  g=$(printf '%s\n' "$src" | gas)
  r=$(printf '%s\n' "$src" | "$hexdump" 2>&1)
  if [ "$g" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### $name"
    printf '%s\n' "$src" | sed 's/^/    /'
    echo "  gas:   $g"
    echo "  rsasm: $r"
  fi
}

run_lines() {
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    compare "$line" "$line"
  done < "$1"
}

compare_object() { # as flag, rsasm arch, name, source
  local d g r
  d=$(mktemp -d)
  printf '%s\n' "$4" > "$d/in.s"
  if as "$1" -o "$d/g.o" "$d/in.s" 2> "$d/err"; then
    g=$("$root/tools/mc-diff/canon.sh" "$d/g.o")
  else
    g="GAS-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
  fi
  if "$rsasm" -a "$2" -o "$d/r.o" "$d/in.s" 2> "$d/err"; then
    r=$("$root/tools/mc-diff/canon.sh" "$d/r.o")
  else
    r="RSASM-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
  fi
  rm -rf "$d"
  if [ "$g" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$2] $3 (object)"
    printf '%s\n' "$4" | sed 's/^/    /'
    echo "  gas:"
    printf '%s\n' "$g" | sed 's/^/    /'
    echo "  rsasm:"
    printf '%s\n' "$r" | sed 's/^/    /'
  fi
}

run_snippets() { # file [compare function and its leading arguments]
  local file=$1 snippet="" name=""
  shift
  [ $# -eq 0 ] && set -- compare
  while IFS= read -r line; do
    case "$line" in
      "==="*)
        [ -n "$snippet" ] && "$@" "$name" "$snippet"
        snippet=""; name="${line#=== }" ;;
      *) snippet="$snippet$line
" ;;
    esac
  done < "$file"
  [ -n "$snippet" ] && "$@" "$name" "$snippet"
  return 0
}

run_objects() { # file
  if ! command -v llvm-readobj > /dev/null || ! command -v llvm-objcopy > /dev/null; then
    echo "llvm-readobj or llvm-objcopy not found; skipping $(basename "$1")" >&2
    return 0
  fi
  case "$(basename "$1")" in
    i386-*) run_snippets "$1" compare_object --32 i386 ;;
    *) run_snippets "$1" compare_object --64 x86-64 ;;
  esac
}

if [ $# -gt 0 ]; then
  case "$1" in
    *relocs*) run_objects "$1" ;;
    *programs*) run_snippets "$1" ;;
    *) run_lines "$1" ;;
  esac
else
  run_lines "$here/instructions.txt"
  run_snippets "$here/programs.txt"
  run_objects "$here/x86-64-relocs.txt"
  run_objects "$here/i386-relocs.txt"
fi

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
