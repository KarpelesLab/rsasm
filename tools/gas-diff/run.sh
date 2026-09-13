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
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

command -v as >/dev/null || { echo "GNU as not found; skipping" >&2; exit 0; }
cargo build --quiet --manifest-path "$root/Cargo.toml" --example hexdump || exit 1
hexdump="$root/target/debug/examples/hexdump"

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

run_snippets() {
  local snippet="" name=""
  while IFS= read -r line; do
    case "$line" in
      "==="*)
        [ -n "$snippet" ] && compare "$name" "$snippet"
        snippet=""; name="${line#=== }" ;;
      *) snippet="$snippet$line
" ;;
    esac
  done < "$1"
  [ -n "$snippet" ] && compare "$name" "$snippet"
}

if [ $# -gt 0 ]; then
  case "$1" in
    *programs*) run_snippets "$1" ;;
    *) run_lines "$1" ;;
  esac
else
  run_lines "$here/instructions.txt"
  run_snippets "$here/programs.txt"
fi

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
