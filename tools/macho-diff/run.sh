#!/bin/bash
# Differential test of Mach-O objects against llvm-mc.
#
# Assembles the same source with `rsasm -a <triple>` and with
# `llvm-mc -triple=<triple> -filetype=obj`, and compares the two objects as
# canon.sh prints them: header, load commands, every section's header and
# bytes, the symbol table and each relocation.
#
#   tools/macho-diff/run.sh              # every machine with a corpus
#   tools/macho-diff/run.sh arm64        # just one
#
# Corpora live in tools/macho-diff/<arch>.txt, one statement per line, each
# assembled as a file of its own, and tools/macho-diff/<arch>-programs.txt,
# multi-line snippets separated by `=== <name>` lines. A line in the first can
# name an undefined symbol and a label on a line of its own after it with
# `;`, which starts a new statement in either assembler.
#
# A case both assemblers refuse counts as a match: Mach-O has no relocation
# for a good many things ELF can express (`adr` to another atom, a 32-bit
# absolute address on x86-64), and refusing those is part of what is checked.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# arch | rsasm target | llvm triple
ARCHES="
x86-64|x86_64-apple-macos|x86_64-apple-macos
arm64|arm64-apple-macos|arm64-apple-macos
"

for tool in llvm-mc llvm-readobj; do
  command -v "$tool" >/dev/null || { echo "$tool not found; skipping" >&2; exit 0; }
done
echo "oracle: $(llvm-mc --version | grep -m1 -oE 'LLVM version [0-9.]+')"
case "$(llvm-mc --version)" in
  *"LLVM version 22."*) ;;
  *) echo "warning: the corpora were verified against LLVM 22; expect version drift" >&2 ;;
esac
cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --bin rsasm || exit 1
rsasm="$root/target/debug/rsasm"

pass=0
fail=0

compare() { # arch, rsasm target, triple, name, source
  local arch=$1 target=$2 triple=$3 name=$4 src=$5 m r d
  d=$(mktemp -d)
  printf '%s\n' "$src" > "$d/in.s"
  if llvm-mc -triple="$triple" -filetype=obj -o "$d/m.o" "$d/in.s" 2> "$d/merr"; then
    m=$("$here/canon.sh" "$d/m.o")
  else
    m="refused"
  fi
  if "$rsasm" -a "$target" -o "$d/r.o" "$d/in.s" 2> "$d/rerr"; then
    r=$("$here/canon.sh" "$d/r.o")
  else
    r="refused"
  fi
  if [ "$m" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$arch] $name"
    printf '%s\n' "$src" | sed 's/^/    /'
    if [ "$m" = refused ] || [ "$r" = refused ]; then
      echo "  llvm-mc: $( [ "$m" = refused ] && head -2 "$d/merr" | tr '\n' ' ' || echo accepted)"
      echo "  rsasm:   $( [ "$r" = refused ] && head -2 "$d/rerr" | tr '\n' ' ' || echo accepted)"
    else
      diff <(printf '%s\n' "$m") <(printf '%s\n' "$r") | sed 's/^/  /'
    fi
  fi
  rm -rf "$d"
}

# Runs `compare` over each `=== name` snippet of a file.
snippets() { # file, arch, rsasm target, triple
  local file=$1 snippet="" name="" line
  shift
  while IFS= read -r line; do
    case "$line" in
      "==="*)
        [ -n "$snippet" ] && compare "$@" "$name" "$snippet"
        snippet=""; name="${line#=== }" ;;
      *) snippet="$snippet$line
" ;;
    esac
  done < "$file"
  [ -n "$snippet" ] && compare "$@" "$name" "$snippet"
  return 0
}

run_arch() { # arch, rsasm target, triple
  local arch=$1 lines="$here/$1.txt" progs="$here/$1-programs.txt"
  local before=$((pass + fail))
  if [ -f "$lines" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in \#*) continue ;; esac
      compare "$@" "$line" "$(printf '%s\n' "$line" | tr ';' '\n')"
    done < "$lines"
  fi
  [ -f "$progs" ] && snippets "$progs" "$@"
  echo "[$arch] $((pass + fail - before)) cases"
}

wanted="${*:-}"
while IFS='|' read -r arch target triple; do
  [ -z "$arch" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $arch "*) ;; *) continue ;; esac
  fi
  run_arch "$arch" "$target" "$triple"
done <<< "$ARCHES"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
