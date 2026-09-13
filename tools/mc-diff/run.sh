#!/bin/bash
# Differential test against llvm-mc.
#
# Assembles the same source with rsasm and with `llvm-mc -filetype=obj`, then
# compares the .text bytes. llvm-mc covers every architecture this crate
# targets, which makes it the one oracle that can check all of them; GNU as
# only covers the host (see tools/gas-diff).
#
#   tools/mc-diff/run.sh              # every architecture with a corpus
#   tools/mc-diff/run.sh aarch64      # just one
#
# Corpora live in tools/mc-diff/<arch>.txt, one instruction per line, and
# optionally tools/mc-diff/<arch>-programs.txt, multi-line snippets separated
# by `=== <name>` lines.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# arch | rsasm arch name | llvm triple | extra llvm-mc flags
ARCHES="
x86-64|x86-64|x86_64|
aarch64|aarch64|aarch64|
arm|arm|armv7|
thumb|thumb|thumbv7|
riscv32|riscv32|riscv32|-mattr=+m,+a,+f,+d,+c
riscv64|riscv64|riscv64|-mattr=+m,+a,+f,+d,+c
powerpc|powerpc|powerpc|
powerpc64|powerpc64|powerpc64|
powerpc64le|powerpc64le|powerpc64le|
mips|mips|mips|
mipsel|mipsel|mipsel|
mips64|mips64|mips64|
sparc|sparc|sparc|
sparcv9|sparcv9|sparcv9|
"

command -v llvm-mc >/dev/null || { echo "llvm-mc not found; skipping" >&2; exit 0; }
command -v llvm-objcopy >/dev/null || { echo "llvm-objcopy not found; skipping" >&2; exit 0; }
cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --example hexdump || exit 1
hexdump="$root/target/debug/examples/hexdump"

pass=0
fail=0

mc() { # triple, flags, source on stdin
  local triple=$1 flags=$2 d
  d=$(mktemp -d)
  if ! llvm-mc -triple="$triple" $flags -filetype=obj -o "$d/o.o" > "$d/out" 2> "$d/err"; then
    echo "MC-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
    rm -rf "$d"; return
  fi
  llvm-objcopy -O binary --only-section=.text "$d/o.o" "$d/o.bin" 2>/dev/null
  xxd -p "$d/o.bin" | tr -d '\n' | sed 's/../& /g;s/ $//'
  echo
  rm -rf "$d"
}

compare() { # arch, rsasm_arch, triple, flags, name, source
  local arch=$1 rs=$2 triple=$3 flags=$4 name=$5 src=$6 m r
  m=$(printf '%s\n' "$src" | mc "$triple" "$flags")
  r=$(printf '%s\n' "$src" | "$hexdump" "$rs" 2>&1)
  if [ "$m" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$arch] $name"
    printf '%s\n' "$src" | sed 's/^/    /'
    echo "  llvm-mc: $m"
    echo "  rsasm:   $r"
  fi
}

run_arch() { # arch, rsasm_arch, triple, flags
  local arch=$1 rs=$2 triple=$3 flags=$4
  local lines="$here/$arch.txt" progs="$here/$arch-programs.txt"
  local before=$((pass + fail))

  if [ -f "$lines" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in \#*) continue ;; esac
      compare "$arch" "$rs" "$triple" "$flags" "$line" "$line"
    done < "$lines"
  fi

  if [ -f "$progs" ]; then
    local snippet="" name=""
    while IFS= read -r line; do
      case "$line" in
        "==="*)
          [ -n "$snippet" ] && compare "$arch" "$rs" "$triple" "$flags" "$name" "$snippet"
          snippet=""; name="${line#=== }" ;;
        *) snippet="$snippet$line
" ;;
      esac
    done < "$progs"
    [ -n "$snippet" ] && compare "$arch" "$rs" "$triple" "$flags" "$name" "$snippet"
  fi

  local n=$((pass + fail - before))
  [ "$n" -gt 0 ] && echo "[$arch] $n cases"
  return 0
}

wanted="${*:-}"
while IFS='|' read -r arch rs triple flags; do
  [ -z "$arch" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $arch "*) ;; *) continue ;; esac
  fi
  # Skip architectures that have no corpus yet.
  [ -f "$here/$arch.txt" ] || [ -f "$here/$arch-programs.txt" ] || continue
  run_arch "$arch" "$rs" "$triple" "$flags"
done <<< "$ARCHES"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
