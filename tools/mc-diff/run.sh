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
# by `=== <name>` lines. Snippets in tools/mc-diff/<arch>-relocs.txt are
# compared as whole objects: sections, symbols and relocations, as canon.sh
# prints them.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# arch | rsasm arch name | llvm triple | extra llvm-mc flags | source header
#
# The header is put before every case, with `\n` between lines: that is how
# 16-bit mode and Intel syntax are asked for, since llvm-mc 22 cannot write an
# object for an `i8086` triple.
ARCHES="
x86-64|x86-64|x86_64|
i386|i386|i386|
i386-intel|i386|i386||.intel_syntax noprefix
i8086|i386|i386||.code16
i8086-intel|i386|i386||.code16\\n.intel_syntax noprefix
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
command -v llvm-readobj >/dev/null || { echo "llvm-readobj not found; skipping" >&2; exit 0; }
# The corpora are verified against a specific LLVM, and other versions really do
# answer differently (see README.md). Say which one this run is using, so a
# difference can be told apart from version drift at a glance.
echo "oracle: $(llvm-mc --version | grep -m1 -oE 'LLVM version [0-9.]+')"
case "$(llvm-mc --version)" in
  *"LLVM version 22."*) ;;
  *) echo "warning: the corpora were verified against LLVM 22; expect version drift" >&2 ;;
esac
cargo build --quiet --manifest-path "$root/Cargo.toml" --all-features --example hexdump --bin rsasm || exit 1
hexdump="$root/target/debug/examples/hexdump"
rsasm="$root/target/debug/rsasm"

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

with_header() { # header, source
  [ -n "$1" ] && printf '%b\n' "$1"
  printf '%s\n' "$2"
}

compare() { # arch, rsasm_arch, triple, flags, header, name, source
  local arch=$1 rs=$2 triple=$3 flags=$4 name=$6 src m r
  src=$(with_header "$5" "$7")
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

# What two objects have to agree on, as canon.sh prints it: every allocated
# section's header fields and bytes, the global, weak and undefined symbols,
# and each relocation, with a symbol read the way a linker would read it.
canon() { # object
  "$here/canon.sh" "$1"
}

compare_object() { # arch, rsasm_arch, triple, flags, header, name, source
  local arch=$1 rs=$2 triple=$3 flags=$4 name=$6 src m r d
  src=$(with_header "$5" "$7")
  d=$(mktemp -d)
  printf '%s\n' "$src" > "$d/in.s"
  if llvm-mc -triple="$triple" $flags -filetype=obj -o "$d/m.o" "$d/in.s" 2> "$d/err"; then
    m=$(canon "$d/m.o")
  else
    m="MC-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
  fi
  if "$rsasm" -a "$rs" -o "$d/r.o" "$d/in.s" 2> "$d/err"; then
    r=$(canon "$d/r.o")
  else
    r="RSASM-ERROR: $(head -3 "$d/err" | tr '\n' ' ')"
  fi
  rm -rf "$d"
  if [ "$m" = "$r" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "### [$arch] $name (object)"
    printf '%s\n' "$src" | sed 's/^/    /'
    echo "  llvm-mc:"
    printf '%s\n' "$m" | sed 's/^/    /'
    echo "  rsasm:"
    printf '%s\n' "$r" | sed 's/^/    /'
  fi
}

# Runs `compare` or `compare_object` over each `=== name` snippet of a file.
snippets() { # file, compare function, arch, rsasm_arch, triple, flags, header
  local file=$1 fn=$2 snippet="" name="" line
  shift 2
  while IFS= read -r line; do
    case "$line" in
      "==="*)
        [ -n "$snippet" ] && "$fn" "$@" "$name" "$snippet"
        snippet=""; name="${line#=== }" ;;
      *) snippet="$snippet$line
" ;;
    esac
  done < "$file"
  [ -n "$snippet" ] && "$fn" "$@" "$name" "$snippet"
  return 0
}

run_arch() { # arch, rsasm_arch, triple, flags, header
  local arch=$1 rs=$2 triple=$3 flags=$4 header=$5
  local lines="$here/$arch.txt" progs="$here/$arch-programs.txt" objs="$here/$arch-relocs.txt"
  local before=$((pass + fail))

  if [ -f "$lines" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in \#*) continue ;; esac
      compare "$arch" "$rs" "$triple" "$flags" "$header" "$line" "$line"
    done < "$lines"
  fi

  [ -f "$progs" ] && snippets "$progs" compare "$arch" "$rs" "$triple" "$flags" "$header"
  [ -f "$objs" ] && snippets "$objs" compare_object "$arch" "$rs" "$triple" "$flags" "$header"

  local n=$((pass + fail - before))
  [ "$n" -gt 0 ] && echo "[$arch] $n cases"
  return 0
}

wanted="${*:-}"
while IFS='|' read -r arch rs triple flags header; do
  [ -z "$arch" ] && continue
  if [ -n "$wanted" ]; then
    case " $wanted " in *" $arch "*) ;; *) continue ;; esac
  fi
  # Skip architectures that have no corpus yet.
  [ -f "$here/$arch.txt" ] || [ -f "$here/$arch-programs.txt" ] || [ -f "$here/$arch-relocs.txt" ] || continue
  run_arch "$arch" "$rs" "$triple" "$flags" "$header"
done <<< "$ARCHES"

echo "--- $pass matched, $fail differed"
[ "$fail" -eq 0 ]
