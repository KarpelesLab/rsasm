#!/bin/bash
# Build the reference assemblers the differential tests compare against, for
# targets that neither the host's GNU as nor llvm-mc can assemble.
#
#   tools/oracles/build.sh            # everything
#   tools/oracles/build.sh m68k-elf   # just one
#
# Installs into target/oracles/ (gitignored). Nothing outside the repo is
# touched, and nothing needs root.
#
# Versions are pinned on purpose. An assembler's output is part of what the
# corpora record, and it changes between releases: llvm-mc 18 and 22 disagree
# on nine of our x86/RISC-V/SPARC cases, and none of them were rsasm bugs.
# Bump a version only after reading every difference the new one produces.
set -euo pipefail

BINUTILS_VERSION=2.47
BINUTILS_URL="https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILS_VERSION.tar.xz"
BINUTILS_SHA256=154ab23b60070e8f27013c22977f1129425d67d1e8acd6e13010e617811e4cff

# vasm publishes no versioned download — this URL always serves the latest
# release — and has no working HTTPS. The checksum is what pins it: if the
# tarball ever changes, the build stops rather than quietly assembling the
# corpora against a different reference. This is vasm 2.0f, m68k backend 2.8c.
VASM_URL="http://sun.hasenbraten.de/vasm/release/vasm.tar.gz"
VASM_SHA256=c84b2de1cbb87831795fe64a85c5d9a7002a766e3a7c30b0a2d7d5e99d878f49

# GNU as and ld, one build per target: gas is single-target by construction.
# The linkers are what the link tests use to check that relocations mean what
# rsasm intends, which comparing bytes against another assembler cannot show.
#   m68k-elf              Motorola 68000 family
#   v850-elf              V850 and RH850 (v850e3v5)
#   rl78-elf              Renesas RL78
#   rx-elf                Renesas RX
#   sh-elf                SuperH
#   avr-elf               Microchip AVR
#   msp430-elf            TI MSP430
# Linkers (and a second assembler) for the targets llvm-mc checks:
#   arm-none-eabi         ARM and Thumb
#   aarch64-elf           AArch64
#   riscv64-elf           RISC-V, 32- and 64-bit
#   powerpc64-linux-gnu   PowerPC, 32/64-bit, both byte orders
#   mips64-elf            MIPS, 32/64-bit, both byte orders
#   sparc64-elf           SPARC V8 and V9
#   x86_64-elf            x86-64, i386
BINUTILS_TARGETS="m68k-elf v850-elf rl78-elf rx-elf sh-elf avr-elf msp430-elf arm-none-eabi aarch64-elf riscv64-elf powerpc64-linux-gnu mips64-elf sparc64-elf x86_64-elf"

root=$(cd "$(dirname "$0")/../.." && pwd)
# RSASM_ORACLES overrides the install directory, so several checkouts or a CI
# cache can share a single build.
out="${RSASM_ORACLES:-$root/target/oracles}"
src="$out/src"
mkdir -p "$src" "$out/bin"
jobs=$(nproc 2>/dev/null || echo 4)

wanted="${*:-$BINUTILS_TARGETS vasm}"

fetch() { # url dest sha256
  [ -s "$2" ] || { echo "fetching $1"; curl -fsSL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2"; }
  local got
  got=$(sha256sum "$2" | cut -d' ' -f1)
  if [ "$got" != "$3" ]; then
    echo "checksum mismatch for $2" >&2
    echo "  expected $3" >&2
    echo "  got      $got" >&2
    echo "The reference changed upstream. Rebuild it deliberately, re-run the" >&2
    echo "corpora, and read every difference before updating the checksum." >&2
    rm -f "$2"
    exit 1
  fi
}

build_binutils() { # target
  local t=$1
  if [ -x "$out/bin/$t-as" ] && [ -x "$out/bin/$t-ld" ]; then echo "$t already built"; return; fi
  fetch "$BINUTILS_URL" "$src/binutils-$BINUTILS_VERSION.tar.xz" "$BINUTILS_SHA256"
  [ -d "$src/binutils-$BINUTILS_VERSION" ] || tar -xJf "$src/binutils-$BINUTILS_VERSION.tar.xz" -C "$src"
  local b="$out/build/binutils-$t"
  rm -rf "$b" && mkdir -p "$b"
  echo "building binutils $BINUTILS_VERSION for $t"
  (
    cd "$b"
    "$src/binutils-$BINUTILS_VERSION/configure" \
      --target="$t" --prefix="$out" \
      --disable-nls --disable-werror --disable-gdb --disable-gdbserver \
      --disable-sim --disable-readline --disable-libdecnumber \
      --disable-gprof --disable-gprofng --enable-ld --disable-gold \
      --without-zstd --without-debuginfod > configure.log 2>&1
    make -j"$jobs" all-gas all-binutils all-ld > make.log 2>&1
    make install-gas install-binutils install-ld > install.log 2>&1
  ) || { echo "build of $t failed; see $b/*.log" >&2; return 1; }
  echo "built $t-as and $t-ld"
}

build_vasm() {
  if [ -x "$out/bin/vasmm68k_mot" ]; then echo "vasmm68k_mot already built"; return; fi
  fetch "$VASM_URL" "$src/vasm.tar.gz" "$VASM_SHA256"
  rm -rf "$src/vasm" && tar -xzf "$src/vasm.tar.gz" -C "$src"
  echo "building vasm (m68k, Motorola syntax)"
  (cd "$src/vasm" && make -j"$jobs" CPU=m68k SYNTAX=mot > make.log 2>&1) \
    || { echo "vasm build failed; see $src/vasm/make.log" >&2; return 1; }
  cp "$src/vasm/vasmm68k_mot" "$out/bin/"
  echo "built vasmm68k_mot"
}

for w in $wanted; do
  case "$w" in
    vasm) build_vasm ;;
    *) build_binutils "$w" ;;
  esac
done

echo "oracles in $out/bin:"
ls "$out/bin"
