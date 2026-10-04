# Where cargo put the binaries this repo's harnesses run.
#
# `$root/target` is only right when nothing redirects it. A `target-dir` in a
# cargo config, or CARGO_TARGET_DIR, sends the build somewhere else and leaves
# whatever was in `$root/target` behind, where a harness would go on comparing
# against a binary from an older checkout -- which reads as a clean run, or as
# a difference the source does not have. Asking cargo removes the guess.
#
# RSASM and HEXDUMP name a binary outright, for a bisect or a build of one's
# own. `built rsasm` and `built examples/hexdump` are the names the harnesses
# ask for.
built() { # path under the profile directory
  case $1 in
    rsasm) [ -n "${RSASM:-}" ] && { printf '%s\n' "$RSASM"; return; } ;;
    examples/hexdump) [ -n "${HEXDUMP:-}" ] && { printf '%s\n' "$HEXDUMP"; return; } ;;
  esac
  built_require "$(built_target_dir)/debug/$1" "$1"
}

# A binary that is not there is worth stopping for. Left to itself a harness
# would compare the reference against nothing and report every case as a
# difference, which looks like a fault in the assembler rather than a build
# that was never made. The status has to come back through the command
# substitution the callers use -- an `exit` here would end only the subshell --
# so they spell it `rsasm=$(built rsasm) || exit 1`.
built_require() { # path, name
  if [ ! -x "$1" ]; then
    case $2 in
      examples/*) what="--example ${2#examples/}" ;;
      *) what="--bin $2" ;;
    esac
    echo "$(basename "$0"): no $2 at $1" >&2
    echo "  cargo build --all-features $what" >&2
    return 1
  fi
  printf '%s\n' "$1"
}

built_target_dir() {
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    printf '%s\n' "$CARGO_TARGET_DIR"
    return
  fi
  # `cargo metadata` reads the configuration the build itself reads. Its JSON
  # is one line, so the field can be cut out without a parser; a cargo that
  # cannot answer leaves the default, which is right when nothing redirects it.
  cargo metadata --no-deps --format-version 1 --manifest-path "$built_root/Cargo.toml" \
    2>/dev/null | tr ',' '\n' | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1 |
    grep . || printf '%s/target\n' "$built_root"
}
