#!/bin/bash
# Run every differential fuzzer once, with a fixed seed and a bounded number
# of cases, and report what each one compared. This is the entry point CI
# uses; the fuzzers' own command lines are unchanged and still the way to
# chase a finding down.
#
#   tools/fuzz/run.sh                     # the CI set: every fuzzer, seed 1
#   tools/fuzz/run.sh --seed 20260922     # the nightly set uses the date
#   tools/fuzz/run.sh --scale 10          # ten times the cases
#   tools/fuzz/run.sh riscv mips          # only these
#   tools/fuzz/run.sh --list              # the fuzzers and their case counts
#
# Every fuzzer takes `fuzz --seed N --count M`, exits 0 when it found nothing
# and non-zero when it did, and ends its output with
#
#     --- <name>: <n> case(s) compared, <k> finding(s)
#
# so a run that generated nothing cannot pass quietly: a missing or zero count
# fails here, whatever the fuzzer's own exit status was.
#
# Reproducing a failure is the line this script prints under the failing
# fuzzer: the same seed and count give the same cases, and the fuzzer's own
# report names the case.
#
# Environment: RSASM (default target/debug/rsasm), RSASM_ORACLES (default
# target/oracles) for the cross assemblers, and llvm-mc on PATH. A fuzzer
# whose reference is missing fails rather than being skipped, so a CI image
# that loses one cannot read as a pass.
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# name | cases | extra arguments
#
# The counts are chosen so the whole set runs in a few minutes on a
# four-core runner, and are scaled by --scale. Instruction fuzzers compare a
# case in a section of its own and batch 200 of them per assembler run, so
# they are cheap; the whole-program ones (arm-programs, avr, mcs51) run one
# assembler per program and are an order of magnitude dearer per case.
FUZZERS="
x86|30000|
aarch64|20000|
arm|20000|
arm-programs|600|
riscv|20000|
powerpc|20000|
mips|20000|
sparc|12000|
m68k|20000|
sh|12000|
rx|10000|
rl78|10000|
v850|10000|
msp430|20000|
avr|800|
z80|12000|
mos6502|8000|
i8080|6000|
mcs51|1500|
nasm|600|
"

seed=1
scale=1
list=
want=()
while [ $# -gt 0 ]; do
  case "$1" in
    --seed) seed=$2; shift 2 ;;
    --seed=*) seed=${1#*=}; shift ;;
    --scale) scale=$2; shift 2 ;;
    --scale=*) scale=${1#*=}; shift ;;
    --list) list=1; shift ;;
    -h|--help) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//;/^set -u/d'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) want+=("$1"); shift ;;
  esac
done

wanted() { # name
  [ ${#want[@]} -eq 0 ] && return 0
  local w
  for w in "${want[@]}"; do [ "$w" = "$1" ] && return 0; done
  return 1
}

if [ -n "$list" ]; then
  printf '%s\n' "$FUZZERS" | while IFS='|' read -r name count extra; do
    [ -z "$name" ] && continue
    printf '%-14s %8d %s\n' "$name" "$((count * scale))" "$extra"
  done
  exit 0
fi

[ -x "${RSASM:-$root/target/debug/rsasm}" ] || {
  echo "no rsasm at ${RSASM:-$root/target/debug/rsasm}; run cargo build --all-features --bin rsasm" >&2
  exit 1
}

ran=0
cases=0
differed=0
missing=0
log=$(mktemp)
trap 'rm -f "$log"' EXIT

while IFS='|' read -r name count extra; do
  [ -z "$name" ] && continue
  wanted "$name" || continue
  script="$here/$name.py"
  if [ ! -x "$script" ]; then
    echo "### $name: no $script"
    missing=$((missing + 1))
    continue
  fi
  n=$((count * scale))
  echo "=== $name --seed $seed --count $n $extra"
  start=$SECONDS
  # shellcheck disable=SC2086
  "$script" fuzz --seed "$seed" --count "$n" $extra > "$log" 2>&1
  status=$?
  cat "$log"
  took=$((SECONDS - start))
  # The summary line every fuzzer ends with. Its case count is what makes
  # "it found nothing" different from "it ran nothing".
  summary=$(grep -oE -- "--- $name: [0-9]+ case\(s\) compared, [0-9]+ finding\(s\)" "$log" | tail -1)
  if [ -z "$summary" ]; then
    echo "### $name: no summary line -- it did not finish"
    missing=$((missing + 1))
    continue
  fi
  got=$(echo "$summary" | sed -E 's/.*: ([0-9]+) case.*/\1/')
  found=$(echo "$summary" | sed -E 's/.*, ([0-9]+) finding.*/\1/')
  if [ "$got" -eq 0 ]; then
    echo "### $name: compared 0 cases"
    missing=$((missing + 1))
    continue
  fi
  ran=$((ran + 1))
  cases=$((cases + got))
  if [ "$status" -ne 0 ] || [ "$found" -ne 0 ]; then
    differed=$((differed + 1))
    echo "### $name: $found finding(s), exit $status"
    echo "### reproduce: RSASM_ORACLES=${RSASM_ORACLES:-$root/target/oracles} \\"
    echo "###   tools/fuzz/$name.py fuzz --seed $seed --count $n $extra"
  fi
  echo "=== $name: $got case(s) in ${took}s"
done <<< "$FUZZERS"

echo "--- $ran fuzzer(s), $cases case(s) compared, $differed differed, $missing did not run"
[ "$ran" -gt 0 ] && [ "$differed" -eq 0 ] && [ "$missing" -eq 0 ]
