#!/usr/bin/env python3
"""Differential fuzzer for rsasm's Renesas RX backend.

RX instructions are one to eight bytes long, and GNU as parses them with a
generated grammar rather than a table, so there is no list of operand shapes
to draw from. Cases come from the other side instead: GNU objdump's
disassembly of random bytes, which decodes whatever it decodes and prints it
in the spelling GNU as reads. That is the same trick `aarch64.py` uses, and
it shares nothing with rsasm's tables.

Each line is assembled by `rx-elf-as` -- the only reference for RX, since
llvm-mc has no backend for it -- and by rsasm, and the bytes, the
relocations and the accept/reject decision are compared.

    tools/fuzz/rx.py fuzz --count 10000
    tools/fuzz/rx.py fuzz --only '^mov' --seed 7
    tools/fuzz/rx.py check lines.txt

A branch prints its target as an absolute address, so each case carries the
`.skip` that puts it back at the offset it was disassembled at.

`NOT_IMPLEMENTED` says what is left out: README.md claims RXv1, so the RXv2
and RXv3 additions -- the double-precision floating point, the DSP
instructions and the bit-manipulation additions -- are skipped by name.

With one reference there are no splits: a case is `agree`, a named
`deviation`, or a finding. The exit status is 1 when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/rx-elf-as and
bin/rx-elf-objdump).
"""

import re
import sys

import gasfuzz
from gasfuzz import Target

TARGETS = {
    "rx": Target("rx", "rx", gas="rx-elf-as", objdump="rx-elf-objdump",
                 objdump_flags=["-m", "rx"], addr_bits=32),
}

# README.md claims RXv1. Everything RXv2 and RXv3 added is skipped by name,
# so that a generation of the architecture the backend does not have cannot
# read as thousands of identical findings.
NOT_IMPLEMENTED = re.compile(r"""^(
    d(add|sub|mul|div|cmp|mov|abs|neg|sqrt|round|to[a-z]+|from[a-z]+|push|pop)[a-z.]*
  | dbt | dpushm | dpopm | save | rstr | mvfdc | mvtdc | mvfdr
  | fsqrt | ftoi | ftou | utof | fadd | fsub | fmul | fdiv | fcmp | itof | round
  | bfmov | bfmovz | rstr | msbhi | msblo | msbhl | maclh | mvfacgu | mvtacgu
  | racl | racw | rdacl | rdacw | emaca | emsba | emula | maclo | machi
  | mullo | mulhi | mvfachi | mvfaclo | mvfacmi | mvtachi | mvtaclo
)$""", re.X)


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


RULES = gasfuzz.Rules(deviations=[
    ("resolves-a-numeric-target", gasfuzz.resolves_a_numeric_target),
    ("fills-in-a-relocated-field", gasfuzz.fills_in_a_relocated_field),
])


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("rx", TARGETS, RULES, skip, "rx", count=10000))
