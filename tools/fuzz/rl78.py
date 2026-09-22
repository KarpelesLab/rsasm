#!/usr/bin/env python3
"""Differential fuzzer for rsasm's Renesas RL78 backend.

RL78 instructions are one to six bytes long and GNU as parses them with a
generated grammar, so there is no table of operand shapes to draw from.
Cases come from the other side: GNU objdump's disassembly of random bytes,
which decodes whatever it decodes and prints it in the spelling GNU as
reads. That is `aarch64.py`'s trick, and it shares nothing with rsasm's
tables.

Each line is assembled by `rl78-elf-as` -- the only reference for the RL78,
since llvm-mc has no backend for it -- and by rsasm, and the bytes, the
relocations and the accept/reject decision are compared.

    tools/fuzz/rl78.py fuzz --count 10000
    tools/fuzz/rl78.py fuzz --only '^mov' --seed 7
    tools/fuzz/rl78.py check lines.txt

A branch prints its target as an absolute address, so each case carries the
`.skip` that puts it back at the offset it was disassembled at.

The RL78 reads `@` as a comment character, so sections are declared with
`%progbits`.

With one reference there are no splits: a case is `agree`, a named
`deviation`, or a finding. The exit status is 1 when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/rl78-elf-as and
bin/rl78-elf-objdump).
"""

import re
import sys

import gasfuzz
from gasfuzz import Target

TARGETS = {
    "rl78": Target("rl78", "rl78", gas="rl78-elf-as", progbits="%progbits",
                   objdump="rl78-elf-objdump", objdump_flags=["-m", "rl78"],
                   addr_bits=32),
}

# The RL78-S3 multiply-divide-accumulate unit, which README.md does not
# claim. Adding it to the backend is what takes it off this list.
NOT_IMPLEMENTED = re.compile(r"^(mulhu?|divhu|divwu|machu?)$")


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


RULES = gasfuzz.Rules(deviations=[
    ("resolves-a-numeric-target", gasfuzz.resolves_a_numeric_target),
    ("fills-in-a-relocated-field", gasfuzz.fills_in_a_relocated_field),
    ("relocates-an-absolute-target", gasfuzz.relocates_an_absolute_target),
])


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("rl78", TARGETS, RULES, skip, "rl78",
                                 count=10000))
