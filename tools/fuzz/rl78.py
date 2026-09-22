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

A handful of cases are set aside rather than compared: GNU as 2.47 stops on
some short conditional branches with "Infinite loop encountered whilst
attempting to compute the addresses of symbols in section", a fatal error
that names no line (`write.c`'s relaxation loop gives up after
`MAX_ITERATIONS`). The harness halves a batch a tool gave up on until it
finds the case, drops that reference for it, and counts it as `skipped`.

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

# A branch to a label, and the distances worth putting between the two: the
# ends of the eight-bit conditional field, of `br $!`'s sixteen-bit relative
# one, and past it, where the branch has to be given up on.
BRANCH = re.compile(r"^b[a-z]*$")
BRANCHES = ["br $L", "br !L", "bz $L", "bnz $L", "bc $L", "bnc $L",
            "bh $L", "bnh $L", "bt a.3, $L", "bf a.0, $L"]
REACHES = [0, 2, 120, 126, 128, 130, 250, 254, 256, 258, 32000, 32764,
           32766, 32768, 32770]

TARGETS = {
    "rl78": Target("rl78", "rl78", gas="rl78-elf-as", progbits="%progbits",
                   objdump="rl78-elf-objdump", objdump_flags=["-m", "rl78"],
                   addr_bits=32, branches=BRANCHES, reaches=REACHES),
}

# The RL78-S3 multiply-divide-accumulate unit, which README.md does not
# claim. Adding it to the backend is what takes it off this list.
NOT_IMPLEMENTED = re.compile(r"^(mulhu?|divhu|divwu|machu?)$")


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


def truncates_a_long_branch(text, res, target):
    """A conditional branch whose expansion cannot reach either.

    GNU as turns `bz $L` past the eight-bit field into `bnz $+3` over a
    `br $!`, whose relative field is sixteen bits. Past *that* it wraps the
    field and says nothing: disassembling its own output for a gap of 32768
    shows the branch going to `0xffff8005` rather than to the label. rsasm
    refuses instead.
    """
    g, r = res.get("gas"), res.get("rsasm")
    return bool(g and g[0] == "ok" and r[0] == "err"
                and "out of range" in str(r[1]))


def expands_a_branch_that_reaches(text, res, target):
    """A conditional branch at a displacement its own field still holds.

    GNU as gives up on the three-byte conditional branches -- `bh`, `bnh`,
    `bt`, `bf` and their bit-addressed forms -- a little before the end of
    their eight-bit field and writes the opposite branch over a `br $!`
    instead. rsasm writes the one instruction, and GNU objdump reads it as
    going to the same label: `bt a.3, $0x81` for a gap of 126, where GNU as
    wrote six bytes for the same jump.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok":
        return False
    return len(r[1][0]) < len(g[1][0]) and BRANCH.match(text.split()[0]) is not None


RULES = gasfuzz.Rules(deviations=[
    ("resolves-a-numeric-target", gasfuzz.resolves_a_numeric_target),
    ("fills-in-a-relocated-field", gasfuzz.fills_in_a_relocated_field),
    ("relocates-an-absolute-target", gasfuzz.relocates_an_absolute_target),
    ("expands-a-branch-that-reaches", expands_a_branch_that_reaches),
    ("truncates-a-long-branch", truncates_a_long_branch),
])


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("rl78", TARGETS, RULES, skip, "rl78",
                                 count=10000, programs=0.15))
