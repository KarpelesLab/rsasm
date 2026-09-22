#!/usr/bin/env python3
"""Differential fuzzer for rsasm's V850 and RH850 backend.

Cases are GNU objdump's disassembly of random bytes, the way `aarch64.py`
takes its cases from llvm-mc's: every instruction that decodes becomes a
line of source in the spelling GNU as reads, with operands of every value
the encoding allows. The disassembler's tables are not the assembler's
parser, and neither is rsasm's.

Each line is assembled by `v850-elf-as` -- the only reference, since
llvm-mc has no V850 backend -- and by rsasm, and the bytes, the
relocations and the accept/reject decision are compared. The `v850` target
is the base architecture and `rh850` is `-mv850e3v5`, which is what
README.md claims.

    tools/fuzz/v850.py fuzz --count 10000
    tools/fuzz/v850.py fuzz --target rh850 --only '^ld' --seed 7
    tools/fuzz/v850.py check --target v850 lines.txt

A branch prints its target as an absolute address, so each case carries the
`.skip` that puts it back at the offset it was disassembled at.

With one reference there are no splits: a case is `agree`, a named
`deviation`, or a finding. The exit status is 1 when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/v850-elf-as and
bin/v850-elf-objdump).
"""

import re
import sys

import gasfuzz
from gasfuzz import Target

# GNU's V850 assembler reads a branch operand as a *displacement* -- `br 8`
# goes eight bytes on -- while its disassembler prints the *address* the
# branch lands on. A line the disassembler produced therefore does not read
# back as itself, so the address is turned into the displacement it stands
# for before the case is used. (GNU as truncates an out-of-range displacement
# into the field without complaint, which is why leaving it alone would also
# compare rsasm's refusal against a wrong encoding.)
BRANCH = re.compile(r"^(b[a-z]*|jr|jarl|loop)$")
# A jump to a label, and the distances worth putting between the two. Only
# `jr` and `jarl` take one: GNU as reads a conditional branch's operand as a
# displacement, and refuses a symbol there ("condition code not expected").
BRANCHES = ["jr L", "jarl L, r10"]
REACHES = [0, 2, 250, 254, 256, 258, 65530, 65534, 65536, 0x1ffffe, 0x200000]
ADDRESS = re.compile(r"(?<![\w.$])(-?(?:0x[0-9a-f]+|\d+))(?![\w.])")


def to_displacement(text, off):
    m = BRANCH.match(text.split()[0])
    if not m:
        return text
    hit = ADDRESS.search(text, len(m.group(0)))
    if not hit:
        return text
    return text[:hit.start()] + str(int(hit.group(1), 0) - off) + text[hit.end():]


TARGETS = {
    "v850": Target("v850", "v850", gas="v850-elf-as",
                   objdump="v850-elf-objdump", objdump_flags=["-m", "v850"],
                   addr_bits=32, rewrite=to_displacement,
                   branches=BRANCHES, reaches=REACHES),
    "rh850": Target("rh850", "rh850", gas="v850-elf-as",
                    gas_flags=["-mv850e3v5"], objdump="v850-elf-objdump",
                    objdump_flags=["-m", "v850e3v5"], addr_bits=32,
                    rewrite=to_displacement, branches=BRANCHES,
                    reaches=REACHES),
}

# The coprocessor and cache instructions, which README.md does not claim.
NOT_IMPLEMENTED = re.compile(r"""^(
    cmov | c[a-z]*cc | cache | pref | pushsp | popsp | dispose | prepare
  | ldl\.w | stc\.w | snooze | syncm | syncp | synce | syncf | est | dst
  | cll | hvcall | hvtrap | ldvc\.sr | stvc\.sr | ldtc\.[a-z]+ | sttc\.[a-z]+
  | ldm\.mp | stm\.mp | ldsr\.[a-z]+ | stsr\.[a-z]+ | bins | rotl
)$""", re.X)


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


def truncates_a_branch_displacement(text, res, target):
    """A branch whose displacement does not fit its field.

    GNU as cuts it down to the field's width and says nothing -- `ble 4148`
    becomes `ble -4044` on a nine-bit field -- so the branch lands somewhere
    else entirely. rsasm refuses it, as it refuses every over-wide immediate
    (the AArch64 corpora record the same choice against llvm-mc).
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "err":
        return False
    return (BRANCH.match(text.split("\n")[-1].split()[0]) is not None
            and "out of range" in str(r[1]))


RULES = gasfuzz.Rules(deviations=[
    ("truncates-a-branch-displacement", truncates_a_branch_displacement),
    ("resolves-a-numeric-target", gasfuzz.resolves_a_numeric_target),
    ("fills-in-a-relocated-field", gasfuzz.fills_in_a_relocated_field),
    ("relocates-an-absolute-target", gasfuzz.relocates_an_absolute_target),
])


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("v850", TARGETS, RULES, skip, "v850",
                                 count=10000))
