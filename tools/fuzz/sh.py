#!/usr/bin/env python3
"""Differential fuzzer for rsasm's SuperH backend.

Cases are GNU objdump's disassembly of random instruction words, the way
`aarch64.py` takes its cases from llvm-mc's: every halfword that decodes
becomes a line of source in the spelling GNU as reads, with operands of
every value the encoding allows. The disassembler's tables are not the
assembler's parser, and neither is rsasm's.

Each line is assembled by `sh-elf-as` -- the only reference for SuperH,
since llvm-mc has no backend for it -- and by rsasm, and the bytes, the
relocations and the accept/reject decision are compared.

    tools/fuzz/sh.py fuzz --count 12000
    tools/fuzz/sh.py fuzz --target shl --only '^f' --seed 7
    tools/fuzz/sh.py check --target sh lines.txt

A branch prints its target as an absolute address, so each case carries the
`.skip` that puts it back at the offset it was disassembled at; a target in
the top half of the address space is written as the negative number it
stands for.

`NOT_IMPLEMENTED` and `UNIMPLEMENTED` say what is left out of the cases:
the SH-2A, SH-4A-only and SH-DSP additions the README's "SH-1 to SH-4A"
does not stretch to, and the PC-relative literal loads, which a
disassembler prints as the address it read the literal from rather than as
anything an assembler can be asked to produce again.

With one reference there are no splits: a case is `agree`, a named
`deviation`, or a finding. The exit status is 1 when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/sh-elf-as and
bin/sh-elf-objdump).
"""

import re
import sys

import gasfuzz
from gasfuzz import Target

TARGETS = {
    "sh": Target("sh", "sh", gas="sh-elf-as", gas_flags=["-big"],
                 objdump="sh-elf-objdump", objdump_flags=["-m", "sh4", "-EB"],
                 addr_bits=32),
    "shl": Target("shl", "shl", gas="sh-elf-as", gas_flags=["-little"],
                  objdump="sh-elf-objdump", objdump_flags=["-m", "sh4", "-EL"],
                  addr_bits=32),
}

# What README.md's "SuperH SH-1 to SH-4A" does not claim: the SH-2A
# additions, the DSP set, and the privileged instructions after SH-4.
# Adding one to the backend is what takes it off this list.
NOT_IMPLEMENTED = re.compile(r"""^(
    band | bandnot | bclr | bld | bldnot | bor | bornot | bset | bst | bxor
  | movi20 | movi20s | movu\.[bw] | movml\.l | movmu\.l | mulr | divs | divu
  | clips\.[bw] | clipu\.[bw] | jsr/n | rtv/n | rts/n | resbank | icbi | prefi
  | synco | movco\.l | movli\.l | movua\.l | pref
  | pabs | padd.* | pand | pclr.* | pcmp | pcopy | pdec | pdmsb | pinc | pmuls
  | pneg | por | prnd | pshl | pshr | psub.* | pxor | pwad | pwsb | plds | psts
  | ldrs | ldre | ldrc | setrc | movx.* | movy.* | movs.* | nopx | nopy
)$""", re.X)

# A PC-relative literal load prints as `mov.l 0x3cc, r4`: the address the
# literal was read from, not the literal and not a displacement. Asking an
# assembler for that address again is asking for a different instruction, so
# these are left out. `mova` is the same.
LITERAL_LOAD = re.compile(r"^(mov\.[wl]\s+0x[0-9a-f]+\s*,|mova\s)")


def skip(case):
    line = case[1].split("\n")[-1]
    return bool(NOT_IMPLEMENTED.match(case[0]) or LITERAL_LOAD.match(line))


RULES = gasfuzz.Rules(deviations=[
    ("resolves-a-numeric-target", gasfuzz.resolves_a_numeric_target),
])


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("sh", TARGETS, RULES, skip, "sh"))
