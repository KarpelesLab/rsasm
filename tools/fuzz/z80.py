#!/usr/bin/env python3
"""Differential fuzzer for rsasm's Zilog Z80 backend.

Cases are GNU objdump's disassembly of random bytes, the way `aarch64.py`
takes its cases from llvm-mc's: every instruction that decodes becomes a
line of source in the spelling GNU as reads -- the undocumented `ixh`/`ixl`
forms included -- with operands of every value the encoding allows. The
disassembler's tables are not the assembler's parser, and neither is
rsasm's.

    tools/fuzz/z80.py fuzz --count 12000
    tools/fuzz/z80.py fuzz --only '^ld' --seed 7
    tools/fuzz/z80.py check lines.txt

ELF has no class for a 16-bit target, so rsasm writes a flat image (`-f
bin`) and the objects are compared as images: each case is given a
sixteen-byte slot with `.org`, which is what takes the place of a section
each, and the reference's object goes through `z80-elf-objcopy -O binary`.
A Z80 instruction is at most four bytes, so a slot always holds one. That
also means relocations are not compared here -- there are none in a flat
image -- only bytes; `tools/xas-diff` covers the relocated forms.

A jump prints its target as an absolute address, so each case is assembled
in the slot it was disassembled at and the address means the same thing.

With one reference there are no splits: a case is `agree`, a named
`deviation`, or a finding. The exit status is 1 when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/z80-elf-as,
bin/z80-elf-objdump and bin/z80-elf-objcopy).
"""

import re
import sys

import gasfuzz
from gasfuzz import Target

# `jr` and `djnz` are the only PC-relative instructions the Z80 has, and
# GNU's disassembler prints their target as an address. A case is assembled
# at the start of its slot rather than where it was disassembled, so the
# address is turned into the `.`-relative form that means the same wherever
# the instruction lands. Everything else -- `jp`, `call`, `rst` -- takes an
# absolute address, which is position-independent already.
RELATIVE = re.compile(r"^(jr|djnz)$")
ADDRESS = re.compile(r"(?<![\w.$])(-?(?:0x[0-9a-f]+|\d+))(?![\w.])")


def to_dot_relative(text, off):
    m = RELATIVE.match(text.split()[0])
    if not m:
        return text
    hit = ADDRESS.search(text, len(m.group(0)))
    if not hit:
        return text
    return text[:hit.start()] + ".%+d" % (int(hit.group(1), 0) - off) + text[hit.end():]


TARGETS = {
    "z80": Target("z80", "z80", gas="z80-elf-as", objdump="z80-elf-objdump",
                  objdump_flags=["-m", "z80"], objcopy="z80-elf-objcopy",
                  slot=16, section=False, addr_bits=16,
                  rewrite=to_dot_relative),
}

# The Z180, eZ80 and Z80N additions, which README.md's "Zilog Z80" does not
# claim. `z80-elf-as` defaults to the plain Z80, so its disassembler is the
# only place these can come from.
NOT_IMPLEMENTED = re.compile(r"""^(
    in0 | out0 | tst | tstio | mlt | otim | otdm | otimr | otdmr | slp
  | ld\.l | ld\.s | lea | pea | mul | swapnib | mirror | nextreg | pixeldn
  | pixelad | setae | test | bsla | bsra | bsrl | bsrf | brlc | outinb | ldix
  | ldws | lddx | lddrx | ldirx | ldpirx | jp\.l | call\.l | ret\.l | stmix
  | rsmix | ld\.lil | ld\.sil | ld\.sis | ld\.lis
)$""", re.X)


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


RULES = gasfuzz.Rules()


if __name__ == "__main__":
    sys.exit(gasfuzz.disasm_main("z80", TARGETS, RULES, skip, "z80",
                                 count=12000))
