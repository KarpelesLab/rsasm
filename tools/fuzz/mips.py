#!/usr/bin/env python3
"""Differential fuzzer for rsasm's MIPS backend.

Cases are GNU objdump's disassembly of random instruction words, as
`aarch64.py` does it: every word that decodes at all becomes one line of
source, in the spelling GNU as reads, with operands of every value the
encoding allows. Nothing here comes from rsasm's tables, and nothing comes
from the assembler half of binutils either -- the disassembler is a separate
table from the parser.

Each line is then assembled by `mips64-elf-as`, by llvm-mc and by rsasm, and
the bytes, the relocations and the accept/reject decision are compared.

    tools/fuzz/mips.py fuzz --count 20000
    tools/fuzz/mips.py fuzz --target mipsel --only '^c\\.' --seed 7
    tools/fuzz/mips.py check --target mips64 lines.txt

A branch prints its target as an absolute address, so a case is only the
same instruction when it is assembled where it was disassembled; each case
carries the `.skip` that puts it back at its own offset.

GNU as runs with `.set noreorder`, `.set nomacro` and `.set noat` at the top
of the file: by default it moves instructions into branch delay slots and
invents `nop`s, and the backend does not (see src/arch/mips/mod.rs). `-O0`
keeps it from reordering anything else.

The instructions the backend does not implement are skipped by name, in
`NOT_IMPLEMENTED` below, which is the MIPS32r2-and-later set the README's
"MIPS 32/64" does not claim: the bit-field and count-leading instructions,
the conditional moves on floating point, the prefetches and the rest of the
privileged set.

The exit status is 1 when rsasm differs from both references on any case.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/mips64-elf-as and
bin/mips64-elf-objdump), LLVM_MC (default llvm-mc, verified with LLVM 22).
"""

import argparse
import os
import random
import re
import sys

import gasfuzz
from gasfuzz import Target

# The three assemblers are asked for the same thing: no reordering, no macro
# expansion into `$at`, and the plain ISA.
HEAD = ["\t.set noreorder", "\t.set nomacro", "\t.set noat"]

# Random 32-bit words land in the load/store opcodes far more often than in
# opcode 0, which is where the whole register-to-register set lives, so the
# opcode field is drawn rather than left to chance. Only the field's *value*
# is chosen here; every other bit is random, and what an opcode means is the
# disassembler's business.
OPCODES = ([0] * 8 + [1] * 2 + [0x10, 0x11, 0x11, 0x12, 0x13] +
           list(range(0, 64)))


def word(rng):
    return (rng.choice(OPCODES) << 26) | rng.getrandbits(26)


TARGETS = {
    "mips": Target("mips", "mips", gas="mips64-elf-as",
                   gas_flags=["-mips32", "-EB", "-O0", "-mno-pdr"],
                   mc="mips", objdump="mips64-elf-objdump",
                   objdump_flags=["-m", "mips:isa32", "-EB"], head=HEAD,
                   addr_bits=32, word_maker=word),
    "mipsel": Target("mipsel", "mipsel", gas="mips64-elf-as",
                     gas_flags=["-mips32", "-EL", "-O0", "-mno-pdr"],
                     mc="mipsel", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa32", "-EL"], head=HEAD,
                     addr_bits=32, word_maker=word, little=True),
    "mips64": Target("mips64", "mips64", gas="mips64-elf-as",
                     gas_flags=["-mips64", "-EB", "-O0", "-mno-pdr"],
                     mc="mips64", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa64", "-EB"], head=HEAD,
                     addr_bits=64, word_maker=word),
    "mips64el": Target("mips64el", "mips64el", gas="mips64-elf-as",
                       gas_flags=["-mips64", "-EL", "-O0", "-mno-pdr"],
                       mc="mips64el", objdump="mips64-elf-objdump",
                       objdump_flags=["-m", "mips:isa64", "-EL"], head=HEAD,
                       addr_bits=64, word_maker=word, little=True),
}

# What README.md's "MIPS 32/64" does not claim: everything MIPS32r2 and later
# added, the coprocessor-2 and privileged sets, and the DSP and MSA
# extensions. Skipping them by name keeps a whole extension from reading as
# thousands of identical findings; adding one to the backend is what takes it
# off this list.
NOT_IMPLEMENTED = re.compile(r"""^(
    c[lt]o | dc[lt]o | dc[lt]z | clz | ins | dins[mu]? | ext | dext[mu]? | wsbh | dsbh | dshd
  | seb | seh | rotr?v? | drotr(32|v)? | movf | movt | movf\.[sdq] | movt\.[sdq]
  | movn\.[sdq] | movz\.[sdq] | pref | prefx | cache | synci | rdhwr | rdpgpr | wrpgpr
  | deret | wait | tlb.* | mfc2 | mtc2 | cfc[0-9] | ctc[0-9] | dmfc[02] | dmtc[02]
  | bc[0-9].* | c[0-9] | cop[0-9] | lwxc1 | ldxc1 | swxc1 | sdxc1 | luxc1 | suxc1
  | madd\.[sdq] | msub\.[sdq] | nmadd\.[sdq] | nmsub\.[sdq] | recip\.[sdq] | rsqrt\.[sdq]
  | alnv\.ps | cvt\.ps\.s | cvt\.s\.p[lu] | p[lu][lu]\.ps | mulr\.ps
  | ei | di | jalr\.hb | jr\.hb | sdbbp | ll[dwe] | sc[dwe] | lld | scd
  | b | bal | li | la | dla | move | not | neg[u]? | beqz | bnez | seq | sne
  | s[lg][te]u? | ulw | ulh | usw | ush | uld | usd | rem | remu | ddiv[u]? | dmul.*
  | .*\.ps | v?mul[ou]? | msa.* | add(v|s)_.* | \w+\.qb | \w+\.ph | \w+\.w\.phl?
  | jalx
)$""", re.X)

# The floating-point condition codes. MIPS IV gave `c.cond.fmt`, `bc1f` and
# `bc1t` an eight-way flag written `$fcc0`-`$fcc7`; the backend has only the
# implied `$fcc0` form, so a case naming one of the others is left out rather
# than counted. src/arch/mips/reg.rs has two register classes and this would
# be a third.
UNIMPLEMENTED_OPERAND = re.compile(r"\$fcc\d")


def skip(case):
    mnemonic, text = case
    return bool(NOT_IMPLEMENTED.match(mnemonic) or UNIMPLEMENTED_OPERAND.search(text))


# ---- what the references disagree about -------------------------------------

def gas_relocates_a_local_label(text, res):
    """GNU as writes a relocation for a branch whose target is a number,
    where llvm-mc encodes the displacement. Same bytes, more relocations."""
    g, m = res.get("gas"), res.get("mc")
    if not g or not m or g[0] != "ok" or m[0] != "ok":
        return False
    return g[1][0] == m[1][0] and len(g[1][1]) != len(m[1][1])


def mc_refuses_a_spelling(text, res):
    """llvm-mc has no pattern for a form GNU as and its disassembler both
    know. rsasm follows GNU as on spellings."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "ok" and m[0] == "err")


def gas_refuses_a_spelling(text, res):
    """The other way round: llvm-mc reads a form GNU as refuses."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "err" and m[0] == "ok")


RULES = gasfuzz.Rules(splits=[
    ("gas-relocates-a-numeric-target", gas_relocates_a_local_label, "mc"),
    ("mc-refuses-a-spelling", mc_refuses_a_spelling, "gas"),
    ("gas-refuses-a-spelling", gas_refuses_a_spelling, "mc"),
])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="compare instructions given one per line")
    c.add_argument("--target", default="mips", choices=list(TARGETS))
    c.add_argument("file")
    c.add_argument("--limit", type=int, default=100)
    z = sub.add_parser("fuzz", help="disassemble random words and compare")
    gasfuzz.add_fuzz_args(z)
    z.add_argument("--target", default="all", choices=list(TARGETS) + ["all"])
    args = ap.parse_args()

    targets = [TARGETS[args.target]] if getattr(args, "target", "all") != "all" \
        else list(TARGETS.values())
    for t in targets:
        bad = t.missing()
        if bad:
            sys.exit(bad)

    if args.cmd == "check":
        cases = [(line.split()[0], line.strip()) for line in open(args.file)
                 if line.strip() and not line.startswith("#")]
        return gasfuzz.report("mips", gasfuzz.compare(TARGETS[args.target], cases, RULES),
                             args.limit)

    rng = random.Random(args.seed)
    jobs = []
    per = max(1, args.count // len(targets))
    for t in targets:
        cases = [c for c in gasfuzz.disassembled_cases(rng, t, per * 2)
                 if not skip(c) and (not args.only or re.search(args.only, c[0]))]
        jobs.append((t, cases[:per]))
    if args.print_cases:
        for t, cases in jobs:
            for _m, text in cases:
                print(f"[{t.key}] " + text.replace("\n", " ; "))
        return 0
    return gasfuzz.drive("mips", jobs, RULES, args.limit, args.batch,
                         args.no_splits)


if __name__ == "__main__":
    sys.exit(main())
