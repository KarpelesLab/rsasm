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

A case is only the same instruction when it is assembled where it was
disassembled, so each one carries the `.skip` that puts it back at its own
offset. A branch's target needs more than that: the disassembler prints an
address, and the three assemblers do not read a bare number there the same
way, so `assemblable_target` below puts the case's own label in its place.

GNU as runs with `.set noreorder`, `.set nomacro` and `.set noat` at the top
of the file: by default it moves instructions into branch delay slots and
invents `nop`s, and the backend does not (see src/arch/mips/mod.rs). `-O0`
keeps it from reordering anything else.

The instructions the backend does not implement are skipped by name, in
`NOT_IMPLEMENTED` below, which is the MIPS32r2-and-later set the README's
"MIPS 32/64" does not claim: the bit-field and count-leading instructions,
the prefetches, the paired-single and MIPS-3D arithmetic, and the rest of
the privileged set.

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


# Two targets the disassembler prints in a form no assembler reads back.
#
# A conditional branch's target is printed as the address it lands on, and
# the three assemblers do not agree on what a bare *number* written there
# means: rsasm reads it as the address it is, llvm-mc as the displacement
# itself, and GNU as leaves it to the linker as a relocation against the
# absolute section, which overflows the 16-bit field once the address is far
# from the branch (see src/arch/mips/encode.rs). A label is the one spelling
# all three agree on, so the target becomes the case's own, which
# `build_source` defines just after it. The flag, the `tf` and `nd` bits and
# the register fields are what the case was for anyway.
BRANCH = re.compile(r"""^(
    b | bal | b(eq|ne)l? | b(lez|gtz|ltz|gez)l? | b(ltz|gez)all?
  | bc[0-3](any[24])?[ft]l?
)\s""", re.X)
# `jalx` prints its target with the ISA-mode bit set -- `jalx 0x1235` for the
# word whose 26-bit field holds 0x1234 -- because the call lands in MIPS16 or
# microMIPS code. Every assembler refuses a target that is not a multiple of
# four, so the bit comes off, which gives back the same word again.
JALX = re.compile(r"^jalx\s+(-?(?:0x)?[0-9a-f]+)$")
ADDRESS = re.compile(r"-?(?:0x)?[0-9a-f]+$")


def assemblable_target(text, _off):
    m = JALX.match(text)
    if m:
        return f"jalx {int(m.group(1), 0) & ~1:#x}"
    return ADDRESS.sub("L", text) if BRANCH.match(text) else text


TARGETS = {
    "mips": Target("mips", "mips", gas="mips64-elf-as",
                   gas_flags=["-mips32", "-EB", "-O0", "-mno-pdr"],
                   mc="mips", objdump="mips64-elf-objdump",
                   objdump_flags=["-m", "mips:isa32", "-EB"], head=HEAD,
                   addr_bits=32, word_maker=word, rewrite=assemblable_target),
    "mipsel": Target("mipsel", "mipsel", gas="mips64-elf-as",
                     gas_flags=["-mips32", "-EL", "-O0", "-mno-pdr"],
                     mc="mipsel", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa32", "-EL"], head=HEAD,
                     addr_bits=32, word_maker=word, little=True,
                     rewrite=assemblable_target),
    "mips64": Target("mips64", "mips64", gas="mips64-elf-as",
                     gas_flags=["-mips64", "-EB", "-O0", "-mno-pdr"],
                     mc="mips64", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa64", "-EB"], head=HEAD,
                     addr_bits=64, word_maker=word, rewrite=assemblable_target),
    "mips64el": Target("mips64el", "mips64el", gas="mips64-elf-as",
                       gas_flags=["-mips64", "-EL", "-O0", "-mno-pdr"],
                       mc="mips64el", objdump="mips64-elf-objdump",
                       objdump_flags=["-m", "mips:isa64", "-EL"], head=HEAD,
                       addr_bits=64, word_maker=word, little=True,
                       rewrite=assemblable_target),
}

# What README.md's "MIPS 32/64" does not claim: everything MIPS32r2 and later
# added, the coprocessor-2 and privileged sets, and the DSP and MSA
# extensions. Skipping them by name keeps a whole extension from reading as
# thousands of identical findings; adding one to the backend is what takes it
# off this list.
NOT_IMPLEMENTED = re.compile(r"""^(
    c[lt]o | dc[lt]o | dc[lt]z | clz | ins | dins[mu]? | ext | dext[mu]? | wsbh | dsbh | dshd
  | seb | seh | rotr?v? | drotr(32|v)?
  | movn\.[sdq] | movz\.[sdq] | pref | prefx | cache | synci | rdhwr | rdpgpr | wrpgpr
  | deret | wait | tlb.* | mfc2 | mtc2 | cfc[0-9] | ctc[0-9] | dmfc[02] | dmtc[02]
  | bc[023]\w* | bc1any\w* | c[0-9] | cop[0-9] | lwxc1 | ldxc1 | swxc1 | sdxc1 | luxc1 | suxc1
  | madd\.[sdq] | msub\.[sdq] | nmadd\.[sdq] | nmsub\.[sdq] | recip\.[sdq] | rsqrt\.[sdq]
  | alnv\.ps | cvt\.ps\.s | cvt\.s\.p[lu] | p[lu][lu]\.ps | mulr\.ps | cabs\..*
  | ei | di | jalr\.hb | jr\.hb | sdbbp | ll[dwe] | sc[dwe] | lld | scd
  | b | bal | li | la | dla | move | not | neg[u]? | beqz | bnez | seq | sne
  | s[lg][te]u? | ulw | ulh | usw | ush | uld | usd | rem | remu | ddiv[u]? | dmul.*
  | .*\.ps | v?mul[ou]? | msa.* | add(v|s)_.* | \w+\.qb | \w+\.ph | \w+\.w\.phl?
)$""", re.X)


def skip(case):
    return bool(NOT_IMPLEMENTED.match(case[0]))


# ---- what the references disagree about -------------------------------------

def gas_relocates_a_local_label(text, res, target):
    """GNU as writes a relocation for a branch whose target is a number,
    where llvm-mc encodes the displacement. Same bytes, more relocations."""
    g, m = res.get("gas"), res.get("mc")
    if not g or not m or g[0] != "ok" or m[0] != "ok":
        return False
    return g[1][0] == m[1][0] and len(g[1][1]) != len(m[1][1])


def mc_refuses_a_spelling(text, res, target):
    """llvm-mc has no pattern for a form GNU as and its disassembler both
    know. rsasm follows GNU as on spellings."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "ok" and m[0] == "err")


def gas_refuses_a_spelling(text, res, target):
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
