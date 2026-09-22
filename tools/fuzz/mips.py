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
carries the `.skip` that puts it back at its own offset. The target itself
is then written as an offset from the branch, because a bare number there
means three different things to the three assemblers; see
`assemblable_target`.

MIPS objdump also prints a general-purpose register by its ABI name and
without the `$` sigil -- `swl v1,-27583(t7)` -- which none of the three
assemblers reads back, so the disassembly is asked for numbers instead. Put
together those two things are the difference between 5% of the generated
cases being comparable and 99.7% of them.

GNU as runs with `.set noreorder`, `.set nomacro` and `.set noat` at the top
of the file: by default it moves instructions into branch delay slots and
invents `nop`s, and the backend does not (see src/arch/mips/mod.rs). `-O0`
keeps it from reordering anything else.

The instructions the backend does not implement are skipped by name, in
`NOT_IMPLEMENTED` below, which is the MIPS32r2-and-later set the README's
"MIPS 32/64" does not claim: the bit-field and count-leading instructions,
the conditional moves on floating point, the rotates, the prefetches and the
rest of the privileged set, together with coprocessors 2 and 3 and the DSP,
MDMX, MIPS-3D and paired-single extensions.

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


# MIPS objdump prints a general-purpose register by its ABI name and without
# the `$` sigil -- `swl v1,-27583(t7)` -- which no MIPS assembler reads back,
# so the disassembly has to be asked for numbers instead. Floating-point
# registers are already printed as `$f0`.
NUMERIC = "-Mgpr-names=numeric"

# Every mnemonic the MIPS disassembler prints with a PC-relative target
# begins with `b`, and `break` is the only one that begins with `b` and does
# not. `j` and `jal` are left alone: their target is an index into the
# current 256 MB region, which all three assemblers read as the address it
# is printed as.
BRANCH = re.compile(r"b(?!reak$)\w*")
NUMBER = re.compile(r"-?(0x[0-9a-f]+|[0-9]+)")


def assemblable_target(text, off):
    """Writes a branch's target as an offset from the branch itself.

    A disassembler prints the target as the address it computed, and the
    three assemblers do not agree on what a bare number there means: rsasm
    and GNU as read an address, llvm-mc reads the displacement itself, and
    GNU as cannot resolve an absolute address against a section it is still
    assembling, so it leaves a `R_MIPS_PC16` against `*ABS*` that overflows.
    That is a disagreement about a spelling and not about an encoding, and
    `src/arch/mips/encode.rs` records which side rsasm takes.

    `. + d` means the same thing to all three, and with `d` measured from
    where the instruction was disassembled it is the same instruction again,
    down to the bits in the displacement field.
    """
    mnemonic, _, operands = text.partition(" ")
    if not BRANCH.fullmatch(mnemonic) or not operands:
        return text
    ops = operands.rsplit(",", 1)
    last = ops[-1].strip()
    if not NUMBER.fullmatch(last):
        return text
    value = int(last, 16) if "0x" in last else int(last, 10)
    ops[-1] = f".{value - off:+d}"
    return mnemonic + " " + ",".join(ops)


TARGETS = {
    "mips": Target("mips", "mips", gas="mips64-elf-as",
                   gas_flags=["-mips32", "-EB", "-O0", "-mno-pdr"],
                   mc="mips", objdump="mips64-elf-objdump",
                   objdump_flags=["-m", "mips:isa32", "-EB", NUMERIC], head=HEAD,
                   addr_bits=32, word_maker=word, rewrite=assemblable_target),
    "mipsel": Target("mipsel", "mipsel", gas="mips64-elf-as",
                     gas_flags=["-mips32", "-EL", "-O0", "-mno-pdr"],
                     mc="mipsel", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa32", "-EL", NUMERIC], head=HEAD,
                     addr_bits=32, word_maker=word, little=True,
                     rewrite=assemblable_target),
    "mips64": Target("mips64", "mips64", gas="mips64-elf-as",
                     gas_flags=["-mips64", "-EB", "-O0", "-mno-pdr"],
                     mc="mips64", objdump="mips64-elf-objdump",
                     objdump_flags=["-m", "mips:isa64", "-EB", NUMERIC], head=HEAD,
                     addr_bits=64, word_maker=word, rewrite=assemblable_target),
    "mips64el": Target("mips64el", "mips64el", gas="mips64-elf-as",
                       gas_flags=["-mips64", "-EL", "-O0", "-mno-pdr"],
                       mc="mips64el", objdump="mips64-elf-objdump",
                       objdump_flags=["-m", "mips:isa64", "-EL", NUMERIC], head=HEAD,
                       addr_bits=64, word_maker=word, little=True,
                       rewrite=assemblable_target),
}

# What README.md's "MIPS 32/64" does not claim: everything MIPS32r2 and later
# added, the coprocessor-2 and privileged sets, and the DSP, MDMX, MIPS-3D
# and paired-single extensions. Skipping them by name keeps a whole extension
# from reading as thousands of identical findings; adding one to the backend
# is what takes it off this list.
#
# The coprocessor-2 loads and stores belong with the rest of coprocessor 2:
# their register operand is a coprocessor-2 register, which
# src/arch/mips/reg.rs has no class for, and the backend has neither `mfc2`
# nor `cfc2` nor `bc2t` either.
NOT_IMPLEMENTED = re.compile(r"""^(
    c[lt]o | dc[lt]o | dc[lt]z | clz | ins | dins[mu]? | ext | dext[mu]? | wsbh | dsbh | dshd
  | seb | seh | d?ro[lr](32|v)? | d?rot[lr](32|v)? | movf | movt | movf\.[sdq] | movt\.[sdq]
  | movn\.[sdq] | movz\.[sdq] | pref | prefx | cache | synci | rdhwr | rdpgpr | wrpgpr
  | deret | wait | tlb.* | m[ft]c[23] | dm[ft]c[023] | cfc[0-9] | ctc[0-9]
  | [ls][wd]c[023] | bc[023].* | bc1any.* | c[0-9] | cop[0-9]
  | lwxc1 | ldxc1 | swxc1 | sdxc1 | luxc1 | suxc1
  | madd\.[sdq] | msub\.[sdq] | nmadd\.[sdq] | nmsub\.[sdq] | recip\.[sdq] | rsqrt\.[sdq]
  | alnv\.ps | cvt\.ps\.s | cvt\.s\.p[lu] | p[lu][lu]\.ps | mulr\.ps
  | ei | di | jalr\.hb | jr\.hb | sdbbp | ll[dwe] | sc[dwe] | lld | scd
  | dla | seq | sne | s(le|gt|ge)u? | ulw | ulh | usw | ush | uld | usd
  | rem | remu | ddiv[u]? | dmul.*
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

def mc_refuses_a_spelling(text, res, target):
    """llvm-mc has no pattern for a form GNU as and its disassembler both
    know. rsasm follows GNU as on spellings."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "ok" and m[0] == "err")


def gas_refuses_a_spelling(text, res, target):
    """The other way round: llvm-mc reads a form GNU as refuses."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "err" and m[0] == "ok")


# An operand that holds a double: a `.d` mnemonic, the `.d` side of a
# conversion, or the register of `ldc1` / `sdc1`.
DOUBLE = re.compile(r".*\.d|cvt\.d\.\w+|[ls]dc1")
FPR = re.compile(r"\$f(\d+)\b")


def mc_rounds_an_odd_double_register(text, res, target):
    """A double written in an odd floating-point register, which both
    references warn about and then read differently: GNU as encodes the
    number written, llvm-mc rounds it down to the even half of the pair.
    rsasm follows GNU as. Only a 32-bit floating-point file has pairs; see
    src/arch/mips/abi.rs."""
    if target.addr_bits != 32:
        return False
    mnemonic = text.split("\n")[-1].split()[0]
    return bool(DOUBLE.fullmatch(mnemonic)
                and any(int(n) % 2 for n in FPR.findall(text)))


# A REGIMM branch that links, testing the register it is about to write.
LINKING_BRANCH_ON_RA = re.compile(r"b(ltz|gez)all?\s+\$(31|ra)\b")


def gas_refuses_a_link_through_the_register_it_tests(text, res, target):
    """`bltzal $ra` and its three relatives: the branch overwrites `$ra`
    before anything reads the value it tested, which the architecture leaves
    unpredictable. GNU as refuses the form and llvm-mc assembles it; rsasm
    follows GNU as, in src/arch/mips/encode.rs."""
    g, m = res.get("gas"), res.get("mc")
    if not (g and m and g[0] == "err" and m[0] == "ok"):
        return False
    return bool(LINKING_BRANCH_ON_RA.match(text.split("\n")[-1]))


RULES = gasfuzz.Rules(splits=[
    ("mc-rounds-an-odd-double-register", mc_rounds_an_odd_double_register, "gas"),
    ("gas-refuses-a-link-through-the-register-it-tests",
     gas_refuses_a_link_through_the_register_it_tests, "gas"),
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
