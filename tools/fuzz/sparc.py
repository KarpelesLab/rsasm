#!/usr/bin/env python3
"""Differential fuzzer for rsasm's SPARC backend.

Cases are GNU objdump's disassembly of random instruction words, the way
`aarch64.py` takes its cases from llvm-mc's: every word that decodes becomes
a line of source in the spelling GNU as reads, with operands of every value
the encoding allows. The disassembler's tables are not the parser's, and
neither is rsasm's.

Each line is assembled by `sparc64-elf-as`, by llvm-mc and by rsasm, and the
bytes, the relocations and the accept/reject decision are compared.

    tools/fuzz/sparc.py fuzz --count 12000
    tools/fuzz/sparc.py fuzz --target sparcv9 --only '^f' --seed 7
    tools/fuzz/sparc.py check --target sparc lines.txt

A branch prints its target as an absolute address, so each case carries the
`.skip` that puts it back at the offset it was disassembled at; a target in
the top half of the address space is written as the negative number it
stands for.

The two-bit `op` field is drawn rather than left to chance: uniformly random
words are nearly all loads and stores, and the arithmetic set is behind one
value of it.

`NOT_IMPLEMENTED` and `UNIMPLEMENTED` list what README.md's "SPARC V8 / V9"
does not claim --
the VIS extensions, the privileged and hyperprivileged set, the quad-precision
floating point and the coprocessor instructions -- which is skipped by name so
that a whole extension cannot read as thousands of identical findings.

One case is set aside rather than compared: llvm-mc 22 crashes on `call`
with an absolute address (`MCExpr::evaluateAsRelocatableImpl`, reached from
the SPARC call fixup), so for those the only reference left is GNU as. The
harness halves a batch a crashing tool was given until it finds the case,
and counts it as `skipped`; nothing is inferred from a crash.

Both targets take their cases from the V9 disassembly, because this
binutils build's objdump has no `sparc:v8` machine. A V9-only instruction
in the 32-bit target's cases is simply refused by GNU as `-Av8`, by llvm-mc
for the `sparc` triple and by rsasm alike, which is an agreement like any
other.

The exit status is 1 when rsasm differs from both references on any case.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/sparc64-elf-as and
bin/sparc64-elf-objdump), LLVM_MC (default llvm-mc, verified with LLVM 22).
"""

import argparse
import random
import re
import sys

import gasfuzz
from gasfuzz import Target


def word(rng):
    # `op` is two bits: 0 is SETHI and the branches, 1 is CALL, 2 the
    # arithmetic set and 3 the loads and stores. Drawing it evenly is the
    # only thing weighted here.
    return (rng.randrange(4) << 30) | rng.getrandbits(30)


# `call` and the branches print the address they land on. Writing that as a
# displacement from `.` says the same thing wherever the instruction sits --
# and keeps llvm-mc away from the absolute-value fixup it crashes on (see
# the docstring), so `call` is compared rather than set aside.
BRANCHES = r"^(call|b[a-z]*|fb[a-z]*)(,[ap][nt]?)*$"
# Every SPARC instruction is a word, so a branch displacement is a
# multiple of four; anything else is a line the rewrite misread.
ALIGN = 4

TARGETS = {
    "sparc": Target("sparc", "sparc", gas="sparc64-elf-as",
                    gas_flags=["-32", "-Av8"], mc="sparc",
                    objdump="sparc64-elf-objdump",
                    objdump_flags=["-m", "sparc:v9"],
                    addr_bits=64, word_maker=word,
                    rewrite=gasfuzz.dot_relative(BRANCHES, ALIGN)),
    "sparcv9": Target("sparcv9", "sparcv9", gas="sparc64-elf-as",
                      gas_flags=["-64", "-Av9"], mc="sparcv9",
                      objdump="sparc64-elf-objdump",
                      objdump_flags=["-m", "sparc:v9"],
                      addr_bits=64, word_maker=word,
                      rewrite=gasfuzz.dot_relative(BRANCHES, ALIGN)),
}

# What the backend does not claim (README.md: "SPARC V8 / V9"): the VIS
# graphics sets, quad-precision floating point, the privileged and
# hyperprivileged instructions, the cache and coprocessor set, and the
# vendor additions. Adding one to the backend is what takes it off this list.
NOT_IMPLEMENTED = re.compile(r"""^(
    f[a-z0-9]*(16|32)[a-z0-9]*  | fpack.* | fexpand | fpmerge | fmul8.* | fpadd.* | fpsub.*
  | fcmp[a-z]*(16|32)  | falign.* | fzero.* | fone.* | fsrc.* | fnot.* | fand.* | for[a-z]*
  | fxor.* | fnand.* | fnor.* | fxnor.* | fornot.* | fandnot.* | bmask | bshuffle
  | edge.* | array.* | pdist.* | siam | fchksum16 | fsll.* | fsrl.* | fsra.* | fmean16
  | f[a-z]*q | f[a-z]*\.q | .*q$ | fcmpq | fcmpeq | fitoq | fqtoi | fqtos | fqtod
  | fstoq | fdtoq | fxtoq | fqtox | fsqrtq | faddq | fsubq | fmulq | fdivq | fmovq.*
  | fnegq | fabsq | fdmulq
  | rdpr | wrpr | rdhpr | wrhpr | saved | restored | done | retry | sir | invalw | normalw
  | otherw | allclean | flushw | membar | stbar | ldd?a | std?a | ldqa | stqa | casa | casxa
  | prefetch | prefetcha | ldfsr | stfsr | ldxfsr | stxfsr | cbcc.* | c[a-z]+cc
  | ld[cd] | st[cd] | ldcsr | stcsr | ldstub[a]? | swapa
  | (ld|st)[a-z]*a | ldtw | sttw | cas | casl | casx | casxl
  | cb[0-9a-z,]* | impdep[12]
  | illtrap | unimp | pause | cwbe? .* | cw[a-z]+ | movdtox | movstouw | movstosw
  | movxtod | movwtos | fpmaddx.* | aes.* | camellia.* | md5 | sha.* | crc32c | xmulx.*
  | mwait | rd | wr | random
)$""", re.X)


# Three families the backend leaves out altogether, skipped by the whole
# line rather than by mnemonic:
#
#   fb<cc> / fbp<cc>   the floating-point branches
#   fmov<cc> / fmovr   the floating-point conditional moves, of either
#                      condition-code bank
#   %fsr, %fq          the floating-point state registers, which `ld` and
#                      `st` transfer
#   t<cc> %icc, ...    the V9 trap and compare, which name a condition-code
#   fcmp<s|d> %fccN,   bank as their first operand
#   %f32 - %f62        the upper half of V9's floating-point file, which is
#                      addressable only as double and quad registers and
#                      numbers them in a five-bit field by a bit swizzle;
#                      src/arch/sparc/reg.rs stops at %f31
#
# Each is a feature the backend does not have, not a disagreement about one
# it does; they are listed here so a run says nothing about them either way.
UNIMPLEMENTED = re.compile(
    r"^(fb|fmov(r|[sdq][a-z]+)|t[a-z]+ %[ix]cc|fcmp[a-z]* %fcc)"
    r"|%f(sr|q)\b|%f(3[2-9]|[45]\d|6[0-2])\b")


def skip(case):
    # The instruction is the last line; a `.skip` may sit in front of it.
    return bool(NOT_IMPLEMENTED.match(case[0])
                or UNIMPLEMENTED.search(case[1].split("\n")[-1]))


def mc_refuses_a_spelling(text, res, target):
    """llvm-mc has no pattern for a form GNU as and its disassembler both
    know. rsasm follows GNU as on spellings."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "ok" and m[0] == "err")


def gas_refuses_a_spelling(text, res, target):
    """The other way round: llvm-mc reads a form GNU as refuses."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "err" and m[0] == "ok")


def references_relocate_differently(text, res, target):
    """Same bytes, different relocations: one reference left a numeric
    target to the linker and the other computed it."""
    g, m = res.get("gas"), res.get("mc")
    if not g or not m or g[0] != "ok" or m[0] != "ok":
        return False
    return g[1][0] == m[1][0] and g[1][1] != m[1][1]


def resolves_a_numeric_target(text, res, target):
    """`call 0x1234` and the branches to a number.

    GNU as leaves an absolute target to the linker -- a `WDISP30` against the
    absolute section, value and all -- where rsasm works the displacement out
    itself, as llvm-mc does everywhere it does not crash. Same length, and
    every relocation GNU as wrote is one rsasm did not need.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok" or len(g[1][0]) != len(r[1][0]):
        return False
    return bool(g[1][1]) and not r[1][1] and all(w == "*ABS*" for _o, _t, w, _a in g[1][1])


def takes_a_v9_spelling_on_v8(text, res, target):
    """`addc`, `subccc`, `flush`: V9 renamed some V8 instructions and added
    others, and rsasm reads both names whatever the target is -- see the
    comment on `addx | addc` in src/arch/sparc/insn.rs, which says the two
    spellings are one opcode. GNU as `-Av8` and llvm-mc for the `sparc`
    triple refuse the V9 name outright.
    """
    if target.key != "sparc":
        return False
    r = res.get("rsasm")
    return bool(r and r[0] == "ok"
                and all(v[0] == "err" for k, v in res.items() if k != "rsasm"))


RULES = gasfuzz.Rules(deviations=[
    ("resolves-a-numeric-target", resolves_a_numeric_target),
    ("takes-a-v9-spelling-on-v8", takes_a_v9_spelling_on_v8),
], splits=[
    ("references-relocate-differently", references_relocate_differently, None),
    ("mc-refuses-a-spelling", mc_refuses_a_spelling, "gas"),
    ("gas-refuses-a-spelling", gas_refuses_a_spelling, None),
])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="compare instructions given one per line")
    c.add_argument("--target", default="sparc", choices=list(TARGETS))
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
        return gasfuzz.report("sparc",
                              gasfuzz.compare(TARGETS[args.target], cases, RULES),
                              args.limit)

    rng = random.Random(args.seed)
    jobs = []
    per = max(1, args.count // len(targets))
    for t in targets:
        cases = [c for c in gasfuzz.disassembled_cases(rng, t, per * 3)
                 if not skip(c) and (not args.only or re.search(args.only, c[0]))]
        jobs.append((t, cases[:per]))
    if args.print_cases:
        for t, cases in jobs:
            for _m, text in cases:
                print(f"[{t.key}] " + text.replace("\n", " ; "))
        return 0
    return gasfuzz.drive("sparc", jobs, RULES, args.limit, args.batch,
                         args.no_splits)


if __name__ == "__main__":
    sys.exit(main())
