#!/usr/bin/env python3
"""Differential fuzzer for rsasm's RISC-V backend.

Random RV32 and RV64 instructions are generated from the opcode table in GNU
binutils' `opcodes/riscv-opc.c`, read at run time for each row's mnemonic,
the XLEN it is for and its *operand format string* -- never for its encoding
-- assembled by llvm-mc, `riscv64-elf-as` and rsasm, and compared: bytes,
relocations and whether each assembler took the line at all.

    tools/fuzz/riscv.py fuzz --count 20000
    tools/fuzz/riscv.py fuzz --target riscv32 --only '^f' --seed 7
    tools/fuzz/riscv.py check --target riscv64 lines.txt

The format string is what `riscv_ip` in gas reads to parse operands, so it
says exactly which operands a mnemonic takes and in which order; what each
letter *means* is written out in this script, from the same source, and is
the only RISC-V knowledge here. A row whose format uses a letter this script
does not generate is skipped rather than guessed at, so an extension the
backend does not claim cannot turn into a wall of findings.

The rows used are the ones for the base I set and the M, A, F and D
extensions, plus Zicsr and Zifencei, which is what README.md claims
(RV32/RV64 IMAFDC). The C extension is not a set of mnemonics here: rsasm,
llvm-mc and GNU as all shorten what they emit, so compression is exercised
by every case rather than by `c.*` rows, which none of the three accepts
from source in the same way.

GNU as runs with `-mno-relax`: it otherwise pairs every symbolic reference
with an `R_RISCV_RELAX` marker, which is a hint to the linker rather than
part of the encoding, and neither llvm-mc nor rsasm writes one.

One case in eight is a small program rather than a single instruction: a
forward branch to the label the harness defines after every case, over a
gap drawn from the distances that sit on and just past the reach of each
branch form. That is the only way the choice between a two-byte branch, a
four-byte one and the opposite branch over a `jal` is reached at all.

`--mutations` (default 0.25) is the fraction of cases made deliberately
invalid: an immediate past the end of its field, a shift amount too large
for the XLEN, a register from the wrong bank, an instruction on the XLEN it
does not exist for, a rounding mode or fence set that is not one, an operand
too many or too few.

Classes are x86.py's: `agree`, `rsasm` (the findings), `deviation` and
`split`/`convention` where the references part ways. The exit status is 1
when there are findings.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles, for bin/riscv64-elf-as and the
binutils source), LLVM_MC (default llvm-mc, verified with LLVM 22).
"""

import argparse
import os
import random
import re
import sys

import gasfuzz
from gasfuzz import Target

OPCODES = os.path.join(gasfuzz.BINUTILS_SRC, "opcodes", "riscv-opc.c")

TARGETS = {
    "riscv32": Target("riscv32", "riscv32",
                      gas="riscv64-elf-as", gas_flags=["-march=rv32gc", "-mno-relax"],
                      mc="riscv32", mc_flags=["-mattr=+m,+a,+f,+d,+c"]),
    "riscv64": Target("riscv64", "riscv64",
                      gas="riscv64-elf-as", gas_flags=["-march=rv64gc", "-mno-relax"],
                      mc="riscv64", mc_flags=["-mattr=+m,+a,+f,+d,+c"]),
}
XLEN = {"riscv32": 32, "riscv64": 64}

# The extensions README.md claims, by the name riscv-opc.c gives each row's
# INSN_CLASS. Everything else -- the vector set, the bit-manipulation and
# crypto extensions, the vendor sets, the hypervisor instructions -- is left
# out, because the backend does not claim it.
CLASSES = {"I", "M", "M_OR_ZMMUL", "A", "ZAAMO", "ZALRSC", "F", "D",
           "ZICSR", "ZIFENCEI"}

# Operand letters this script knows how to write. A row using any other one
# is skipped. The meanings are gas's, from `riscv_ip` in tc-riscv.c:
#
#   d s t     rd, rs1, rs2                D S T R  frd, frs1, frs2, frs3
#   j         signed 12-bit immediate     o q      the same, as a load or
#   u         20-bit upper immediate               store displacement
#   > <       shift amount, XLEN or 32    a p c    jump, branch and call
#   m         rounding mode                        targets
#   P Q       fence predecessor/successor E Z      CSR and its 5-bit form
#   I         a `li` immediate of any width
#   B         the symbol `la`, `lla` and `lga` load the address of
#
# `A` (the symbol form of a load or store, `lw a0, sym`) is left out: the
# backend does not implement those macros, so generating them would only
# produce the same refusal over and over.
KNOWN = set("dstDSTRjuoq><mPQEZIB")
LITERAL = set(",()")


def parse_table(path):
    """`[(name, xlen, class, format)]` from the opcode table."""
    text = open(path).read()
    rows = re.findall(
        r'^\{"([A-Za-z0-9._]+)",\s*(\d+),\s*INSN_CLASS_([A-Z0-9_]+),\s*'
        r'"((?:[^"\\]|\\.)*)"', text, re.M)
    out, seen = [], set()
    for name, xlen, cls, fmt in rows:
        if cls not in CLASSES or name.startswith("c."):
            continue
        if any(c not in KNOWN and c not in LITERAL for c in fmt):
            continue
        k = (name, int(xlen), fmt)
        if k in seen:
            continue
        seen.add(k)
        out.append((name, int(xlen), cls, fmt))
    return out


# ---- operands ---------------------------------------------------------------

XNAMES = (["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"] +
          [f"a{i}" for i in range(8)] + [f"s{i}" for i in range(2, 12)] +
          [f"t{i}" for i in range(3, 7)])
FNAMES = ([f"ft{i}" for i in range(8)] + ["fs0", "fs1"] +
          [f"fa{i}" for i in range(8)] + [f"fs{i}" for i in range(2, 12)] +
          [f"ft{i}" for i in range(8, 12)])
ROUNDING = ["rne", "rtz", "rdn", "rup", "rmm", "dyn"]
CSRS = ["cycle", "time", "instret", "fflags", "frm", "fcsr", "mstatus",
        "mtvec", "mepc", "mcause", "sstatus", "satp", "0x300", "0x7c0", "0"]
# Values that sit on or just past the end of a field.
EDGES = [0, 1, 2, -1, -2, 4, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
         2047, 2048, -2048, -2049, 0x7ff, 0x800, 0xfff, 0x1000]


def num(rng, lo, hi):
    """A value in [lo, hi], favouring the ends of the range."""
    if rng.random() < 0.45:
        v = rng.choice(EDGES)
        if lo <= v <= hi:
            return v
    return rng.randint(lo, hi)


def spell(rng, v):
    if v < 0 or rng.random() < 0.6:
        return str(v)
    if rng.random() < 0.5:
        return hex(v)
    return f"({v - 1}+1)"


def gpr(rng):
    return f"x{rng.randrange(32)}" if rng.random() < 0.35 else rng.choice(XNAMES)


def fpr(rng):
    return f"f{rng.randrange(32)}" if rng.random() < 0.35 else rng.choice(FNAMES)


def fence_set(rng):
    bits = [c for c in "iorw" if rng.random() < 0.5]
    return "".join(bits) or "iorw"


def symbolic(rng, kind):
    """A `%hi`/`%lo`-style reference, or None for a plain number."""
    base = rng.choice(["ext", "L"])
    if kind == "u":
        return rng.choice([f"%hi({base})", f"%pcrel_hi({base})"])
    return rng.choice([f"%lo({base})", f"%lo({base})"])


def operand(rng, c, xlen, mutate):
    """One operand for format letter `c`. Returns None to drop the case."""
    if c in "dst":
        if mutate and rng.random() < 0.4:
            return rng.choice([fpr(rng), "x32", "x-1", "a99", "ft3"])
        return gpr(rng)
    if c in "DSTR":
        if mutate and rng.random() < 0.4:
            return rng.choice([gpr(rng), "f32", "fa9", "ft12"])
        return fpr(rng)
    if c in "joq":
        if mutate and rng.random() < 0.5:
            return spell(rng, rng.choice([2048, -2049, 4096, -4096, 0x100000]))
        if rng.random() < 0.2:
            return symbolic(rng, "j")
        return spell(rng, num(rng, -2048, 2047))
    if c == "u":
        if mutate and rng.random() < 0.5:
            return spell(rng, rng.choice([0x100000, -1, 0x200000]))
        if rng.random() < 0.25:
            return symbolic(rng, "u")
        return spell(rng, num(rng, 0, 0xfffff))
    if c == ">":
        top = xlen - 1
        return spell(rng, num(rng, 0, top) if not mutate else rng.choice([top + 1, 64, -1]))
    if c == "<":
        return spell(rng, num(rng, 0, 31) if not mutate else rng.choice([32, 63, -1]))
    if c in "apc":
        if mutate and rng.random() < 0.4:
            return rng.choice(["1", "0x10001", "-3"])
        if c == "p" and rng.random() < 0.15:
            return "ext"
        return rng.choice(["L", "ext", "ext"]) if c != "p" else rng.choice(["L", "L", "ext"])
    if c == "B":
        return rng.choice(["ext", "L"])
    if c == "m":
        return rng.choice(ROUNDING) if not mutate else rng.choice(["rzz", "rne2", "x0"])
    if c in "PQ":
        return fence_set(rng) if not mutate else rng.choice(["z", "iorwx", "0"])
    if c == "E":
        return rng.choice(CSRS) if not mutate else rng.choice(["0x1000", "nosuchcsr", "-1"])
    if c == "Z":
        return spell(rng, num(rng, 0, 31) if not mutate else rng.choice([32, -1, 64]))
    if c == "I":
        if mutate and rng.random() < 0.3:
            return "0x1ffffffffffffffff"
        width = rng.choice([12, 20, 32, 48, 64])
        v = rng.getrandbits(width) - (1 << (width - 1))
        return spell(rng, v)
    return None


def render(rng, fmt, xlen, mutate):
    """The operand text for a format string, or None if it cannot be made."""
    out, target = [], -1
    letters = [i for i, c in enumerate(fmt) if c in KNOWN]
    if mutate and letters and rng.random() < 0.7:
        target = rng.choice(letters)
    for i, c in enumerate(fmt):
        if c in LITERAL:
            out.append(c + (" " if c == "," else ""))
            continue
        if c not in KNOWN:
            return None
        text = operand(rng, c, xlen, i == target)
        if text is None:
            return None
        out.append(text)
    return "".join(out).strip()


# Distances that sit on and just past the reach of each branch form: the
# 16-bit `c.beqz` (+-256 bytes), `c.j` (+-2 KiB) and the 32-bit conditional
# branch (+-4 KiB). What is emitted for each of them is the assembler's
# choice, and where it changes is where the choice is interesting.
REACHES = [0, 4, 200, 254, 256, 258, 2040, 2048, 2050, 4090, 4096, 4098]
# Past `jal`'s +-1 MiB there is nothing left to expand into. The gap is a
# megabyte of real zeroes in the object, so it comes up rarely.
OUT_OF_REACH = 0x100002


def program(rng, target, mutate):
    """A few statements with a forward branch over them.

    An instruction on its own never exercises the part of the assembler that
    chooses between a two-byte branch, a four-byte one and a pair -- that
    only happens once there is something in between and a label at the end.
    The label is the one `gasfuzz` defines after every case, so the branch is
    always forward and its distance is whatever the filler adds up to.
    """
    branch = rng.choice(["beq a0, a1, L", "bne a0, zero, L", "beqz a0, L",
                         "bnez s1, L", "blt t0, t1, L", "bgeu a2, a3, L",
                         "j L", "jal L", "jal t0, L"])
    lines = [branch]
    gap = rng.choice(REACHES)
    if (mutate and rng.random() < 0.15) or rng.random() < 0.01:
        # Past what even `jal` reaches, so the branch cannot be encoded at
        # all: llvm-mc and rsasm refuse it, GNU as truncates the
        # displacement and lands somewhere else.
        gap = OUT_OF_REACH
    if rng.random() < 0.4:
        lines.append(f".p2align {rng.randrange(1, 5)}")
    if gap:
        lines.append(f".skip {gap}")
    if rng.random() < 0.5:
        lines.append(rng.choice(["nop", "addi a0, a0, 1", "c.nop" if False else "ebreak"]))
    return branch.split()[0], "\n".join(lines)


def make(rng, target, mutate, forms):
    """One `(mnemonic, source)` case."""
    xlen = XLEN[target.key]
    # A share of the cases are small programs rather than one instruction,
    # which is the only way the branch-width choice is reached.
    if rng.random() < 0.12:
        return program(rng, target, mutate)
    for _ in range(40):
        name, need, _cls, fmt = rng.choice(forms)
        if need and need != xlen and not (mutate and rng.random() < 0.3):
            continue
        ops = render(rng, fmt, xlen, mutate)
        if ops is None:
            continue
        text = f"{name} {ops}".strip()
        if mutate and rng.random() < 0.15:
            # An operand too many, or one too few.
            parts = [p for p in ops.split(", ") if p]
            if rng.random() < 0.5 and parts:
                parts = parts[:-1]
            else:
                parts = parts + [gpr(rng)]
            text = f"{name} " + ", ".join(parts)
        return name, text.strip()
    return None


# ---- what the references disagree about -------------------------------------

def resolves_a_local_label(text, res, target):
    """Same bytes, fewer relocations.

    GNU as leaves every reference to a label to the linker, because linker
    relaxation may still move it; llvm-mc resolves the ones it can, and rsasm
    does too -- README.md records RISC-V as checked against llvm-mc, and
    src/arch/riscv/mod.rs says relaxation is not implemented, so objects come
    out as llvm-mc writes them without it. `-mno-relax` does not change what
    GNU as does here.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok":
        return False
    return g[1][0] == r[1][0] and len(g[1][1]) > len(r[1][1])


def relocates_a_bare_symbol(text, res, target):
    """`andi a0, a1, sym` and `lw a0, sym(a1)`.

    Both references insist the symbol carry a `%lo` or `%pcrel_lo`, and
    refuse a bare one. rsasm puts it in the field and leaves the low twelve
    bits to the linker: `imm12` in src/arch/riscv/asm.rs takes an unmodified
    symbol on purpose, which is a superset of what the references read.
    """
    r = res.get("rsasm")
    if not r or r[0] != "ok" or not r[1][1]:
        return False
    return all(v[0] == "err" for k, v in res.items() if k != "rsasm")


def takes_a_signed_upper_immediate(text, res, target):
    """`lui a0, -1` and `auipc a0, -1`.

    rsasm reads the 20-bit field of `lui` and `auipc` as signed as well as
    unsigned (`imm20` in src/arch/riscv/asm.rs), so -1 and 0xfffff name the
    same instruction. GNU as and llvm-mc take only 0..0xfffff.
    """
    if not re.match(r"^(lui|auipc)\b.*[ ,]-\d", text):
        return False
    r = res.get("rsasm")
    return bool(r and r[0] == "ok"
                and all(v[0] == "err" for k, v in res.items() if k != "rsasm"))


def mc_takes_an_out_of_range_value(text, res, target):
    """llvm-mc truncates where GNU as refuses. rsasm refuses, as GNU as
    does."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "err" and m[0] == "ok")


def gas_takes_more_spellings(text, res, target):
    """GNU as reads forms llvm-mc has no pattern for -- `%pcrel_hi` on `lui`,
    an alias only binutils knows. rsasm follows GNU as where it is the looser
    of the two on a spelling."""
    g, m = res.get("gas"), res.get("mc")
    return bool(g and m and g[0] == "ok" and m[0] == "err")


def gas_relocates_a_local_label(text, res, target):
    """GNU as leaves a `%pcrel_hi`/`%pcrel_lo` pair against a local label to
    the linker, because relaxation may still move it; llvm-mc computes the
    displacement. The bytes differ, since one has the field zeroed."""
    g, m = res.get("gas"), res.get("mc")
    if not g or not m or g[0] != "ok" or m[0] != "ok":
        return False
    return len(g[1][1]) > len(m[1][1])


def gas_does_not_shorten_an_alias(text, res, target):
    """An alias GNU as resolves late -- `add a0, a1, 0`, `jalr ra, 0` -- comes
    out of it at full width, where llvm-mc runs it through compression like
    anything else."""
    g, m = res.get("gas"), res.get("mc")
    if not g or not m or g[0] != "ok" or m[0] != "ok":
        return False
    return len(g[1][0]) > len(m[1][0])


def li_expands_differently(text, res, target):
    """`li` is a macro, and the two references synthesise different
    sequences for some values; rsasm follows llvm-mc's, which is the shorter
    (see src/arch/riscv/matint.rs)."""
    return text.split()[0] == "li"


RULES = gasfuzz.Rules(
    deviations=[
        ("resolves-a-local-label", resolves_a_local_label),
        ("relocates-a-bare-symbol", relocates_a_bare_symbol),
        ("takes-a-signed-upper-immediate", takes_a_signed_upper_immediate),
    ],
    splits=[
        ("mc-takes-an-out-of-range-value", mc_takes_an_out_of_range_value, "gas"),
        ("gas-takes-more-spellings", gas_takes_more_spellings, "gas"),
        ("li-expands-differently", li_expands_differently, "mc"),
        ("gas-relocates-a-local-label", gas_relocates_a_local_label, "mc"),
        ("gas-does-not-shorten-an-alias", gas_does_not_shorten_an_alias, "mc"),
    ])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="compare instructions given one per line")
    c.add_argument("--target", default="riscv64", choices=list(TARGETS))
    c.add_argument("file")
    c.add_argument("--limit", type=int, default=100)
    z = sub.add_parser("fuzz", help="generate random instructions and compare")
    gasfuzz.add_fuzz_args(z)
    z.add_argument("--target", default="all", choices=list(TARGETS) + ["all"])
    args = ap.parse_args()

    if not os.path.exists(OPCODES):
        sys.exit(f"no {OPCODES}; run tools/oracles/build.sh")
    targets = [TARGETS[args.target]] if getattr(args, "target", "all") != "all" \
        else list(TARGETS.values())
    for t in targets:
        bad = t.missing()
        if bad:
            sys.exit(bad)
    forms = parse_table(OPCODES)

    if args.cmd == "check":
        cases = [(line.split()[0], line.strip()) for line in open(args.file)
                 if line.strip() and not line.startswith("#")]
        target = TARGETS[args.target]
        return gasfuzz.report("riscv", gasfuzz.compare(target, cases, RULES),
                             args.limit)

    rng = random.Random(args.seed)
    jobs = gasfuzz.generate(rng, lambda r, t, m: make(r, t, m, forms), targets,
                            args.count, args.only, args.mutations)
    if args.print_cases:
        for t, cases in jobs:
            for _m, text in cases:
                print(f"[{t.key}] {text}")
        return 0
    print(f"# {len(forms)} forms from {os.path.basename(OPCODES)}")
    return gasfuzz.drive("riscv", jobs, RULES, args.limit, args.batch,
                         args.no_splits)


if __name__ == "__main__":
    sys.exit(main())
