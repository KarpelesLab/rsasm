#!/usr/bin/env python3
"""Regenerate src/arch/arm/table.rs from GNU binutils.

The A32 and T32 instruction sets have, between them, some hundreds of forms
that are nothing but a fixed opcode word with register and immediate fields
punched into it: the saturating and packing instructions, the parallel
arithmetic, the bitfield moves, the load/store exclusives, the halfword
multiplies, the hint and barrier space, the coprocessor instructions and the
system forms. Retyping those from the architecture manual is how an
assembler ends up with a wrong bit, so rsasm's table is derived from the one
GNU's own disassembler carries:

    opcodes/arm-dis.c   arm_opcodes[], thumb_opcodes[], thumb32_opcodes[]
                        and generic_coprocessor_opcodes[]

Each row there is an opcode word, a mask and a format string that spells the
instruction out -- `"ssat%c\\t%12-15R, %{I:#%16-20W%}, %0-3R%s"` says the
mnemonic takes a condition, then a register at bits 12-15, then an immediate
at bits 16-20 written one greater than the field, then a register at bits
0-3, then an optional shift. Read the other way round that is exactly what an
assembler needs, so this turns the format strings into rsasm's `Op` lists
and writes the table; `super::generic` encodes from it.

    tools/tables/arm.py table     # rewrite src/arch/arm/table.rs
    tools/tables/arm.py check     # exit 1 if it is out of date
    tools/tables/arm.py audit     # print every row and where it went

Nothing is dropped silently. Every row of the four tables is accounted for:
it becomes a form, or its mnemonic is in HAND because a hand-written encoder
owns it -- the instructions whose encoding depends on more than the operand
list: the data-processing group with its Thumb width selection, the branches
and their relocations, `ldr`/`str` and the literal pool, `ldm`/`stm`, `it`,
`cbz`, `msr`/`mrs` -- or it is a spelling only the disassembler has (DIS), or
its architecture is one rsasm does not claim, which FEATURES decides. A row
that is none of those is an error.

The tree is the one tools/oracles/build.sh unpacks (RSASM_ORACLES, default
target/oracles).
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
BINUTILS = os.path.join(ORACLES, "src", "binutils-2.47")
TABLE = os.path.join(ROOT, "src", "arch", "arm", "table.rs")
TC_ARM = os.path.join(BINUTILS, "gas", "config", "tc-arm.c")

# ============================================================================
# Reading arm-dis.c
# ============================================================================

TABLES = [
    ("static const struct opcode32 arm_opcodes[] =", "arm"),
    ("static const struct opcode16 thumb_opcodes[] =", "t16"),
    ("static const struct opcode32 thumb32_opcodes[] =", "t32"),
    ("static const struct sopcode32 generic_coprocessor_opcodes[] =", "cop"),
]

ENTRY = re.compile(
    r"\{\s*(?:ANY\s*,\s*)?(ARM_FEATURE\w*\s*\([^)]*\)|[A-Za-z_0-9]+)\s*,\s*"
    r"(0[xX][0-9a-fA-F]+|\d+)\s*,\s*(0[xX][0-9a-fA-F]+|\d+)\s*,\s*"
    r'((?:"(?:[^"\\]|\\.)*"\s*)+)\}'
)

# The extensions an ARMv7-A/R/M core can have, which is what this backend
# claims. `-march=armv7ve` turns on all of them at once, and that is what
# tools/xas-diff checks the instructions gated behind SEC, VIRT and DIV
# against. Everything else -- the ARMv8 additions, ARMv8-M's security
# extension, ARMv8.1-M's low-overhead loops and MVE, and ARMv8.1-M PACBTI --
# is out of scope, and README says so.
FEATURES = {
    "ARM_EXT_V1", "ARM_EXT_V2", "ARM_EXT_V2S", "ARM_EXT_V3", "ARM_EXT_V3M",
    "ARM_EXT_V4", "ARM_EXT_V4T", "ARM_EXT_V5", "ARM_EXT_V5T", "ARM_EXT_V5E",
    "ARM_EXT_V5ExP", "ARM_EXT_V5J", "ARM_EXT_V6", "ARM_EXT_V6K",
    "ARM_EXT_V6T2", "ARM_EXT_V6Z", "ARM_EXT_V7", "ARM_EXT_DIV",
    "ARM_EXT_ADIV", "ARM_EXT_MP", "ARM_EXT_SEC", "ARM_EXT_VIRT",
    "ARM_EXT2_V6T2_V8M",
}

# Mnemonics a hand-written encoder owns, because the bytes depend on more
# than the operands do: which width a Thumb instruction takes, where a
# literal pool went, what a branch is relocated as, or an addressing mode
# shared with the literal load.
HAND = set("""
    and eor sub rsb add adc sbc rsc tst teq cmp cmn orr mov bic mvn orn neg
    lsl lsr asr ror rrx addw subw movw movt mul mla mls
    umull umlal smull smlal
    ldr str ldrb strb ldrh strh ldrsb ldrsh ldrd strd
    ldrt strt ldrbt strbt ldrht strht ldrsbt ldrsht
    ldm ldmia ldmib ldmda ldmdb stm stmia stmib stmda stmdb
    ldmfd ldmfa ldmed ldmea stmfd stmfa stmed stmea push pop
    b bl bx blx cbz cbnz adr it
    msr mrs pld pldw pli
""".split())
# ...and the flag-setting spellings of the same, which the mnemonic patterns
# expand to.
HAND |= {n + "s" for n in HAND}
# `tstp` and its relatives set the flags into the PSR on an ARMv2; GNU as has
# no syntax for them and only the disassembler prints them.
DIS = {"tstp", "teqp", "cmpp", "cmnp"}

# Rows the disassembler has that spell no instruction GNU as assembles: the
# second copy of the unallocated hint space, the `mov rd, rd` a pre-ARMv6T2
# core used as a no-op, and the one-register `push`/`pop` printed for a
# plain store.
DIS_ROWS = [
    ("arm", 0x0320F000, 0x0FFFFF00),  # nop {imm}, twice over
    ("t16", 0x0000BF00, 0x0000FF0F),  # nop {imm}, which Thumb has no syntax for
    ("t32", 0xF3AF8000, 0xFFFFFF00),  # nop.w {imm}, likewise
    ("arm", 0xE1A00000, 0xFFFFFFFF),  # mov r0, r0
    ("t16", 0x000046C0, 0x0000FFFF),  # mov r8, r8
    ("arm", 0x052D0004, 0x0FFF0FFF),  # push {rt} as a store
    ("arm", 0x049D0004, 0x0FFF0FFF),  # pop {rt} as a load
]

# Where a row and the instruction GNU as assembles part company, and what
# this writes instead. The disassembler need not print an operand it can
# work out, and need not read a field it does not use.
OVERRIDE = {
    # `ldrexd`/`strexd` name both halves of the pair; only the first is
    # encoded, and GNU as takes the spelling that leaves the second out too.
    ("ldrexd", "Arm"): (("Reg", 12, 4), ("Next",), ("Base", 16, 4)),
    ("strexd", "Arm"): (("Reg", 12, 4), ("Reg", 0, 4), ("Next",),
                        ("Base", 16, 4)),
    # `smc` takes a four-bit immediate, which the disassembler prints out of
    # a wider field.
    ("smc", "Arm"): (("Imm", ((0, 4),), 1, 0),),
    ("smc", "T32"): (("Imm", ((16, 4),), 1, 0),),
    # `nop`'s hint number has to be written in braces; the opcode fields of
    # `cdp` and `mcr`, which the disassembler prints the same way, do not.
    ("nop", "Arm"): (("Hint", ((0, 8),)),),
    # The A32 bitfield extracts print the width as a plain field; it is the
    # same `#lsb, #width` pair the Thumb rows spell with `%F`, and the width
    # has to fit above the bit position.
    ("sbfx", "Arm"): (("Reg", 12, 4), ("Reg", 0, 4), ("Lsb", ((7, 5),)),
                      ("Width", ((16, 5),))),
    ("ubfx", "Arm"): (("Reg", 12, 4), ("Reg", 0, 4), ("Lsb", ((7, 5),)),
                      ("Width", ((16, 5),))),
    # The halfword saturations take a four-bit position, which the T32 rows
    # print out of the five-bit field their word-sized siblings use.
    ("ssat16", "T32"): (("Reg", 8, 4), ("Imm", ((0, 4),), 1, 1), ("Reg", 16, 4)),
    ("usat16", "T32"): (("Reg", 8, 4), ("Imm", ((0, 4),), 1, 0), ("Reg", 16, 4)),
}
# `pkhtb`'s shift is `asr` alone, and its type bit -- 6 in A32, hw2's 5 in
# T32 -- is the one a shift of zero clears, which turns it into a `pkhbt`.
OVERRIDE[("pkhtb", "Arm")] = (
    ("Reg", 12, 4), ("Reg", 16, 4), ("Reg", 0, 4),
    ("SatShift", 7, 5, 64 + 6, 255, 0),
)
OVERRIDE[("pkhtb", "T32")] = (
    ("Reg", 8, 4), ("Reg", 16, 4), ("Reg", 0, 4),
    ("SatShift", 6, 2, 64 + 5, 12, 3),
)

# `do_strex` refuses a status register that is also one of the transfer
# registers or the base. The Thumb encoder makes that check for the byte,
# halfword and doubleword forms only; `do_t_strex` has no such constraint.
STREX = {
    "strex": ("Arm",),
    "strexb": ("Arm", "T32"),
    "strexh": ("Arm", "T32"),
    "strexd": ("Arm", "T32"),
}

# `do_t_ldrexd` moves into two registers, which have to differ.
OVERRIDE[("ldrexd", "T32")] = (
    ("Reg", 12, 4), ("Reg", 8, 4), ("Distinct",), ("Base", 16, 4),
)

# `mrrc` moves into two registers, which `do_mrrc` requires to differ.
for _m in ("mrrc", "mrrc2"):
    OVERRIDE[(_m, "*")] = (
        ("Coproc", 8), ("Imm", ((4, 4),), 1, 0), ("Reg", 12, 4),
        ("Reg", 16, 4), ("Distinct",), ("CReg", 0),
    )

# `srs` writes its base register as `sp`, or leaves it out.
for _srs in ("srsia", "srsib", "srsda", "srsdb"):
    OVERRIDE[(_srs, "*")] = (("SpBase", 16, 21), ("Imm", ((0, 5),), 1, 0))

# Bits a row leaves out because the disassembler works them out for itself.
# `cps` is printed from a row whose mask leaves the M bit free, since the
# forms with and without a mode share it; GNU as sets it, this row being the
# one that takes a mode.
WORD_FIX = {("cps", "Arm"): 1 << 17}

# The T32 forms of the one-register operations hold `Rm` twice, and the
# disassembler reads only the copy at bits 16-19.
for _dup in ("rev", "rev16", "revsh", "rbit", "clz"):
    OVERRIDE[(_dup, "T32")] = (("Reg", 8, 4), ("RegTwice", 16, 0))

# Forms GNU as assembles that no row of the disassembler's table describes,
# because it prints them as another instruction. `do_pkhtb` turns a `pkhtb`
# with no shift into `pkhbt rd, rm, rn`, in both instruction sets.
EXTRA = [
    ("pkhtb", "Arm", 0x06800010, True,
     (("Reg", 12, 4), ("Reg", 0, 4), ("Reg", 16, 4))),
    ("pkhtb", "T32", 0xEAC00000, True,
     (("Reg", 8, 4), ("Reg", 0, 4), ("Reg", 16, 4))),
    # `sdiv rd, rm` divides the destination, which GNU as writes as the
    # optional middle operand of `(RR, oRR, RR)`.
    ("sdiv", "Arm", 0x0710F010, True, (("RegTwice", 16, 0), ("Reg", 8, 4))),
    ("udiv", "Arm", 0x0730F010, True, (("RegTwice", 16, 0), ("Reg", 8, 4))),
    ("sdiv", "T32", 0xFB90F0F0, True, (("RegTwice", 8, 16), ("Reg", 0, 4))),
    ("udiv", "T32", 0xFBB0F0F0, True, (("RegTwice", 8, 16), ("Reg", 0, 4))),
]

# Where an encoder checks a register GNU as's operand kind leaves open:
# `do_div` refuses the PC in all three of its registers, which `RR` does not
# say. The value is the least restrictive class the form's registers take.
CLASS_FIX = {("sdiv", "Arm"): 1, ("udiv", "Arm"): 1}

# ============================================================================
# Taking a format string apart
# ============================================================================

# `%<lo>-<hi><code>` or `%<bit><code>`, the two spellings of a bitfield.
FIELD = re.compile(r"%(\d+)(?:-(\d+))?(.)")


class Unsupported(Exception):
    pass


def read_entries(src):
    """Every row of the four tables, in order."""
    lines = open(src).read().split("\n")
    out = []
    for head, which in TABLES:
        i = next(n for n, l in enumerate(lines) if l.startswith(head))
        j = i
        while not lines[j].startswith("};"):
            j += 1
        body = re.sub(r"/\*.*?\*/", "", "\n".join(lines[i + 1:j]), flags=re.S)
        for m in ENTRY.finditer(body):
            fmt = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(4)))
            out.append(
                {
                    "val": int(m.group(2), 0),
                    "mask": int(m.group(3), 0),
                    "fmt": fmt,
                    "set": which,
                    "feats": set(re.findall(r"ARM_EXT\w*", m.group(1))),
                }
            )
    return out


def split_fmt(fmt):
    """The mnemonic half of a format string and the operand half, with the
    disassembler's trailing `@ ...` commentary dropped."""
    parts = fmt.split("\\t")
    ops = parts[1] if len(parts) > 1 else ""
    return parts[0], ops.split("@")[0].strip()


def expand_mnemonic(mnem, val):
    """Every concrete spelling a mnemonic pattern stands for, as
    (name, opcode word, takes a condition).

    `%<bit>'c` prints `c` when the bit is one, `%<bit>`c` when it is zero and
    `%<field>?abc` selects a letter by the field's value, so each of those is
    two or more instructions sharing one row. A `.w` or `.n` in the name is
    the width the disassembler prints, which the encoder decides for itself."""
    out = [("", val, False)]
    i = 0
    while i < len(mnem):
        if mnem[i] != "%":
            out = [(n + mnem[i], v, c) for n, v, c in out]
            i += 1
            continue
        if mnem[i:i + 2] == "%c":
            out = [(n, v, True) for n, v, c in out]
            i += 2
            continue
        # The letters the disassembler works out from the whole instruction
        # rather than from one field. Each stands for a set of spellings, all
        # of them instructions a hand-written encoder owns.
        if mnem[i + 1] in "CptwI":
            code, i = mnem[i + 1], i + 2
            tails = {
                # `%C` prints the condition, or `s` outside an `it` block.
                "C": ["", "s"],
                # `%p` prints `p` on the ARMv2 forms that set the PSR.
                "p": ["", "p"],
                # `%t` prints `t` on a post-indexed user-mode transfer.
                "t": ["", "t"],
                # `%w` prints a core load or store's width and signedness;
                # only a load can be signed.
                "w": ["", "b", "h", "sb", "sh"],
                # `%I` prints an `it` block's mask and condition.
                "I": [""],
            }[code]
            out = [
                (n + t, v, c or code == "C")
                for n, v, c in out
                for t in tails
                if code != "w" or n.endswith("ldr") or t in ("", "b", "h")
            ]
            continue
        m = FIELD.match(mnem, i)
        if not m:
            raise Unsupported("mnemonic %r" % mnem)
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        lo, hi = min(lo, hi), max(lo, hi)
        bits = hi - lo + 1
        code = m.group(3)
        i = m.end()
        if code in "'`":
            ch, i = mnem[i], i + 1
            ones = ((1 << bits) - 1) << lo
            on, off = (ones, 0) if code == "'" else (0, ones)
            out = [(n + ch, v | on, c) for n, v, c in out] + [
                (n, v | off, c) for n, v, c in out
            ]
        elif code == "?":
            letters = mnem[i:i + (1 << bits)]
            i += 1 << bits
            nxt = []
            for value in range(1 << bits):
                # print_insn_arm indexes c[(1 << width) - value], counting
                # back from the end of the letters.
                ch = letters[(1 << bits) - value - 1]
                nxt += [(n + ch, v | (value << lo), c) for n, v, c in out]
            out = nxt
        elif code == "c":
            # A condition in a field of its own, which the mnemonic carries
            # as a suffix either way.
            out = [(n, v, True) for n, v, _ in out]
        else:
            raise Unsupported("mnemonic %r" % mnem)
    return [(n.replace(".w", "").replace(".n", "").strip(), v, c) for n, v, c in out]


def field(lo, hi):
    return ((lo, hi - lo + 1),)


# The lsb and width fields of `bfc`/`bfi` (%E) and `sbfx`/`ubfx` (%F). A32
# keeps each whole; T32 splits the lsb over hw2[14:12] and hw2[7:6].
LSB = {"arm": ((7, 5),), "t32": ((6, 2), (12, 3))}
MSB = {"arm": ((16, 5),), "t32": ((0, 5),)}


def parse_ops(text, which, val=0, mask=0):
    """The operand half of a format string, as a list of `Op` constructors."""
    ops = []
    i, n = 0, len(text)

    def bitfield():
        nonlocal i
        m = FIELD.match(text, i)
        if not m:
            raise Unsupported("field at %r" % text[i:])
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        i = m.end()
        return min(lo, hi), max(lo, hi), m.group(3)

    def skip_unique():
        nonlocal i
        # `u` and `U` only say that two register fields must differ, which
        # the disassembler warns about and an assembler need not.
        while i < n and text[i] in "uU":
            i += 1

    while i < n:
        if text[i] in ", ":
            i += 1
            continue
        if text[i] == "[":
            i = parse_mem(text, i, ops, which)
            continue
        if text.startswith("%{", i):
            i = parse_braced(text, i, ops, which)
            continue
        if text[i] == "{":
            # `{imm}`: the coprocessor opcode of `cdp` and `mcr`, and the
            # hint number of `nop`, both of which may be left out.
            m = re.compile(r"\{%\{I:%(\d+)-(\d+)d%\}\}").match(text, i)
            if not m:
                raise Unsupported("braces %r" % text[i:])
            i = m.end()
            ops.append(("OptImm", field(int(m.group(1)), int(m.group(2)))))
            continue
        if text.startswith("ROR ", i):
            # One `uxtab16` row spells the rotation in plain capitals where
            # its siblings use the styling wrapper.
            ops.append(("Shift", "ror"))
            i += 4
            continue
        if text[i] != "%":
            raise Unsupported("literal %r in %r" % (text[i], text))
        if text[i + 1].isdigit():
            lo, hi, code = bitfield()
            skip_unique()
            if code in "rRS":
                ops.append(("Reg", lo, hi - lo + 1))
            elif code == "T":
                ops.append(("Next",))
            elif code in "dx":
                ops.append(("Imm", field(lo, hi), 1, 0))
            elif code == "'":
                ch, i = text[i], i + 1
                if ch != "!":
                    raise Unsupported("flag %r" % ch)
                ops.append(("Writeback", lo))
            else:
                raise Unsupported("field code %r" % code)
            continue
        code = text[i + 1]
        i += 2
        if code == "e":
            # `smc`, `hvc` and A32 `udf`: bits 8-19 above bits 0-3.
            ops.append(("Imm", ((0, 4), (8, 12)), 1, 0))
        elif code == "V":
            ops.append(("Imm", ((0, 12), (16, 4)), 1, 0))
        elif code == "H":
            # T32 `udf.w`: the four bits of hw1 above the twelve of hw2,
            # which is where `%V` puts them too.
            ops.append(("Imm", ((0, 12), (16, 4)), 1, 0))
        elif code == "K":
            # T32 `smc`: hw2[3:0], hw1[3:0], hw2[11:4].
            ops.append(("Imm", ((4, 8), (16, 4), (0, 4)), 1, 0))
        elif code == "E":
            ops.append(("Lsb", LSB[which]))
            ops.append(("Msb", MSB[which]))
        elif code == "F":
            ops.append(("Lsb", LSB[which]))
            ops.append(("Width", MSB[which]))
        elif code == "U":
            ops.append(("Barrier",))
        elif code == "R" and which == "t32":
            ops.append(("Rotate", 4))
        elif code == "s" and which == "t32":
            ops.append(("SatShift", 6, 2, 21, 12, 3))
        elif code == "S" and which == "t32":
            # A shifted register. Where the row's mask fixes the two type
            # bits, as it does for `pkhbt` and `pkhtb`, only that one shift
            # is allowed and the amount is all that is written.
            if mask & 0x30 == 0x30:
                ops.append(("Reg", 0, 4))
                # The type bit is hw2's bit 5, which a zero shift clears.
                ops.append(("SatShift", 6, 2, 64 + 5 if val & 0x20 else 255, 12, 3))
            else:
                ops.append(("Shifted",))
        elif code == "A":
            ops.append(("CoprocMem",))
        elif code in "xX":
            pass  # a disassembler warning, not an operand
        else:
            raise Unsupported("code %%%s" % code)
    return ops


def parse_mem(text, i, ops, which):
    """A bracketed address the table can hold whole: `[rn]`, `[rn, rm]`,
    `[rn, rm, lsl #1]` and `[rn, #imm]`."""
    end = text.index("]", i)
    body = text[i + 1:end]
    i = end + 1
    parts = [p.strip() for p in body.split(",")]
    m = FIELD.fullmatch(re.sub(r"[uU]+$", "", parts[0]))
    if not m or m.group(3) not in "rRS":
        raise Unsupported("base %r" % parts[0])
    base = int(m.group(1))
    if len(parts) == 1:
        ops.append(("Base", base, 4))
        return i
    m = FIELD.fullmatch(parts[1])
    if m and m.group(3) in "rRS":
        shift = 0
        if len(parts) == 3:
            if parts[2] != "%{B:lsl%} %{I:#1%}":
                raise Unsupported("index shift %r" % parts[2])
            shift = 1
        ops.append(("IdxMem", base, int(m.group(1)), shift))
        return i
    if len(parts) != 2:
        raise Unsupported("address %r" % body)
    kind, lo, hi, scale, bias = braced_imm(parts[1], which)
    if kind != "Imm":
        raise Unsupported("address %r" % body)
    ops.append(("OffMem", base, field(lo, hi), scale))
    return i


def braced_imm(body, which):
    """`%{I:#%<lo>-<hi><code>%}`, as (kind, lo, hi, scale, bias)."""
    m = re.fullmatch(r"%\{I:#(.*)%\}", body)
    if not m:
        raise Unsupported("immediate %r" % body)
    f = FIELD.fullmatch(m.group(1))
    if not f:
        return ("Fixed", int(m.group(1)), 0, 0, 0)
    lo = int(f.group(1))
    hi = int(f.group(2)) if f.group(2) else lo
    lo, hi = min(lo, hi), max(lo, hi)
    scale, bias = 1, 0
    code = f.group(3)
    if code == "W":
        # A32 prints the field plus one; Thumb prints it times four.
        bias, scale = (1, 1) if which in ("arm", "cop") else (0, 4)
    elif code == "D":
        bias = 1
    elif code == "H":
        scale = 2
    elif code not in "dxX":
        raise Unsupported("immediate code %r" % code)
    return ("Imm", lo, hi, scale, bias)


def parse_braced(text, i, ops, which):
    """`%{I:...%}`, `%{R:...%}` and `%{B:...%}`, the disassembler's styling
    wrappers, which hold an immediate, a register name or a keyword."""
    kind = text[i + 2]
    end = text.index("%}", i)
    body, i = text[i + 4:end], end + 2
    if kind == "I":
        if body == "#%e":
            ops.append(("Imm", ((0, 4), (8, 12)), 1, 0))
            return i
        m = re.fullmatch(r"0x(%\d+-\d+X){4}", body)
        if m:
            # `bkpt` and `hlt`, whose immediate is printed a nibble at a time.
            ops.append(("Imm", ((0, 4), (8, 12)), 1, 0))
            return i
        f = FIELD.fullmatch(body)
        if f and f.group(3) == "d" and not body.startswith("#"):
            # A number printed with no `#`. At bits 8-11 it is the
            # coprocessor, written `p15`; the rest are the opcode fields of
            # `cdp`, `mcr` and their relatives, written as plain numbers.
            lo = int(f.group(1))
            hi = int(f.group(2)) if f.group(2) else lo
            if lo == 8:
                ops.append(("Coproc", lo))
            else:
                ops.append(("Imm", field(lo, hi), 1, 0))
            return i
        kind, lo, hi, scale, bias = braced_imm("%{I:" + body + "%}", which)
        if kind == "Fixed":
            ops.append(("Fixed", lo))
        else:
            ops.append(("Imm", field(lo, hi), scale, bias))
        return i
    if kind == "R":
        m = re.fullmatch(r"cr%(\d+)-(\d+)d", body)
        if m:
            ops.append(("CReg", int(m.group(1))))
            return i
        if body == "APSR_nzcv":
            ops.append(("ApsrNzcv",))
            return i
        m = re.fullmatch(r"r%(\d+)-(\d+)d", body)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            ops.append(("Reg", lo, hi - lo + 1))
            return i
        raise Unsupported("register %r" % body)
    if kind == "B":
        if body in ("lsl", "asr", "ror"):
            ops.append(("Shift", body))
            return i
        m = re.fullmatch(r"%(\d+)'a%(\d+)'i%(\d+)'f", body)
        if m:
            ops.append(("IntFlags", int(m.group(3))))
            return i
        m = re.fullmatch(r"%(\d+)\?ble", body)
        if m:
            ops.append(("Endian", int(m.group(1))))
            return i
        raise Unsupported("keyword %r" % body)
    raise Unsupported("%%{%s:" % kind)


# ============================================================================
# Reading gas's own table, for the registers each operand may hold
# ============================================================================

# `gas/config/tc-arm.c`'s `insns[]` names each operand's kind, which is where
# the register restrictions live: `RRnpc` is any register but the PC, and
# `RRnpcsp` -- gas's `BadReg` -- neither the PC nor the stack pointer. The
# disassembler's table cannot say this, since an UNPREDICTABLE encoding still
# has to print.
GAS_CLASS = {
    "RR": 0, "APSR_RR": 0,
    "RRnpc": 1, "RRnpcb": 1, "RRw": 1, "RRnpctw": 1, "RRe": 1,
    "RRnpc_npcsp": 1, "RRnpc_I0": 1,
    "RRnpcsp": 2, "RRo": 2, "RRnpcsp_I32": 2,
}
# In Thumb, `do_t_*` puts nearly every register operand through
# `reject_bad_reg`, which refuses the stack pointer as well as the PC, whatever
# the table's own kind says. `rfe`'s base is the exception the table records
# itself, and `RRw` keeps its meaning.
THUMB_BAD = {"RR", "RRnpc", "RRnpcb", "RRnpcsp", "RRnpc_npcsp", "RRnpc_I0"}


def read_insns(src):
    """Mnemonic -> the operand kinds of its first row in `insns[]`."""
    text = open(src).read()
    start = text.index("static const struct asm_opcode insns[] =")
    end = text.index("\n};", start)
    body = re.sub(r"/\*.*?\*/", "", text[start:end], flags=re.S)
    out = {}
    row = re.compile(
        r"^[ \t]*\w+\s*\(\s*\"?([\w.]+)\"?\s*,(?:[^()\n]|\n)*?"
        r",\s*\d+\s*,\s*\(([^()]*)\)", re.M)
    for m in row.finditer(body):
        name = m.group(1)
        kinds = [k.strip() for k in m.group(2).split(",") if k.strip()]
        out.setdefault(name, kinds)
    return out


def reg_classes(name, ops, thumb, insns):
    """One class per operand the form reads, in the order they are written."""
    kinds = insns.get(name)
    if kinds is None:
        return None
    reading = [o for o in ops
               if o[0] not in ("Writeback", "Distinct", "FirstDistinct")]
    # An operand GNU as marks optional may simply not be in the form: the
    # 16-bit Thumb extends have no rotation to write, and `sdiv rd, rm`
    # leaves out the middle register.
    while len(kinds) > len(reading) and any(k.startswith("o") for k in kinds):
        drop = max(i for i, k in enumerate(kinds) if k.startswith("o"))
        kinds = kinds[:drop] + kinds[drop + 1:]
    if len(kinds) != len(reading):
        return None
    out = []
    least = CLASS_FIX.get((name, "T32" if thumb else "Arm"), 0)
    for op, kind in zip(reading, kinds):
        bare = kind[1:] if kind.startswith("o") and len(kind) > 1 else kind
        if op[0] in ("Base", "OffMem"):
            out.append(1 if thumb else GAS_CLASS.get(bare, 255))
        elif op[0] in ("Reg", "RegTwice", "Next"):
            if thumb and bare in THUMB_BAD:
                out.append(2)
            else:
                out.append(max(least, GAS_CLASS.get(bare, 255)) if
                           GAS_CLASS.get(bare, 255) != 255 else 255)
        else:
            out.append(255)
    return out if any(c != 255 for c in out) else None


# ============================================================================
# Merging the rows that spell one instruction
# ============================================================================


def merge(forms):
    """Several rows of the disassembler's table are one instruction as an
    assembler sees it, because a fixed field it prints is an operand that
    may be left out: the rotation of `sxtab`, the shift of `ssat` and
    `pkhbt`, the offset of a Thumb `ldrex`. Each group is folded into the
    row that has no such operand, with the operand added back."""
    out, by_key = [], {}
    for f in forms:
        trail = trailing_shift(f["ops"])
        key = (f["name"], f["set"], tuple(f["ops"][:len(f["ops"]) - len(trail)]))
        by_key.setdefault(key, []).append((f, trail))
    for key, group in by_key.items():
        base = group[0][0]
        trails = [t for _, t in group]
        if all(not t for t in trails):
            for f, _ in group:
                out.append(f)
            continue
        vals = [f["word"] for f, _ in group]
        common = 0
        for v in vals:
            common |= v ^ vals[0]
        lo = (common & -common).bit_length() - 1
        bits = common.bit_length() - lo
        kinds = {t[0][1] for t in trails if t}
        word = min(vals)
        ops = list(base["ops"][:len(base["ops"]) - len(trails[0])]) if trails[0] else list(base["ops"])
        # `sxtab r0, r1, r2, ror #8` and its three siblings: one instruction
        # with an optional rotation.
        if kinds == {"ror"}:
            ops.append(("Rotate", lo))
        elif kinds <= {"lsl", "asr"}:
            # `ssat`, `usat` and `pkhbt`: an optional shift whose kind is one
            # bit and whose amount is a field. A group that allows only `asr`
            # cannot say which bit means it, and `pkhtb`, the one instruction
            # that has such a group, is written out in OVERRIDE instead.
            amt = [t[1] for t in trails if len(t) > 1 and t[1][0] == "Imm"]
            if not amt:
                raise Unsupported("shift group %r" % (key,))
            f = amt[0][1]
            if kinds == {"asr"}:
                raise Unsupported("`asr`-only shift group %r" % (key,))
            asr = lo if "asr" in kinds else 255
            ops.append(("SatShift", f[0][0], f[0][1], asr, 255, 0))
        else:
            raise Unsupported("shift group %r %r" % (key, kinds))
        out.append(dict(base, word=word, ops=tuple(ops)))
    return out


def trailing_shift(ops):
    """The `, lsl #n` / `, ror #8` tail of an operand list, if it has one."""
    for i, op in enumerate(ops):
        if op[0] == "Shift":
            return tuple(ops[i:])
    return ()


# ============================================================================
# Building the table
# ============================================================================

# Which instruction sets a row's table serves. The coprocessor instructions
# are one table for both, because a T32 coprocessor instruction is the A32
# word with the condition field left at `al`, halfword by halfword.
SETS = {
    "arm": ["Arm"], "t16": ["T16"], "t32": ["T32"], "cop": ["Arm", "T32"],
}

# Spellings GNU as takes as another instruction in the table: the stack
# orders of `rfe` and `srs`, which are `ia` and `db` under other names, and
# `swi`, the pre-UAL name of `svc`.
ALIASES = [
    ("rfe", "rfeia"), ("rfeea", "rfedb"), ("rfeed", "rfeib"),
    ("rfefa", "rfeda"), ("rfefd", "rfeia"),
    ("srs", "srsia"), ("srsea", "srsia"), ("srsed", "srsda"),
    ("srsfa", "srsib"), ("srsfd", "srsdb"),
    ("swi", "svc"),
]


def build(entries, insns):
    """The forms, and the audit trail: one line per row saying where it
    went."""
    forms, audit = [], []
    for e in entries:
        mnem, optext = split_fmt(e["fmt"])
        why = None
        if any((e["set"], e["val"], e["mask"]) == row for row in DIS_ROWS):
            why = "disassembly only"
        elif e["feats"] and not (e["feats"] & FEATURES):
            why = "out of scope: %s" % ",".join(sorted(e["feats"]))
        if why:
            audit.append("%-4s %08x %-24s -- %s" % (e["set"], e["val"], mnem, why))
            continue
        try:
            names = expand_mnemonic(mnem, e["val"])
        except Unsupported as exc:
            audit.append("%-4s %08x %-24s -- ?? %s" % (e["set"], e["val"], mnem, exc))
            continue
        mine = [n for n in names if n[0] not in HAND and n[0] not in DIS]
        if not mine:
            kind = "hand-written" if any(n in HAND for n, _, _ in names) else (
                "disassembly only")
            audit.append("%-4s %08x %-24s -- %s" % (e["set"], e["val"], mnem, kind))
            continue
        ops = tuple(parse_ops(optext, e["set"], e["val"], e["mask"]))
        for name, word, cond in mine:
            for which in SETS[e["set"]]:
                w, has_cond = word, cond
                # An A32 word with `1111` in the condition field is one of
                # the unconditional instructions, whatever `%c` says: the
                # disassembler prints the field, and GNU as refuses a
                # condition on it.
                if which == "Arm" and w >> 28 == 0xF:
                    has_cond = False
                if e["set"] == "cop" and which == "T32" and cond:
                    # Thumb has no condition field: a T32 coprocessor
                    # instruction is the A32 word with `al` left in it.
                    w, has_cond = word | 0xE000_0000, False
                w |= WORD_FIX.get((name, which), 0)
                use = OVERRIDE.get((name, which), OVERRIDE.get((name, "*"), ops))
                forms.append(
                    {"name": name, "set": which, "word": w,
                     "cond": has_cond, "ops": use}
                )
        audit.append("%-4s %08x %-24s -> %s"
                     % (e["set"], e["val"], mnem,
                        " ".join(n for n, _, _ in mine)))
    for form in forms:
        if form["set"] in STREX.get(form["name"], ()):
            form["ops"] = tuple(form["ops"]) + (("FirstDistinct",),)
    for name, which, word, cond, ops in EXTRA:
        forms.append({"name": name, "set": which, "word": word, "cond": cond,
                      "ops": ops})
    forms = merge(forms)
    seen, out = set(), []
    for f in forms:
        key = (f["name"], f["set"], f["word"], tuple(f["ops"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    order = {"T16": 0, "T32": 1, "Arm": 2}
    out.sort(key=lambda f: (f["name"], order[f["set"]], f["word"]))
    for form in out:
        form["regs"] = reg_classes(
            form["name"], form["ops"], form["set"] != "Arm", insns)
    return out, audit


# ============================================================================
# Writing the Rust
# ============================================================================

HEADER = '''//! The ARM instruction table, generated from GNU binutils 2.47.
//!
//! Do not edit: `tools/tables/arm.py table` writes this file from the
//! disassembler's own tables in `opcodes/arm-dis.c`. [`super::generic`]
//! encodes from it, and the script's doc comment says which instructions
//! are here and which a hand-written encoder owns.

/// Where a value's bits live in the instruction word, from the value's own
/// low bits up: `(lsb, width)` pieces. A 32-bit Thumb instruction is one
/// word with its first halfword on top, which is how `arm-dis.c` numbers
/// the bits too.
pub type Field = &'static [(u8, u8)];

/// Which instruction set a form belongs to, and how wide it is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Set {
    /// A32, four bytes, with a condition field.
    Arm,
    /// T32, two bytes.
    T16,
    /// T32, four bytes.
    T32,
}

/// One operand of a form, and where its value goes.
#[derive(Copy, Clone, Debug)]
pub enum Op {
    /// A core register: `bits` bits at `lsb`.
    Reg(u8, u8),
    /// A core register whose four bits the encoding holds twice.
    RegTwice(u8, u8),
    /// The second half of a register pair, which must be the register after
    /// the one before it and carries no bits of its own.
    Next,
    /// A base register written `[rn]`.
    Base(u8, u8),
    /// An immediate `#v`, holding `v / scale - bias`.
    Imm(Field, u8, u8),
    /// A trailing `, {imm}`, which may be left out: the coprocessor opcode
    /// of `cdp`, `mcr` and `mrc`, written with or without the braces.
    OptImm(Field),
    /// `nop`'s hint number, which may be left out and needs its braces.
    Hint(Field),
    /// The `#lsb` of a bitfield instruction.
    Lsb(Field),
    /// Its `#width`, held as the most significant bit it reaches.
    Msb(Field),
    /// Its `#width`, held one less.
    Width(Field),
    /// An optional `, ror #8`, `#16` or `#24`, two bits at `lsb`.
    Rotate(u8),
    /// An optional shift: `amount` bits at `lsb`, and which kinds it may
    /// be -- under 32, the bit that means `asr` rather than `lsl`; 255,
    /// `lsl` alone; 64 plus a bit, `asr` alone, that bit being the one a
    /// shift of zero clears, since a zero shift is always `lsl`. A second
    /// field holds an amount the first cannot.
    SatShift(u8, u8, u8, u8, u8),
    /// A coprocessor number, `p0` to `p15`.
    Coproc(u8),
    /// A coprocessor register, `c0` to `c15`.
    CReg(u8),
    /// A barrier option, `sy` where none is written.
    Barrier,
    /// `APSR_nzcv`, which `mrc` takes in place of a register.
    ApsrNzcv,
    /// The two registers before it must be different, which is what the
    /// disassembler's `u` marker means where GNU as makes it an error.
    Distinct,
    /// The first register the form reads must differ from every other one:
    /// `do_strex`'s rule that the status register is none of the others.
    FirstDistinct,
    /// `!` on the register before it, the bit at `lsb`.
    Writeback(u8),
    /// The `a`, `i` and `f` letters of `cpsie` and `cpsid`, the `f` bit at
    /// `lsb`.
    IntFlags(u8),
    /// `be` or `le`, the bit at `lsb`.
    Endian(u8),
    /// `[rn, rm]`, or `[rn, rm, lsl #1]` where the third field is 1: the
    /// table branches.
    IdxMem(u8, u8, u8),
    /// `[rn]` or `[rn, #imm]`, the base at the first position and the
    /// offset in the field, scaled.
    OffMem(u8, Field, u8),
    /// The addressing modes of `ldc` and `stc`.
    CoprocMem,
    /// `srs`'s base register, which may be left out and must be `sp`: the
    /// register goes at the first position and the `!` bit at the second.
    SpBase(u8, u8),
}

/// One way of writing one instruction.
pub struct Form {
    pub name: &'static str,
    pub set: Set,
    /// The opcode word, with every fixed bit already in place.
    pub word: u32,
    /// Whether the instruction may carry a condition. An A32 form that may
    /// not has its condition field in `word`.
    pub cond: bool,
    pub ops: &'static [Op],
    /// Which registers each operand may hold, in the order they are
    /// written: 0 any, 1 not the PC, 2 neither the PC nor the stack
    /// pointer, 255 not a register at all. Empty where GNU as's own table
    /// says nothing.
    pub regs: &'static [u8],
}

const fn f(
    name: &'static str,
    set: Set,
    word: u32,
    cond: bool,
    ops: &'static [Op],
    regs: &'static [u8],
) -> Form {
    Form { name, set, word, cond, ops, regs }
}

/// Mnemonics GNU as takes as another spelling of one in the table.
pub static SPELLINGS: &[(&str, &str)] = &[
'''


def rust_field(f):
    return "&[%s]" % ", ".join("(%d, %d)" % p for p in f)


def rust_op(op):
    k = op[0]
    if k == "Reg":
        return "Op::Reg(%d, %d)" % (op[1], op[2])
    if k == "RegTwice":
        return "Op::RegTwice(%d, %d)" % (op[1], op[2])
    if k == "Base":
        return "Op::Base(%d, %d)" % (op[1], op[2])
    if k == "Next":
        return "Op::Next"
    if k == "Imm":
        return "Op::Imm(%s, %d, %d)" % (rust_field(op[1]), op[2], op[3])
    if k == "OptImm":
        return "Op::OptImm(%s)" % rust_field(op[1])
    if k == "Hint":
        return "Op::Hint(%s)" % rust_field(op[1])
    if k in ("Lsb", "Msb", "Width"):
        return "Op::%s(%s)" % (k, rust_field(op[1]))
    if k == "Rotate":
        return "Op::Rotate(%d)" % op[1]
    if k == "SatShift":
        return "Op::SatShift(%d, %d, %d, %d, %d)" % op[1:]
    if k in ("Coproc", "CReg", "Writeback", "IntFlags", "Endian"):
        return "Op::%s(%d)" % (k, op[1])
    if k in ("Barrier", "ApsrNzcv", "CoprocMem", "Distinct", "FirstDistinct"):
        return "Op::%s" % k
    if k == "IdxMem":
        return "Op::IdxMem(%d, %d, %d)" % (op[1], op[2], op[3])
    if k == "SpBase":
        return "Op::SpBase(%d, %d)" % (op[1], op[2])
    if k == "OffMem":
        return "Op::OffMem(%d, %s, %d)" % (op[1], rust_field(op[2]), op[3])
    raise Unsupported("emit %r" % (op,))


def render(forms):
    out = [HEADER]
    for a, b in ALIASES:
        out.append('    ("%s", "%s"),\n' % (a, b))
    out.append("];\n\n")
    out.append("/// Every form, sorted by name.\n")
    out.append("pub static FORMS: &[Form] = &[\n")
    for form in forms:
        out.append(
            '    f("%s", Set::%s, %#010x, %s, &[%s], &[%s]),\n'
            % (form["name"], form["set"], form["word"],
               "true" if form["cond"] else "false",
               ", ".join(rust_op(o) for o in form["ops"]),
               ", ".join(str(c) for c in form["regs"] or ()))
        )
    out.append("];\n")
    text = "".join(out)
    try:
        text = subprocess.run(
            ["rustfmt", "--edition", "2024", "--emit", "stdout"],
            input=text, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit("rustfmt failed (%s)" % e)
    return text


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in ("table", "check", "audit"):
        sys.exit(__doc__)
    entries = read_entries(os.path.join(BINUTILS, "opcodes", "arm-dis.c"))
    forms, audit = build(entries, read_insns(TC_ARM))
    if cmd == "audit":
        for line in audit:
            print(line)
        print("%d forms" % len(forms), file=sys.stderr)
        return
    text = render(forms)
    stale = not os.path.exists(TABLE) or open(TABLE).read() != text
    if cmd == "check":
        if stale:
            print("out of date: %s" % os.path.relpath(TABLE, ROOT))
        sys.exit(1 if stale else 0)
    if stale:
        with open(TABLE, "w") as fh:
            fh.write(text)
    print("rewrote %d file(s)" % stale, file=sys.stderr)


if __name__ == "__main__":
    main()
