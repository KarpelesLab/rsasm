#!/usr/bin/env python3
"""Differential fuzzer for rsasm's NEC 78K0 backend.

Random whole programs are generated from a table of instruction forms written
from NEC's *78K/0 Series User's Manual: Instructions* -- not from rsasm's own
tables -- and assembled twice: by rsasm in its CA78K0 dialect, and by the
Macro Assembler AS, whose name for the family is `78070`. The two flat images
are compared byte for byte.

    AS        `asl -cpu 78070` writes a code file and `p2bin -q -l 0 -r 0-0x`
              turns it into an image that runs from address 0 to the last
              byte written, zero where nothing was.
    rsasm     `rsasm -a 78k0 -d renesas -f bin`, whose image runs from 0 too:
              `ORG` in the Renesas dialect moves the location counter within
              the section rather than placing it, so the gap it leaves is
              part of the image.

A program is comments, equates, `ORG`, `DB`/`DW`/`DS`, labels and instructions
covering every addressing mode the backend claims: the eight registers and
four pairs in both spellings (`A`/`R1`, `AX`/`RP0`, `[HL+B]`/`[RP3+R3]`),
immediates at the ends of their ranges, short direct and SFR addresses over
the whole of both windows, `!addr16`, `[DE]`, `[HL]`, `[HL+byte]`, `[HL+B]`,
`[HL+C]`, every bit term (`saddr.bit`, `sfr.bit`, `A.bit`, `PSW.bit`,
`[HL].bit`), `CALLF`, `CALLT`, the register-bank select and all three widths
of branch.

    tools/fuzz/nec78k0.py fuzz --count 3000
    tools/fuzz/nec78k0.py fuzz --count 500 --seed 7 --mutations 0.5
    tools/fuzz/nec78k0.py check prog.s      # one program, or a corpus file
    tools/fuzz/nec78k0.py corpus lines > tools/xas-diff/78k0.txt
    tools/fuzz/nec78k0.py corpus pairs > tools/xas-diff/78k0-pairs.txt

`corpus` prints every form with its operands at their boundaries, one
instruction per line, for tools/xas-diff.

`check` reads a file of programs in `tools/xas-diff`'s format (snippets
separated by `=== name`, or one program if there is no such line) and prints
what each assembler made of each. A finding prints both spellings of its whole
program, so saving one to a file and running `check` on it is the way to narrow
a finding down; the same `--seed` and `--count` generate the same cases.

Each case is classified:

    agree       the two images are the same, or both assemblers refused.
    rsasm       they differ. These are the findings; the exit status is 1 if
                there are any.
    align       AS warns "address is not properly aligned" and assembles
                anyway where rsasm refuses: a `MOVW` whose `saddrp` or `sfrp`
                address is odd. The manual makes the even address part of the
                operand (`saddrp`, U12326EJ4V0UM Table 4-1), so refusing it is
                right and AS's warning is the lenient reading.

The two spellings

Nearly every program reads the same to both assemblers, so one text is
generated and handed to both. Two operands cannot be reconciled, and for those
a case carries a spelling each and the bytes are compared:

  * `CALLF !addr11`. NEC's operand is the whole target address, 0800H to
    0FFFH; AS reads an 11-bit number and puts it straight in the opcode, so
    its operand is that address less 0800H. `CALLF !0800H` here is `callf !0`
    there, and both are `0C 00`.
  * `CALLT [addr5]`. NEC's operand is the call-table address, an even 40H to
    7EH; AS reads a 6-bit number, so its operand is that address less 40H.
    `CALLT [40H]` here is `callt [0]` there, and both are `C1`.

`PSW` and `SP` need no second spelling, only a prelude: AS has no name for
either, but the code table's own rows say `PSW` is the short direct address
FF1EH and `SP` is FF1CH, so the AS half is assembled after two `EQU`s and
`MOV A,PSW` reaches AS's short direct form with the same two bytes.

What this deliberately does not generate, since the two are known to part
company there and nothing is settled by generating it again:

  * `BR expr` with no sigil, the one size choice CA78K0 makes. AS decides it
    from `target - (PC - 2)` in -128..126 and then encodes a displacement
    from `PC + 2`, so its window is four bytes adrift of the reachable one at
    both ends; rsasm relaxes on the displacement it is going to write.
    `BR $expr` and `BR !expr`, which name the width, are generated.
  * `[HL+0]`, which AS folds into `[HL]` (one byte) where rsasm writes the
    displaced form (`AE 00`). The manual gives `[HL+byte]` its own row and no
    rule for eliding it.
  * a bare address outside short direct and SFR space, where AS falls back to
    absolute addressing and rsasm refuses: `ADD A,0FF30H` is `ADD A,!0FF30H`
    to AS, though `ADD` has no `sfr` form, and an address in FFD0H to FFDFH
    is absolute to AS for every mnemonic. Table 2-21 of the RA78K0 manual
    lists the windows each operand takes, and an address outside them is not
    that operand.
  * the first operand of `ADDW`, `SUBW` and `CMPW` as anything but `AX`. AS
    accepts any pair and encodes AX's opcode; the manual has only `AX,#word`.
  * `XCH saddr,A` and the other reversed spellings AS accepts by swapping its
    operands when the second is `A`. The code table lists `XCH A,saddr`.
  * a `D` or `T` decimal radix suffix, which AS has not got, and `$` for the
    location counter, which is a branch sigil here and the 78K0 target names
    `PC`.

Environment: RSASM (default target/debug/rsasm under the repository root) and
RSASM_ORACLES (default target/oracles), which must hold asl and p2bin in `bin`
from tools/oracles/build.sh.
"""

import argparse
import collections
import concurrent.futures
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RSASM = os.environ.get("RSASM", os.path.join(ROOT, "target", "debug", "rsasm"))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
BIN = os.path.join(ORACLES, "bin")

# AS has no register name for either, so the reference half of every program
# is assembled after these. Both are the code table's own aliases: `MOV A,PSW`
# is `F0 1E` and `MOV A,0FF1EH` is the short direct form with the same bytes.
PRELUDE = "PSW\tEQU\t0FF1EH\nSP\tEQU\t0FF1CH\n"

# --- the instruction set -----------------------------------------------------
#
# Operand kinds, named as U12326EJ4V0UM section 4.2.2 names its operand column:
#
#   A X B C AX CY PSW SP 1            themselves
#   [DE] [HL] [HL+B] [HL+C]           register indirect and indexed
#   r rA                              an 8-bit register, or one that is not A
#   rp rpB                            a register pair, or one that is not AX
#   #byte #word                       immediate data
#   saddr saddrp sfr sfrp             short direct and SFR addressing
#   !addr16 !addr11 [addr5]           absolute, CALLF and CALLT targets
#   $rel                              a relative branch target
#   [HL+byte]                         based addressing
#   saddr.bit sfr.bit A.bit           a bit term
#   PSW.bit [HL].bit
#   RBn                               a register bank
#
# `saddr` and `sfr` are separate kinds because the mnemonics differ in which
# they have: `MOV` has both, `ADD` only `saddr`. Generating an SFR address for
# an `ADD` would only find AS falling back to absolute addressing, which the
# module docstring lists as not generated.


def build_forms():
    f = []
    for m in ("NOP", "BRK", "RET", "RETB", "RETI", "EI", "DI", "HALT", "STOP",
              "ADJBA", "ADJBS"):
        f.append((m, ()))
    # 8-bit data transfer (page 39).
    f += [("MOV", ("r", "#byte")), ("MOV", ("saddr", "#byte")),
          ("MOV", ("sfr", "#byte")), ("MOV", ("A", "rA")), ("MOV", ("rA", "A")),
          ("MOV", ("A", "saddr")), ("MOV", ("saddr", "A")),
          ("MOV", ("A", "sfr")), ("MOV", ("sfr", "A")),
          ("MOV", ("A", "!addr16")), ("MOV", ("!addr16", "A")),
          ("MOV", ("PSW", "#byte")), ("MOV", ("A", "PSW")), ("MOV", ("PSW", "A")),
          ("MOV", ("A", "[DE]")), ("MOV", ("[DE]", "A")),
          ("MOV", ("A", "[HL]")), ("MOV", ("[HL]", "A")),
          ("MOV", ("A", "[HL+byte]")), ("MOV", ("[HL+byte]", "A")),
          ("MOV", ("A", "[HL+B]")), ("MOV", ("[HL+B]", "A")),
          ("MOV", ("A", "[HL+C]")), ("MOV", ("[HL+C]", "A"))]
    for src in ("rA", "saddr", "sfr", "!addr16", "[DE]", "[HL]", "[HL+byte]",
                "[HL+B]", "[HL+C]"):
        f.append(("XCH", ("A", src)))
    # 16-bit data transfer (page 40) and the stack forms (page 44).
    f += [("MOVW", ("rp", "#word")), ("MOVW", ("saddrp", "#word")),
          ("MOVW", ("sfrp", "#word")), ("MOVW", ("AX", "saddrp")),
          ("MOVW", ("saddrp", "AX")), ("MOVW", ("AX", "sfrp")),
          ("MOVW", ("sfrp", "AX")), ("MOVW", ("AX", "rpB")),
          ("MOVW", ("rpB", "AX")), ("MOVW", ("AX", "!addr16")),
          ("MOVW", ("!addr16", "AX")), ("XCHW", ("AX", "rpB")),
          ("MOVW", ("SP", "#word")), ("MOVW", ("SP", "AX")), ("MOVW", ("AX", "SP"))]
    # 8-bit operation (pages 40 to 42).
    for m in ("ADD", "ADDC", "SUB", "SUBC", "AND", "OR", "XOR", "CMP"):
        f += [(m, ("A", "#byte")), (m, ("saddr", "#byte")), (m, ("A", "rA")),
              (m, ("r", "A")), (m, ("A", "saddr")), (m, ("A", "!addr16")),
              (m, ("A", "[HL]")), (m, ("A", "[HL+byte]")),
              (m, ("A", "[HL+B]")), (m, ("A", "[HL+C]"))]
    # 16-bit operation, multiply/divide, increment/decrement, rotate (page 43).
    for m in ("ADDW", "SUBW", "CMPW"):
        f.append((m, ("AX", "#word")))
    f += [("MULU", ("X",)), ("DIVUW", ("C",))]
    f += [("INC", ("r",)), ("INC", ("saddr",)), ("DEC", ("r",)), ("DEC", ("saddr",))]
    f += [("INCW", ("rp",)), ("DECW", ("rp",))]
    for m in ("ROR", "ROL", "RORC", "ROLC"):
        f.append((m, ("A", "1")))
    f += [("ROR4", ("[HL]",)), ("ROL4", ("[HL]",))]
    # Bit manipulation (pages 43 and 44).
    BITS = ("saddr.bit", "sfr.bit", "A.bit", "PSW.bit", "[HL].bit")
    for b in BITS:
        f += [("MOV1", ("CY", b)), ("MOV1", (b, "CY"))]
    for m in ("AND1", "OR1", "XOR1"):
        for b in BITS:
            f.append((m, ("CY", b)))
    for m in ("SET1", "CLR1"):
        for b in BITS:
            f.append((m, (b,)))
        f.append((m, ("CY",)))
    f.append(("NOT1", ("CY",)))
    # Call and return, stack manipulation (page 44).
    f += [("CALL", ("!addr16",)), ("CALLF", ("!addr11",)), ("CALLT", ("[addr5]",))]
    f += [("PUSH", ("PSW",)), ("PUSH", ("rp",)), ("POP", ("PSW",)), ("POP", ("rp",))]
    # Branches and CPU control (page 45).
    f += [("BR", ("!addr16",)), ("BR", ("$rel",)), ("BR", ("AX",))]
    for m in ("BC", "BNC", "BZ", "BNZ"):
        f.append((m, ("$rel",)))
    for m in ("BT", "BF", "BTCLR"):
        for b in BITS:
            f.append((m, (b, "$rel")))
    f += [("DBNZ", ("B", "$rel")), ("DBNZ", ("C", "$rel")),
          ("DBNZ", ("saddr", "$rel"))]
    f.append(("SEL", ("RBn",)))
    return f


FORMS = build_forms()

# The two register-name spellings U12326EJ4V0UM page 38 gives: the function
# names and the absolute ones. Both assemblers read either.
REG8 = [("X", "R0"), ("A", "R1"), ("C", "R2"), ("B", "R3"),
        ("E", "R4"), ("D", "R5"), ("L", "R6"), ("H", "R7")]
REG16 = [("AX", "RP0"), ("BC", "RP1"), ("DE", "RP2"), ("HL", "RP3")]
# The indirect forms take either spelling of the pair and of the index
# register, so `[RP3+R3]` is `[HL+B]`.
INDIRECT = {
    "[DE]": ["[DE]", "[RP2]"],
    "[HL]": ["[HL]", "[RP3]"],
    "[HL+B]": ["[HL+B]", "[RP3+B]", "[HL+R3]", "[RP3+R3]"],
    "[HL+C]": ["[HL+C]", "[RP3+C]", "[HL+R2]", "[RP3+R2]"],
}

# Short direct addressing is FE20H to FF1FH, SFR addressing FF20H to FFCFH and
# FFE0H to FFFFH -- the part of the SFR window below FF20H is short direct to
# both assemblers, and FFD0H to FFDFH is neither. The ends of every window are
# drawn more often than the middle.
SADDR_EDGES = [0xFE20, 0xFE21, 0xFF1E, 0xFF1F, 0xFEA0, 0xFF00]
SFR_EDGES = [0xFF20, 0xFF21, 0xFFCE, 0xFFCF, 0xFFE0, 0xFFFF]

# Mutations: statements both assemblers have to refuse. Each is a pair, the
# rsasm spelling and AS's; they differ only where the docstring says they do.
BAD = [
    ("MOV A,#256", None), ("MOV A,#-129", None), ("MOVW AX,#10000H", None),
    ("MOV A,#8000H", None), ("MOVW AX,#-32769", None),
    ("INC 0FE1FH", None), ("DEC 0FF20H", None), ("MOV 0FE1FH,#1", None),
    ("ADD AX,#1", None), ("DBNZ 0FF20H,$0", None),
    ("MOV A,A", None), ("MOV R1,R1", None), ("XCH A,A", None),
    ("MOVW AX,AX", None), ("MOVW RP0,RP0", None), ("XCHW AX,AX", None),
    ("ROR A,2", None), ("ROL A,0", None), ("ROR4 [DE]", None),
    ("MULU A", None), ("DIVUW A", None), ("INC AX", None), ("INCW A", None),
    ("SET1 0FE20H.8", None), ("CLR1 A.9", None), ("MOV1 CY,[DE].0", None),
    ("SEL RB4", None), ("DBNZ A,$0", None), ("PUSH A", None),
    ("CALLF !1000H", "CALLF !800H"), ("CALLF !7FFH", "CALLF !-1"),
    ("CALLT [7FH]", "CALLT [3FH]"), ("CALLT [80H]", "CALLT [40H]"),
    ("CALLT [3EH]", "CALLT [-2]"),
    ("MOV A,!NOWHERE", None), ("CALL !NOWHERE", None), ("FROB A", None),
]

# Odd 16-bit short direct and SFR addresses, which rsasm refuses and AS only
# warns about: the `align` class. Drawn rarely, so that the class is exercised
# without swamping the run.
ODD = ["MOVW AX,0FE21H", "MOVW 0FF1DH,AX", "MOVW AX,0FF21H", "MOVW 0FFE1H,#1"]


# --- operands ----------------------------------------------------------------
#
# An operand is a small tree rendered per spelling: ("num", v), ("sym", name),
# ("reg", text), ("imm", inner), ("abs", inner), ("rel", inner),
# ("ind", inner), ("hl+", inner), ("bit", base, inner), and the two that
# differ, ("callf", addr) and ("callt", addr).


def hexnum(v):
    s = "%XH" % v
    return "0" + s if s[0] in "ABCDEF" else s


def render_radix(a, rng):
    r = rng.random()
    if r < 0.6:
        return hexnum(a)
    if r < 0.85:
        return "%d" % a
    if r < 0.93:
        return "%sB" % bin(a)[2:]
    return "%o%s" % (a, rng.choice("QO"))


def render_num(v, rng):
    neg = v < 0
    a = -v if neg else v
    # Now and then the value is written as a sum or a difference instead, so
    # that operands are parsed as expressions rather than single tokens. A bit
    # term is the reason it matters: both assemblers split the operand at its
    # `.` before either half is evaluated, so `0FE1FH+1.3` is FE20H bit 3 to
    # both, whatever precedence would otherwise say.
    if not neg and a >= 2 and rng.random() < 0.12:
        k = rng.randint(1, min(a, 16))
        if rng.random() < 0.5:
            return "%s+%s" % (render_radix(a - k, rng), render_radix(k, rng))
        return "%s-%s" % (render_radix(a + k, rng), render_radix(k, rng))
    text = render_radix(a, rng)
    return "-" + text if neg else text


def render(op, spelling, rng):
    kind = op[0]
    if kind == "reg":
        # Register names are case-insensitive to both assemblers; symbols are
        # not, so only these are folded.
        return op[1].lower() if rng.random() < 0.25 else op[1]
    if kind == "num":
        return render_num(op[1], rng)
    if kind == "sym":
        return op[1]
    if kind == "imm":
        return "#" + render(op[1], spelling, rng)
    if kind == "abs":
        return "!" + render(op[1], spelling, rng)
    if kind == "rel":
        return "$" + render(op[1], spelling, rng)
    if kind == "ind":
        return "[%s]" % render(op[1], spelling, rng)
    if kind == "hl+":
        return "[%s+%s]" % (rng.choice(("HL", "hl", "RP3")), render(op[1], spelling, rng))
    if kind == "bit":
        return "%s.%s" % (render(op[1], spelling, rng), render(op[2], spelling, rng))
    if kind == "callf":
        # AS's operand is the address less the 0800H the opcode implies.
        return "!" + render_num(op[1] - (0 if spelling == "rs" else 0x800), rng)
    if kind == "callt":
        # AS's operand is the call-table address less the 40H it starts at.
        return "[%s]" % render_num(op[1] - (0 if spelling == "rs" else 0x40), rng)
    raise ValueError(op)


class Gen:
    """Draws operands. `equates` maps a symbol to its value, `labels` is the
    list of labels the program will define."""

    def __init__(self, rng, equates, labels):
        self.rng = rng
        self.equates = equates
        self.labels = labels

    def named(self, prefix, value):
        """A symbol for `value`, defining one if the program has not got it."""
        for n, v in self.equates.items():
            if v == value and n.startswith(prefix):
                return n
        n = "%s%d" % (prefix, len(self.equates))
        self.equates[n] = value
        return n

    def address_value(self, lo, hi, edges, even):
        rng = self.rng
        v = rng.choice(edges) if rng.random() < 0.45 else rng.randint(lo, hi)
        if even:
            v &= ~1
            if v < lo:
                v = lo + (lo & 1)
        return v

    def as_operand(self, prefix, v):
        if self.rng.random() < 0.3:
            return ("sym", self.named(prefix, v))
        return ("num", v)

    def saddr(self, even=False):
        return self.as_operand(
            "SDR", self.address_value(0xFE20, 0xFF1F, SADDR_EDGES, even))

    def sfr(self, even=False):
        v = self.address_value(0xFF20, 0xFFFF, SFR_EDGES, even)
        # FFD0H to FFDFH has no SFR address; redraw rather than leave a value
        # AS would turn into absolute addressing, which is not an `sfr`
        # operand at all.
        while 0xFFD0 <= v <= 0xFFDF:
            v = self.address_value(0xFF20, 0xFFFF, SFR_EDGES, even)
        return self.as_operand("SFR", v)

    def byte(self):
        rng = self.rng
        if rng.random() < 0.15:
            return ("num", -rng.randint(1, 128))
        if rng.random() < 0.4:
            return ("num", rng.choice([0, 1, 0x7F, 0x80, 0xFF]))
        return ("num", rng.randint(0, 0xFF))

    def word(self):
        rng = self.rng
        if rng.random() < 0.1:
            return ("num", -rng.randint(1, 0x8000))
        if rng.random() < 0.3:
            return ("num", rng.choice([0, 1, 0x7FFF, 0x8000, 0xFFFF]))
        if self.labels and rng.random() < 0.2:
            return ("sym", rng.choice(self.labels))
        return ("num", rng.randint(0, 0xFFFF))

    def addr16(self):
        rng = self.rng
        if self.labels and rng.random() < 0.5:
            return ("sym", rng.choice(self.labels))
        return ("num", rng.choice([0, 1, 0x100, 0x7FFF, 0x8000, 0xFFFF,
                                   rng.randint(0, 0xFFFF)]))

    def bitpos(self):
        n = self.rng.randint(0, 7)
        if self.rng.random() < 0.15:
            return ("sym", self.named("BIT", n))
        return ("num", n)

    def reg(self, names, skip=None):
        pair = self.rng.choice([p for p in names if skip is None or p[0] != skip])
        return ("reg", pair[self.rng.randrange(2)])

    def operand(self, kind):
        rng = self.rng
        if kind in INDIRECT:
            return ("reg", rng.choice(INDIRECT[kind]))
        if kind in ("A", "X", "B", "C", "AX", "CY", "PSW", "SP", "1"):
            return ("reg", kind)
        if kind == "r":
            return self.reg(REG8)
        if kind == "rA":
            return self.reg(REG8, skip="A")
        if kind == "rp":
            return self.reg(REG16)
        if kind == "rpB":
            return self.reg(REG16, skip="AX")
        if kind == "#byte":
            return ("imm", self.byte())
        if kind == "#word":
            return ("imm", self.word())
        if kind == "saddr":
            return self.saddr()
        if kind == "saddrp":
            return self.saddr(even=True)
        if kind == "sfr":
            return self.sfr()
        if kind == "sfrp":
            return self.sfr(even=True)
        if kind == "!addr16":
            return ("abs", self.addr16())
        if kind == "!addr11":
            # Every page of the CALLF area, and both ends.
            return ("callf", rng.choice([0x800, 0x801, 0xFFE, 0xFFF,
                                         rng.randrange(0x800, 0x1000)]))
        if kind == "[addr5]":
            return ("callt", rng.choice([0x40, 0x42, 0x7C, 0x7E,
                                         0x40 + 2 * rng.randrange(32)]))
        if kind == "$rel":
            return ("rel", ("sym", rng.choice(self.labels)))
        if kind == "[HL+byte]":
            # Never 0: AS folds `[HL+0]` into `[HL]`, which the manual does not.
            if rng.random() < 0.3:
                return ("hl+", ("num", rng.choice([1, 0x7F, 0x80, 0xFF])))
            return ("hl+", ("num", rng.randint(1, 0xFF)))
        if kind == "saddr.bit":
            return ("bit", self.saddr(), self.bitpos())
        if kind == "sfr.bit":
            return ("bit", self.sfr(), self.bitpos())
        if kind == "A.bit":
            return ("bit", ("reg", "A"), self.bitpos())
        if kind == "PSW.bit":
            return ("bit", ("reg", "PSW"), self.bitpos())
        if kind == "[HL].bit":
            return ("bit", ("reg", rng.choice(("[HL]", "[RP3]"))), self.bitpos())
        if kind == "RBn":
            return ("reg", "RB%d" % rng.randint(0, 3))
        raise ValueError(kind)


# --- programs ----------------------------------------------------------------


def generate(rng, mutate):
    """A program: a list of statements, each a tuple whose first item names it.

    `equates` is filled as operands are drawn, so the equates are written out
    once the body is complete -- ahead of the code, since a forward `saddr` or
    `sfr` reference is a different addressing mode to each assembler."""
    labels = ["LBL%d" % i for i in range(rng.randint(1, 6))]
    equates = {}
    gen = Gen(rng, equates, labels)
    body = []

    def instruction():
        m, kinds = rng.choice(FORMS)
        ops = [gen.operand(k) for k in kinds]
        if rng.random() < 0.3:
            m = m.lower()
        body.append(("insn", m, ops))

    # The image AS writes starts at the first byte emitted, so the program has
    # to open with something that emits one.
    instruction()
    for _ in range(rng.randint(2, 30)):
        r = rng.random()
        if r < 0.78:
            instruction()
        elif r < 0.86:
            body.append(("db", [rng.randint(0, 0xFF) for _ in range(rng.randint(1, 4))]))
        elif r < 0.9:
            body.append(("dw", [rng.randint(0, 0xFFFF) for _ in range(rng.randint(1, 3))]))
        elif r < 0.92:
            body.append(("ds", rng.randint(1, 8)))
        elif r < 0.94:
            # Enough to put a branch target on either side of the reach of a
            # one-byte displacement, which is where the two could part company.
            body.append(("ds", rng.randint(118, 134)))
        else:
            body.append(("comment",))
    instruction()
    # Labels go anywhere, so branches run in both directions.
    for lab in labels:
        body.insert(rng.randint(0, len(body)), ("label", lab))
    if mutate and rng.random() < 0.4:
        # Reserved space pushes a relative branch out of reach. It must not go
        # last: `DS` emits nothing, so AS's image would end at the byte before
        # it where rsasm's covers the whole span.
        body.insert(rng.randint(1, len(body) - 1),
                    ("ds", rng.choice([120, 127, 128, 130, 200])))
    head = [("org", rng.choice([0, 0, 0, 0x20, 0x100, 0x800, 0x1000]))]
    head += [("equ", n, v) for n, v in sorted(equates.items())]
    stmts = head + body
    if mutate:
        if rng.random() < 0.1:
            stmts.insert(rng.randint(1, len(stmts)), ("bad", (rng.choice(ODD), None)))
        else:
            stmts.insert(rng.randint(1, len(stmts)), ("bad", rng.choice(BAD)))
    return stmts


def render_program(stmts, spelling, rng):
    out = []
    for st in stmts:
        k = st[0]
        if k == "org":
            out.append("\tORG\t%s" % render_num(st[1], rng))
        elif k == "equ":
            out.append("%s\tEQU\t%s" % (st[1], render_num(st[2], rng)))
        elif k == "label":
            out.append("%s:" % st[1])
        elif k == "comment":
            out.append("; a comment")
        elif k == "db":
            out.append("\tDB\t%s" % ",".join(render_num(v, rng) for v in st[1]))
        elif k == "dw":
            out.append("\tDW\t%s" % ",".join(render_num(v, rng) for v in st[1]))
        elif k == "ds":
            out.append("\tDS\t%s" % render_num(st[1], rng))
        elif k == "bad":
            rs, asm = st[1]
            out.append("\t%s" % (rs if spelling == "rs" or asm is None else asm))
        else:
            sep = rng.choice((",", ",", ",", ", ", " , "))
            ops = sep.join(render(o, spelling, rng) for o in st[2])
            line = "\t%s%s" % (st[1], "\t" + ops if ops else "")
            out.append(line + ("\t; what it does" if rng.random() < 0.1 else ""))
    return "\n".join(out) + "\n"


# --- running the assemblers --------------------------------------------------


def run(cmd, cwd):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as exc:
        return 127, str(exc)
    return p.returncode, p.stdout + p.stderr


def image(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def first_error(log):
    for line in log.splitlines():
        if "rror" in line:
            return line.strip().lstrip("> ")[:160]
    return (log.strip().splitlines() or ["error"])[0][:160]


def asl(source, workdir):
    """AS then p2bin, the pair tools/xas-diff/run.sh uses for the 8-bit
    targets. Returns (status, image-or-message, warned-about-alignment)."""
    with open(os.path.join(workdir, "as.s"), "w") as fh:
        fh.write(PRELUDE + source)
    for f in ("as.p", "as.bin"):
        try:
            os.unlink(os.path.join(workdir, f))
        except OSError:
            pass
    code, log = run([os.path.join(BIN, "asl"), "-cpu", "78070", "-q",
                     "-o", "as.p", "as.s"], workdir)
    align = "not properly aligned" in log
    # `-q` keeps AS quiet, so anything with "error" in it is a refusal even
    # where the exit status is 0.
    if code != 0 or "error" in log.lower():
        return ("ERROR", first_error(log), align)
    # `-r 0-0x` runs the image from address 0 to the last byte written, which
    # is the span rsasm's `-f bin` writes; `-l 0` is the filler for the rest.
    code, log = run([os.path.join(BIN, "p2bin"), "-q", "-l", "0", "-r", "0-0x",
                     "as.p", "as.bin"], workdir)
    if code != 0:
        return ("ERROR", first_error(log), align)
    return ("OK", image(os.path.join(workdir, "as.bin")) or b"", align)


def rsasm(source, workdir):
    src = os.path.join(workdir, "rs.s")
    out = os.path.join(workdir, "rs.bin")
    with open(src, "w") as fh:
        fh.write(source)
    code, log = run([RSASM, "-a", "78k0", "-d", "renesas", "-f", "bin",
                     "-o", out, src], workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    return ("OK", image(out) or b"")


def same(a, b):
    if a[0] != b[0]:
        return False
    return a[0] == "ERROR" or a[1] == b[1]


def classify(ref, ours):
    if same(ref, ours):
        return "agree"
    # AS's alignment complaint is a warning, so it assembles a `MOVW` with an
    # odd short direct or SFR address that rsasm refuses outright. Both halves
    # have to say so, or a real difference in a program that happens to hold
    # an odd address would be filed here too.
    if ref[2] and ref[0] == "OK" and ours[0] == "ERROR" and "must be even" in ours[1]:
        return "align"
    return "rsasm"


def compare(rs_text, as_text=None):
    as_text = rs_text if as_text is None else as_text
    with tempfile.TemporaryDirectory() as d:
        ref = asl(as_text, d)
        ours = rsasm(rs_text, d)
    return {"class": classify(ref, ours), "rs_text": rs_text, "as_text": as_text,
            "as": ref, "rs": ours}


def one(job):
    seed, mutate = job
    rng = random.Random(seed)
    stmts = generate(rng, mutate)
    rs_text = render_program(stmts, "rs", rng)
    as_text = render_program(stmts, "as", rng)
    r = compare(rs_text, as_text)
    r["seed"] = seed
    return r


def fmt(res):
    if res[0] == "ERROR":
        return "ERROR " + res[1]
    return res[1].hex(" ")


def report(r, name=None):
    print("### %s%s" % (r["class"], " %s" % name if name else " seed %d" % r.get("seed", 0)))
    print("  --- rsasm spelling")
    print("\n".join("    |" + l for l in r["rs_text"].splitlines()))
    if r["as_text"] != r["rs_text"]:
        print("  --- AS spelling")
        print("\n".join("    |" + l for l in r["as_text"].splitlines()))
    print("  AS:    " + fmt(r["as"]))
    print("  rsasm: " + fmt(r["rs"]))


def fuzz(args):
    rng = random.Random(args.seed)
    jobs = [(rng.getrandbits(48), rng.random() < args.mutations)
            for _ in range(args.count)]
    counts = collections.Counter()
    findings = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        for r in ex.map(one, jobs, chunksize=4):
            counts[r["class"]] += 1
            if r["class"] == "rsasm":
                findings.append(r)
    print("cases: %d  %s"
          % (args.count, "  ".join("%s %d" % kv for kv in sorted(counts.items()))))
    findings.sort(key=lambda r: len(r["rs_text"]))
    for r in findings[: args.limit]:
        report(r)
    # The last line is the one tools/fuzz/run.sh reads.
    print("--- nec78k0: %d case(s) compared, %d finding(s)"
          % (sum(counts.values()), counts["rsasm"]))
    return 1 if counts["rsasm"] else 0


# --- check -------------------------------------------------------------------


def split_programs(text):
    """tools/xas-diff's programs format: snippets separated by `=== name`."""
    progs, name, buf = [], None, []
    for line in text.splitlines():
        if line.startswith("==="):
            if buf:
                progs.append((name, "\n".join(buf) + "\n"))
            name, buf = line[3:].strip(), []
        else:
            buf.append(line)
    if buf:
        progs.append((name, "\n".join(buf) + "\n"))
    return [(n or "program %d" % i, t) for i, (n, t) in enumerate(progs) if t.strip()]


def check(args):
    with open(args.file) as fh:
        text = fh.read()
    bad = 0
    total = 0
    for name, prog in split_programs(text):
        r = compare(prog)
        total += 1
        if r["class"] != "agree":
            bad += 1
            if bad <= args.limit:
                report(r, name)
        else:
            print("ok   %s" % name)
    print("--- nec78k0: %d case(s) compared, %d finding(s)" % (total, bad))
    return 1 if bad else 0


# --- the one-line corpora ----------------------------------------------------
#
# Every form with its operands at their boundaries, one instruction per line,
# for tools/xas-diff. A line stands alone at address 0, so a branch names an
# absolute target after `$` rather than a label.


def corpus_choices(kind):
    if kind in INDIRECT:
        return INDIRECT[kind]
    if kind in ("A", "X", "B", "C", "AX", "CY", "PSW", "SP", "1"):
        return [kind]
    if kind == "r":
        return [p[0] for p in REG8] + [REG8[0][1], REG8[7][1]]
    if kind == "rA":
        return [p[0] for p in REG8 if p[0] != "A"] + [REG8[0][1], REG8[7][1]]
    if kind == "rp":
        return [p[0] for p in REG16] + [REG16[0][1], REG16[3][1]]
    if kind == "rpB":
        return [p[0] for p in REG16 if p[0] != "AX"] + [REG16[1][1], REG16[3][1]]
    if kind == "#byte":
        return ["#0", "#1", "#7FH", "#80H", "#0FFH", "#-128"]
    if kind == "#word":
        return ["#0", "#1234H", "#0FFFFH", "#-32768"]
    if kind == "saddr":
        return ["0FE20H", "0FEA0H", "0FF00H", "0FF1FH"]
    if kind == "saddrp":
        return ["0FE20H", "0FEA0H", "0FF1EH"]
    if kind == "sfr":
        return ["0FF20H", "0FFCFH", "0FFE0H", "0FFFFH"]
    if kind == "sfrp":
        return ["0FF20H", "0FFCEH", "0FFE0H", "0FFFEH"]
    if kind == "!addr16":
        return ["!0", "!1234H", "!0FFFFH"]
    if kind == "$rel":
        # Measured from the end of the instruction, so +81H is the furthest
        # forward a two-byte branch reaches and 0 the furthest back.
        return ["$0", "$2", "$40H", "$81H"]
    if kind == "[HL+byte]":
        return ["[HL+1]", "[HL+7FH]", "[HL+80H]", "[HL+0FFH]", "[RP3+1]"]
    if kind == "saddr.bit":
        return ["0FE20H.%d" % b for b in range(8)] + ["0FF1FH.0"]
    if kind == "sfr.bit":
        return ["0FF20H.%d" % b for b in range(8)] + ["0FFFFH.7"]
    if kind == "A.bit":
        return ["A.%d" % b for b in range(8)]
    if kind == "PSW.bit":
        return ["PSW.%d" % b for b in range(8)]
    if kind == "[HL].bit":
        return ["[HL].%d" % b for b in range(8)] + ["[RP3].0"]
    if kind == "RBn":
        return ["RB%d" % n for n in range(4)]
    return None


def corpus_lines():
    """The forms both assemblers spell alike."""
    out = ["# Every 78K0 instruction in CA78K0 syntax, with each operand walked",
           "# through the ends of its range. `PSW` and `SP` are the short direct",
           "# addresses FF1EH and FF1CH, which tools/xas-diff/run.sh gives AS as",
           "# two `EQU`s, since AS has no name for either. `CALLF` and `CALLT`,",
           "# whose operand AS reads as an offset rather than an address, are in",
           "# 78k0-pairs.txt. Generated by tools/fuzz/nec78k0.py corpus lines."]
    for m, kinds in FORMS:
        opts = [corpus_choices(k) for k in kinds]
        if any(o is None for o in opts):
            continue
        base = [o[0] for o in opts]
        rows = [base]
        # Each operand is walked with the others at their first choice, so the
        # corpus stays linear in the number of choices.
        for i, o in enumerate(opts):
            for alt in o[1:]:
                rows.append(base[:i] + [alt] + base[i + 1:])
        for ops in rows:
            out.append("\t%s%s" % (m, "\t" + ",".join(ops) if ops else ""))
    return "\n".join(out) + "\n"


def corpus_pairs():
    """`CALLF` and `CALLT`, whose operand the two assemblers spell
    differently; see the module docstring."""
    callf = [0x800, 0x801, 0x8FF, 0x900, 0xA00, 0xB00, 0xC00, 0xD00, 0xE00,
             0xF00, 0xFFE, 0xFFF]
    callt = list(range(0x40, 0x80, 2))
    out = [
        "# `CALLF` and `CALLT` in both spellings: NEC's operand is the target",
        "# address, AS's is that address less the 0800H (`CALLF`) or 40H",
        "# (`CALLT`) the opcode implies. The pairing is what is under test.",
        "# Generated by tools/fuzz/nec78k0.py corpus pairs.",
        "=== callf over the whole 0800H to 0FFFH area",
    ]
    out += ["\tCALLF\t!%s" % hexnum(v) for v in callf]
    out.append("--- gnu")
    out += ["\tCALLF\t!%s" % hexnum(v - 0x800) for v in callf]
    out.append("=== callt over the whole call table")
    out += ["\tCALLT\t[%s]" % hexnum(v) for v in callt]
    out.append("--- gnu")
    out += ["\tCALLT\t[%s]" % hexnum(v - 0x40) for v in callt]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    fz = sub.add_parser("fuzz")
    fz.add_argument("--count", type=int, default=2000)
    fz.add_argument("--seed", type=int, default=1)
    fz.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    fz.add_argument("--mutations", type=float, default=0.25)
    fz.add_argument("--limit", type=int, default=20)
    ck = sub.add_parser("check")
    ck.add_argument("file")
    ck.add_argument("--limit", type=int, default=20)
    co = sub.add_parser("corpus")
    co.add_argument("part", choices=["lines", "pairs"])
    args = ap.parse_args()
    if args.cmd == "corpus":
        sys.stdout.write(corpus_lines() if args.part == "lines" else corpus_pairs())
        return 0
    return check(args) if args.cmd == "check" else fuzz(args)


if __name__ == "__main__":
    sys.exit(main())
