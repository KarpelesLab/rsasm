#!/usr/bin/env python3
"""Differential fuzzer for rsasm's MOS 6502 backend.

Random whole programs are generated from a table of the 151 official NMOS 6502
opcodes written from the datasheet -- not from rsasm's own tables -- and laid
out with labels, data, reserved space and branches that reach exactly as far as
they may. Each program is rendered in one or both of two spellings and given to
rsasm and to the assembler that reads that spelling:

    ca65      cc65's `ca65` + `ld65`, the assembler most 6502 source is
              written for: `.org`, `.byte`, `.res`, `name = value`, `z:` and
              `a:`, `<`/`>` byte selectors, `*` for the location counter.
    vasm      `vasm6502_oldstyle -quiet -Fbin`, reading the older spelling:
              `org`, `byte`, `word`, `ds`, `blk`, `name equ value`, and no
              dotted directives or size overrides.

A program is generated once and rendered twice, so the two spellings mean the
same thing; what only one reference reads goes into a program of its own.
`ld65` lays the object out from address 0 with one memory area, exactly as
`tools/xas-diff/run.sh` does, and rsasm writes a flat binary, so the images are
comparable byte for byte.

    tools/fuzz/mos6502.py fuzz --count 8000
    tools/fuzz/mos6502.py fuzz --count 2000 --seed 7 --mutations 0.5
    tools/fuzz/mos6502.py check prog.s        # one program, or a corpus file

`check` reads a file of programs in `tools/xas-diff`'s format (snippets
separated by `=== name`, or one program if there is no such line) and prints
what each assembler made of each. A finding prints its whole program, so
saving that program to a file and running `check` on it is the way to narrow
one down; the same `--seed` and `--count` generate the same cases.

Each case is classified:

    agree       every assembler that was given the program produced the same
                image, or every one refused it.
    rsasm       a reference and rsasm differ. These are the findings; the exit
                status is 1 if there are any.
    lenient     vasm assembles what ca65 and rsasm both refuse, which vasm does
                for a value past the end of its field (it truncates without a
                word). rsasm has to refuse, as ca65 does.
    vasm        the references disagree otherwise, and rsasm follows ca65.
                Listed, since ca65 is the reference that decides here; see
                `tools/xas-diff/README.md` on the 6502.
    negative    ca65 refuses a negative value in a byte or word field and
                rsasm assembles it, as vasm does: rsasm's 8-bit fields run
                from -128 to 255 on purpose (`NEGATIVE` below).
    parens      rsasm assembles what both references refuse, because a fully
                bracketed operand on an instruction with no indirect form is a
                bracketed expression to rsasm and an illegal addressing mode to
                them: `lda ($12)` is `lda $12`, `ror ($12),x` is `ror $12,x`.
                The rule is `PARENS_GROUP` below and the decision is written
                out in `src/arch/retro/mos6502.rs`.

Some programs are made invalid on purpose (`--mutations`, default 0.25): an
immediate past 255, a `z:` on an address that is not in the zero page, a
branch pushed out of reach by reserved space, an addressing mode the
instruction does not have, a reference to nothing. Only programs ca65 reads
are mutated, so that a vasm-only program has no reason to be refused and any
disagreement there is a finding.

What this deliberately does not generate, because the references part company
by design and README.md says which side rsasm takes:

  * a second `.org`: rsasm pads up to it and ca65 does not, so a mid-program
    `org` is only put in vasm programs, where both pad.
  * a forward reference whose value turns out to fit in the zero page: ca65
    and rsasm make it absolute, vasm makes it zero page. vasm programs
    therefore start at $0100 or above, so that every label is absolute either
    way, and only ca65 programs refer forward to a zero-page value.
  * a comparison, which is 1 in ca65 and rsasm and -1 in vasm, and `&` mixed
    with `+` without brackets, whose precedence the two read differently.

Environment: RSASM (default target/debug/rsasm under the repository root) and
RSASM_ORACLES (default target/oracles), which must hold ca65, ld65 and
vasm6502_oldstyle in `bin` from tools/oracles/build.sh.
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

# The linker script tools/xas-diff/run.sh uses: one memory area from address 0
# holding every segment ca65 names, so the image is the code in order.
LD65_CFG = """MEMORY { M: start = 0, size = $10000, file = %O; }
SEGMENTS { CODE: load = M, type = rw; RODATA: load = M, type = rw, optional = yes;
  DATA: load = M, type = rw, optional = yes; ZEROPAGE: load = M, type = rw, optional = yes; }
"""

# --- the instruction set -----------------------------------------------------
#
# Shapes are the syntax of an operand, not an opcode:
#   none                    no operand          nop
#   acc                     the accumulator     asl / asl a
#   imm                     #expr               lda #$12
#   mem  memx  memy         expr [,x] [,y]      lda $12 / lda $1234,x
#   ind  indx  indy         (expr) (expr,x) (expr),y
#   rel                     a branch target
#
# `mem`, `memx` and `memy` carry the sizes the instruction has: "z" for a zero
# page form only, "a" for an absolute form only, "za" for both. Which one a
# line assembles to is decided by the value, so the generator picks the size
# first and then writes an expression of that size.

IMPLIED = ("brk php clc plp sec rti pha cli rts pla sei dey txa tya txs tay "
           "tax clv tsx iny dex cld inx nop sed").split()
BRANCHES = "bpl bmi bvc bvs bcc bcs bne beq".split()
ALU = "ora and eor adc sta lda cmp sbc".split()
SHIFTS = "asl rol lsr ror".split()


def build_forms():
    f = {}
    for m in IMPLIED:
        f[m] = [("none", "")]
    for m in BRANCHES:
        f[m] = [("rel", "")]
    for m in ALU:
        # No zero page,Y for the accumulator group: `lda $12,y` is absolute,Y.
        forms = [("mem", "za"), ("memx", "za"), ("memy", "a"),
                 ("indx", ""), ("indy", "")]
        if m != "sta":
            forms.insert(0, ("imm", ""))
        f[m] = forms
    for m in SHIFTS:
        f[m] = [("acc", ""), ("mem", "za"), ("memx", "za")]
    for m in ("inc", "dec"):
        f[m] = [("mem", "za"), ("memx", "za")]
    f["ldx"] = [("imm", ""), ("mem", "za"), ("memy", "za")]
    f["ldy"] = [("imm", ""), ("mem", "za"), ("memx", "za")]
    f["stx"] = [("mem", "za"), ("memy", "z")]
    f["sty"] = [("mem", "za"), ("memx", "z")]
    f["cpx"] = [("imm", ""), ("mem", "za")]
    f["cpy"] = [("imm", ""), ("mem", "za")]
    f["bit"] = [("mem", "za")]
    f["jmp"] = [("mem", "a"), ("ind", "")]
    f["jsr"] = [("mem", "a")]
    return f


FORMS = build_forms()
MNEMONICS = sorted(FORMS)

# --- expressions -------------------------------------------------------------
#
# An expression is a small tree rendered per spelling:
#   ("n", v)            a number
#   ("sym", name)       a symbol
#   ("off", name, d)    a symbol plus or minus a constant
#   ("star", d)         the location counter, `*` or `*+d`
#   ("lo", e) ("hi", e) the low or high byte, `<e` / `>e`
#   ("bin", op, a, b)   a bracketed binary operation


def render_num(v, rng):
    """A number in one of the spellings both assemblers read."""
    neg = v < 0
    a = -v if neg else v
    r = rng.random()
    if r < 0.55:
        text = "$%X" % a
    elif r < 0.8:
        text = "%d" % a
    elif r < 0.92 and a <= 0xFF:
        text = "%%%s" % bin(a)[2:]
    elif a < 0x80 and chr(a).isalnum():
        # Alphanumeric only: a bracket or a comma inside a character literal
        # is something vasm's operand parser reads as punctuation.
        text = "'%s'" % chr(a)
    else:
        text = "$%X" % a
    return "-" + text if neg else text


def render_expr(e, rng):
    k = e[0]
    if k == "n":
        return render_num(e[1], rng)
    if k == "sym":
        return e[1]
    if k == "off":
        return "%s%+d" % (e[1], e[2])
    if k == "star":
        return "*" if e[1] == 0 else "*%+d" % e[1]
    if k == "lo":
        return "<" + render_expr(e[1], rng)
    if k == "hi":
        return ">" + render_expr(e[1], rng)
    if k == "bin":
        return "(%s %s %s)" % (render_expr(e[2], rng), e[1], render_expr(e[3], rng))
    raise ValueError(e)


# --- generating a program ----------------------------------------------------
#
# Statements, each with a size known as it is generated, so labels have exact
# addresses and a branch can be aimed at the last byte it can reach:
#   ("equ", name, value)        ("label", name)
#   ("insn", mnemonic, shape, operand-text-parts)
#   ("byte"|"word"|"dbyt"|"addr"|"dword", [expr])
#   ("str", directive, text)    ("res", n, fill-or-None)
#   ("org", addr)               a mid-program org, vasm spelling only

DATA_ITEM = {"byte": 1, "word": 2, "dbyt": 2, "addr": 2, "dword": 4}


class Gen:
    """Builds one program, tracking the address so every label is known."""

    def __init__(self, rng, mode, mutate):
        self.rng = rng
        self.mode = mode          # "ca65", "both" or "vasm"
        self.mutate = mutate
        self.items = []
        self.equates = {}         # name -> value, all defined before the code
        self.late = {}            # name -> value, defined after the code
        self.labels = {}          # name -> address, defined so far
        self.future = []          # label names not placed yet
        self.addr = 0
        self.broken = False       # a mutation was planted

    # -- helpers --------------------------------------------------------------

    def emit(self, item, size):
        self.items.append(item)
        self.addr += size

    def zp_symbols(self):
        return [n for n, v in self.equates.items() if v <= 0xFF]

    def abs_symbols(self):
        return [n for n, v in self.equates.items() if v > 0xFF]

    def zp_labels(self):
        return [n for n, a in self.labels.items() if a <= 0xFF]

    def abs_labels(self):
        return [n for n, a in self.labels.items() if a > 0xFF]

    # -- expressions ----------------------------------------------------------

    def zp_expr(self):
        """An expression whose value is known here and fits in the zero page,
        so ca65 and rsasm both choose zero page addressing for it."""
        rng = self.rng
        pool = []
        syms = self.zp_symbols()
        if syms:
            pool.append("sym")
        labs = self.zp_labels()
        if labs:
            pool.append("label")
        if self.mode == "ca65":
            pool.append("lo")     # `<addr` forces the zero page in ca65
        pool += ["num", "num", "num"]
        pick = rng.choice(pool)
        if pick == "sym":
            n = rng.choice(syms)
            d = self.equates[n]
            if rng.random() < 0.3 and d + 2 <= 0xFF:
                return ("off", n, rng.randint(1, 2))
            return ("sym", n)
        if pick == "label":
            return ("sym", rng.choice(labs))
        if pick == "lo":
            return ("lo", ("n", rng.randint(0x100, 0xFFFF)))
        # No bracketed expression here: `lda ($7F+0)` is indirect syntax on
        # this target, not a memory operand with brackets round its value.
        return ("n", rng.choice([0, 1, 0x7F, 0x80, 0xFE, 0xFF, rng.randint(0, 0xFF)]))

    def simple_zp_expr(self):
        """A zero page address with no byte selector, for an indirect."""
        rng = self.rng
        syms = self.zp_symbols()
        if syms and rng.random() < 0.3:
            return ("sym", rng.choice(syms))
        labs = self.zp_labels()
        if labs and rng.random() < 0.2:
            return ("sym", rng.choice(labs))
        return ("n", rng.choice([0, 1, 0x7F, 0xFE, 0xFF, rng.randint(0, 0xFF)]))

    def abs_expr(self):
        """An expression that assembles to an absolute address: a number above
        the zero page, a symbol above it, or a forward reference, which ca65
        and rsasm make absolute whatever it turns out to be."""
        rng = self.rng
        pool = ["num", "num"]
        syms = self.abs_symbols()
        if syms:
            pool.append("sym")
        labs = self.abs_labels()
        if labs:
            pool.append("label")
        if self.future:
            pool.append("future")
        if self.late:
            pool.append("late")
        if self.mode == "ca65":
            pool.append("force")  # `a:` on a zero page value
        pick = rng.choice(pool)
        if pick == "sym":
            return ("sym", rng.choice(syms))
        if pick == "label":
            n = rng.choice(labs)
            if rng.random() < 0.3:
                return ("off", n, rng.choice([-1, 1, 2]))
            return ("sym", n)
        if pick == "future":
            return ("sym", rng.choice(self.future))
        if pick == "late":
            return ("sym", rng.choice(sorted(self.late)))
        if pick == "force":
            return ("force", self.zp_expr())
        v = rng.choice([0x100, 0x200, 0x1234, 0xFFFF, 0xC000,
                        rng.randint(0x100, 0xFFFF)])
        return ("n", v)

    def imm_expr(self):
        rng = self.rng
        r = rng.random()
        if r < 0.2:
            base = ("n", rng.randint(0x100, 0xFFFF))
            return ("lo", base) if rng.random() < 0.5 else ("hi", base)
        if r < 0.3 and (self.labels or self.future):
            names = sorted(self.labels) + self.future
            base = ("sym", rng.choice(names))
            return ("lo", base) if rng.random() < 0.5 else ("hi", base)
        if r < 0.4 and self.mode == "ca65":
            # The right-hand side stays below the left: ca65 refuses a
            # negative value where rsasm and vasm read it as two's complement,
            # which is the `negative` rule and is planted on purpose instead.
            return ("bin", rng.choice(["+", "-", "&", "|", "^", "<<", ">>"]),
                    ("n", rng.randint(4, 0xFF)), ("n", rng.randint(0, 3)))
        return ("n", rng.choice([0, 1, 0x7F, 0x80, 0xFF, rng.randint(0, 0xFF)]))

    # -- one instruction ------------------------------------------------------

    def operand_text(self, shape, sizes):
        """Returns (text, size-in-bytes) for one instruction's operand."""
        rng = self.rng
        if shape == "none":
            return "", 1
        if shape == "acc":
            return rng.choice(["", " a", " A"]), 1
        if shape == "imm":
            return " #" + render_expr(self.imm_expr(), rng), 2
        if shape in ("ind", "indx", "indy"):
            # An indirect operand is a plain zero page address (or any address
            # for `jmp (...)`); a size override there means nothing.
            e = self.abs_expr() if shape == "ind" else self.simple_zp_expr()
            text = render_expr(self.strip_force(e), rng)
            if shape == "ind":
                return " (%s)" % text, 3
            if shape == "indx":
                return " (%s,%s)" % (text, rng.choice("xX")), 2
            return " (%s),%s" % (text, rng.choice("yY")), 2
        # A memory operand: pick the size the instruction has, then write it.
        want = rng.choice(list(sizes)) if len(sizes) > 1 else sizes
        if want == "z":
            e, size = self.zp_expr(), 2
        else:
            e, size = self.abs_expr(), 3
        text = self.render_mem(e, rng)
        if shape == "mem":
            return " " + text, size
        return " %s,%s" % (text, rng.choice("xX" if shape == "memx" else "yY")), size

    @staticmethod
    def strip_force(e):
        return e[1] if e[0] == "force" else e

    def render_mem(self, e, rng):
        """`a:` and `z:` are ca65's overrides; only ca65 programs carry them."""
        if e[0] == "force":
            return "a:" + render_expr(e[1], rng)
        text = render_expr(e, rng)
        # `z:` on something already in the zero page changes nothing, which is
        # the point: it is the spelling ca65 source uses to insist.
        if self.mode == "ca65" and e[0] == "n" and 0 <= e[1] <= 0xFF and rng.random() < 0.1:
            return "z:" + text
        return text

    def instruction(self):
        rng = self.rng
        mn = rng.choice(MNEMONICS)
        shape, sizes = rng.choice(FORMS[mn])
        if shape == "rel":
            return self.branch(mn)
        text, size = self.operand_text(shape, sizes)
        if rng.random() < 0.3:
            mn = mn.upper()
        self.emit(("insn", mn + text), size)

    def branch(self, mn):
        """A branch to a label already placed, or to the location counter."""
        rng = self.rng
        back = [n for n, a in self.labels.items() if -128 <= a - (self.addr + 2) <= 127]
        if back and rng.random() < 0.6:
            target = rng.choice(back)
            self.emit(("insn", "%s %s" % (mn, target)), 2)
            return
        # `*+d` puts the target d bytes past the branch, so the displacement
        # stored is d-2: d of -126 and 129 are the two ends of the range.
        d = rng.choice([0, 2, -126, 129, rng.randint(-126, 129)])
        self.emit(("insn", "%s *%+d" % (mn, d) if d else "%s *" % mn), 2)

    def branch_gadget(self):
        """A forward branch over reserved space, so the displacement is the
        size of the gap and can be put on either side of the +127 edge."""
        rng = self.rng
        mn = rng.choice(BRANCHES)
        gap = rng.choice([0, 1, 125, 126, 127])
        if self.mutate and not self.broken and rng.random() < 0.5:
            gap = rng.choice([128, 129, 200])
            self.broken = True
        name = self.new_label()
        self.emit(("insn", "%s %s" % (mn, name)), 2)
        self.emit(("res", gap, None), gap)
        self.place_label(name)

    def back_gadget(self):
        """The same backwards: a label, a gap, then a branch. The displacement
        is -(gap + 2), so a gap of 126 is the far end of the range."""
        rng = self.rng
        mn = rng.choice(BRANCHES)
        gap = rng.choice([0, 1, 124, 125, 126])
        if self.mutate and not self.broken and rng.random() < 0.5:
            gap = rng.choice([127, 128, 200])
            self.broken = True
        name = self.new_label()
        self.place_label(name)
        self.emit(("res", gap, None), gap)
        self.emit(("insn", "%s %s" % (mn, name)), 2)

    # -- labels and data ------------------------------------------------------

    def new_label(self):
        n = len(self.labels) + len(self.future)
        name = "l%d" % n
        while name in self.labels or name in self.future:
            n += 1
            name = "l%d" % n
        self.future.append(name)
        return name

    def place_label(self, name):
        if name in self.future:
            self.future.remove(name)
        self.labels[name] = self.addr
        self.items.append(("label", name))

    def label(self):
        """Place a label: one promised at the start, or a fresh one. Placing a
        promised one late is what makes the references to it forward ones."""
        if self.future and self.rng.random() < 0.6:
            self.place_label(self.rng.choice(self.future))
        else:
            self.place_label(self.new_label())

    def data(self):
        rng = self.rng
        kinds = ["byte", "byte", "word"]
        if self.mode == "ca65":
            kinds += ["dbyt", "addr", "dword"]
        kind = rng.choice(kinds)
        if kind == "byte" and rng.random() < 0.25:
            text = "".join(rng.choice("abcXYZ01 ") for _ in range(rng.randint(1, 6)))
            self.emit(("str", "byte", text), len(text))
            return
        n = rng.randint(1, 4)
        items = []
        for _ in range(n):
            if kind == "byte":
                items.append(self.zp_expr() if rng.random() < 0.3
                             else ("n", rng.randint(0, 0xFF)))
            elif kind == "dword":
                items.append(("n", rng.randint(0, 0x7FFFFFFF)))
            elif rng.random() < 0.4:
                items.append(("star", 0))
            elif rng.random() < 0.5 and (self.labels or self.future):
                items.append(("sym", rng.choice(sorted(self.labels) + self.future)))
            else:
                items.append(("n", rng.randint(0, 0xFFFF)))
        self.emit((kind, items), n * DATA_ITEM[kind])

    def reserve(self):
        rng = self.rng
        n = rng.choice([1, 2, 3, 8, 16, rng.randint(1, 40)])
        fill = rng.randint(0, 0xFF) if rng.random() < 0.4 else None
        self.emit(("res", n, fill), n)

    def mid_org(self):
        """Only in vasm programs: rsasm and vasm pad up to a later `org`,
        ca65 does not, which README.md's 8-bit dialect section records."""
        self.addr += self.rng.choice([1, 2, 16, 64, 100])
        self.emit(("org", self.addr), 0)


def pick_org(rng, mode):
    """Where the program is loaded. vasm programs start at $0100 or above so
    that every label is an absolute address in both assemblers."""
    low = [0x0000, 0x0010, 0x0080, 0x00F0]
    high = [0x0200, 0x0400, 0x0801, 0x1000, 0x01F8, 0x0FFE, 0xC000, 0xD000]
    if mode == "ca65":
        return rng.choice(low + high + high)
    return rng.choice(high)


MUTATIONS = [
    "imm-range",      # an immediate past 255
    "zp-force",       # `z:` on an address outside the zero page
    "no-mode",        # an addressing mode the instruction does not have
    "no-mode",
    "undefined",      # a reference to a symbol nobody defines
    "dup-label",      # a label defined twice
    "negative",       # a negative value in a byte or word field
]

# Lines with an addressing mode the instruction has not got. All three
# assemblers refuse every one of them.
NO_MODE = [
    "tax $12", "inx $1234", "brk $12", "nop a", "bne #$12", "lda #$12,x",
    "sty $1234,x", "stx $1234,y", "cpx $12,x", "jmp $12,x", "lda $12,a",
    "lda ($1234),y", "lda ($12),x", "sta ($12,y)",
]
# The named deviation: rsasm reads a fully bracketed operand on an instruction
# with no indirect form as a bracketed expression, so `lda ($12)` is `lda $12`
# and `ror ($12),x` is `ror $12,x`, where ca65 and vasm call it an illegal
# addressing mode. It is deliberate and says so in `src/arch/retro/mos6502.rs`:
# "`(expr)` is an indirect operand only where the instruction has one; for
# everything else the parentheses are just grouping, as in `lda (base+2)`."
PARENS_GROUP = [
    "jsr ($1234)", "lda ($12)", "ror ($12),x", "ldx ($12),y", "bit ($1234)",
    "adc ($12)", "asl ($12)", "cpy ($12)",
]
# The second named deviation, and one where rsasm has vasm on its side: ca65
# refuses every negative value in a byte or a word field, and rsasm and vasm
# read it as two's complement. rsasm's 8-bit fields are -128..255 on purpose
# -- `Enc::imm8` in `src/arch/retro/common.rs`, whose strict sibling
# `Enc::addr8` exists precisely because the MCS-51 wants `-1` refused there.
# Immediates only: for an absolute operand vasm warns that the value does not
# fit in 16 bits while still assembling it, which counts as a refusal here.
NEGATIVE = [
    "lda #-1", "ldx #-2", "cpy #-128", "and #-16", "adc #-3", "ora #-100",
]


def generate(rng, mode, mutate):
    g = Gen(rng, mode, mutate)
    org = pick_org(rng, mode)
    g.addr = org
    # Equates first, so their values are known where they are used; a couple
    # more are defined after the code, which is what a forward reference is.
    for i in range(rng.randint(0, 4)):
        g.equates["c%d" % i] = rng.choice(
            [rng.randint(0, 0xFF), rng.randint(0x100, 0xFFFF)])
    for i in range(rng.randint(0, 2)):
        # In a vasm program a forward reference has to land outside the zero
        # page, or vasm would pick zero page where ca65 and rsasm do not.
        lo = 0 if mode == "ca65" else 0x100
        g.late["k%d" % i] = rng.randint(lo, 0xFFFF)
    # A few labels are promised now and placed during the body, so that a
    # reference to one before it appears is a forward reference: ca65 reads
    # those as absolute however small they turn out to be.
    for _ in range(rng.randint(0, 3)):
        g.new_label()
    head = [("org", org)]
    for n in sorted(g.equates):
        head.append(("equ", n, g.equates[n]))
    n = rng.randint(4, 30)
    for _ in range(n):
        r = rng.random()
        if r < 0.62:
            g.instruction()
        elif r < 0.70:
            g.label()
        elif r < 0.80:
            g.data()
        elif r < 0.86:
            g.reserve()
        elif r < 0.92:
            g.branch_gadget()
        elif r < 0.97:
            g.back_gadget()
        elif mode == "vasm":
            g.mid_org()
        else:
            g.instruction()
    # Every label a branch aimed at has to exist.
    for name in list(g.future):
        g.place_label(name)
    g.emit(("insn", "nop"), 1)
    tail = [("equ", n, g.late[n]) for n in sorted(g.late)]
    items = head + g.items + tail
    expect = ""
    if mutate:
        items, expect = apply_mutation(rng, items)
    return items, expect


def apply_mutation(rng, items):
    """Break one statement on purpose. Returns the program and the name of the
    deviation it is expected to show, if any."""
    kind = rng.choice(MUTATIONS)
    idx = [i for i, it in enumerate(items) if it[0] == "insn"]
    if not idx:
        return items, ""
    i = rng.choice(idx)
    text = items[i][1]
    mn = text.split()[0].lower()
    if kind == "imm-range" and " #" in text:
        head = text.split(" #")[0]
        items[i] = ("insn", "%s #%s" % (head, rng.choice(["$1234", "300", "-200", "$FFFF"])))
    elif kind == "zp-force":
        # A fixed list: `z:` on a branch target is a case of its own and not
        # what this mutation is for.
        items[i] = ("insn", rng.choice([
            "lda z:$1234", "sta z:$4400", "ldx z:$2000", "inc z:$FFFF",
            "cmp z:$100,x", "sty z:$0300,x",
        ]))
    elif kind == "no-mode":
        if rng.random() < 0.35:
            items[i] = ("insn", rng.choice(PARENS_GROUP))
            return items, "parens"
        items[i] = ("insn", rng.choice(NO_MODE))
    elif kind == "negative":
        items[i] = ("insn", rng.choice(NEGATIVE))
        return items, "negative"
    elif kind == "undefined":
        items[i] = ("insn", "%s nowhere" % mn)
    else:
        items.insert(i, ("label", "dup0"))
        items.insert(i, ("label", "dup0"))
    return items, ""


# --- rendering ---------------------------------------------------------------

CA65_DIR = {"byte": ".byte", "word": ".word", "dbyt": ".dbyt", "addr": ".addr",
            "dword": ".dword"}
VASM_DIR = {"byte": "byte", "word": "word"}


def render_program(items, spelling, rng):
    out = []
    ca = spelling == "ca65"
    for it in items:
        k = it[0]
        if k == "org":
            out.append("\t%s $%04X" % (".org" if ca else "org", it[1]))
        elif k == "equ":
            out.append("%s%s %s" % (it[1], " =" if ca else "\tequ", render_num(it[2], rng)))
        elif k == "label":
            out.append("%s:" % it[1] if ca or rng.random() < 0.5 else it[1])
        elif k == "insn":
            out.append("\t" + it[1])
        elif k == "str":
            out.append('\t%s "%s"' % (".byte" if ca else "byte", it[2]))
        elif k == "res":
            n, fill = it[1], it[2]
            if ca:
                out.append("\t.res %d%s" % (n, "" if fill is None else ", $%02X" % fill))
            elif fill is None:
                out.append("\tds %d" % n)
            else:
                out.append("\tblk %d,$%02X" % (n, fill))
        else:
            d = CA65_DIR[k] if ca else VASM_DIR[k]
            out.append("\t%s %s" % (d, ",".join(render_expr(e, rng) for e in it[1])))
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
        if "rror" in line or "arning" in line:
            return line.strip()[:160]
    return (log.strip().splitlines() or ["error"])[0][:160]


def ca65(source, workdir):
    """ca65 then ld65, laid out from 0 the way tools/xas-diff/run.sh does."""
    with open(os.path.join(workdir, "ca.s"), "w") as fh:
        fh.write(source)
    with open(os.path.join(workdir, "flat.cfg"), "w") as fh:
        fh.write(LD65_CFG)
    for f in ("ca.o", "ca.bin"):
        try:
            os.unlink(os.path.join(workdir, f))
        except OSError:
            pass
    code, log = run([os.path.join(BIN, "ca65"), "-o", "ca.o", "ca.s"], workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    code, log = run([os.path.join(BIN, "ld65"), "-C", "flat.cfg", "-o", "ca.bin", "ca.o"],
                    workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    return ("OK", image(os.path.join(workdir, "ca.bin")) or b"")


def vasm(source, workdir):
    with open(os.path.join(workdir, "va.s"), "w") as fh:
        fh.write(source)
    try:
        os.unlink(os.path.join(workdir, "va.bin"))
    except OSError:
        pass
    code, log = run([os.path.join(BIN, "vasm6502_oldstyle"), "-quiet", "-Fbin",
                     "-o", "va.bin", "va.s"], workdir)
    # vasm warns rather than stopping for a truncated operand, and its exit
    # status is 0 either way, so a warning counts as a refusal here.
    if code != 0 or "error" in log or "warning" in log:
        return ("ERROR", first_error(log))
    return ("OK", image(os.path.join(workdir, "va.bin")) or b"")


def rsasm(source, workdir, tag):
    src = os.path.join(workdir, "rs%s.s" % tag)
    out = os.path.join(workdir, "rs%s.bin" % tag)
    with open(src, "w") as fh:
        fh.write(source)
    code, log = run([RSASM, "-a", "6502", "-d", "8bit", "-f", "bin", "-o", out, src],
                    workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    return ("OK", image(out) or b"")


def same(a, b):
    if a is None or b is None:
        return True
    if a[0] != b[0]:
        return False
    return a[0] == "ERROR" or a[1] == b[1]


def classify(ca, va, rs_ca, rs_va, expect=""):
    """Returns (class, detail) for one program."""
    ca_ok = None if ca is None else same(ca, rs_ca)
    va_ok = None if va is None else same(va, rs_va)
    if ca_ok is not False and va_ok is not False:
        return ("agree", "")
    # The one deviation this fuzzer plants on purpose: see PARENS_GROUP.
    if expect == "parens":
        refused = [r for r in (ca, va) if r is not None]
        ours = [r for r in (rs_ca, rs_va) if r is not None]
        if all(r[0] == "ERROR" for r in refused) and all(r[0] == "OK" for r in ours):
            return ("parens", "")
    if expect == "negative" and ca is not None and ca[0] == "ERROR":
        # rsasm assembles it, and where vasm saw the program it did too.
        if rs_ca[0] == "OK" and (va is None or (va[0] == "OK" and va_ok)):
            return ("negative", "")
    if ca_ok is False:
        return ("rsasm", "ca65")
    # Only vasm differs. ca65 is the reference that decides for this backend.
    if ca is not None and ca[0] == "ERROR" and va[0] == "OK" and rs_va[0] == "ERROR":
        return ("lenient", "")
    if ca is None:
        return ("rsasm", "vasm")
    return ("vasm", "")


def compare(ca_text, va_text, expect=""):
    """Assembles one program's spellings and classifies the result."""
    with tempfile.TemporaryDirectory() as d:
        ca = ca65(ca_text, d) if ca_text else None
        rs_ca = rsasm(ca_text, d, "c") if ca_text else None
        va = vasm(va_text, d) if va_text else None
        rs_va = rsasm(va_text, d, "v") if va_text else None
    cls, detail = classify(ca, va, rs_ca, rs_va, expect)
    return {"class": cls, "detail": detail, "ca_text": ca_text, "va_text": va_text,
            "ca": ca, "va": va, "rs_ca": rs_ca, "rs_va": rs_va}


def one(job):
    seed, mode, mutate = job
    rng = random.Random(seed)
    items, expect = generate(rng, mode, mutate)
    ca_text = render_program(items, "ca65", rng) if mode != "vasm" else None
    va_text = render_program(items, "vasm", rng) if mode != "ca65" else None
    r = compare(ca_text, va_text, expect)
    r["seed"] = seed
    return r


def fmt(res):
    if res is None:
        return "-"
    if res[0] == "ERROR":
        return "ERROR " + res[1]
    return res[1].hex(" ")


def report(r, name=None):
    print("### %s%s%s" % (r["class"], " (%s)" % r["detail"] if r["detail"] else "",
                          " %s" % name if name else " seed %d" % r.get("seed", 0)))
    if r["ca_text"]:
        print("  --- ca65 spelling")
        print("\n".join("    |" + l for l in r["ca_text"].splitlines()))
    if r["va_text"]:
        print("  --- vasm spelling")
        print("\n".join("    |" + l for l in r["va_text"].splitlines()))
    print("  ca65:         " + fmt(r["ca"]))
    print("  vasm:         " + fmt(r["va"]))
    print("  rsasm (ca65): " + fmt(r["rs_ca"]))
    print("  rsasm (vasm): " + fmt(r["rs_va"]))


def fuzz(args):
    rng = random.Random(args.seed)
    jobs = []
    for _ in range(args.count):
        r = rng.random()
        mode = "ca65" if r < 0.55 else ("both" if r < 0.87 else "vasm")
        # Only ca65 programs are mutated: a vasm program that both sides refuse
        # would hide a real disagreement, since vasm is the looser of the two.
        mutate = mode != "vasm" and rng.random() < args.mutations
        jobs.append((rng.getrandbits(48), mode, mutate))
    counts = collections.Counter()
    findings = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        for r in ex.map(one, jobs, chunksize=4):
            counts[r["class"]] += 1
            if r["class"] in ("rsasm", "vasm"):
                findings.append(r)
    print("cases: %d  %s" % (args.count, "  ".join("%s %d" % kv for kv in sorted(counts.items()))))
    findings.sort(key=lambda r: (r["class"] != "rsasm", len(r["ca_text"] or r["va_text"])))
    for r in findings[: args.limit]:
        report(r)
    # The last line is the one tools/fuzz/run.sh reads.
    print("--- mos6502: %d case(s) compared, %d finding(s)"
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


def guess_spelling(text):
    """ca65 unless the source is written the way only vasm reads it."""
    for line in text.splitlines():
        word = line.strip().split()[:1]
        if word and (word[0].startswith(".") or "z:" in line or "a:" in line):
            return "ca65"
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lower() in ("equ", "org", "byte", "word", "blk", "ds"):
            return "vasm"
        if parts[:1] and parts[0].lower() in ("org", "byte", "word", "blk", "ds"):
            return "vasm"
    return "ca65"


def check(args):
    with open(args.file) as fh:
        text = fh.read()
    bad = 0
    total = 0
    for name, prog in split_programs(text):
        spelling = args.spelling if args.spelling != "auto" else guess_spelling(prog)
        r = compare(prog if spelling == "ca65" else None,
                    prog if spelling == "vasm" else None)
        total += 1
        if r["class"] != "agree":
            bad += 1
            if bad <= args.limit:
                report(r, name)
        else:
            print("ok   %s (%s)" % (name, spelling))
    print("--- mos6502: %d case(s) compared, %d finding(s)" % (total, bad))
    return 1 if bad else 0


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
    ck.add_argument("--spelling", choices=["auto", "ca65", "vasm"], default="auto")
    ck.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    return check(args) if args.cmd == "check" else fuzz(args)


if __name__ == "__main__":
    sys.exit(main())
