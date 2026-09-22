#!/usr/bin/env python3
"""Differential fuzzer for whole ARM and Thumb programs, literal pools above all.

Each case is a *file*, not a statement: literal loads of numbers and symbols
(`ldr`, the halfword and byte loads, and the VFP `vldr`, whose double entries
are eight bytes wide), `.ltorg` and `.pool` at every point one can stand,
data between and after the code, labels on it, `.arm`/`.thumb`/`.code 16`
switches, `.thumb_func`, section and subsection switches, `.macro` and
`.rept` bodies that load and flush, `adr`, `adrl`, `it` blocks and branches
that relax. It is assembled by `arm-none-eabi-as` with the flags
`tools/xas-diff/run.sh` uses for its `arm` and `thumb` keys, and by rsasm,
and the two objects are compared whole with `tools/mc-diff/canon.sh --full`:
every allocated section's header and bytes, `e_flags`, every symbol -- the
mapping symbols among them -- and every relocation.

    tools/fuzz/arm-programs.py fuzz --count 20000 --seed 1
    tools/fuzz/arm-programs.py fuzz --target thumb --skip vldr,subsec
    tools/fuzz/arm-programs.py check --target arm prog.s

Where a pool goes, what shares an entry with what, and in which order the
entries land is decided across a whole file, so it is whole files this
fuzzer compares. The rules it is looking for are `add_to_lit_pool`,
`s_ltorg` and `arm_cleanup` in `gas/config/tc-arm.c`: a pool per section
*and subsection*, entries in the order they were asked for, a four-byte
padding slot in front of an eight-byte entry that would land unaligned
(reusable by a later four-byte entry), a pool aligned to eight from the
first eight-byte entry in it onwards -- and from then on for every later
pool in the section -- and at most 1024 slots. So the values a program
loads repeat, and its doubleword values are chosen to share, pad and be
shared: the halves of a `vldr dN, =x` are words a `ldr` may ask for too.

A case is:

    agree     both wrote the same object, or both refused the same line.
    rsasm     they differ. These are the findings; the exit status is 1 when
              there are any. Each is shown reduced: statements are dropped
              while the difference stays the same kind.
    known     they differ in a way this fuzzer is not about, each with its
              reason: `KNOWN` and `KNOWN_GAS` list the ones told apart by
              what the assembler that refused said, and `known_object` the
              one that shows in the object itself.

`--mutations` (default 0.15) is the fraction of programs given something
meant to be refused: a pool out of reach, a `=` on a store or an `ldrd`, an
over-wide literal, an eight-byte entry that is not a number.

Environment: RSASM (default target/debug/rsasm under the repository root)
and RSASM_ORACLES (default target/oracles), whose `bin` holds
`arm-none-eabi-as` from tools/oracles/build.sh.
"""

import collections
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RSASM = os.environ.get("RSASM", os.path.join(ROOT, "target", "debug", "rsasm"))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
GAS = os.environ.get("GAS", os.path.join(ORACLES, "bin", "arm-none-eabi-as"))
CANON = os.path.join(ROOT, "tools", "mc-diff", "canon.sh")

# The flags tools/xas-diff/run.sh gives its `arm` and `thumb` keys.
FLAGS = ["-march=armv7ve", "-mfpu=neon-vfpv4"]
TARGETS = {"arm": FLAGS, "thumb": FLAGS + ["-mthumb"]}

# What rsasm refuses where GNU as does not, matched against rsasm's message.
# Each is a difference this fuzzer is not about:
#
#   * GNU as keeps the low 32 bits of a literal that does not fit a word (or
#     a doubleword) and assembles a load of the truncated value; rsasm says
#     so instead.
#   * an `adr` naming a label in another section cannot be resolved and has
#     no relocation; GNU as writes a fixed value that is wrong wherever the
#     linker puts the two sections, and rsasm refuses it. The generator does
#     not write one, but reducing a finding can.
#   * subsections (`.text 1`, `.subsection 2`) are not modelled: rsasm reads
#     the number as trailing tokens. GNU as keeps a pool per subsection,
#     which is why the generator writes them at all.
KNOWN = [("does not fit in the 32-bit word", "literal wider than a word"),
         ("does not fit in the 64-bit", "literal wider than a doubleword"),
         ("no relocation exists for a 4-byte PC-relative reference",
          "an `adr` out of its own section"),
         ("unexpected trailing tokens", "a subsection"),
         ("unknown directive `.subsection`", "a subsection")]

# The other way round: what GNU as refuses and rsasm assembles, matched
# against GNU as's message. An ARM `bl` or `b` must land on a word boundary,
# and GNU as checks the offset that `arm_fix_adjustable` folded into the
# addend of a reference to a local label in another section, although where
# that section goes is the linker's; rsasm names the label, as llvm-mc does,
# and leaves the whole reference to the linker. A label an odd number of
# halfwords into Thumb code is the way to write one. The ARM backend's module
# documentation says why this one is deliberate, and
# tools/mc-diff/arm-relocs.txt holds the case.
KNOWN_GAS = [("misaligned branch destination",
              "an ARM branch to a target GNU as checks before the linker")]

# Parts of the language a run can leave out, for bisecting a finding.
FEATURES = ["vldr", "subsec", "macro", "sections", "state", "data", "adr",
            "halfword", "big"]


# ============================================================================
# Running the two assemblers
# ============================================================================


def run(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, p.stdout + p.stderr


def canon(path):
    rc, out = run([CANON, "--full", path])
    return out if rc == 0 else f"CANON-ERROR {out}"


def first_error(text, gas):
    """The line the first error is on, and the message, so that two refusals
    can be told apart."""
    for line in text.splitlines():
        if gas:
            if ": Error: " in line or ": Fatal error" in line:
                where = line.split(":")
                return (where[1] if where[1].isdigit() else "?",
                        line.split("Error:")[-1].strip())
        elif line.startswith("error:"):
            return "?", line[len("error:"):].strip()
    return "?", text.strip().splitlines()[0] if text.strip() else ""


def rsasm_error_line(text):
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("--> "):
            parts = stripped.split(":")
            if len(parts) >= 3 and parts[-2].isdigit():
                return parts[-2]
    return "?"


def assemble(source, target, workdir):
    """(gas, rsasm), each a dict with ok, text (the canonical object or the
    first error), line (where it complained) and log."""
    src = os.path.join(workdir, "in.s")
    with open(src, "w") as f:
        f.write(source)
    out = {}
    rc, log = run([GAS] + TARGETS[target] + ["-o", "ref.o", "in.s"], workdir)
    if rc == 0 and "Error" not in log:
        out["gas"] = dict(ok=True, text=canon(os.path.join(workdir, "ref.o")), log=log)
    else:
        line, msg = first_error(log, True)
        out["gas"] = dict(ok=False, text=msg, line=line, log=log)
    rc, log = run([RSASM, "-a", target, "-o", "rs.o", "in.s"], workdir)
    if rc == 0:
        out["rsasm"] = dict(ok=True, text=canon(os.path.join(workdir, "rs.o")), log=log)
    elif rc == 1:
        _, msg = first_error(log, False)
        out["rsasm"] = dict(ok=False, text=msg, line=rsasm_error_line(log), log=log)
    else:
        out["rsasm"] = dict(ok=False, text=f"CRASH {rc}: {log.strip()[:200]}", line="?", log=log)
    return out["gas"], out["rsasm"]


# ============================================================================
# Programs
# ============================================================================

# Numbers a literal load may ask for. Each group is there for what GNU as
# does with it: a number an ARM `mov` or `mvn` can hold, or a Thumb `mov.w`,
# `mvn.w` or `movw`, is assembled as that instruction and never reaches a
# pool; the rest do.
MOV_CONSTS = [0, 1, 12, 0xff, 0x104, 0xff000000, 0x3fc, -1, -2, 0xfc000003]
MOVW_CONSTS = [0x1234, 0xffff, 0x8001, 0xabcd]
BIG_CONSTS = [0x12345678, 0x11223344, 0xdeadbeef, 0x01020304, 0xfffffffe,
              0x7fffffff, 0x80000001, 0xcafebabe, 0x55556666,
              # The halves of the doubleword values below, which a four-byte
              # entry may share a slot with -- or take the second half of,
              # once an eight-byte entry has been written over the first.
              0x55667788, 0x99887766, 0xaabbccdd, 0x400921fb, 0x54442d18]
# Doubleword values for `vldr dN, =`: the ones a NEON `vmov` immediate or
# `fconstd` can hold, and the ones only a pool can.
D_CONSTS = [0, 1, 0xff, 0x3ff0000000000000, 0xffffffff00000000, 0x00ff00ff00ff00ff,
            0x1122334455667788, 0x99887766aabbccdd, 0xdeadbeefcafebabe,
            0x400921fb54442d18, -1, -2,
            # A low half of zero, which a padding slot holds too, and a value
            # whose halves are the two BIG_CONSTS above it.
            0x1234567800000000, 0x1122334400000000]
S_CONSTS = [0x3f800000, 0x40000000, 0x12345678, 0, 1, 0xbf800000, 0x7f7fffff]

HALF_LOADS = ["ldrh", "ldrsh", "ldrsb", "ldrb"]

# name | the directive that switches to it | whether code may go in it
SECTIONS = [
    (".text", ".text", True),
    (".data", ".data", False),
    (".rodata", '.section .rodata,"a",%progbits', False),
    (".foo", '.section .foo,"ax",%progbits', True),
    (".bar", '.section .bar,"aw",%progbits', False),
]


class Program:
    """A random file, built statement by statement.

    Which section each label lands in is tracked as the statements are
    generated, so that a reference is one a linker could resolve: `adr`
    reaches only its own section (GNU as writes a wrong fixed value for one
    that does not, where rsasm refuses it), and a branch goes to a label in
    a section that holds code.
    """

    def __init__(self, rng, target, mutate, skip=()):
        self.rng = rng
        self.target = target
        self.thumb = target == "thumb"
        self.skip = set(skip)
        self.mutation = None
        self.stmts = []
        # Labels this program defines somewhere, and names it never defines,
        # which a literal entry has to relocate.
        self.labels = [f"l{i}" for i in range(rng.randrange(2, 6))]
        self.undefined = [f"ext{i}" for i in range(rng.randrange(1, 3))]
        self.where = {}
        # Of those, the ones data of an odd length left at an address no
        # instruction can have; see `code_label`.
        self.misaligned = set()
        # The `=` values this program has asked for already, so that it asks
        # again: a pool entry shared is a pool entry not appended, and which
        # slot a later literal lands in depends on it.
        self.used = []
        self.dused = []
        self.macros = []
        self.header = [".syntax unified"]
        if rng.random() < 0.5:
            self.header.append(f".globl {self.labels[0]}")
        # Where the statements so far have left the assembler.
        self.section = ".text"
        self.exec_section = True
        self.previous = ".text"
        self.stack = []
        # Data of an unknown length since the last alignment, per section: an
        # instruction after it would sit at an address no instruction can
        # have, which is a kind of program of its own (see KNOWN), not what
        # this is for. It is per section because that is where the location
        # counter is: leaving a section and coming back finds it where it was.
        self.dirty = {}
        self.gen(mutate)

    @property
    def after_data(self):
        return self.dirty.get(self.section, False)

    @after_data.setter
    def after_data(self, value):
        self.dirty[self.section] = value

    # -- the section the next statement goes in ----------------------------

    def switch(self, name, exec_ok):
        if name != self.section:
            self.previous = self.section
        self.section, self.exec_section = name, exec_ok

    def section_stmt(self):
        rng = self.rng
        choices = ["switch", "switch", "previous", "push"]
        if self.stack:
            choices.append("pop")
        what = rng.choice(choices)
        if what == "switch":
            name, directive, exec_ok = rng.choice(SECTIONS)
            self.switch(name, exec_ok)
            return directive
        if what == "previous":
            prev, self.previous = self.previous, self.section
            self.section = prev
            self.exec_section = next(
                (e for n, _d, e in SECTIONS if n == prev), True)
            return ".previous"
        if what == "push":
            name = f".push{rng.randrange(2)}"
            self.stack.append((self.section, self.previous, self.exec_section))
            self.section, self.exec_section = name, True
            return f'.pushsection {name},"ax",%progbits'
        self.section, self.previous, self.exec_section = self.stack.pop()
        return ".popsection"

    # -- pieces ------------------------------------------------------------

    def reg(self, lo=False):
        return f"r{self.rng.randrange(4) if lo else self.rng.randrange(11)}"

    def value(self):
        """The `=` operand of a word-sized literal load.

        A value this program has asked for already is asked for again often:
        an entry shared is an entry not appended, and which slot every later
        literal lands in follows from that."""
        rng = self.rng
        r = rng.random()
        if r < 0.2 and self.used:
            return rng.choice(self.used)
        if r < 0.4:
            v = str(rng.choice(MOV_CONSTS))
        elif r < 0.5:
            v = hex(rng.choice(MOVW_CONSTS))
        elif r < 0.75:
            v = hex(rng.choice(BIG_CONSTS))
        else:
            name = rng.choice(self.labels + self.undefined)
            v = name + rng.choice(["", "", "+4", "+0x100", "-8"])
        self.used.append(v)
        return v

    def dvalue(self):
        """The `=` operand of a `vldr dN`, which is eight bytes wide and has
        to be a number."""
        rng = self.rng
        if rng.random() < 0.25 and self.dused:
            return rng.choice(self.dused)
        v = hex(rng.choice(D_CONSTS)) if rng.random() < 0.8 else str(
            rng.choice(D_CONSTS))
        self.dused.append(v)
        return v

    def vldr(self):
        """A VFP pool load. A `d` register asks for an eight-byte entry, an
        `s` register for a four-byte one, and GNU as reads a data type on
        either and never looks at it."""
        rng = self.rng
        if rng.random() < 0.55:
            suffix = rng.choice(["", "", ".64", ".f64"])
            return f"vldr{suffix} d{rng.randrange(32)}, ={self.dvalue()}"
        suffix = rng.choice(["", "", ".32", ".f32"])
        v = rng.choice([hex(rng.choice(S_CONSTS))] * 3 + self.labels)
        self.used.append(v)
        return f"vldr{suffix} s{rng.randrange(32)}, ={v}"

    def here_label(self):
        """A label already placed in the section the next statement goes in,
        for an `adr`, or None.

        A label that data of an odd length left at an address no instruction
        can have is one of these: GNU as ORs the Thumb bit of a `.thumb_func`
        label into the `adr`'s *addend*, which at an odd address is not the
        same number as ORing it into the finished value, and that is a
        difference worth generating."""
        here = [n for n, s in self.where.items() if s == self.section]
        return self.rng.choice(here) if here else None

    def code_label(self):
        """A label in a section that holds code, for a branch; an undefined
        name otherwise, which is a relocation either way.

        A label that data of an odd length left at an address no instruction
        can have is not one: the two assemblers disagree about a branch to
        one (GNU as writes an ARM `bl` to an odd address and refuses a
        Thumb one; rsasm is the other way round), and it says nothing about
        pools."""
        code = [n for n, s in self.where.items()
                if s in (".text", ".foo", ".push0", ".push1")
                and n not in self.misaligned]
        code += self.undefined
        return self.rng.choice(code)

    # -- statements --------------------------------------------------------

    def insn(self):
        rng = self.rng
        r = rng.random()
        if r < 0.25:
            return f"ldr {self.reg()}, ={self.value()}"
        if r < 0.32 and "halfword" not in self.skip:
            return f"{rng.choice(HALF_LOADS)} {self.reg()}, ={self.value()}"
        if r < 0.42 and "vldr" not in self.skip:
            return self.vldr()
        if r < 0.5 and "adr" not in self.skip:
            target = self.here_label()
            if target:
                kind = "adrl" if not self.thumb and rng.random() < 0.3 else "adr"
                # An addend of its own, since GNU as sets the Thumb bit in the
                # addend and so changes nothing when it is already odd.
                addend = rng.choice(["", "", "", " + 1", " + 2", " - 1"])
                return f"{kind} {self.reg()}, {target}{addend}"
        if r < 0.6:
            return rng.choice([
                f"b {self.code_label()}", f"bl {self.code_label()}",
                f"beq {self.code_label()}", f"bne {self.code_label()}",
                f"blx {self.code_label()}",
            ])
        if r < 0.65 and self.thumb:
            return "it eq\n\tmoveq " + self.reg() + ", " + self.reg()
        return rng.choice([
            "nop", "bx lr", f"mov {self.reg()}, {self.reg()}",
            f"add {self.reg()}, {self.reg()}, #{rng.randrange(256)}",
            "push {r4, lr}", "pop {r4, pc}",
            f"ldr {self.reg()}, [{self.reg(True)}]",
            f"str {self.reg()}, [{self.reg(True)}, #4]",
        ])

    def data(self):
        rng = self.rng
        return rng.choice([
            f".byte {rng.randrange(256)}",
            f".byte {rng.randrange(256)}, {rng.randrange(256)}, {rng.randrange(256)}",
            f".short {rng.randrange(65536)}",
            f".word {rng.randrange(1 << 31)}",
            f".word {rng.choice(list(self.where) or self.undefined)}",
            f".word {self.undefined[0]}",
            '.asciz "hello"',
            '.ascii "ab"',
            f".space {rng.choice([1, 2, 3, 4, 8, 12, 40])}",
            f".align {rng.choice([1, 2, 3, 4])}",
            f".balign {rng.choice([2, 4, 8, 16])}",
            f".p2align {rng.choice([1, 2, 3])}",
        ])

    def gen(self, mutate):
        rng = self.rng
        if "macro" not in self.skip and rng.random() < 0.3:
            body = [f"\tldr r{rng.randrange(8)}, =\\v"]
            if rng.random() < 0.6:
                body.append("\t.ltorg")
            self.header += [".macro lit v"] + body + [".endm"]
            self.macros.append("lit")
        if self.thumb and rng.random() < 0.3:
            self.stmts.append(".thumb_func")
        n = rng.randrange(6, 30)
        todo = list(self.labels)
        rng.shuffle(todo)
        # A pool at the very start, as the file that started this had.
        if rng.random() < 0.15:
            self.stmts.append(rng.choice([".ltorg", ".pool"]))
        for _ in range(n):
            if todo and rng.random() < 0.3:
                self.place(todo.pop())
            self.stmts.append(self.statement())
        for name in todo:
            self.place(name)
            self.stmts.append(self.code("nop") if self.exec_section
                              else ".word 0")
        if rng.random() < 0.4:
            self.stmts.append(rng.choice([".ltorg", ".pool"]))
        if mutate:
            self.add_mutation()

    def place(self, name):
        if self.thumb and self.exec_section and self.rng.random() < 0.2:
            self.stmts.append(".thumb_func")
        self.where[name] = self.section
        if self.after_data:
            self.misaligned.add(name)
        self.stmts.append(f"{name}:")

    def code(self, *stmts):
        """One or more instructions, behind an alignment where data of an odd
        length came before them: an instruction at an address no instruction
        can have is a kind of program of its own, and the two assemblers
        disagree about several of them (which PC an `adr` rounds to, and
        whether a branch to a misaligned label is refused). It says nothing
        about pools, which is what this is for."""
        lines = list(stmts)
        if self.after_data:
            self.after_data = False
            lines.insert(0, self.rng.choice([".align 2", ".balign 4", ".p2align 2"]))
        return "\n\t".join(lines)

    def statement(self):
        """One statement, or a small block of them."""
        rng = self.rng
        r = rng.random()
        if r < 0.45 and self.exec_section:
            return self.code(self.insn())
        if r < 0.55:
            return rng.choice([".ltorg", ".pool"])
        if r < 0.62 and self.macros and self.exec_section:
            return self.code(f"lit {self.value()}")
        if r < 0.68 and "macro" not in self.skip and self.exec_section:
            body = "\n".join("\t" + self.insn() for _ in range(rng.randrange(1, 3)))
            return self.code(f".rept {rng.randrange(2, 4)}\n{body}\n.endr")
        if r < 0.8 and "data" not in self.skip:
            stmt = self.data()
            self.after_data = not stmt.startswith((".align", ".balign", ".p2align"))
            return stmt
        if r < 0.9 and "state" not in self.skip:
            return rng.choice([".arm", ".thumb", ".code 16", ".code 32",
                               ".align 2\n\t.arm", ".thumb"])
        if "sections" in self.skip:
            return self.data()
        if r < 0.99 or "subsec" in self.skip:
            return self.section_stmt()
        return rng.choice([".text 1", ".text 2", ".text 0", ".data 1",
                           f".subsection {rng.randrange(3)}"])

    def add_mutation(self):
        rng = self.rng
        kind, stmt = rng.choice([
            ("far pool", f".space {rng.choice([4100, 5000, 1100])}"),
            ("store from a pool", f"str {self.reg()}, =4"),
            ("vector store from a pool", "vstr d0, =1"),
            ("literal wider than a word", "ldr r0, =0x1122334455667788"),
            ("literal wider than a doubleword", "vldr d0, =0x112233445566778899"),
            ("float literal", "ldr r0, =1.5"),
            ("pool entry that is not a number", "vldr d0, =l0"),
            ("doubleword pool load", "ldrd r0, r1, =0x1122334455667788"),
            ("halfword pool load out of reach",
             f"ldrh r0, =0x12345678\n\t.space {rng.choice([300, 600])}"),
            ("a quadword register", "vldr q0, =1"),
            ("a lane", "vldr d0[1], =1"),
            ("a narrow literal load", "ldrh.n r0, =4"),
        ])
        self.mutation = kind
        at = rng.randrange(len(self.stmts) + 1)
        self.stmts.insert(at, stmt)

    # -- text --------------------------------------------------------------

    def source(self, stmts=None):
        stmts = self.stmts if stmts is None else stmts
        out = ["\t" + h if not h.startswith(("\t", " ")) else h for h in self.header]
        for s in stmts:
            for line in s.split("\n"):
                if line.endswith(":") or line.startswith((".macro", ".endm", ".rept", ".endr")):
                    out.append(line)
                elif line.startswith("\t"):
                    out.append(line)
                else:
                    out.append("\t" + line)
        return "\n".join(out) + "\n"


# ============================================================================
# Comparing
# ============================================================================


def known(gas, rsasm):
    if gas["ok"] and not rsasm["ok"]:
        for needle, why in KNOWN:
            if needle in rsasm["text"]:
                return why
    if rsasm["ok"] and not gas["ok"]:
        for needle, why in KNOWN_GAS:
            if needle in gas["text"]:
                return why
    return None


def canon_parts(text):
    """A canonical object split into the parts this compares: the bytes of
    each section by name, the relocations by (table, offset, type), and every
    other line in order."""
    sections, relocs, rest = {}, {}, []
    name = None
    for line in text.splitlines():
        if line.startswith("section "):
            name = line.split()[1]
            rest.append(line)
        elif line.startswith("  ") and name:
            sections[name] = line.strip()
        elif line.startswith("."):
            f = line.split()
            if len(f) == 4:
                relocs[tuple(f[:3])] = f[3]
                continue
            rest.append(line)
        else:
            rest.append(line)
    return sections, relocs, rest


def known_object(gas, rsasm):
    """The one difference between two objects that this fuzzer is not about,
    or None if there is anything else.

    *Which symbol a relocation names.* GNU as's `arm_fix_adjustable`
    relocates a reference to a local label against the label's *section*,
    folding the label's offset into the field; llvm-mc names the label and
    leaves the field alone, and rsasm follows it (`relocates_with_label` in
    src/arch/arm/mod.rs, which tools/dwarf-diff compares against llvm-mc).
    A linker reads the two the same. A branch out of its own section is how
    to write one: the relocation's table, offset and type agree, both
    targets name the same section, and the four bytes of the field differ."""
    g_sec, g_rel, g_rest = canon_parts(gas)
    r_sec, r_rel, r_rest = canon_parts(rsasm)
    if g_rel.keys() != r_rel.keys() or g_rest != r_rest:
        return None
    reason = None
    # Where the two may differ, as (first, last) byte offsets per section.
    spans = {}
    for key, target in g_rel.items():
        other = r_rel[key]
        if target == other:
            continue
        if "+" not in target or "+" not in other:
            return None
        if target.rsplit("+", 1)[0] != other.rsplit("+", 1)[0]:
            return None
        table, offset, _ = key
        if not table.startswith((".rel.", ".rela.")):
            return None
        at = int(offset, 16)
        spans.setdefault("." + table.split(".", 2)[2], []).append((at, at + 3))
        reason = "a relocation naming the label, as llvm-mc names it"
    if reason is None:
        return None
    for name, hexed in g_sec.items():
        other = r_sec.get(name)
        if other == hexed:
            continue
        if other is None or len(other) != len(hexed):
            return None
        for i in range(0, len(hexed), 2):
            if hexed[i:i + 2] == other[i:i + 2]:
                continue
            if not any(lo <= i // 2 <= hi for lo, hi in spans.get(name, ())):
                return None
    return reason


def classify(gas, rsasm):
    if gas["ok"] != rsasm["ok"]:
        why = known(gas, rsasm)
        if why:
            return "known", why
        return "rsasm", "accepts" if rsasm["ok"] else "refuses"
    if not gas["ok"]:
        # Both refused. Which line each stopped on is reported, since a
        # refusal for another reason would agree here by accident, but it is
        # not a finding on its own: the two word their messages differently
        # and stop at different points in a file.
        if gas["line"] != rsasm["line"] and "?" not in (gas["line"], rsasm["line"]):
            return "agree", "refused elsewhere"
        return "agree", None
    if gas["text"] != rsasm["text"]:
        why = known_object(gas["text"], rsasm["text"])
        if why:
            return "known", why
        return "rsasm", "object"
    return "agree", None


def reduce(prog, kind, target, workdir):
    stmts = list(prog.stmts)
    i = len(stmts) - 1
    while i >= 0:
        trial = stmts[:i] + stmts[i + 1:]
        g, r = assemble(prog.source(trial), target, workdir)
        if classify(g, r) == ("rsasm", kind):
            stmts = trial
        i -= 1
    return stmts


def run_case(job):
    seed, target, mutate, skip = job
    rng = random.Random(seed)
    prog = Program(rng, target, mutate, skip)
    with tempfile.TemporaryDirectory() as d:
        g, r = assemble(prog.source(), target, d)
        cls, detail = classify(g, r)
        shown = prog.source()
        if cls == "rsasm":
            shown = prog.source(reduce(prog, detail, target, d))
            g, r = assemble(shown, target, d)
    return dict(seed=seed, target=target, cls=cls, detail=detail,
                mutation=prog.mutation, source=shown, gas=g, rsasm=r)


def diff_text(a, b, limit=40):
    import difflib
    lines = list(difflib.unified_diff(a.splitlines(), b.splitlines(), "gas", "rsasm",
                                      n=0, lineterm=""))
    return "\n".join(lines[2:limit])


def fuzz(args):
    import multiprocessing

    targets = [args.target] if args.target else list(TARGETS)
    skip = tuple(s for s in args.skip.split(",") if s)
    for s in skip:
        if s not in FEATURES:
            sys.exit(f"--skip {s!r} is not one of " + ", ".join(FEATURES))
    rng = random.Random(args.seed)
    jobs = [(rng.randrange(1 << 30), rng.choice(targets),
             rng.random() < args.mutations, skip) for _ in range(args.count)]
    workers = args.jobs or max(1, (os.cpu_count() or 2) - 2)
    results = []
    with multiprocessing.Pool(workers) as pool:
        for res in pool.imap_unordered(run_case, jobs, chunksize=2):
            results.append(res)
            if args.progress and len(results) % args.progress == 0:
                bad = sum(1 for r in results if r["cls"] == "rsasm")
                print(f"  {len(results)} programs, {bad} findings", flush=True)
    totals = collections.Counter(r["cls"] for r in results)
    print(f"=== {len(results)} programs: "
          + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    accepted = sum(1 for r in results if r["cls"] == "agree" and r["gas"]["ok"])
    elsewhere = sum(1 for r in results if r["detail"] == "refused elsewhere")
    print(f"  agreed on an object: {accepted}, agreed on refusing: {totals['agree'] - accepted}"
          f" ({elsewhere} of them stopping on different lines)")
    reasons = collections.Counter(r["detail"] for r in results if r["cls"] == "known")
    if reasons:
        print("  known: " + ", ".join(f"{k} {v}" for k, v in reasons.most_common()))
    findings = [r for r in results if r["cls"] == "rsasm"]
    findings.sort(key=lambda r: len(r["source"]))
    groups = collections.Counter((f["detail"], f["target"]) for f in findings)
    if groups:
        print("  findings: " + ", ".join(f"{d} [{t}] {n}" for (d, t), n in groups.most_common()))
    for f in findings[: args.limit]:
        print(f"--- [{f['target']}] seed {f['seed']}: {f['detail']}"
              + (f" (mutation: {f['mutation']})" if f["mutation"] else ""))
        print("    " + f["source"].rstrip().replace("\n", "\n    "))
        g, r = f["gas"], f["rsasm"]
        if f["detail"] == "object":
            print(diff_text(g["text"], r["text"]))
        else:
            print(f"  gas:   {g['text'][:200]}\n  rsasm: {r['text'][:200]}")
    if len(findings) > args.limit:
        print(f"... {len(findings) - args.limit} more findings")
    # The last line is the one tools/fuzz/run.sh reads.
    print(f"--- arm-programs: {len(results)} case(s) compared, {len(findings)} finding(s)")
    return 1 if findings else 0


def check(args):
    source = open(args.file).read()
    with tempfile.TemporaryDirectory() as d:
        g, r = assemble(source, args.target, d)
    cls, detail = classify(g, r)
    print(cls + (f" ({detail})" if detail else ""))
    if cls != "agree":
        if detail == "object":
            print(diff_text(g["text"], r["text"], 200))
        else:
            print(f"gas:   {g['text'][:400]}\nrsasm: {r['text'][:400]}")
    return 1 if cls == "rsasm" else 0


def main():
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    z = sub.add_parser("fuzz", help="generate random programs and compare objects")
    z.add_argument("--seed", type=int, default=1)
    z.add_argument("--count", type=int, default=1000)
    z.add_argument("--target", choices=sorted(TARGETS), help="default: both")
    z.add_argument("--mutations", type=float, default=0.15)
    z.add_argument("--skip", default="", help="leave features out: " + ",".join(FEATURES))
    z.add_argument("--jobs", type=int, default=0)
    z.add_argument("--limit", type=int, default=20, help="findings shown")
    z.add_argument("--progress", type=int, default=0, help="report every N programs")
    c = sub.add_parser("check", help="compare one program")
    c.add_argument("--target", choices=sorted(TARGETS), default="arm")
    c.add_argument("file")
    args = ap.parse_args()
    if not os.path.exists(GAS):
        sys.exit(f"no arm-none-eabi-as at {GAS}; run tools/oracles/build.sh")
    sys.exit(fuzz(args) if args.cmd == "fuzz" else check(args))


if __name__ == "__main__":
    main()
