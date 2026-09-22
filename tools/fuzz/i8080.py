#!/usr/bin/env python3
"""Differential fuzzer for rsasm's Intel 8080 backend.

Random whole programs are generated from a table of all 244 8080 opcodes
written from Intel's assembly manual -- not from rsasm's own tables -- and
assembled twice: by rsasm in its 8-bit dialect, and by the Macro Assembler AS,
which is the only reference that reads Intel's mnemonics faithfully (see
`tools/xas-diff/README.md`). The two flat images are compared byte for byte.

    AS        `asl -cpu 8080` writes a code file, `p2bin -q -l 0` turns it
              into an image whose first byte is the lowest address written --
              the same invocation `tools/xas-diff/run.sh` uses.
    rsasm     `rsasm -a i8080 -d 8bit -f bin`, whose image starts at the
              program's `ORG`.

A program is labels, equates, `ORG`, `DB`/`DW`/`DS` and instructions with
operands of every shape: registers and register pairs, `M`, immediates at the
ends of their range, `$` and `$+n`, forward and backward references, and
addresses written in each of the radixes both read (`12H`, `1010B`, `377Q`,
decimal, `'c'`).

    tools/fuzz/i8080.py fuzz --count 6000
    tools/fuzz/i8080.py fuzz --count 2000 --seed 7 --mutations 0.5
    tools/fuzz/i8080.py check prog.s        # one program, or a corpus file

`check` reads a file of programs in `tools/xas-diff`'s format (snippets
separated by `=== name`, or one program if there is no such line) and prints
what each assembler made of each. A finding prints its whole program, so
saving that program to a file and running `check` on it is the way to narrow
one down; the same `--seed` and `--count` generate the same cases.

Each case is classified:

    agree       the two images are the same, or both assemblers refused.
    rsasm       they differ. These are the findings; the exit status is 1 if
                there are any.
    stax-hl     AS assembles `STAX H` and `LDAX H` as `MOV M,A` and `MOV A,M`
                and rsasm refuses them, on purpose: only BC and DE can be
                used indirectly, and `src/arch/retro/i8080.rs` says so --
                "`STAX H` is not an instruction".

Some programs are made invalid on purpose (`--mutations`, default 0.25): an
immediate or an `RST` vector past the end of its field, a register pair that
does not exist for the instruction, a missing or extra operand, a reference to
nothing, a label defined twice.

What this deliberately does not generate, since the two are known to part
company there and nothing is settled by generating it again:

  * `$` inside a `DB` or `DW` list, which is the item's address to rsasm and
    the statement's to AS (`tools/xas-diff/README.md`, under 8080).
  * `^`, which is exponentiation in AS and XOR in the 8-bit dialect, as it is
    in C; AS spells XOR `!`, which the dialect does not read.
  * a negative port in `IN` or `OUT`: AS takes a negative immediate anywhere
    else, but reads a port as unsigned, where rsasm's 8-bit fields all run
    from -128 to 255.
  * reserved space at the start or the end of a program: `DS` emits nothing,
    so AS's image begins at the first byte actually written and ends at the
    last, where rsasm's covers the whole span from `ORG`. A `DS` between two
    instructions is generated, and there `p2bin -l 0` fills the gap.
  * an `ORG` that goes backwards, or past $FFFF: rsasm refuses the first and
    pads for the second, AS does the opposite.
  * two spellings of a symbol that differ only in case: AS folds them
    together and rsasm does not.
  * AS's own extensions -- `DUP`, `MOD`, `SHL`, `NOT`/`AND` as word
    operators, a string of more than two characters in a `DW` -- and a `D`
    radix suffix, which AS has not got.

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

# --- the instruction set -----------------------------------------------------
#
# Operand kinds:
#   r8      B C D E H L M A        a register, or the byte at HL
#   rp      B D H SP               a pair, named by its high register
#   pp      B D H PSW              the pairs PUSH and POP take
#   rp2     B D                    the pairs that can be used indirectly
#   d8      an immediate           port an I/O port, which AS reads as
#                                  unsigned where an immediate may be negative
#   d16 a16 an address             vec  an RST vector

R8 = ["B", "C", "D", "E", "H", "L", "M", "A"]
RP = ["B", "D", "H", "SP"]
PP = ["B", "D", "H", "PSW"]
RP2 = ["B", "D"]

NO_OPERAND = ("NOP RLC RRC RAL RAR DAA CMA STC CMC HLT RET PCHL XTHL XCHG "
              "SPHL DI EI RNZ RZ RNC RC RPO RPE RP RM").split()
ARITH = "ADD ADC SUB SBB ANA XRA ORA CMP".split()
ARITH_IMM = "ADI ACI SUI SBI ANI XRI ORI CPI".split()
ADDR16 = ("JMP CALL JNZ JZ JNC JC JPO JPE JP JM CNZ CZ CNC CC CPO CPE CP CM "
          "SHLD LHLD STA LDA").split()


def build_forms():
    """(mnemonic, operand kinds, encoded size). 244 opcodes between them:
    63 MOV, 64 accumulator operations, 25 without an operand, and the rest."""
    f = [("MOV", ("r8", "r8"), 1), ("MVI", ("r8", "d8"), 2),
         ("INR", ("r8",), 1), ("DCR", ("r8",), 1)]
    for m in ARITH:
        f.append((m, ("r8",), 1))
    for m in ARITH_IMM:
        f.append((m, ("d8",), 2))
    f += [("LXI", ("rp", "d16"), 3), ("DAD", ("rp",), 1),
          ("INX", ("rp",), 1), ("DCX", ("rp",), 1),
          ("PUSH", ("pp",), 1), ("POP", ("pp",), 1),
          ("STAX", ("rp2",), 1), ("LDAX", ("rp2",), 1),
          ("IN", ("port",), 2), ("OUT", ("port",), 2), ("RST", ("vec",), 1)]
    for m in NO_OPERAND:
        f.append((m, (), 1))
    for m in ADDR16:
        f.append((m, ("a16",), 3))
    return f


FORMS = build_forms()

# --- numbers -----------------------------------------------------------------


def render_num(v, rng):
    """A number in one of the radixes AS and the 8-bit dialect share. AS has
    no `D` suffix, so a decimal number is written bare."""
    neg = v < 0
    a = -v if neg else v
    r = rng.random()
    if r < 0.45:
        text = "%XH" % a
        if text[0] not in "0123456789":
            text = "0" + text
    elif r < 0.7:
        text = "%d" % a
    elif r < 0.8 and a <= 0xFF:
        text = "%sB" % bin(a)[2:]
    elif r < 0.88 and a <= 0xFFFF:
        text = "%oQ" % a
    elif a < 0x80 and chr(a).isalnum():
        # Alphanumeric only: a quote or a comma inside a character literal is
        # punctuation to one parser or the other.
        text = "'%s'" % chr(a)
    else:
        text = "0%XH" % a
    return "-" + text if neg else text


def render_expr(e, rng):
    """Expressions are always bracketed, so no rule about precedence is being
    tested by accident; what each operator means is what the corpus checks."""
    k = e[0]
    if k == "n":
        return render_num(e[1], rng)
    if k == "sym":
        return e[1]
    if k == "off":
        return "%s%+d" % (e[1], e[2])
    if k == "here":
        return "$" if e[1] == 0 else "$%+d" % e[1]
    if k == "bin":
        return "(%s %s %s)" % (render_expr(e[2], rng), e[1], render_expr(e[3], rng))
    raise ValueError(e)


# --- generating a program ----------------------------------------------------
#
# Statements:
#   ("org", addr)  ("equ", name, value, "EQU"|"SET")  ("label", name)
#   ("insn", text) ("db", [expr]) ("dw", [expr]) ("str", text) ("ds", n)


class Gen:
    """Builds one program, tracking the address so that a later `ORG` can be
    put in front of it rather than behind."""

    def __init__(self, rng, mutate):
        self.rng = rng
        self.mutate = mutate
        self.items = []
        self.addr = 0
        self.equates = {}       # name -> value, defined before the code
        self.labels = []        # placed so far
        self.future = []        # promised, placed later in the body

    def emit(self, item, size):
        self.items.append(item)
        self.addr += size

    # -- operands -------------------------------------------------------------

    def byte_expr(self, signed=True):
        rng = self.rng
        r = rng.random()
        small = [n for n, v in self.equates.items() if 0 <= v <= 0xFF]
        if r < 0.12 and small:
            return ("sym", rng.choice(small))
        if r < 0.24:
            # The high or low byte of an address, written the way AS reads it:
            # there is no `<`/`>` selector here, only shifts and masks.
            names = sorted(self.equates) + self.labels + self.future
            base = ("sym", rng.choice(names)) if names else ("n", rng.randint(0, 0xFFFF))
            op, rhs = rng.choice([(">>", 8), ("&", 0xFF)])
            return ("bin", op, base, ("n", rhs))
        if r < 0.32:
            # No `^`: it is exponentiation in AS, where XOR is `!`, so the two
            # would be reading different arithmetic rather than the same.
            return ("bin", rng.choice(["+", "-", "*", "&", "|", "<<", ">>"]),
                    ("n", rng.randint(4, 0x3F)), ("n", rng.randint(0, 3)))
        if r < 0.40 and signed:
            return ("n", -rng.randint(1, 128))
        return ("n", rng.choice([0, 1, 0x7F, 0x80, 0xFF, rng.randint(0, 0xFF)]))

    def word_expr(self):
        rng = self.rng
        r = rng.random()
        names = sorted(self.equates) + self.labels + self.future
        if r < 0.3 and names:
            n = rng.choice(names)
            return ("off", n, rng.choice([-2, -1, 1, 2])) if rng.random() < 0.3 else ("sym", n)
        if r < 0.4:
            return ("here", rng.choice([0, 3, 6, -3]))
        if r < 0.5:
            return ("n", -rng.randint(1, 0x8000))
        return ("n", rng.choice([0, 1, 0xFF, 0x100, 0x1234, 0xFFFF,
                                 rng.randint(0, 0xFFFF)]))

    def operand(self, kind):
        rng = self.rng
        if kind == "r8":
            return self.case(rng.choice(R8))
        if kind == "rp":
            return self.case(rng.choice(RP))
        if kind == "pp":
            return self.case(rng.choice(PP))
        if kind == "rp2":
            return self.case(rng.choice(RP2))
        if kind == "vec":
            return "%d" % rng.randint(0, 7)
        if kind == "d8":
            return render_expr(self.byte_expr(), rng)
        if kind == "port":
            # AS refuses a negative port number where it takes a negative
            # immediate, so a port is written unsigned.
            return render_expr(self.byte_expr(signed=False), rng)
        return render_expr(self.word_expr(), rng)

    def case(self, text):
        return text.lower() if self.rng.random() < 0.3 else text

    # -- statements -----------------------------------------------------------

    def instruction(self):
        rng = self.rng
        mn, kinds, size = rng.choice(FORMS)
        while mn == "MOV":
            # The one hole in the MOV square: that encoding is HLT.
            a, b = rng.choice(R8), rng.choice(R8)
            if a == "M" and b == "M":
                continue
            self.emit(("insn", "%s %s,%s" % (self.case(mn), self.case(a), self.case(b))), 1)
            return
        ops = ",".join(self.operand(k) for k in kinds)
        self.emit(("insn", ("%s %s" % (self.case(mn), ops)).strip()), size)

    def new_label(self):
        n = len(self.labels) + len(self.future)
        name = "L%d" % n
        while name in self.labels or name in self.future:
            n += 1
            name = "L%d" % n
        self.future.append(name)
        return name

    def place_label(self, name=None):
        if name is None:
            if self.future and self.rng.random() < 0.6:
                name = self.rng.choice(self.future)
            else:
                name = self.new_label()
        if name in self.future:
            self.future.remove(name)
        self.labels.append(name)
        self.items.append(("label", name))

    def data(self):
        rng = self.rng
        if rng.random() < 0.2:
            text = "".join(rng.choice("abcXYZ019 ") for _ in range(rng.randint(1, 8)))
            self.emit(("str", text), len(text))
            return
        n = rng.randint(1, 4)
        if rng.random() < 0.6:
            self.emit(("db", [self.clamped_byte() for _ in range(n)]), n)
        else:
            self.emit(("dw", [self.clamped_word() for _ in range(n)]), n * 2)

    def clamped_byte(self):
        """A data byte has to fit: unlike an immediate, `DB -129` is refused
        by both, and that belongs in a mutation rather than in every program."""
        e = self.byte_expr()
        if e[0] == "n" and not -128 <= e[1] <= 0xFF:
            return ("n", e[1] & 0xFF)
        return e

    def clamped_word(self):
        e = self.word_expr()
        # `$` in a data list means the item's address to rsasm and the
        # statement's to AS; see the module comment.
        if e[0] == "here":
            return ("n", self.rng.randint(0, 0xFFFF))
        if e[0] == "n" and not -0x8000 <= e[1] <= 0xFFFF:
            return ("n", e[1] & 0xFFFF)
        return e

    def reserve(self):
        n = self.rng.choice([1, 2, 3, 8, 16, self.rng.randint(1, 64)])
        self.emit(("ds", n), n)

    def mid_org(self):
        """A later `ORG` pads up to its address in both, which `p2bin -l 0`
        fills with the same zeros rsasm writes."""
        self.addr += self.rng.choice([1, 2, 16, 64, 100, 256])
        self.emit(("org", self.addr), 0)


# Lines with a register, a register pair or an operand count the instruction
# has not got. AS and rsasm both refuse every one of them.
NO_FORM = [
    "MOV M,M", "MOV B,SP", "MOV SP,A", "INR SP", "INR PSW", "PUSH SP",
    "POP SP", "STAX SP", "LDAX A", "STAX A", "DAD PSW", "INX PSW", "DCX PSW",
    "LXI PSW,1234H", "ADD A,B", "ADD", "MOV A", "MVI A", "NOP A", "JMP",
    "RST", "MOV A,B,C", "MVI M", "POP A",
]
# Values past the end of their field.
OUT_OF_RANGE = [
    "MVI A,256", "MVI A,-129", "ADI 300", "CPI 0FFFFH", "RST 8", "RST -1",
    "IN 256", "OUT 100H", "LXI B,-32769", "LXI H,10000H", "MVI M,-200",
]
# The one named deviation: AS reads `STAX H` and `LDAX H` as the equivalent
# `MOV M,A` and `MOV A,M`. rsasm refuses them, and says why in
# `src/arch/retro/i8080.rs`: "Only BC and DE can be used indirectly, so the
# `p` field is one bit wide here; `STAX H` is not an instruction."
STAX_HL = ["STAX H", "LDAX H", "stax h", "ldax h"]

# Weighted: the planted deviation is worth showing but should not crowd out
# the mutations that are meant to be refused on both sides.
MUTATIONS = (["no-form"] * 4 + ["range"] * 4 + ["undefined"] * 3
             + ["dup-label"] * 2 + ["stax-hl"])


def generate(rng, mutate):
    g = Gen(rng, mutate)
    # Well clear of $FFFF: an `ORG` past the top of memory is a case of its
    # own, refused by AS and padded by rsasm, and not what these programs are.
    org = rng.choice([0x0000, 0x0000, 0x0008, 0x0038, 0x0100, 0x0100, 0x0800,
                      0x1000, 0x2000, 0x4000])
    g.addr = org
    for i in range(rng.randint(0, 4)):
        g.equates["C%d" % i] = rng.choice(
            [rng.randint(0, 0xFF), rng.randint(0x100, 0xFFFF)])
    for _ in range(rng.randint(0, 3)):
        g.new_label()
    head = [("org", org)]
    for n in sorted(g.equates):
        head.append(("equ", n, g.equates[n], "EQU"))
    # `SET` is the redefinable one; it is given a name of its own so that a
    # later definition cannot collide with an `EQU`.
    if rng.random() < 0.15:
        head.append(("equ", "V", rng.randint(0, 0xFF), "SET"))
        g.equates["V"] = 0
    # AS's image starts at the first byte actually written, so a program has to
    # open with something that writes one.
    g.instruction()
    for _ in range(rng.randint(3, 30)):
        r = rng.random()
        if r < 0.64:
            g.instruction()
        elif r < 0.72:
            g.place_label()
        elif r < 0.84:
            g.data()
        elif r < 0.92:
            g.reserve()
        else:
            g.mid_org()
    for name in list(g.future):
        g.place_label(name)
    # ... and close with one, for the same reason.
    g.emit(("insn", "NOP"), 1)
    items = head + g.items
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
    if kind == "no-form":
        items[i] = ("insn", rng.choice(NO_FORM))
    elif kind == "range":
        items[i] = ("insn", rng.choice(OUT_OF_RANGE))
    elif kind == "stax-hl":
        items[i] = ("insn", rng.choice(STAX_HL))
        return items, "stax-hl"
    elif kind == "undefined":
        items[i] = ("insn", rng.choice(["LXI H,NOWHERE", "JMP NOWHERE",
                                        "MVI A,NOWHERE", "CALL NOWHERE"]))
    else:
        items.insert(i, ("label", "DUP0"))
        items.insert(i, ("label", "DUP0"))
    return items, ""


# --- rendering ---------------------------------------------------------------


def render_program(items, rng):
    out = []
    for it in items:
        k = it[0]
        if k == "org":
            out.append("\tORG\t%s" % render_num(it[1], rng))
        elif k == "equ":
            out.append("%s\t%s\t%s" % (it[1], it[3], render_num(it[2], rng)))
        elif k == "label":
            # Both spellings: a word in the first column is a label with or
            # without its colon.
            out.append("%s:" % it[1] if rng.random() < 0.6 else it[1])
        elif k == "insn":
            out.append("\t" + it[1])
        elif k == "str":
            quote = "'" if rng.random() < 0.6 else '"'
            out.append("\tDB\t%s%s%s" % (quote, it[1], quote))
        elif k == "ds":
            out.append("\tDS\t%s" % render_num(it[1], rng))
        else:
            out.append("\t%s\t%s" % (k.upper(),
                                     ",".join(render_expr(e, rng) for e in it[1])))
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
    """AS then p2bin, the pair tools/xas-diff/run.sh uses for this target."""
    with open(os.path.join(workdir, "as.s"), "w") as fh:
        fh.write(source)
    for f in ("as.p", "as.bin"):
        try:
            os.unlink(os.path.join(workdir, f))
        except OSError:
            pass
    code, log = run([os.path.join(BIN, "asl"), "-cpu", "8080", "-q",
                     "-o", "as.p", "as.s"], workdir)
    # `-q` keeps AS quiet, so anything with "error" in it is a refusal even
    # where the exit status is 0.
    if code != 0 or "error" in log.lower():
        return ("ERROR", first_error(log))
    code, log = run([os.path.join(BIN, "p2bin"), "-q", "-l", "0",
                     "as.p", "as.bin"], workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    return ("OK", image(os.path.join(workdir, "as.bin")) or b"")


def rsasm(source, workdir):
    src = os.path.join(workdir, "rs.s")
    out = os.path.join(workdir, "rs.bin")
    with open(src, "w") as fh:
        fh.write(source)
    code, log = run([RSASM, "-a", "i8080", "-d", "8bit", "-f", "bin",
                     "-o", out, src], workdir)
    if code != 0:
        return ("ERROR", first_error(log))
    return ("OK", image(out) or b"")


def same(a, b):
    if a[0] != b[0]:
        return False
    return a[0] == "ERROR" or a[1] == b[1]


def classify(ref, ours, expect=""):
    if same(ref, ours):
        return ("agree", "")
    # The one deviation these programs plant on purpose: see STAX_HL.
    if expect == "stax-hl" and ref[0] == "OK" and ours[0] == "ERROR":
        return ("stax-hl", "")
    return ("rsasm", "")


def compare(text, expect=""):
    with tempfile.TemporaryDirectory() as d:
        ref = asl(text, d)
        ours = rsasm(text, d)
    cls, detail = classify(ref, ours, expect)
    return {"class": cls, "detail": detail, "text": text, "as": ref, "rs": ours}


def one(job):
    seed, mutate = job
    rng = random.Random(seed)
    items, expect = generate(rng, mutate)
    r = compare(render_program(items, rng), expect)
    r["seed"] = seed
    return r


def fmt(res):
    if res[0] == "ERROR":
        return "ERROR " + res[1]
    return res[1].hex(" ")


def report(r, name=None):
    print("### %s%s" % (r["class"], " %s" % name if name else " seed %d" % r.get("seed", 0)))
    print("\n".join("    |" + l for l in r["text"].splitlines()))
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
    findings.sort(key=lambda r: len(r["text"]))
    for r in findings[: args.limit]:
        report(r)
    # The last line is the one tools/fuzz/run.sh reads.
    print("--- i8080: %d case(s) compared, %d finding(s)"
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
    print("--- i8080: %d case(s) compared, %d finding(s)" % (total, bad))
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
    ck.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    return check(args) if args.cmd == "check" else fuzz(args)


if __name__ == "__main__":
    sys.exit(main())
