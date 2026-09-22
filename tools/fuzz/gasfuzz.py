#!/usr/bin/env python3
"""Shared machinery for the instruction-level differential fuzzers.

The fuzzers written while each backend was built all do the same thing: put
every case in a section of its own, assemble a batch with each assembler at
once, re-run the ones that rejected a line without it, and compare the
sections' bytes and relocations. `x86.py`, `arm.py`, `powerpc.py` and
`msp430.py` each carry their own copy of that, because each grew alongside
its backend. The fuzzers added afterwards share this one instead; the code
here is theirs, not a refactoring of the older scripts.

What a fuzzer supplies is a `Target` (which assemblers to run and how) and a
generator of cases. What it gets back is a classification per case and a
report in the shape the older fuzzers print.

A case is `(mnemonic, text)`. `text` may hold several statements separated by
newlines; `L` in it is rewritten to the case's own label, which is defined
after the statements, and `ext` is left undefined, so both kinds of
relocation are compared.

Classes, as x86.py names them:

    agree       every reference and rsasm produced the same result.
    rsasm       the references agree and rsasm does not. The findings.
    deviation   the references agree and rsasm differs on purpose, as a rule
                the fuzzer passed in explains.
    split       the references disagree (only with two of them), listed with
                the side rsasm follows.
    convention  the references disagree in a way a rule explains, and rsasm
                follows the side the rule prefers.

With one reference there are no splits: a case is `agree`, `deviation` or
`rsasm`.
"""

import collections
import os
import re
import struct
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
RSASM = os.environ.get("RSASM", os.path.join(ROOT, "target", "debug", "rsasm"))
LLVM_MC = os.environ.get("LLVM_MC", "llvm-mc")
BINUTILS_SRC = os.path.join(ORACLES, "src", "binutils-2.47")


def oracle(name):
    """Path to a cross tool from tools/oracles/build.sh."""
    return os.path.join(ORACLES, "bin", name)


class Target:
    """One thing to fuzz: an rsasm architecture and the references for it.

    `gas` is a cross assembler's file name under the oracles' `bin`, `mc` an
    llvm-mc triple; either may be None, but not both. `head` is put at the
    top of every generated file (a `.option` or a `.set`, say), `tail` after
    each case's label, and `progbits` is `@progbits` except where the target
    reads `@` as a comment.
    """

    def __init__(self, key, arch, *, gas=None, gas_flags=(), mc=None,
                 mc_flags=(), rsasm_flags=(), head=(), tail=(),
                 progbits="@progbits", section=True, objdump=None,
                 objdump_flags=(), addr_bits=None, word_maker=None,
                 word_size=4, little=False, slot=0, objcopy=None,
                 rewrite=None):
        self.key = key
        self.arch = arch
        self.objdump = objdump
        self.objdump_flags = list(objdump_flags)
        self.addr_bits = addr_bits
        self.word_maker = word_maker
        self.word_size = word_size
        self.little = little
        # A 16-bit target has no ELF class, so rsasm writes it as a flat
        # image (`-f bin`). `slot` is how many bytes each case is given in
        # that image, which is what takes the place of a section per case;
        # `objcopy` turns the reference's object into the same thing.
        self.slot = slot
        self.objcopy = oracle(objcopy) if objcopy else None
        # Some targets' disassembly does not read back as itself: V850's
        # objdump prints a branch target as an address where its assembler
        # reads a displacement. `rewrite(text, offset)` puts such a line back
        # into the form the assembler takes, and is the target's own business.
        self.rewrite = rewrite
        self.gas = oracle(gas) if gas else None
        self.gas_flags = list(gas_flags)
        self.mc = mc
        self.mc_flags = list(mc_flags)
        self.rsasm_flags = list(rsasm_flags)
        self.head = list(head)
        self.tail = list(tail)
        self.progbits = progbits
        self.section = section

    @property
    def tools(self):
        out = []
        if self.gas:
            out.append("gas")
        if self.mc:
            out.append("mc")
        return out + ["rsasm"]

    def missing(self):
        """A message naming the reference that is not installed, or None."""
        if self.gas and not os.path.exists(self.gas):
            return f"no {self.gas}; run tools/oracles/build.sh"
        if self.objdump and not os.path.exists(oracle(self.objdump)):
            return f"no {oracle(self.objdump)}; run tools/oracles/build.sh"
        if not os.path.exists(RSASM):
            return f"no {RSASM}; run cargo build --all-features --bin rsasm"
        return None


# ---- reading objects -------------------------------------------------------

def read_elf(path):
    """Per section named `.tN`: (bytes as hex, relocations).

    A relocation is `(offset, type, target, addend)`, named the way a linker
    reads it rather than the way the assembler wrote it. A reference to a
    local label can be written either against that label with no addend or
    against its section with the label's offset as the addend -- assemblers
    differ, and the linker computes `S + A` either way -- so a local target
    is reduced to its section, with the symbol's value folded into the
    addend. That leaves a difference in the relocation *type*, the place it
    applies to or the value it will produce, which is what matters.
    """
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        return {}
    wide = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if wide:
        shoff, = struct.unpack_from(end + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", data, 0x3a)
        hdr = end + "IIQQQQIIQQ"
        symfmt, symsz = end + "IBBHQQ", 24
    else:
        shoff, = struct.unpack_from(end + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", data, 0x2e)
        hdr = end + "IIIIIIIIII"
        symfmt, symsz = end + "IIIBBH", 16
    shdrs = [struct.unpack_from(hdr, data, shoff + i * shentsize) for i in range(shnum)]

    def cstr(off):
        return data[off:data.index(b"\0", off)].decode("utf-8", "replace")

    names = [cstr(shdrs[shstrndx][4] + h[0]) for h in shdrs]
    syms = []
    for h in shdrs:
        if h[1] == 2:  # SHT_SYMTAB
            strtab = shdrs[h[6]]
            for j in range(h[5] // symsz):
                f = struct.unpack_from(symfmt, data, h[4] + j * symsz)
                if wide:
                    nm, info, _o, shndx, val = f[0], f[1], f[2], f[3], f[4]
                else:
                    nm, val, info, shndx = f[0], f[1], f[3], f[5]
                syms.append((cstr(strtab[4] + nm), val, info, shndx))
    out = {}
    for i, h in enumerate(shdrs):
        if names[i].startswith(".t") and h[1] == 1:  # SHT_PROGBITS
            out[names[i]] = [data[h[4]:h[4] + h[5]].hex(), []]
    for h in shdrs:
        if h[1] not in (4, 9):  # SHT_RELA, SHT_REL
            continue
        rela = h[1] == 4
        if wide:
            fmt, size = (end + "QQq" if rela else end + "QQ"), (24 if rela else 16)
        else:
            fmt, size = (end + "IIi" if rela else end + "II"), (12 if rela else 8)
        target = names[h[7]]
        if target not in out:
            continue
        for j in range(h[5] // size):
            f = struct.unpack_from(fmt, data, h[4] + j * size)
            off, info = f[0], f[1]
            addend = f[2] if rela else None
            if wide:
                sym, ty = info >> 32, info & 0xffffffff
            else:
                sym, ty = info >> 8, info & 0xff
            name, val, sinfo, shndx = syms[sym] if sym < len(syms) else ("?", 0, 0, 0)
            if sym == 0:
                who = "*ABS*"
            elif sinfo & 0xf == 3 or (sinfo >> 4 == 0 and shndx not in (0, 0xfff1)):
                # A section symbol, or a local one: name it by its section and
                # fold its value into the addend (see the docstring). With no
                # addend field there is nothing to fold it into, so the value
                # stays in the name.
                if shndx >= len(names):
                    who = name
                elif addend is None:
                    who = f"{names[shndx]}+{val:#x}"
                else:
                    who, addend = names[shndx], addend + val
            else:
                who = name
            out[target][1].append((off, ty, who, addend))
    for k in out:
        out[k][1].sort()
        out[k] = (out[k][0], tuple(out[k][1]))
    return out


# ---- running the assemblers -------------------------------------------------

GAS_RX = re.compile(r"in\.s:(\d+): (?:Error|Fatal error):\s*(.*)")
MC_RX = re.compile(r"in\.s:(\d+):\d+: error:\s*(.*)")
RSASM_AT = re.compile(r"-->\s*\S*in\.s:(\d+):")


def diagnostics(tool, stderr):
    """`{source line: message}` for the lines the tool refused.

    rsasm prints the message first and the location on the next line, so its
    output is read as a pair rather than line by line.
    """
    out = {}
    if tool == "gas":
        for m in GAS_RX.finditer(stderr):
            out.setdefault(int(m.group(1)), m.group(2).strip()[:160])
    elif tool == "mc":
        for m in MC_RX.finditer(stderr):
            out.setdefault(int(m.group(1)), m.group(2).strip()[:160])
    else:
        pending = None
        for line in stderr.split("\n"):
            if line.startswith("error"):
                pending = line.split(":", 1)[1].strip() if ":" in line else line
                continue
            m = RSASM_AT.search(line)
            if m and pending is not None:
                out.setdefault(int(m.group(1)), pending[:160])
                pending = None
    return out


def build_source(target, cases, skip):
    """The source for a batch, and which case each line belongs to."""
    lines = list(target.head)
    owner = {}
    n = 0
    for i, (_m, text) in cases:
        if i in skip:
            continue
        if target.slot:
            # One fixed-width slot per case in a flat image, which is what a
            # 16-bit target has instead of a section each. Only the cases
            # that are still in take a slot, so the slices line up with what
            # `assemble` hands back.
            lines.append(f"\t.org {n * target.slot}")
            n += 1
        elif target.section:
            lines.append(f'\t.section .t{i},"ax",{target.progbits}')
        for statement in text.split("\n"):
            owner[len(lines) + 1] = i
            lines.append("\t" + re.sub(r"\bL\b", f"L{i}", statement))
        lines.append(f"L{i}:")
        lines += target.tail
    if target.slot:
        lines.append(f"\t.org {n * target.slot}")
    return "\n".join(lines) + "\n", owner


def argv(tool, target, src, obj):
    if tool == "gas":
        return [target.gas, *target.gas_flags, "-o", obj, src]
    if tool == "mc":
        return [LLVM_MC, f"-triple={target.mc}", *target.mc_flags,
                "-filetype=obj", "-o", obj, src]
    if target.slot:
        return [RSASM, "-a", target.arch, "-f", "bin", *target.rsasm_flags,
                "-o", obj, src]
    return [RSASM, "-a", target.arch, *target.rsasm_flags, "-o", obj, src]


def assemble(tool, target, cases, workdir):
    """One result per case index: ("ok", (hex, relocs)) or ("err", message)."""
    src = os.path.join(workdir, "in.s")
    obj = os.path.join(workdir, tool + ".o")
    rejected = {}
    last = ""
    for _round in range(16):
        text, owner = build_source(target, cases, rejected)
        open(src, "w").write(text)
        try:
            p = subprocess.run(argv(tool, target, src, obj), capture_output=True,
                               text=True, cwd=workdir, timeout=120)
        except subprocess.TimeoutExpired:
            return {i: ("err", "timeout") for i, _ in cases}
        # GNU as can report an error and still exit 0 for a warning-shaped
        # diagnostic, so the text decides, not only the status.
        ok = p.returncode == 0 and "Error:" not in p.stderr
        # A crash, or a fatal error that blames no line: GNU as 2.47 gives up
        # on some RL78 input with "Infinite loop encountered whilst
        # attempting to compute the addresses of symbols", which is the
        # reference failing rather than refusing. Either way the tool has no
        # answer for one of these cases and the output does not say which.
        fatal = ("Fatal error" in p.stderr
                 and not any(ln in owner for ln in diagnostics(tool, p.stderr)))
        if p.returncode in (-11, -6, 101, 134, 139) or fatal:
            # Which case did it is not in the output, so the batch is halved
            # until one is left; that one gets the PANIC, and the rest of the
            # batch keeps its answers.
            live = [c for c in cases if c[0] not in rejected]
            if len(live) <= 1:
                for i, _ in live:
                    rejected[i] = "PANIC " + p.stderr.strip().split("\n")[0][:120]
                break
            mid = len(live) // 2
            out = {i: ("err", rejected[i]) for i, _ in cases if i in rejected}
            out.update(assemble(tool, target, live[:mid], workdir))
            out.update(assemble(tool, target, live[mid:], workdir))
            return out
        if ok:
            if target.slot:
                image = flat_image(tool, target, obj, workdir)
                live = [i for i, _ in cases if i not in rejected]
                out = {i: ("err", rejected[i]) for i in rejected}
                for n, i in enumerate(live):
                    out[i] = ("ok", (image[2 * n * target.slot:
                                           2 * (n + 1) * target.slot], ()))
                return out
            secs = read_elf(obj)
            return {i: ("err", rejected[i]) if i in rejected
                    else ("ok", secs.get(f".t{i}", ("", ())))
                    for i, _ in cases}
        last = p.stderr
        diag = diagnostics(tool, p.stderr)
        bad = {owner[ln]: msg for ln, msg in diag.items() if ln in owner}
        for i in set(bad) & set(rejected):
            del bad[i]
        if not bad:
            break
        rejected.update(bad)
    # Nothing more could be blamed on a line: if one case is left, it is the
    # one at fault; otherwise split the batch and try each half.
    live = [c for c in cases if c[0] not in rejected]
    if len(live) <= 1:
        out = {i: ("err", rejected[i]) for i in rejected if i in {c[0] for c in cases}}
        for i, _ in live:
            out[i] = ("err", _clean(last.strip().split("\n")[-1]) or "rejected")
        return out
    mid = len(live) // 2
    out = {i: ("err", rejected[i]) for i, _ in cases if i in rejected}
    out.update(assemble(tool, target, live[:mid], workdir))
    out.update(assemble(tool, target, live[mid:], workdir))
    return out


def _clean(msg):
    msg = re.sub(r"^\S*in\.s:\d+(:\d+)?:\s*", "", msg.strip())
    msg = re.sub(r"^(Error|error):\s*", "", msg)
    return msg[:160]


def run_batch(target, cases):
    """`{tool: {case index: result}}` for one batch of `(index, case)`."""
    with tempfile.TemporaryDirectory() as d:
        return {t: assemble(t, target, cases, d) for t in target.tools}


# ---- classification ---------------------------------------------------------

def key(res):
    return ("err",) if res[0] == "err" else ("ok",) + tuple(res[1])


class Rules:
    """The exceptions a fuzzer knows about.

    `deviations` are `(name, predicate)` where the predicate takes the case
    text, the per-tool results and the `Target`, and says whether rsasm
    differs from an agreeing reference on purpose. `splits` are
    `(name, predicate, preferred)` for the two-reference targets, as arm.py's
    KNOWN_SPLITS are.
    """

    def __init__(self, deviations=(), splits=()):
        self.deviations = list(deviations)
        self.splits = list(splits)


def panicked(r):
    return r[0] == "err" and str(r[1]).startswith("PANIC")


def classify(res, rules, text, target):
    """(class, detail) for one case's results, keyed by tool name."""
    if panicked(res["rsasm"]):
        return "rsasm", "panic"
    r = key(res["rsasm"])
    # A reference that crashed has no answer to compare against. llvm-mc 22
    # does crash on some SPARC input; that is the reference's bug, not
    # rsasm's, and the case is set aside rather than counted either way.
    refs = {t: key(v) for t, v in res.items()
            if t != "rsasm" and not panicked(v)}
    if not refs:
        return "skipped", "a reference crashed"
    if all(v == r for v in refs.values()):
        return "agree", None
    for name, pred in rules.deviations:
        if pred(text, res, target):
            return "deviation", name
    if len(refs) == 1:
        return "rsasm", None
    (ta, a), (tb, b) = sorted(refs.items())
    if a == b:
        return "rsasm", None
    follows = ta if r == a else tb if r == b else "neither"
    for name, pred, preferred in rules.splits:
        if pred(text, res, target):
            if follows == "neither":
                return "rsasm", name
            if preferred and follows != preferred:
                return "split", f"{name}:{follows}"
            return "convention", f"{name}:{follows}"
    return "split", follows


# ---- the driver -------------------------------------------------------------

def show(res):
    if res[0] == "err":
        return f"ERROR ({res[1]})" if res[1] else "ERROR"
    data, relocs = res[1]
    out = " ".join(data[i:i + 2] for i in range(0, len(data), 2)) or "(empty)"
    if relocs:
        out += " | " + " ".join(f"{o:#x}:{t}:{w}" + ("" if a is None else f"{a:+#x}")
                                for o, t, w, a in relocs)
    return out[:220]


SKIP_RX = re.compile(r"^\.skip (\d+)\n")


def trim_skip(text, res):
    """Drops the padding a `.skip` put in front of the instruction.

    A case disassembled at some offset carries a `.skip` so that it is
    assembled where it was read, which makes every tool's section start with
    that many zero bytes. They are the same for all of them and they drown
    the instruction in the report, so they come off -- unless one tool put
    something else there, in which case they stay and the difference shows.
    """
    m = SKIP_RX.match(text)
    if not m:
        return res
    n = int(m.group(1))
    pad = "00" * n
    if any(v[0] == "ok" and not v[1][0].startswith(pad) for v in res.values()):
        return res
    return {
        k: v if v[0] != "ok" else
        ("ok", (v[1][0][2 * n:],
                tuple((o - n, ty, who, a) for o, ty, who, a in v[1][1])))
        for k, v in res.items()
    }


def compare(target, cases, rules, offset=0):
    """`[(target key, mnemonic, text, class, detail, results)]` for a batch."""
    indexed = [(offset + n, c) for n, c in enumerate(cases)]
    res = run_batch(target, indexed)
    out = []
    for i, (m, text) in indexed:
        per = {t: res[t].get(i, ("err", "missing")) for t in target.tools}
        cls, detail = classify(per, rules, text, target)
        out.append((target.key, m, text, cls, detail, trim_skip(text, per)))
    return out


def drive(name, jobs_spec, rules, limit=40, batch=200, no_splits=False):
    """Run the batches, report, and return the exit status.

    `jobs_spec` is a list of `(target, [case, ...])`.
    """
    batches = []
    for target, cases in jobs_spec:
        for b in range(0, len(cases), batch):
            batches.append((target, cases[b:b + batch], b))
    workers = min(len(batches) or 1, os.cpu_count() or 4)
    results = []
    with ThreadPoolExecutor(workers) as ex:
        for part in ex.map(lambda j: compare(j[0], j[1], rules, j[2]), batches):
            results += part
    return report(name, results, limit, no_splits)


LISTED = {"rsasm": "rsasm differs from the reference(s)",
          "split": "references disagree"}


def report(name, results, limit, no_splits=False):
    totals = collections.Counter()
    by_target = collections.defaultdict(collections.Counter)
    details = collections.Counter()
    buckets = collections.OrderedDict()
    for tgt, mnem, text, cls, detail, per in results:
        totals[cls] += 1
        by_target[tgt][cls] += 1
        if cls != "agree" and detail:
            details[f"{cls}:{detail}"] += 1
        if cls in LISTED:
            k = (cls, detail, tgt, mnem,
                 tuple(sorted((t, v[0]) for t, v in per.items())))
            b = buckets.setdefault(k, [0, None])
            b[0] += 1
            if b[1] is None or len(text) < len(b[1][0]):
                b[1] = (text, per)
    print(f"=== {len(results)} cases: " +
          ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    for tgt, c in sorted(by_target.items()):
        print(f"  [{tgt}] " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
    if details:
        print("  explained: " + ", ".join(f"{k} {v}" for k, v in sorted(details.items())))
    for cls, title in LISTED.items():
        if cls == "split" and no_splits:
            continue
        rows = [(k, v) for k, v in buckets.items() if k[0] == cls]
        if not rows:
            continue
        print(f"--- {title}: {len(rows)} distinct")
        rows.sort(key=lambda kv: (-kv[1][0], kv[0][2], kv[0][3]))
        for k, (count, (text, per)) in rows[:limit]:
            tag = f"[{k[2]}]" + (f" (x{count})" if count > 1 else "")
            extra = f" ({k[1]})" if k[1] else ""
            print(f"{tag} {text.replace(chr(10), ' ; ')}{extra}")
            for t in sorted(per):
                print(f"    {t:<6} {show(per[t])}")
        if len(rows) > limit:
            print(f"    ... {len(rows) - limit} more (raise --limit)")
    print(f"--- {name}: {len(results)} case(s) compared, {totals['rsasm']} finding(s)")
    return 1 if totals["rsasm"] else 0


def add_fuzz_args(parser, count=20000, limit=40):
    """The command line every fuzzer shares."""
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--count", type=int, default=count,
                        help="total cases, split across targets")
    parser.add_argument("--only", help="regex on the mnemonic")
    parser.add_argument("--mutations", type=float, default=0.25,
                        help="fraction of cases made deliberately invalid")
    parser.add_argument("--batch", type=int, default=200)
    parser.add_argument("--limit", type=int, default=limit,
                        help="distinct findings printed")
    parser.add_argument("--no-splits", action="store_true")
    parser.add_argument("--print-cases", action="store_true",
                        help="print the generated cases instead of running them")
    return parser


def generate(rng, maker, targets, count, only=None, mutations=0.25):
    """`[(target, cases)]`, `count` cases in all, spread over the targets."""
    jobs = []
    per = max(1, count // len(targets))
    for t in targets:
        cases = []
        tries = 0
        while len(cases) < per and tries < per * 400:
            tries += 1
            c = maker(rng, t, rng.random() < mutations)
            if c is None:
                continue
            if only and not re.search(only, c[0]):
                continue
            cases.append(c)
        jobs.append((t, cases))
    return jobs


# ---- cases taken from a disassembler ----------------------------------------
#
# aarch64.py takes its cases from llvm-mc's disassembly of random instruction
# words rather than from a table of forms, which reaches every operand value a
# form allows and shares nothing with the assembler's own parser. The same
# trick works for every target with a GNU objdump: random bytes go in, and
# what comes out is one line per instruction, in the spelling GNU as reads.
#
# The offset matters. A branch prints its target as an absolute address, so a
# case is only the same instruction when it is assembled where it was
# disassembled; each case therefore carries the `.skip` that puts it back at
# its own offset.

DIS_LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+|[0-9a-f]{8})\s*\t?(\S.*)$")
DIS_SKIP = re.compile(r"^(\.\w+|\.word|\.long|\.short|\.byte|unknown|\(bad\)|bad)\b|\(bad\)|undefined")


def disassemble(objdump, flags, blob, workdir):
    """`[(offset, text)]` for the instructions GNU objdump reads in `blob`.

    Lines it could not decode, and ones whose text is a data directive or
    mentions a symbol, are dropped: a case has to be something an assembler
    can be asked to produce again.
    """
    path = os.path.join(workdir, "blob.bin")
    with open(path, "wb") as fh:
        fh.write(blob)
    p = subprocess.run([objdump, "-D", "-b", "binary", *flags, path],
                       capture_output=True, text=True, timeout=120)
    out = []
    for line in p.stdout.split("\n"):
        m = DIS_LINE.match(line)
        if not m:
            continue
        text = re.sub(r"\s*(//|;|!|#|@).*$", "", m.group(3)).strip()
        text = re.sub(r"\s+", " ", text.replace("\t", " "))
        if not text or DIS_SKIP.search(text) or "<" in text:
            continue
        out.append((int(m.group(1), 16), text))
    return out


def disassembled_cases(rng, target, count, chunk=4096):
    """`(mnemonic, text)` cases for `count` instructions of random bytes.

    `target` needs `objdump` (a tool name under the oracles' `bin`) and
    `objdump_flags`.
    """
    cases = []
    with tempfile.TemporaryDirectory() as d:
        while len(cases) < count:
            blob = random_blob(rng, target, chunk)
            got = disassemble(oracle(target.objdump), target.objdump_flags, blob, d)
            if not got:
                break
            for off, text in got:
                if len(cases) >= count:
                    break
                mnem = text.split()[0]
                text = signed_addresses(text, target.addr_bits)
                if target.rewrite:
                    text = target.rewrite(text, off)
                    if text is None:
                        continue
                head = "" if target.slot else (f".skip {off}\n" if off else "")
                cases.append((mnem, head + text))
    return cases


def signed_addresses(text, bits):
    """Writes a backward branch target the way an assembler will read it.

    A disassembler prints the target of a backward branch as the address it
    wraps to -- `0xffffd738` for -10440 on a 32-bit target -- and an
    assembler asked for that address computes a displacement far out of
    range. Anything in the top half of the address space is therefore
    rewritten as the negative number it stands for, which is the same
    instruction again. Immediates never reach that far, so nothing else is
    touched.
    """
    if not bits:
        return text

    def fix(m):
        v = int(m.group(0), 16)
        return str(v - (1 << bits)) if v >= 1 << (bits - 1) else m.group(0)

    return re.sub(r"\b0x[0-9a-f]+\b", fix, text)


def random_blob(rng, target, size):
    """The bytes to disassemble.

    Uniformly random bytes reach every instruction eventually, but not
    evenly: on a fixed-width target most words land in whichever opcodes
    happen to be dense, and the ones behind a single opcode value -- MIPS's
    SPECIAL, SPARC's op=2 -- come up once in 64 words. A target may hand over
    a `word_maker` that draws the opcode field itself; everything below it
    stays random, so no encoding is written here.
    """
    if target.word_maker is None:
        return bytes(rng.getrandbits(8) for _ in range(size))
    order = "little" if target.little else "big"
    n = target.word_size
    return b"".join(target.word_maker(rng).to_bytes(n, order)
                    for _ in range(size // n))


def flat_image(tool, target, obj, workdir):
    """The flat image a slot-per-case batch produced, as hex.

    rsasm wrote one directly (`-f bin`); the reference wrote an object, so
    its code section is extracted with the matching objcopy. Padding between
    slots is zero in both, which is what makes the slices comparable.
    """
    if tool == "rsasm":
        return open(obj, "rb").read().hex()
    out = os.path.join(workdir, "ref.bin")
    subprocess.run([target.objcopy, "-O", "binary", obj, out],
                   capture_output=True, text=True, timeout=120)
    try:
        return open(out, "rb").read().hex()
    except OSError:
        return ""


def disasm_main(name, targets, rules, skip=None, default=None, count=12000,
                limit=40, over=3):
    """The command line the disassembly-sourced fuzzers share.

    `skip` says which cases to leave out -- what the backend does not claim,
    which each fuzzer lists for itself -- and `over` how many cases to
    disassemble for each one kept, since skipping eats into the count.
    """
    import argparse
    import random

    ap = argparse.ArgumentParser(description=f"differential fuzzer for {name}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    default = default or next(iter(targets))
    c = sub.add_parser("check", help="compare instructions given one per line")
    c.add_argument("--target", default=default, choices=list(targets))
    c.add_argument("file")
    c.add_argument("--limit", type=int, default=100)
    z = sub.add_parser("fuzz", help="disassemble random words and compare")
    add_fuzz_args(z, count, limit)
    z.add_argument("--target", default="all", choices=list(targets) + ["all"])
    args = ap.parse_args()

    chosen = [targets[args.target]] if getattr(args, "target", "all") != "all" \
        else list(targets.values())
    for t in chosen:
        bad = t.missing()
        if bad:
            raise SystemExit(bad)

    if args.cmd == "check":
        cases = [(line.split()[0], line.strip()) for line in open(args.file)
                 if line.strip() and not line.startswith("#")]
        return report(name, compare(targets[args.target], cases, rules), args.limit)

    rng = random.Random(args.seed)
    jobs = []
    per = max(1, args.count // len(chosen))
    for t in chosen:
        cases = [c for c in disassembled_cases(rng, t, per * over)
                 if (skip is None or not skip(c))
                 and (not args.only or re.search(args.only, c[0]))]
        jobs.append((t, cases[:per]))
    if args.print_cases:
        for t, cases in jobs:
            for _m, text in cases:
                print(f"[{t.key}] " + text.replace("\n", " ; "))
        return 0
    return drive(name, jobs, rules, args.limit, args.batch, args.no_splits)


def resolves_a_numeric_target(text, res, target):
    """A branch or call whose target is written as a number.

    GNU as leaves it to the linker on several targets -- a relocation
    against the absolute section, with the whole value as the addend and the
    field left as written -- where rsasm works the displacement out itself.
    The instruction is the same either way: the linker computes `S + A` with
    `S` zero, which is the value rsasm already put in, so a linked image is
    identical. Only the object differs, and only in carrying a relocation
    that resolves to what is already there.

    Recognised as: the same bytes, every relocation GNU as wrote against
    `*ABS*`, and none from rsasm.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok" or g[1][0] != r[1][0]:
        return False
    return bool(g[1][1]) and not r[1][1] and all(w == "*ABS*" for _o, _t, w, _a in g[1][1])


def fills_in_a_relocated_field(text, res, target):
    """The same relocations, and a field one of them is about to overwrite.

    GNU as computes an absolute target and writes it into the instruction
    *as well as* emitting the relocation for it; rsasm leaves the field
    zero. With RELA the addend is what the linker uses and the field's old
    contents are thrown away, so the two objects link to the same image --
    checked by linking a differing case with the target's own `ld` and
    comparing the result byte for byte.

    Recognised as: both accepted, the same relocations with addends, the
    same length, and every bit rsasm set also set by GNU as -- that is,
    rsasm's bytes are GNU as's with the relocated bits cleared, and nothing
    else differs.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok":
        return False
    if (not g[1][1] or g[1][1] != r[1][1] or len(g[1][0]) != len(r[1][0])
            or any(a is None for _o, _t, _w, a in g[1][1])):
        return False
    gb, rb = bytes.fromhex(g[1][0]), bytes.fromhex(r[1][0])
    return all(rv & ~gv == 0 for gv, rv in zip(gb, rb))


def relocates_an_absolute_target(text, res, target):
    """A branch whose target is written as an absolute address.

    GNU as works the displacement out as if the section were loaded at zero
    and emits nothing for the linker. rsasm keeps the relocation, because
    where the section ends up is the linker's business -- and on a target
    with branch relaxation that means it must also take the long form, since
    it cannot yet know the displacement is short.

    Both branch to the same address once linked at zero, which was checked
    by linking a differing case with the target's own `ld` and reading the
    image; rsasm's is the one that still works if the section moves.

    Recognised as: both accepted, GNU as wrote no relocation, and every
    relocation rsasm wrote is against the absolute section.
    """
    g, r = res.get("gas"), res.get("rsasm")
    if not g or g[0] != "ok" or r[0] != "ok":
        return False
    return (not g[1][1] and bool(r[1][1])
            and all(w == "*ABS*" for _o, _t, w, _a in r[1][1]))


ADDRESS_TOKEN = re.compile(r"(?<![\w.$%])(-?(?:0x[0-9a-f]+|\d+))(?![\w.])")


def dot_relative(mnemonics):
    """A `rewrite` that turns a printed branch target into `.`-relative form.

    A disassembler prints where a branch lands; an assembler asked for that
    address computes the displacement from wherever the instruction ends up,
    which is only the same instruction if it ends up where it was read.
    Writing the target as `.` plus the displacement says what the encoding
    says and means the same at any address -- and, on SPARC, keeps llvm-mc
    away from the absolute-value fixup it crashes on.

    The *last* address-shaped token is the target: a predicted branch names
    its condition-code bank first.
    """
    rx = re.compile(mnemonics)

    def rewrite(text, off):
        if not rx.match(text.split()[0]):
            return text
        hits = list(ADDRESS_TOKEN.finditer(text))
        if not hits:
            return text
        hit = hits[-1]
        # Only a whole trailing operand is a target. `call %g3 + 8` is an
        # indirect call through an address, and the 8 in it is a
        # displacement from a register, not from here.
        if hit.end() != len(text) or text[:hit.start()].rstrip().endswith(("+", "-")):
            return text
        return (text[:hit.start()] + ".%+d" % (int(hit.group(1), 0) - off)
                + text[hit.end():])

    return rewrite
