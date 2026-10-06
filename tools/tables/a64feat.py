#!/usr/bin/env python3
"""Reads GNU as's AArch64 feature model out of binutils.

`src/arch/aarch64/cpu_data.rs` -- what `.arch`, `.cpu`, `.arch_extension`,
`-march=` and `-mcpu=` select, and which instructions each selection has --
is not written by hand. Everything in it comes from binutils 2.47:

    include/opcode/aarch64.h    the feature bit numbering (`enum
                                aarch64_feature_bit`) and what each
                                architecture version turns on
                                (`AARCH64_ARCH_*`)
    gas/config/tc-aarch64.c     the names `-march=`, `-mcpu=` and the `+`
                                suffixes take (`aarch64_archs`,
                                `aarch64_cpus`, `aarch64_features`), the
                                dependencies between them, and the default
    opcodes/aarch64-tbl.h       the feature set of every instruction, which
                                is what gates the general-purpose
                                instructions `src/arch/aarch64/insn.rs`
                                encodes by hand

`src/arch/aarch64/cpu.rs` is the same model and the same test; this writes
it its tables. The forms of the generated table carry a feature set of their
own, measured rather than read; `tools/tables/aarch64.py` writes those.

    tools/tables/a64feat.py table   # rewrite src/arch/aarch64/cpu_data.rs
    tools/tables/a64feat.py check   # exit 1 if it is out of date

Environment: RSASM_ORACLES (default target/oracles).
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
BINUTILS = os.path.join(ORACLES, "src", "binutils-2.47")
AARCH64_H = os.path.join(BINUTILS, "include", "opcode", "aarch64.h")
TC = os.path.join(BINUTILS, "gas", "config", "tc-aarch64.c")
TBL = os.path.join(BINUTILS, "opcodes", "aarch64-tbl.h")
OUT = os.path.join(ROOT, "src", "arch", "aarch64", "cpu_data.rs")

# What rsasm's AArch64 backend is when the source says nothing: the
# `-march=` tools/xas-diff assembles the reference with, which is every
# extension the backend has an instruction for. Keep it in step with
# tools/xas-diff/run.sh. GNU as's own default for `aarch64-elf` is
# `armv8-a`, which this is not; `src/arch/aarch64/cpu.rs` says why.
DEFAULT_MARCH = (
    "armv9.5-a+crc+crypto+fp+lse+lsfe+lse128+lsui+simd+pan+lor+ras+rdma+fp16"
    "+fp16fml+fprcvt+profile+sve+tme+fcma+jscvt+rcpc+rcpc2+dotprod+sha2"
    "+frintts+sb+predres+predres2+poe2+tev+aes+sm4+sha3+rng+ssbs+lscp+memtag"
    "+occmo+cmpbr+sve2+sve2-sm4+sve2-aes+sve2-sha3+sve2-bitperm+sme"
    "+sme-f64f64+sme-i16i64+sme2+bf16+i8mm+f32mm+f64mm+ls64+flagm+flagm2"
    "+pauth+xs+wfxt+mops+hbc+cssc+chk+gcs+the+rasv2+ite+d128+sve-b16b16"
    "+sve-bfscale+sme2p1+sve2p1+sve-f16f32mm+f8f32mm+f8f16mm+sve-aes"
    "+sve-aes2+ssve-aes+sve-bitperm+ssve-bitperm+rcpc3+cpa+faminmax+fp8+lut"
    "+brbe+sme-lutv2+fp8fma+fp8dot4+fp8dot2+ssve-fp8fma+ssve-fp8dot4"
    "+ssve-fp8dot2+sme-f8f32+sme-f8f16+sme-f16f16+sme-b16b16+pops+sve2p2"
    "+sme2p2+gcie+ssve-fexpa+sme-tmop+sme-mop4+mops-go+sve2p3+sme2p3"
    "+f16f32dot+f16f32mm+f16mm+sve-b16mm+mtetc+tlbid+sme-fa64"
)

WORDS = 3
W64 = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Feature sets
# ---------------------------------------------------------------------------


def read(path):
    text = open(path, errors="replace").read()
    return re.sub(r"/\*.*?\*/", " ", text, flags=re.S).replace("\\\n", " ")


class Model:
    """The bit numbering, and the sets each name stands for."""

    def __init__(self):
        self.h = read(AARCH64_H)
        self.tc = read(TC)
        self.bits = {}
        block = self.h.split("enum aarch64_feature_bit", 1)[1].split("};", 1)[0]
        for name in re.findall(r"AARCH64_FEATURE_(\w+)", block):
            self.bits.setdefault(name, len(self.bits))
        if len(self.bits) > WORDS * 64:
            sys.exit("%d feature bits will not fit in %d words"
                     % (len(self.bits), WORDS))
        # `AARCH64_ARCH_<V>(X)` is one architecture version's whole set, a
        # union of `AARCH64_FEATBIT (X, NAME)` and of earlier versions, with
        # the odd bit taken away again (`armv8-r` has no `V8A` and no `LOR`).
        self.arch_macros = {}
        for m in re.finditer(r"#\s*define\s+AARCH64_ARCH_(\w+)\s*\(X\)\s+(.*)$",
                             self.h, re.M):
            self.arch_macros[m.group(1)] = m.group(2).strip()

    def bit(self, name):
        n = self.bits[name]
        out = [0] * WORDS
        out[n // 64] = 1 << (n % 64)
        return tuple(out)

    def arch(self, name, depth=0):
        """One `AARCH64_ARCH_*` macro, evaluated."""
        if depth > 40:
            sys.exit("macro loop in AARCH64_ARCH_%s" % name)
        expr = self.arch_macros[name]
        expr = re.sub(r"AARCH64_FEATBIT\s*\(\s*X\s*,\s*(\w+)\s*\)",
                      lambda m: "b('%s')" % m.group(1), expr)
        expr = re.sub(r"AARCH64_ARCH_(\w+)\s*\(\s*X\s*\)",
                      lambda m: "a('%s')" % m.group(1), expr)
        # `|` is a union and `& ~x` a difference; nothing else appears.
        expr = expr.replace("&~", "- ").replace("& ~", "- ")
        env = {"b": lambda n: Set(self.bit(n)),
               "a": lambda n: Set(self.arch(n, depth + 1)),
               "__builtins__": {}}
        value = eval(expr, env)
        # `AARCH64_ARCH_NONE` is a plain `0`, which is every word of it.
        return NONE if isinstance(value, int) else tuple(value)

    def features(self, expr):
        """One `aarch64_feature_set` initializer, as a set.

        `AARCH64_CPU_FEATURES (ARCH, n, F...)` is an architecture version's
        whole set with some bits added; `AARCH64_FEATURES (n, F...)` is the
        same with no architecture, and `AARCH64_FEATURE (F)` one bit.
        """
        expr = " ".join(expr.split())
        if expr == "AARCH64_NO_FEATURES":
            return (0,) * WORDS
        if expr == "AARCH64_ALL_FEATURES":
            return tuple(W64 for _ in range(WORDS))
        m = re.match(r"AARCH64_ARCH_FEATURES\s*\(\s*(\w+)\s*\)$", expr)
        if m:
            return self.arch(m.group(1))
        m = re.match(r"AARCH64_FEATURE\s*\(\s*(\w+)\s*\)$", expr)
        if m:
            return self.bit(m.group(1))
        m = re.match(r"AARCH64_(CPU_)?FEATURES\s*\((.*)\)$", expr)
        if m:
            args = [a.strip() for a in m.group(2).split(",")]
            arch = args.pop(0) if m.group(1) else "NONE"
            args.pop(0)  # the count, which the names after it say again
            out = self.arch(arch)
            for n in args:
                out = union(out, self.bit(n))
            return out
        sys.exit("cannot read feature set %r" % expr)


class Set(tuple):
    """A feature set with `|` and `-`, for evaluating the arch macros."""

    def __or__(self, other):
        return Set(union(self, other))

    def __sub__(self, other):
        return Set(without(self, other))


def union(a, b):
    return tuple(x | y for x, y in zip(a, b))


def without(a, b):
    return tuple(x & ~y for x, y in zip(a, b))


def has_all(a, b):
    return all(~x & y == 0 for x, y in zip(a, b))


def has_any(a, b):
    return any(x & y for x, y in zip(a, b))


NONE = (0,) * WORDS


# ---------------------------------------------------------------------------
# The option tables
# ---------------------------------------------------------------------------


def table_rows(text, decl):
    """The `{ "name", value... }` rows of one of tc-aarch64.c's tables."""
    body = text.split(decl, 1)[1].split("\n};", 1)[0]
    out = []
    for m in re.finditer(r'\{\s*"([^"]*)"\s*,', body):
        i, depth, last = m.end(), 1, m.end()
        args = []
        while depth:
            c = body[i]
            if c in "({[":
                depth += 1
            elif c in ")}]":
                depth -= 1
                if depth == 0:
                    args.append(body[last:i])
                    break
            elif c == "," and depth == 1:
                args.append(body[last:i])
                last = i + 1
            i += 1
        out.append((m.group(1), [a.strip() for a in args]))
    return out


def option_tables(model):
    archs = [(n, model.features(a[0])) for n, a in
             table_rows(model.tc, "aarch64_arch_option_table aarch64_archs[] =")]
    cpus = [(n, model.features(a[0])) for n, a in
            table_rows(model.tc, "aarch64_cpu_option_table aarch64_cpus[] =")]
    exts = [(n, model.features(a[0]), model.features(a[1])) for n, a in
            table_rows(model.tc, "aarch64_option_cpu_value_table aarch64_features[] =")]
    deps = []
    body = model.tc.split("aarch64_virtual_dependency_table aarch64_dependencies[] =", 1)[1]
    body = body.split("\n};", 1)[0]
    for m in re.finditer(r"\{\s*(AARCH64_FEATURES?\s*\([^{}]*?\))\s*,\s*"
                         r"(AARCH64_FEATURES?\s*\([^{}]*?\))\s*\}", body, re.S):
        deps.append((model.features(m.group(1)), model.features(m.group(2))))
    return archs, cpus, exts, deps


def default_feature_set(model, archs, exts, deps):
    """What DEFAULT_MARCH selects, through the same steps GNU as takes."""
    name, _, rest = DEFAULT_MARCH.partition("+")
    base = dict(archs)[name]
    for ext in rest.split("+"):
        value = next((v for n, v, _ in exts if n == ext), None)
        if value is None:
            sys.exit("DEFAULT_MARCH names `%s`, which GNU as has no extension "
                     "called" % ext)
        base = union(base, enable_set(model, exts, value))
    sme = model.bit("SME")
    if has_all(base, sme):
        base = union(base, union(model.bit("SVE"), model.bit("SVE2")))
    return virtual(deps, base)


def enable_set(model, exts, want):
    """`aarch64_feature_enable_set`: everything `want` depends on, with the
    special case that `+sme` brings `+sve2` whatever else was asked for."""
    sme, sve2 = model.bit("SME"), model.bit("SVE2")
    prev = NONE
    while not has_all(prev, want):
        prev = want
        for _n, value, require in exts:
            if has_all(want, value):
                want = union(want, require)
        if has_all(want, sme):
            want = union(want, sve2)
    return want


def virtual(deps, want):
    """`aarch64_update_virtual_dependencies`."""
    for _test, enables in deps:
        want = without(want, enables)
    for test, enables in deps:
        if has_all(want, test):
            want = union(want, enables)
    return want


# ---------------------------------------------------------------------------
# What each instruction needs
# ---------------------------------------------------------------------------


def opcode_rows(model):
    """Every row of `aarch64-tbl.h`, as (name, opcode, mask, feature set).

    A row's feature set comes from the macro it is written with: each
    `*_INSN` macro puts one of the `aarch64_feature_*` variables in the
    row, and that is the set `md_assemble` tests the target against.
    """
    text = read(TBL)
    sets = {}
    for m in re.finditer(r"static const aarch64_feature_set (\w+)\s*=\s*([^;]*);",
                         text, re.S):
        sets[m.group(1)] = model.features(m.group(2))
    short = {}
    for m in re.finditer(r"^#\s*define\s+(\w+)\s+&(aarch64_feature_\w+)\s*$",
                         text, re.M):
        if m.group(2) in sets:
            short[m.group(1)] = sets[m.group(2)]
    macros = {}
    for m in re.finditer(r"^#\s*define\s+(\w*_INSN\w*)\s*\(([^)]*)\)\s+(\{.*)$",
                         text, re.M):
        params = {p.strip() for p in m.group(2).split(",")}
        found = [short[t] for t in re.findall(r"\b(\w+)\b", m.group(3))
                 if t in short and t not in params]
        if len(found) == 1:
            macros[m.group(1)] = found[0]
    out = []
    for m in re.finditer(r"\b(\w*_INSN\w*)\s*\(\s*\"([^\"]+)\"\s*,\s*"
                         r"(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)", text):
        want = macros.get(m.group(1))
        if want is not None:
            out.append((m.group(2), int(m.group(3), 0), int(m.group(4), 0), want))
    return out


class Opcodes:
    """What each form of a generated table needs, by mnemonic and opcode.

    A form of `src/arch/aarch64/table_data.rs` is the opcode word left when
    every operand is zero, so the row that encodes it is the one of that
    mnemonic whose fixed bits it has. That row's feature set is the gate GNU
    as applies, per form rather than per mnemonic: `fmmla` wants `+f32mm` for
    single-precision and `+f64mm` for double.
    """

    def __init__(self, model):
        self.by_name = {}
        for name, op, mask, want in opcode_rows(model):
            self.by_name.setdefault(name, []).append((op, mask, want))
        self.by_mnemonic = instruction_features(model)

    def of(self, name, word):
        """The feature set of the row this form came from.

        A spelling only llvm-mc has -- the reversed three-register `cmle`,
        `facle` and their like -- matches no row, and falls back to what
        every row of that mnemonic needs, or to nothing where GNU as has no
        such mnemonic at all. They are all SIMD aliases of forms that do
        match.
        """
        hit = [want for op, mask, want in self.by_name.get(name, ())
               if word & mask == op]
        if hit:
            out = hit[0]
            for other in hit[1:]:
                out = intersect(out, other)
            return out
        return self.by_mnemonic.get(name, NONE)


def instruction_features(model):
    """Mnemonic -> the feature set GNU as needs for it, from aarch64-tbl.h.

    Each row of the opcode table names a feature set, and `md_assemble`
    refuses the instruction unless the target has every bit of it. A
    mnemonic with several rows -- one per operand shape -- is tested against
    whichever row took the operands, so the gate a name alone can carry is
    the least demanding of them: the bits every row of that name needs.
    """
    text = read(TBL)
    # `static const aarch64_feature_set aarch64_feature_x = ...;`
    sets = {}
    for m in re.finditer(r"static const aarch64_feature_set (\w+)\s*=\s*([^;]*);",
                         text, re.S):
        sets[m.group(1)] = model.features(m.group(2))
    # `#define SHORT &aarch64_feature_x`
    short = {}
    for m in re.finditer(r"^#\s*define\s+(\w+)\s+&(aarch64_feature_\w+)\s*$",
                         text, re.M):
        if m.group(2) in sets:
            short[m.group(1)] = sets[m.group(2)]
    # `#define NAME_INSN(...) { ..., SHORT, ... }`: whichever short name the
    # body names is the feature set every row written with that macro has.
    macros = {}
    for m in re.finditer(r"^#\s*define\s+(\w*_INSN\w*)\s*\(([^)]*)\)\s+(\{.*)$",
                         text, re.M):
        params = {p.strip() for p in m.group(2).split(",")}
        found = [short[t] for t in re.findall(r"\b(\w+)\b", m.group(3))
                 if t in short and t not in params]
        if len(found) == 1:
            macros[m.group(1)] = found[0]
    out = {}
    for m in re.finditer(r"\b(\w*_INSN\w*)\s*\(\s*\"([^\"]+)\"", text):
        want = macros.get(m.group(1))
        if want is None:
            continue
        name = m.group(2)
        out[name] = want if name not in out else intersect(out[name], want)
    return out


def intersect(a, b):
    return tuple(x & y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Writing the Rust
# ---------------------------------------------------------------------------

HEADER = '''//! What `.arch`, `.cpu`, `.arch_extension`, `-march=` and `-mcpu=` select,
//! and which instructions each selection has, read out of GNU binutils 2.47.
//!
//! Do not edit: `tools/tables/a64feat.py table` writes this file. The
//! architecture, CPU and extension tables are GNU as's own (`aarch64_archs`,
//! `aarch64_cpus`, `aarch64_features` and `aarch64_dependencies` in
//! `gas/config/tc-aarch64.c`), the bit numbering and the architecture
//! versions' sets are `include/opcode/aarch64.h`'s, and what each
//! hand-written instruction needs is its own row's feature set in
//! `opcodes/aarch64-tbl.h`. A form of the generated table carries a set
//! measured for it instead; see [`super::table_data`]. See [`super::cpu`].

use super::cpu::{Ext, Set};

'''


def rust_set(set_):
    return "[%s]" % ", ".join("%#x" % w for w in set_)


def render(model):
    archs, cpus, exts, deps = option_tables(model)
    default = default_feature_set(model, archs, exts, deps)
    insns = instruction_features(model)

    # How a diagnostic names a missing feature: the `+name` GNU as's
    # extension table spells it, and the bit's own name lowered where no
    # suffix turns it on by itself -- a bit an architecture version brings.
    # A name that turns on exactly this bit is the one to use: `+aes` says
    # what is missing where `+crypto`, which is AES and SHA2 together, would
    # name more than the instruction wanted.
    spelling = {}
    for exact in (True, False):
        for name, value, _require in exts:
            for bit in model.bits:
                one = model.bit(bit)
                if bit in spelling or not has_all(value, one):
                    continue
                if exact and value != one:
                    continue
                spelling[bit] = name

    order, sets = {NONE: 0}, [NONE]

    def index(set_):
        if set_ not in order:
            order[set_] = len(sets)
            sets.append(set_)
        return order[set_]

    mnemonics = [(name, index(insns[name])) for name in sorted(insns)]

    out = [HEADER]
    out.append("/// Every feature bit, in `aarch64.h`'s own order, and how a\n"
               "/// diagnostic names it.\n")
    out.append("pub static NAMES: &[(Set, &str)] = &[\n")
    for bit in model.bits:
        out.append('    (%s, "%s"),\n'
                   % (rust_set(model.bit(bit)), spelling.get(bit, bit.lower())))
    out.append("];\n\n")

    out.append("/// Every feature set a hand-written instruction needs, all\n"
               "/// of whose bits the target must have. Index 0 is the empty\n"
               "/// set, which every target has.\n")
    out.append("pub static FEATS: &[Set] = &[\n")
    for set_ in sets:
        out.append("    %s,\n" % rust_set(set_))
    out.append("];\n\n")

    out.append("/// The names `.arch` and `-march=` take. `.arch` passes over\n"
               "/// the first, `all`, which only the option has.\n")
    out.append("pub static ARCHS: &[(&str, Set)] = &[\n")
    for name, value in archs:
        out.append('    ("%s", %s),\n' % (name, rust_set(value)))
    out.append("];\n\n")

    out.append("/// The names `.cpu` and `-mcpu=` take, `all` likewise first.\n")
    out.append("pub static CPUS: &[(&str, Set)] = &[\n")
    for name, value in cpus:
        out.append('    ("%s", %s),\n' % (name, rust_set(value)))
    out.append("];\n\n")

    out.append("/// GNU as's `aarch64_features`: the `+name` suffixes, what\n"
               "/// each turns on, and what each needs turned on with it.\n")
    out.append("pub static EXTENSIONS: &[Ext] = &[\n")
    for name, value, require in exts:
        out.append('    Ext { key: "%s", value: %s, require: %s },\n'
                   % (name, rust_set(value), rust_set(require)))
    out.append("];\n\n")

    out.append("/// GNU as's `aarch64_dependencies`: a feature the opcode\n"
               "/// table names but no option does, and what has to be on for\n"
               "/// it to be.\n")
    out.append("pub static DEPENDENCIES: &[(Set, Set)] = &[\n")
    for test, enables in deps:
        out.append("    (%s, %s),\n" % (rust_set(test), rust_set(enables)))
    out.append("];\n\n")

    out.append("/// What a mnemonic [`super::insn`] encodes by hand needs:\n"
               "/// the bits every `aarch64-tbl.h` row of that name needs, as\n"
               "/// an index into [`FEATS`]. Sorted by name.\n")
    out.append("pub static MNEMONICS: &[(&str, u16)] = &[\n")
    for name, idx in mnemonics:
        out.append('    ("%s", %d),\n' % (name, idx))
    out.append("];\n\n")

    out.append("/// What the backend has when the source names nothing:\n"
               "/// `-march=%s`,\n/// as `tools/xas-diff` runs the reference.\n"
               % DEFAULT_MARCH)
    out.append("pub const DEFAULT: Set = %s;\n\n" % rust_set(default))
    out.append("/// `+sme` and the `+sve`, `+sve2` it drags in whatever else\n"
               "/// was asked for; see [`super::cpu::parse_features`].\n")
    out.append("pub const SME: Set = %s;\n" % rust_set(model.bit("SME")))
    out.append("pub const SVE_SVE2: Set = %s;\n\n"
               % rust_set(union(model.bit("SVE"), model.bit("SVE2"))))
    out.append("/// `V8R`, which `src/arch/aarch64/sysreg.rs` asks about by\n"
               "/// name: an ARMv8-R core has no EL3, so none of the\n"
               "/// system-instruction operands that address it is available\n"
               "/// there, however the rest of the target reads.\n")
    out.append("pub const V8R: Set = %s;\n" % rust_set(model.bit("V8R")))

    text = "".join(out)
    try:
        return subprocess.run(
            ["rustfmt", "--edition", "2024", "--emit", "stdout"],
            input=text, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit("rustfmt failed (%s)" % e)


def form_features():
    """An [`Opcodes`] for `tools/tables/aarch64.py`, which gives each form of
    its table the feature set of the row it came from."""
    return Opcodes(Model())


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "table"
    if cmd not in ("table", "check"):
        sys.exit(__doc__)
    text = render(Model())
    stale = not os.path.exists(OUT) or open(OUT).read() != text
    if cmd == "check":
        print("out of date: %s" % os.path.relpath(OUT, ROOT) if stale
              else "up to date")
        sys.exit(1 if stale else 0)
    if stale:
        with open(OUT, "w") as fh:
            fh.write(text)
    print("rewrote %d file(s)" % stale, file=sys.stderr)


if __name__ == "__main__":
    main()
