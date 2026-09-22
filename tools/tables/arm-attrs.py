#!/usr/bin/env python3
"""Derives rsasm's ARM build-attribute table from GNU as.

`src/arch/arm/attr_data.rs` — what `.arch`, `.cpu`, `.fpu`,
`.arch_extension`, `.object_arch` and `.eabi_attribute` put in
`.ARM.attributes` — is not written by hand. The names come from binutils' own
tables (`arm_archs`, `arm_cpus`, `arm_fpus`, `arm_extensions` and
`arm_convert_symbolic_attribute` in `gas/config/tc-arm.c`), and every tag
value comes from assembling the directive with `arm-none-eabi-as` and reading
the section back: nothing here says what an attribute should be.

    tools/tables/arm-attrs.py table   # rewrite the table
    tools/tables/arm-attrs.py check   # exit 1 if it is out of date

Everything is measured through the directive, under the command line
`tools/xas-diff` runs the reference as (`-march=armv7ve -mfpu=neon-vfpv4`),
because that is the one rsasm has to reproduce: GNU as does not answer the
same for `-mfpu=neon` as for `.fpu neon`, since the option merges the unit
with the CPU's own and the directive replaces it.

So a CPU's entry is every tag `.arch <name>` or `.cpu <name>` leaves behind,
an FPU's is the tags `.fpu <name>` puts in their place, and an extension's is
what `.arch_extension <name>` changed about its CPU. A CPU with one unit, or
with one extension, is exactly what GNU as writes, and `verify` assembles
every such pair to prove it. Two extensions together, or an extension beside
an `.fpu`, are put together rather than measured -- see `combine`, and the
backend's `attrs` module, which says so.

Environment: RSASM_ORACLES (default target/oracles), GAS (default
arm-none-eabi-as from there).
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
BINUTILS = os.path.join(ORACLES, "src", "binutils-2.47")
GAS = os.environ.get("GAS") or os.path.join(ORACLES, "bin", "arm-none-eabi-as")
OUT = os.path.join(ROOT, "src", "arch", "arm", "attr_data.rs")

# The command line the backend is; see tools/xas-diff/run.sh.
OPTIONS = ["-march=armv7ve", "-mfpu=neon-vfpv4"]

# The tags whose value is a NUL-terminated string rather than a number.
STR_TAGS = {4, 5, 32, 65, 67}
# Tag_CPU_name, the one string tag any of this writes.
TAG_CPU_NAME = 5


def sections(path):
    """The (name, bytes) of every section of an ELF file."""
    with open(path, "rb") as f:
        d = f.read()
    end = "<" if d[5] == 1 else ">"
    shoff = struct.unpack_from(end + "I", d, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", d, 46)
    hdrs = [
        struct.unpack_from(end + "10I", d, shoff + i * shentsize) for i in range(shnum)
    ]
    stroff = hdrs[shstrndx][4]
    out = []
    for h in hdrs:
        name = d[stroff + h[0] : d.index(b"\0", stroff + h[0])].decode()
        out.append((name, d[h[4] : h[4] + h[5]]))
    return out


def uleb(d, i):
    v = s = 0
    while True:
        b = d[i]
        i += 1
        v |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return v, i


def parse_attributes(data):
    """The `aeabi` File subsection of a `.ARM.attributes` section, as a dict."""
    out = {}
    i = 1
    while i < len(data):
        length = struct.unpack_from("<I", data, i)[0]
        end = i + length
        j = data.index(b"\0", i + 4) + 1
        while j < end:
            _kind, j = uleb(data, j)
            sublen = struct.unpack_from("<I", data, j)[0]
            subend, j = j + sublen - 1, j + 4
            while j < subend:
                tag, j = uleb(data, j)
                if tag in STR_TAGS:
                    k = data.index(b"\0", j)
                    out[tag], j = data[j:k].decode(), k + 1
                else:
                    out[tag], j = uleb(data, j)
            j = subend
        i = end
    return out


TMP = None
# The tags an `.fpu` decides, worked out by `collect`.
FP_TAGS = set()


def measure(src=""):
    """The attributes GNU as writes for this source, or None if it refuses."""
    asm = os.path.join(TMP, "in.s")
    obj = os.path.join(TMP, "out.o")
    with open(asm, "w") as f:
        f.write(src)
    p = subprocess.run(
        [GAS] + OPTIONS + ["-o", obj, asm], capture_output=True, text=True
    )
    if p.returncode != 0:
        return None
    for name, data in sections(obj):
        if name == ".ARM.attributes":
            return parse_attributes(data)
    return {}


def names_in(text, table, macro):
    """The names listed in one of tc-arm.c's option tables."""
    body = text.split(table + "[] =")[1].split("\n};")[0]
    seen, out = set(), []
    for n in re.findall(macro + r'2?\s*\(\s*"([^"]+)"', body):
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def fpu_names(text):
    body = text.split("arm_fpus[] =")[1].split("\n};")[0]
    seen, out = set(), []
    for n in re.findall(r'\{\s*"([^"]+)"', body):
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# Tag_FP_arch numbers a unit's capability out of order: the `-d16` halves
# (4, 6, 8) come after the full units they are a subset of (3, 5, 7).
FP_ARCH_ORDER = [0, 1, 2, 4, 3, 6, 5, 8, 7]


def combine(tag, old, new):
    """What one tag becomes where two choices each give it a value."""
    if tag == 10:  # Tag_FP_arch
        return max(old, new, key=FP_ARCH_ORDER.index)
    if tag == 68:  # Tag_Virtualization_use: TrustZone and virtualization bits
        return old | new
    return max(old, new)


def merge(cpu, fpu, *deltas):
    """The tag map the backend builds from a CPU, an `.fpu` and extensions.

    An `.fpu` replaces every tag the unit decides rather than adding to the
    CPU's: GNU as's directive selects a unit where its `-mfpu=` merges one in.
    An extension replaces what the CPU said and combines with what the unit
    or another extension said.
    """
    out = dict(cpu)
    if fpu is not None:
        for tag in FP_TAGS:
            out.pop(tag, None)
        out.update(fpu)
    for d in deltas:
        for tag, value in d.items():
            shared = (fpu is not None and tag in fpu) or any(
                tag in e for e in deltas if e is not d
            )
            if tag in out and shared:
                out[tag] = combine(tag, out[tag], value)
            else:
                out[tag] = value
    return out


def tag_names(text):
    """`.eabi_attribute`'s symbolic tag names, and the tag each stands for.

    The names are GNU as's own list (`arm_convert_symbolic_attribute`); the
    numbers come from setting each to a value no CPU writes and seeing which
    tag it landed on.
    """
    body = text.split("arm_convert_symbolic_attribute")[1].split("#undef T")[0]
    out = {}
    for name in re.findall(r"T \((Tag_\w+)\)", body):
        t = measure(".eabi_attribute %s, 42\n" % name)
        if t is None:
            continue
        found = [k for k, v in t.items() if v == 42]
        if len(found) == 1:
            out[name] = found[0]
    return out


def collect():
    path = os.path.join(BINUTILS, "gas", "config", "tc-arm.c")
    with open(path, errors="replace") as f:
        text = f.read()

    # `.arch` and `.cpu` read tables that overlap without agreeing:
    # `.arch xscale` calls the CPU `xscale` and `.cpu xscale` calls it
    # `XSCALE`. Each takes only its own table's names, and neither takes
    # every name the matching option does.
    cpus = {}
    for directive, table, macro in (
        (".arch", "arm_archs", "ARM_ARCH_OPT"),
        (".cpu", "arm_cpus", "ARM_CPU_OPT"),
    ):
        for name in names_in(text, table, macro):
            t = measure("%s %s\n" % (directive, name))
            if t is not None:
                cpus[(directive, name)] = t

    # What `.fpu` puts in place of the tags a unit decides. The default is
    # the unit the command line selected, which is in every CPU's entry
    # already.
    global FP_TAGS
    default = cpus[(".arch", "armv7ve")]
    fpus = {}
    for name in fpu_names(text):
        t = measure(".fpu %s\n" % name)
        if t is not None:
            fpus[name] = t
    FP_TAGS = {
        tag
        for t in fpus.values()
        for tag in set(t) | set(default)
        if t.get(tag) != default.get(tag) and tag != TAG_CPU_NAME
    }
    fpu_tags = {n: {k: v for k, v in t.items() if k in FP_TAGS} for n, t in fpus.items()}

    # What `.arch_extension` changes, which depends on the CPU it is added
    # to: `+fp` is VFPv2 on ARMv6 and VFPv3-d16 on ARMv7-A, and `+sec` on
    # ARMv6K makes the architecture ARMv6KZ.
    exts = names_in(text, "arm_extensions", "ARM_EXT_OPT")
    ext_tags = {}
    for key, base in cpus.items():
        for ext in exts:
            t = measure("%s %s\n.arch_extension %s\n" % (key[0], key[1], ext))
            if t is None:
                continue
            ext_tags.setdefault(key, {})[ext] = {
                k: v for k, v in t.items() if base.get(k) != v
            }
    return cpus, fpu_tags, ext_tags, tag_names(text)


def verify(cpus, fpu_tags, ext_tags, quick=False):
    """Checks the table against GNU as. Returns the failures."""
    bad = []
    for key, tags in cpus.items():
        for fpu, entry in sorted(fpu_tags.items()):
            if quick and fpu not in ("softvfp", "neon-vfpv4", "fp-armv8", "vfpv2"):
                continue
            want = measure("%s %s\n.fpu %s\n" % (key[0], key[1], fpu))
            got = merge(tags, entry)
            if got != want:
                bad.append(("%s %s .fpu %s" % (key[0], key[1], fpu), want, got))
        for ext, delta in sorted(ext_tags.get(key, {}).items()):
            want = measure("%s %s\n.arch_extension %s\n" % (key[0], key[1], ext))
            got = merge(tags, None, delta)
            if got != want:
                bad.append(("%s %s +%s" % (key[0], key[1], ext), want, got))
    return bad


def tag_list(tags):
    ints = sorted((t, v) for t, v in tags.items() if not isinstance(v, str))
    return "&[" + ", ".join("(%d, %d)" % (t, v) for t, v in ints) + "]"


def rust(cpus, fpu_tags, ext_tags, tag_map):
    out = [
        "//! What `.arch`, `.cpu`, `.fpu`, `.arch_extension`, `.object_arch`",
        "//! and `.eabi_attribute` put in `.ARM.attributes`, measured from",
        "//! `arm-none-eabi-as` by `tools/tables/arm-attrs.py`. Do not edit.",
        "//!",
        "//! A CPU's entry is every tag `.arch` or `.cpu` naming it leaves",
        "//! behind, an FPU's is what `.fpu` puts in place of the tags a unit",
        "//! decides, and an extension's is what adding it to that CPU",
        "//! changed. See [`super::attrs`].",
        "",
        "use super::attrs::{Cpu, Named};",
        "",
    ]

    def named(items):
        return "\n".join(
            '    Named { key: "%s", tags: %s },' % (key, tag_list(tags))
            for key, tags in sorted(items.items())
        )

    # CPUs of one generation take the same extensions to the same effect, so
    # each distinct list is written once and shared by every CPU that has it.
    shared, order = {}, []
    rows = {".arch": [], ".cpu": []}
    for key, tags in cpus.items():
        body = named(ext_tags.get(key, {}))
        if body not in shared:
            shared[body] = "EXTS_%d" % len(shared)
            order.append((shared[body], body))
        rows[key[0]].append(
            '    Cpu { key: "%s", cpu_name: "%s", tags: %s, exts: %s },'
            % (key[1], tags.get(TAG_CPU_NAME, ""), tag_list(tags), shared[body])
        )
    for label, body in order:
        out.append("/// The extensions one CPU takes, and what each changes.")
        out.append("static %s: &[Named] = &[" % label)
        if body:
            out.append(body)
        out.append("];")
        out.append("")
    out.append("/// The tags an `.fpu` replaces, which are the unit's own.")
    out.append("pub(crate) static FP_TAGS: &[u8] = &[")
    out.append("    " + ", ".join(str(t) for t in sorted(FP_TAGS)) + ",")
    out.append("];")
    out.append("")
    out.append("/// Every `.fpu` name, and the tags it leaves.")
    out.append("pub(crate) static FPUS: &[Named] = &[")
    out.append(named(fpu_tags))
    out.append("];")
    out.append("")
    out.append("/// The names `.eabi_attribute` takes for a tag, lowercased,")
    out.append("/// and the tag each names.")
    out.append("pub(crate) static TAG_NAMES: &[(&str, u32)] = &[")
    for name, tag in sorted(tag_map.items()):
        out.append('    ("%s", %d),' % (name.lower(), tag))
    out.append("];")
    out.append("")
    for directive, label in ((".arch", "ARCHS"), (".cpu", "CPUS")):
        out.append("/// Every architecture `%s` names." % directive)
        out.append("pub(crate) static %s: &[Cpu] = &[" % label)
        out.extend(rows[directive])
        out.append("];")
        out.append("")
    # rustfmt's layout, so that `cargo fmt` leaves the file as written.
    try:
        return subprocess.run(
            ["rustfmt", "--edition", "2024", "--emit", "stdout"],
            input="\n".join(out),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit("rustfmt failed (%s)" % e)


def main():
    global TMP
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["table", "check"])
    ap.add_argument("--quick", action="store_true", help="verify a sample of units")
    args = ap.parse_args()
    if not os.path.exists(GAS):
        print("no %s; run tools/oracles/build.sh" % GAS, file=sys.stderr)
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        TMP = tmp
        cpus, fpu_tags, ext_tags, tag_map = collect()
        bad = verify(cpus, fpu_tags, ext_tags, args.quick)
        if bad:
            for what, want, got in bad[:20]:
                print("%s: want %s got %s" % (what, want, got), file=sys.stderr)
            print("%d combinations differ" % len(bad), file=sys.stderr)
            return 1
        text = rust(cpus, fpu_tags, ext_tags, tag_map)
    if args.action == "check":
        with open(OUT) as f:
            if f.read() != text:
                print("%s is out of date" % OUT, file=sys.stderr)
                return 1
        return 0
    with open(OUT, "w") as f:
        f.write(text)
    print(
        "%s: %d architectures and CPUs, %d units, %d CPU/extension pairs"
        % (OUT, len(cpus), len(fpu_tags), sum(len(e) for e in ext_tags.values()))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
