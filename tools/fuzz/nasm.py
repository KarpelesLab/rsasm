#!/usr/bin/env python3
"""Differential fuzzer for rsasm's NASM dialect, against NASM itself.

Each case is a whole program, not a statement: NASM source is a language of
sections, a preprocessor and a location counter, and what a line assembles to
depends on every other line. A program is written out once and given to both
assemblers the way `tools/nasm-diff/run.sh` gives its corpus to them --

    nasm  -f <format> -o ref.out  in.asm
    rsasm -d nasm -f <format> -o ours.out in.asm

-- and what they produced is compared:

    bin           the flat image, byte for byte.
    elf32 elf64   each section's type, flags, alignment, size and bytes, every
                  relocation (offset, type, symbol and addend) and every
                  global, weak or undefined symbol. Local symbols are left
                  out, as the corpus harness leaves them out: NASM writes
                  every label into the symbol table and rsasm, like GNU as,
                  keeps them to itself.
    win32 win64   the whole object as tools/coff-diff/canon.sh prints it:
                  section characteristics and bytes, every symbol with its
                  auxiliary records, and every relocation.

What is generated is what the `### NASM` section of README.md claims: sections
(`.text`, `.data`, `.bss`, `.rodata`/`.rdata` and named ones with attributes),
`bits`, `org`, `default rel`, `extern`/`global`/`common`, `db` through `dq`
with strings and expressions, the `resb` family, `equ`, `times`,
`struc`/`istruc`/`at`/`iend`, `align`/`alignb`, `%define`/`%assign`/`%macro`/
`%rep`/`%if`, labels global and local (`.loop`, and `owner.loop` from
elsewhere), and instructions in NASM's operand syntax -- `byte`/`word`/
`dword`/`qword` with no `ptr`, `[rel sym]`, `[abs sym]`, `[rax+rbx*4+8]`,
16-bit addressing, segment overrides -- with `wrt ..plt`, `..got`, `..sym` and
`..gotoff` in ELF and `wrt ..imagebase` in COFF. Jumps run forward and back
over padding chosen to sit either side of the point where a short branch stops
reaching, so both assemblers have to relax the same way.

    tools/fuzz/nasm.py fuzz --seed 1 --count 600
    tools/fuzz/nasm.py fuzz --format elf64 --count 5000 --mutations 0.5 --jobs 8
    tools/fuzz/nasm.py check prog.asm --format bin

A case is classified:

    agree       both produced the same output, or both refused the program.
    rsasm       they differ. These are the findings; the exit status is 1 when
                there are any, and each is printed in full, so that pasting it
                into a file and running the two commands above reproduces it.
                `--limit` (default 20) is how many are shown.
    deviation   they differ in a way `DEVIATIONS` below accounts for --
                `prefix-order`, `macro-local-name` and `branch-width` -- each
                named and counted rather than listed.

`check` says which of the three one program is, and exits 1 only for a
finding, so it can be used on a case pared down by hand.

`--mutations` (default 0.25) is the fraction of programs given a statement
meant to be refused: a register of the wrong width or from another mode, an
immediate past its size, a memory operand with no size where one is needed,
a negative `times`, a label defined twice, a macro called with the wrong
number of arguments, an unterminated `%if`.

Nothing that is compared is written in this script: every byte comes out of a
NASM run. What the two already differ over, and what is therefore left out of
the programs, is the `NOT GENERATED` list below, each entry with a case that
shows it and a note where it would have been written.

Environment: RSASM (default target/debug/rsasm under the repository root),
RSASM_ORACLES (default target/oracles), whose `bin` holds the NASM 2.16.03
that tools/oracles/build.sh builds, and NASM to name another one; llvm-readobj
on the PATH, for the COFF objects. A reference that is missing or is another
version stops the run rather than being skipped.
"""

import argparse
import collections
import concurrent.futures
import difflib
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RSASM = os.environ.get("RSASM", os.path.join(ROOT, "target", "debug", "rsasm"))
ORACLES = os.environ.get("RSASM_ORACLES", os.path.join(ROOT, "target", "oracles"))
NASM = os.environ.get("NASM", os.path.join(ORACLES, "bin", "nasm"))
COFF_CANON = os.path.join(ROOT, "tools", "coff-diff", "canon.sh")

# The output formats tools/nasm-diff/run.sh has a corpus for, with the word
# size each one fixes. `bin` fixes none: it takes a `bits` of its own.
FORMATS = {
    "bin": None,
    "elf32": 32,
    "elf64": 64,
    "win32": 32,
    "win64": 64,
}

# Where rsasm parts from NASM on purpose. Each is a rewriting of both outputs
# that makes the difference disappear: if the two are equal once it has been
# applied, the case is that deviation and not a finding.
#
# prefix-order
#     `lock`, `rep` and `repne` come before the operand-size prefix in NASM
#     (`f0 66 01 01`) and after it in rsasm (`66 f0 01 01`), which is the
#     order GNU as writes prefixes in and the order the backend is written
#     to: see the comment at the head of `encode` in src/arch/x86/encode.rs
#     ("In the order GNU as writes them ... llvm-mc orders some of them
#     differently; the CPU does not care"). The two decode to the same
#     instruction.
#
# macro-local-name
#     `%%foo` expands to `..@<n>.foo`, where <n> counts macro expansions.
#     NASM's count includes expansions of its own standard macros, so the
#     same source gives the same labels different numbers. Only the name
#     differs, and only in COFF, where local symbols are compared at all
#     (see src/nasm/pp.rs, `frame.unique`).
#
# branch-width
#     NASM leaves a forward `jcc` in its six-byte form where the two-byte
#     one would reach by exactly 127 bytes and the section already holds a
#     relocation; rsasm shortens it. Both branch to the same instruction --
#     shortening moves everything after it four bytes down, which is why the
#     displacement is 127 either way -- and every other address in the object
#     moves with it. It is NASM that is being careful here.
#
# NOT GENERATED
#
# The rest of what these runs turned up is left out of the programs rather
# than waved through, since a fuzzer that reports the same handful of
# differences on every run reports nothing. Each is written where it would
# have been generated; this is the list, with the whole of a case that shows
# it. Where "NASM warns" is written, NASM assembles the line and prints a
# warning, and rsasm stops.
#
#   2  `jmp short l`, `jmp near l`, `jz short l`: rsasm reads the keyword as
#      an unexpected token.
#   3  `push dword 0x20` in 16-bit code (and `push word` in 32-bit) is
#      `66 6a 20` to NASM; rsasm ignores the keyword and pushes a word.
#   4  an `extern` nothing refers to is left out of NASM's symbol table and
#      written as undefined by rsasm.
#   5  `-f bin` with more than one section: NASM starts each at a multiple of
#      four and leaves `.bss` out of the file; rsasm lays them end to end and
#      writes `.bss` out as zeroes.
#   6  a segment override that names the default segment (`[ds:ebx]`,
#      `[ss:ebp+1]`, and `[ss:esi*5]`, whose index becomes the base): NASM
#      writes the prefix, rsasm drops it as GNU as does.
#   7  `[sym wrt ..got]` in a 32-bit object, in anything but the `mov eax`
#      moffs form: rsasm writes R_386_GOT32X where NASM writes R_386_GOT32.
#   8  a branch or a `[rel x]` naming a symbol declared `global` in the
#      section it is in: NASM resolves it, rsasm relocates it, as GNU as does.
#   9  re-opening a COFF section with `align=n` after an `align` inside it
#      raised the alignment: NASM keeps the larger, rsasm takes the `align=`.
#  10  a value that does not fit the field it is written into, unless it is a
#      literal (which both truncate, with a warning): `db b - a` where the
#      distance is 300, `and rdi, 0x80000000`, `push 0xffffffff` in 64-bit
#      code, `mov qword [rbx], 0xffffffff`. NASM warns; rsasm refuses.
#  11  `dw label` or `db label` in a COFF object: NASM writes a *four*-byte
#      relocation into the field; rsasm says COFF has no relocation that
#      size. `dq label` in a 32-bit object is the same story.
#  12  a label defined twice at the same address: NASM takes it.
#  13  `[ss:abs sym]` and `[ss:rel sym]`: rsasm reads the `abs`/`rel` after a
#      segment override as an unexpected token.
#  14  `xchg rax, rax` is `48 90` to NASM and `90` to rsasm, as to GNU as.
#  15  an object with nothing in `.text`: rsasm writes the empty section out
#      anyway, NASM leaves it out.
#  16  what NASM lets through with a warning and rsasm refuses: `db` with no
#      operand, an instruction in `.bss`, an unknown section attribute
#      (`section .s data` in ELF), `jmp 0` to an address rather than a label
#      (where rsasm writes a relocation against no symbol at all).


def hex_field(line):
    """A line's hex byte string, and what comes before it."""
    if line and all(c in "0123456789abcdef" for c in line) and len(line) % 2 == 0:
        return "", line
    if line.startswith(("bytes ", "section ")):
        head, _, hexed = line.rpartition(" ")
        if hexed and all(c in "0123456789abcdef" for c in hexed) and not len(hexed) % 2:
            return head + " ", hexed
    return line, ""


# The legacy prefixes, the bytes a run of which may come in either order.
PREFIX_BYTES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}


def sort_prefix_runs(lines):
    """Every run of legacy prefix bytes put in one order, in every hex
    string. Two encodings that differ only in the order of their prefixes
    become equal; one that differs in which prefixes it has stays different."""
    out = []
    for line in lines:
        head, hexed = hex_field(line)
        if hexed:
            b = list(bytes.fromhex(hexed))
            i = 0
            while i < len(b):
                j = i
                while j < len(b) and b[j] in PREFIX_BYTES:
                    j += 1
                if j - i > 1:
                    b[i:j] = sorted(b[i:j])
                i = max(j, i + 1)
            hexed = bytes(b).hex()
        out.append(head + hexed)
    return out


def renumber_macro_locals(lines):
    """`..@17.foo` as `..@N.foo`: the number is a count of expansions. The
    lines come back sorted, since the numbers were what ordered them."""
    return sorted(re.sub(r"\.\.@\d+\.", "..@N.", line) for line in lines)


def strip_numbers(line):
    return re.sub(r"0x[0-9a-fA-F]+|[0-9]+", "", line)


def shorten_long_branches(lines):
    """Every `0f 8x <disp32>` and `e9 <disp32>` whose displacement fits a
    byte, rewritten as its short form. Returns the lines and whether
    anything was rewritten."""
    out = []
    changed = False
    for line in lines:
        head, hexed = hex_field(line)
        if not hexed:
            out.append(line)
            continue
        b = list(bytes.fromhex(hexed))
        short = []
        i = 0
        while i < len(b):
            long_jcc = b[i] == 0x0F and i + 5 < len(b) and 0x80 <= b[i + 1] <= 0x8F
            long_jmp = b[i] == 0xE9 and i + 4 < len(b)
            if long_jcc or long_jmp:
                at = i + (2 if long_jcc else 1)
                disp = int.from_bytes(bytes(b[at:at + 4]), "little", signed=True)
                if -128 <= disp <= 127:
                    short += [0xEB if long_jmp else b[i + 1] - 0x10, disp & 0xFF]
                    i = at + 4
                    continue
            short.append(b[i])
            i += 1
        changed = changed or short != b
        out.append(head + bytes(short).hex())
    return out, changed


def same_but_for_branch_width(left, right):
    """A long branch and the short one it could have been, read alike.

    Shortening a branch moves everything after it four bytes down, so every
    address in the object moves with it; where a branch was rewritten, the
    numbers go too, and what is left is which bytes are there rather than
    where. Where neither side had a branch to shorten nothing is touched, so
    a difference in an address alone is still a difference."""
    left, lchanged = shorten_long_branches(left)
    right, rchanged = shorten_long_branches(right)
    if not (lchanged or rchanged):
        return left, right
    return ([strip_numbers(l) for l in left], [strip_numbers(l) for l in right])


# Each entry rewrites both outputs; a pair that is equal afterwards is that
# deviation rather than a finding.
DEVIATIONS = [
    ("prefix-order", lambda l, r: (sort_prefix_runs(l), sort_prefix_runs(r))),
    ("macro-local-name", lambda l, r: (renumber_macro_locals(l), renumber_macro_locals(r))),
    ("branch-width", same_but_for_branch_width),
]


# --- reading what came out ---------------------------------------------------


def run(cmd, cwd):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, p.stdout + p.stderr


SH_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
}
SH_FLAGS = [(0x1, "W"), (0x2, "A"), (0x4, "X"), (0x10, "M"), (0x20, "S"),
            (0x40, "I"), (0x80, "L"), (0x200, "G"), (0x400, "T")]
ST_BIND = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
ST_TYPE = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
           5: "COMMON", 6: "TLS"}
ST_VIS = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}
# Relocation numbers are compared as numbers; these names are only so that a
# finding reads as something. Anything not listed prints as its number.
R_386 = {1: "R_386_32", 2: "R_386_PC32", 3: "R_386_GOT32", 4: "R_386_PLT32",
         9: "R_386_GOTOFF", 10: "R_386_GOTPC", 20: "R_386_16", 21: "R_386_PC16",
         22: "R_386_8", 23: "R_386_PC8", 43: "R_386_GOT32X"}
R_X86_64 = {1: "R_X86_64_64", 2: "R_X86_64_PC32", 3: "R_X86_64_GOT32",
            4: "R_X86_64_PLT32", 9: "R_X86_64_GOTPCREL", 10: "R_X86_64_32",
            11: "R_X86_64_32S", 12: "R_X86_64_16", 13: "R_X86_64_PC16",
            14: "R_X86_64_8", 15: "R_X86_64_PC8", 24: "R_X86_64_PC64",
            25: "R_X86_64_GOTOFF64", 26: "R_X86_64_GOTPC32",
            41: "R_X86_64_GOTPCRELX", 42: "R_X86_64_REX_GOTPCRELX"}


def reloc_name(machine, num):
    table = R_X86_64 if machine == 62 else R_386 if machine == 3 else {}
    return table.get(num, str(num))


def flag_letters(flags):
    out = "".join(c for bit, c in SH_FLAGS if flags & bit)
    rest = flags & ~sum(bit for bit, _ in SH_FLAGS)
    return out + ("+0x%x" % rest if rest else "")


def describe_elf(path):
    """An ELF object in the form tools/nasm-diff/run.sh compares: sections,
    their bytes, relocations, and the symbols a linker would see."""
    with open(path, "rb") as fh:
        elf = fh.read()
    if elf[:4] != b"\x7fELF":
        return ["not an ELF file"]
    wide = elf[4] == 2
    machine = struct.unpack_from("<H", elf, 18)[0]
    if wide:
        shoff, = struct.unpack_from("<Q", elf, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 0x3A)
        shfmt = "<IIQQQQIIQQ"
    else:
        shoff, = struct.unpack_from("<I", elf, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 0x2E)
        shfmt = "<IIIIIIIIII"
    secs = []
    for i in range(shnum):
        f = struct.unpack_from(shfmt, elf, shoff + i * shentsize)
        name, typ, flags, addr, off, size, link, info, align, entsize = f
        secs.append(dict(name_off=name, type=typ, flags=flags, addr=addr,
                         off=off, size=size, link=link, info=info,
                         align=align, entsize=entsize))

    def string(table, at):
        end = elf.index(b"\0", table + at)
        return elf[table + at:end].decode("utf-8", "replace")

    shstr = secs[shstrndx]["off"] if shnum else 0
    for s in secs:
        s["name"] = string(shstr, s["name_off"])

    def symbols(idx):
        """(name, value, size, info, other, shndx) for one symbol table."""
        sec = secs[idx]
        strtab = secs[sec["link"]]["off"]
        out = []
        step = 24 if wide else 16
        for at in range(sec["off"], sec["off"] + sec["size"], step):
            if wide:
                nm, info, other, shndx, val, size = struct.unpack_from("<IBBHQQ", elf, at)
            else:
                nm, val, size, info, other, shndx = struct.unpack_from("<IIIBBH", elf, at)
            out.append((string(strtab, nm), val, size, info, other, shndx))
        return out

    lines = []
    for s in secs:
        kind = SH_TYPES.get(s["type"], "0x%x" % s["type"])
        if kind in ("NULL", "SYMTAB", "STRTAB", "RELA", "REL"):
            continue
        lines.append("section %s %s flags=%s align=%d size=0x%x"
                     % (s["name"], kind, flag_letters(s["flags"]), s["align"], s["size"]))
        if kind == "PROGBITS":
            lines.append("bytes %s %s" % (s["name"], elf[s["off"]:s["off"] + s["size"]].hex()))
    for s in secs:
        if s["type"] not in (4, 9):
            continue
        syms = symbols(s["link"])
        target = secs[s["info"]]["name"]
        rela = s["type"] == 4
        step = (24 if rela else 16) if wide else (12 if rela else 8)
        for at in range(s["off"], s["off"] + s["size"], step):
            if wide:
                off, info = struct.unpack_from("<QQ", elf, at)
                sym, typ = info >> 32, info & 0xFFFFFFFF
            else:
                off, info = struct.unpack_from("<II", elf, at)
                sym, typ = info >> 8, info & 0xFF
            addend = ""
            if rela:
                a, = struct.unpack_from("<q" if wide else "<i", elf, at + (16 if wide else 8))
                addend = "%+d" % a
            name = syms[sym][0] if sym < len(syms) else "?"
            if not name and sym < len(syms) and syms[sym][5] < len(secs):
                name = secs[syms[sym][5]]["name"]
            lines.append("reloc %s 0x%x %s %s%s"
                         % (target, off, reloc_name(machine, typ), name, addend))
    for i, s in enumerate(secs):
        if s["type"] != 2:
            continue
        for name, val, size, info, other, shndx in symbols(i):
            bind = ST_BIND.get(info >> 4, str(info >> 4))
            if bind == "LOCAL" and shndx != 0:
                continue
            if not name:
                continue
            where = ("UND" if shndx == 0 else "ABS" if shndx == 0xFFF1 else
                     "COM" if shndx == 0xFFF2 else
                     secs[shndx]["name"] if shndx < len(secs) else str(shndx))
            lines.append("symbol %s value=0x%x size=%d %s %s %s %s"
                         % (name, val, size, ST_TYPE.get(info & 0xF, str(info & 0xF)),
                            bind, ST_VIS.get(other & 3, str(other)), where))
    return sorted(lines)


def describe(fmt, path, workdir):
    if fmt == "bin":
        with open(path, "rb") as fh:
            return [fh.read().hex()]
    if fmt.startswith("win"):
        code, text = run([COFF_CANON, path], workdir)
        if code != 0:
            return ["canon.sh failed: " + text.strip()[:200]]
        return text.splitlines()
    return describe_elf(path)


def first_error(log):
    for line in log.splitlines():
        if "error" in line.lower():
            return line.strip()[:200]
    return (log.strip().splitlines() or ["error"])[0][:200]


def assemble(source, fmt, workdir):
    """Both assemblers on one program. Each returns ("OK", lines) or
    ("ERROR", message)."""
    with open(os.path.join(workdir, "in.asm"), "w") as fh:
        fh.write(source)
    out = {}
    for who, cmd, name in (
        ("nasm", [NASM, "-f", fmt, "-o", "ref.out", "in.asm"], "ref.out"),
        ("rsasm", [RSASM, "-d", "nasm", "-f", fmt, "-o", "ours.out", "in.asm"], "ours.out"),
    ):
        path = os.path.join(workdir, name)
        if os.path.exists(path):
            os.unlink(path)
        code, log = run(cmd, workdir)
        if code != 0 or not os.path.exists(path):
            out[who] = ("ERROR", first_error(log))
        else:
            out[who] = ("OK", describe(fmt, path, workdir))
    return out["nasm"], out["rsasm"]


def classify(ref, ours):
    if ref[0] == "ERROR" and ours[0] == "ERROR":
        return "agree", None
    if ref[0] != ours[0]:
        return "rsasm", "accepts" if ref[0] == "ERROR" else "refuses"
    if ref[1] == ours[1]:
        return "agree", None
    left, right = ref[1], ours[1]
    matched = []
    for name, rewrite in DEVIATIONS:
        was = (set(left), set(right))
        left, right = rewrite(left, right)
        # A rewriting that only reordered the lines has explained nothing.
        if (set(left), set(right)) != was:
            matched.append(name)
        if left == right:
            return "deviation", "+".join(matched) or "reordered"
    return "rsasm", "output"


# --- the source a case is made of --------------------------------------------

REGS = {
    16: {
        8: ["al", "bl", "cl", "dl", "ah", "ch"],
        16: ["ax", "bx", "cx", "dx", "si", "di", "bp"],
        32: ["eax", "ebx", "ecx", "edx", "esi", "edi"],
    },
    32: {
        8: ["al", "bl", "cl", "dl", "ah", "dh"],
        16: ["ax", "bx", "cx", "dx", "si", "di"],
        32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
    },
    64: {
        8: ["al", "bl", "cl", "dl", "sil", "dil", "r8b", "r13b"],
        16: ["ax", "bx", "cx", "dx", "si", "di", "r9w", "r14w"],
        32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "r10d", "r15d"],
        64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r11", "r12"],
    },
}
SIZE_KEYWORD = {8: "byte", 16: "word", 32: "dword", 64: "qword"}
DATA_KEYWORD = {8: "db", 16: "dw", 32: "dd", 64: "dq"}
RES_KEYWORD = {8: "resb", 16: "resw", 32: "resd", 64: "resq"}
CONDITIONS = ["e", "ne", "l", "le", "g", "ge", "a", "ae", "b", "be", "s", "ns",
              "z", "nz", "o", "no", "p", "np"]
SEGMENTS = ["es", "cs", "ss", "ds", "fs", "gs"]
ALU = ["add", "sub", "and", "or", "xor", "cmp", "adc", "sbb"]
SHIFTS = ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr"]
# Padding lengths around the point a short branch stops reaching, so both
# assemblers have to decide a jump's width the same way.
PADDINGS = [1, 2, 3, 120, 124, 125, 126, 127, 128, 129, 130, 131, 200, 300]


class Gen:
    """Draws NASM source for one program.

    Labels are planned before any statement is written, so a reference may run
    forward as easily as back; whatever is still undefined when the blocks are
    done is defined at the end of a block of its kind.
    """

    def __init__(self, rng, fmt, mutate):
        self.rng = rng
        self.fmt = fmt
        self.mutate = mutate
        self.bits = FORMATS[fmt] or rng.choice([16, 32, 64])
        self.elf = fmt.startswith("elf")
        self.coff = fmt.startswith("win")
        self.obj = self.elf or self.coff
        self.rel = self.bits == 64 and rng.random() < 0.4
        self.underscore = "_" if fmt == "win32" else ""
        self.code = []
        self.data = []
        self.bss = []
        self.defined = set()
        self.externs = []
        self.commons = []
        self.equs = []
        self.strucs = []
        self.mutations = []
        self.declared = set()

    # -- names ---------------------------------------------------------------

    def plan(self):
        pre = self.underscore
        self.code = ["%scode%d" % (pre, i) for i in range(self.rng.randint(2, 5))]
        self.data = ["%sdat%d" % (pre, i) for i in range(self.rng.randint(1, 4))]
        # A flat binary holds one section here; see `source` for why.
        self.bss = ([] if self.fmt == "bin" else
                    ["%sbuf%d" % (pre, i) for i in range(self.rng.randint(0, 2))])
        if self.obj:
            self.externs = ["%sext%d" % (pre, i) for i in range(self.rng.randint(0, 2))]
            if self.rng.random() < 0.2:
                self.commons = ["%scom%d" % (pre, i) for i in range(1)]
        self.locals = {}          # owner -> [local names]
        self.equs = ["eq%d" % i for i in range(self.rng.randint(0, 2))]
        # A branch to a symbol declared `global` is resolved by NASM, where
        # it is in the section the branch is in, and relocated by rsasm, as
        # GNU as relocates one (the linker may preempt the symbol). So an
        # exported code label is not used as a branch target here; the
        # difference is NOT GENERATED 8, not a finding.
        self.exported = set()
        if self.obj:
            # The first code label stays unexported, so there is always
            # somewhere to branch to.
            self.exported = {n for n in self.code[1:] + self.data + self.bss
                             if self.rng.random() < 0.5}

    def label(self, kinds="cdb", with_local=True):
        """A label to refer to: a planned one, a local of one, an extern or a
        constant from `equ`."""
        rng = self.rng
        pool = []
        if "c" in kinds:
            pool += [n for n in self.code if n not in self.exported]
        if "d" in kinds:
            pool += self.data
        if "b" in kinds:
            pool += self.bss
        pool += self.externs + self.commons
        if with_local:
            for owner, names in self.locals.items():
                pool += ["%s%s" % (owner, n) for n in names]
        if not pool:
            return "0"
        return rng.choice(pool)

    # -- expressions and operands -------------------------------------------

    def number(self, bits):
        rng = self.rng
        edges = {8: [0, 1, 0x7F, 0x80, 0xFF, -1, -128],
                 16: [0, 1, 0x7FFF, 0x8000, 0xFFFF, -1, -32768],
                 32: [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, -1],
                 64: [0, 1, 0x7FFFFFFFFFFFFFFF, -1, 0x100000000]}[bits]
        r = rng.random()
        if r < 0.35:
            return rng.choice(edges)
        if r < 0.5:
            return rng.randint(0, 127)
        return rng.randint(0, (1 << min(bits, 32)) - 1)

    def spell(self, value):
        """A number in one of NASM's spellings."""
        rng = self.rng
        neg = value < 0
        v = -value if neg else value
        r = rng.random()
        if r < 0.45:
            text = "0x%x" % v
        elif r < 0.65:
            text = "%d" % v
        elif r < 0.75:
            # NASM's trailing-radix spellings. A hex number written this way
            # has to start with a digit, or it is read as a name.
            h = "%x" % v
            text = ("0" + h if h[0] in "abcdef" else h) + "h"
        elif r < 0.85:
            text = "0b%s" % bin(v)[2:]
        elif r < 0.95 and v:
            text = "%oo" % v
        else:
            text = "%d" % v
        return "-" + text if neg else text

    def imm(self, bits):
        """An immediate: a number, an expression over numbers, or a symbol."""
        rng = self.rng
        r = rng.random()
        if r < 0.1 and self.equs:
            return rng.choice(self.equs)
        if r < 0.2 and bits >= 32 and (self.data or self.code):
            return self.label("cd")
        if r < 0.3:
            a, b = rng.randint(0, 40), rng.randint(1, 8)
            op = rng.choice(["+", "-", "*", "<<", ">>", "|", "&", "^", "/", "%"])
            return "(%d %s %d)" % (a, op, b)
        return self.spell(self.number(bits))

    def alu_imm(self, mnemonic, size, to_reg=True):
        """The immediate an arithmetic instruction takes. A 64-bit operand
        takes a *signed* 32 bits, except `mov` into a register, which has an
        imm64 form; NASM warns and truncates one that does not fit, and rsasm
        refuses it (NOT GENERATED 10), so one that does not fit is not
        written here."""
        if size == 64 and not (mnemonic == "mov" and to_reg):
            return self.spell(self.rng.choice(
                [0, 1, 0x7FFFFFFF, -1, -0x80000000, self.rng.randint(0, 0xFFFF)]))
        return self.imm(min(size, 32))

    def mem(self, size=None, forbid_rel=False):
        """A memory operand, with a size keyword where `size` asks for one."""
        rng = self.rng
        prefix = (SIZE_KEYWORD[size] + " ") if size else ""
        # A segment override is written only where it is not the default for
        # the base register. NASM writes a redundant one out (`3e` on
        # `[ds:rbx]`) and rsasm drops it, as GNU as does -- the split
        # tools/fuzz/README.md names under x86.py's conventions.
        def override(*bases):
            # `bases` is every register that may end up the base: for
            # `[reg*5]`, which both assemblers fold into `[reg+reg*4]`, the
            # index becomes one.
            if rng.random() >= 0.08:
                return ""
            out = {"ss" if re.match(r"^(r|e)?(bp|sp)", b) else "ds" for b in bases}
            return rng.choice([s for s in SEGMENTS if s not in out]) + ":"

        if self.bits == 16:
            base = rng.choice(["bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bx", "bp"])
            seg = override(base)
            disp = rng.choice(["", "", "+%d" % rng.randint(1, 0x7F), "-%d" % rng.randint(1, 0x7F),
                               "+0x%x" % rng.randint(0x80, 0x7FFF)])
            # A displacement on its own has no base, so its default segment
            # is ds whatever the register form's would have been.
            noseg = override("")
            forms = ["[%s%s%s]" % (seg, base, disp),
                     "[%s%s]" % (noseg, self.spell(rng.randint(0, 0xFFFF))),
                     "[%s%s]" % (noseg, self.label("db"))]
            return prefix + rng.choice(forms)
        wide = self.bits == 64
        gpr = REGS[self.bits][64 if wide else 32]
        base = rng.choice(gpr)
        seg = override(base)
        index = rng.choice([r for r in gpr if r not in ("rsp", "esp")])
        scale = rng.choice([1, 2, 4, 8])
        disp = rng.choice(["", "", "+%d" % rng.randint(1, 0x7F), "-%d" % rng.randint(1, 0x7F),
                           "+0x%x" % rng.randint(0x80, 0x7FFFF)])
        # With no base register, a scale of 1 becomes the base, 2 becomes
        # `reg + reg*1` and 3, 5 or 9 become `reg + reg*2/4/8`; only 4 and 8
        # are encoded as they are written, since an index alone costs a
        # four-byte displacement.
        alone = rng.choice([1, 2, 3, 4, 5, 8, 9])
        noseg = override("")
        indexseg = override("", index)
        forms = ["[%s%s%s]" % (seg, base, disp),
                 "[%s%s+%s*%d%s]" % (seg, base, index, scale, disp),
                 "[%s%s*%d%s]" % (indexseg, index, alone, disp),
                 "[%s%s]" % (noseg, self.spell(rng.randint(0, 0xFFFF)))]
        sym = self.label("db")
        if not forbid_rel and sym != "0":
            if wide:
                # `rel` and `abs` go without a segment override: rsasm reads
                # `[ss:abs sym]`, which NASM takes, as a bad operand
                # (NOT GENERATED 13), so the two are not combined here.
                forms += ["[rel %s]" % sym, "[abs %s]" % sym]
                # A `wrt ..got` reference in an instruction is written in
                # 64-bit code only: in 32-bit code rsasm writes
                # R_386_GOT32X for every ModRM form where NASM writes
                # R_386_GOT32 (NOT GENERATED 7). `dd sym wrt ..got` in data,
                # which both write as R_386_GOT32, is still generated.
                if self.elf and self.externs and rng.random() < 0.5:
                    forms.append("[rel %s wrt ..got]" % self.extern())
            else:
                forms += ["[%s%s]" % (noseg, sym), "[%s%s+%s*4]" % (noseg, sym, index)]
        return prefix + rng.choice(forms)

    def extern(self):
        return self.rng.choice(self.externs)

    def reg(self, size):
        return self.rng.choice(REGS[self.bits][size])

    def op_size(self):
        sizes = [8, 16, 32] + ([64] if self.bits == 64 else [])
        return self.rng.choice(sizes)

    # -- instructions --------------------------------------------------------

    def instruction(self):
        rng = self.rng
        pick = rng.random()
        size = self.op_size()
        if pick < 0.22:
            m = rng.choice(ALU + ["mov", "test", "xchg"])
            form = rng.random()
            # `xchg` has no immediate form at all, so draw it another way
            # rather than spend the case on a refusal both agree on.
            if m == "xchg" and (0.25 <= form < 0.5 or form >= 0.9):
                form = 0.8
            if form < 0.25:
                dst, src = self.reg(size), self.reg(size)
                # `xchg rax, rax` is `48 90` to NASM and `90` -- a plain
                # `nop`, as GNU as writes it -- to rsasm, so the two
                # registers are kept apart (NOT GENERATED 14).
                while m == "xchg" and dst == src:
                    src = self.reg(size)
                return "%s %s, %s" % (m, dst, src)
            if form < 0.5:
                return "%s %s, %s" % (m, self.reg(size), self.alu_imm(m, size))
            if form < 0.75:
                return "%s %s, %s" % (m, self.reg(size), self.mem())
            if form < 0.9:
                return "%s %s, %s" % (m, self.mem(), self.reg(size))
            return "%s %s, %s" % (m, self.mem(size), self.alu_imm(m, size, to_reg=False))
        if pick < 0.3:
            m = rng.choice(["inc", "dec", "neg", "not", "mul", "imul", "div", "idiv"])
            if rng.random() < 0.6:
                return "%s %s" % (m, self.reg(size))
            return "%s %s" % (m, self.mem(size))
        if pick < 0.36:
            width = 64 if self.bits == 64 else self.bits
            if rng.random() < 0.5:
                return "push %s" % self.reg(width)
            if rng.random() < 0.5:
                return "pop %s" % self.reg(width)
            if rng.random() < 0.5:
                return "push %s" % self.mem(width)
            # In 64-bit mode a `push` immediate is a *signed* 32-bit one.
            return "push %s" % (self.alu_imm("push", 64) if self.bits == 64
                                else self.imm(self.bits))
        if pick < 0.42:
            return "lea %s, %s" % (self.reg(64 if self.bits == 64 else self.bits),
                                   self.mem(forbid_rel=self.bits != 64))
        if pick < 0.48:
            m = rng.choice(SHIFTS)
            dst = self.reg(size) if rng.random() < 0.6 else self.mem(size)
            src = rng.choice(["1", "cl", str(rng.randint(0, 31))])
            return "%s %s, %s" % (m, dst, src)
        if pick < 0.54:
            big = 64 if self.bits == 64 else 32
            small = rng.choice([8, 16])
            if small >= big:
                small = 8
            m = rng.choice(["movzx", "movsx"])
            if rng.random() < 0.5:
                return "%s %s, %s" % (m, self.reg(big), self.reg(small))
            return "%s %s, %s" % (m, self.reg(big), self.mem(small))
        if pick < 0.6:
            cc = rng.choice(CONDITIONS)
            if rng.random() < 0.5:
                return "set%s %s" % (cc, self.reg(8) if rng.random() < 0.7 else self.mem(8))
            return "cmov%s %s, %s" % (cc, self.reg(max(size, 16)), self.reg(max(size, 16)))
        if pick < 0.66:
            m = rng.choice(["bt", "bts", "btr", "btc", "bsf", "bsr"])
            wide = max(size, 16)
            if m.startswith("bs"):
                return "%s %s, %s" % (m, self.reg(wide), self.reg(wide))
            return "%s %s, %s" % (m, self.reg(wide),
                                  str(rng.randint(0, 31)) if rng.random() < 0.5 else self.reg(wide))
        if pick < 0.72:
            return rng.choice([
                "nop", "ret", "leave", "cld", "std", "cli", "sti", "hlt", "pause",
                "cpuid", "rdtsc", "int3", "ud2", "xlatb", "lahf", "sahf",
                "ret %d" % rng.randint(0, 64), "int %s" % self.spell(rng.randint(0, 255)),
                "cwd" if self.bits == 16 else "cdq", "bswap %s" % self.reg(max(32, size)),
            ] + (["syscall", "cqo", "cdqe"] if self.bits == 64 else []))
        if pick < 0.78:
            m = rng.choice(["movsb", "movsw", "stosb", "stosw", "lodsb", "scasb", "cmpsb"])
            if self.bits >= 32:
                m = rng.choice([m, m[:-1] + "d"])
            return rng.choice(["", "rep ", "repe ", "repne "]) + m
        if pick < 0.84:
            # A jump or call, forward or back over whatever padding is between.
            target = self.label("c", with_local=True)
            m = rng.choice(["jmp", "call"] + ["j" + c for c in CONDITIONS])
            if self.elf and self.externs and m == "call" and rng.random() < 0.3:
                return "call %s wrt ..plt" % self.extern()
            return "%s %s" % (m, target)
        if pick < 0.88:
            kind = rng.choice(["reg", "mem"])
            width = 64 if self.bits == 64 else self.bits
            if kind == "reg":
                return "%s %s" % (rng.choice(["jmp", "call"]), self.reg(width))
            return "%s %s" % (rng.choice(["jmp", "call"]), self.mem(width))
        if pick < 0.92:
            m = rng.choice(["xadd", "cmpxchg"])
            wide = max(size, 16)
            return "lock %s %s, %s" % (m, self.mem(wide), self.reg(wide))
        if pick < 0.96:
            # A symbol as an immediate or an accumulator load: the relocations
            # an object format has to write for data references from code.
            sym = self.label("db")
            if sym == "0":
                return "nop"
            if self.bits == 64:
                return rng.choice([
                    "mov rax, %s" % sym,
                    "mov eax, %s" % sym,
                    "lea %s, [rel %s]" % (self.reg(64), sym),
                    "mov %s, [rel %s]" % (self.reg(32), sym),
                    "mov %s [rel %s], %s" % (SIZE_KEYWORD[32], sym, self.imm(32)),
                ])
            forms = [
                "mov %s, %s" % (self.reg(32), sym),
                "mov %s, [%s]" % (self.reg(32), sym),
                "mov [%s], %s" % (sym, self.reg(32)),
                "push %s %s" % (SIZE_KEYWORD[self.bits], sym),
                "mov %s [%s], %s" % (SIZE_KEYWORD[8], sym, self.spell(rng.randint(0, 255))),
            ]
            return rng.choice(forms)
        m = rng.choice(["movaps", "movdqa", "movups", "paddd", "pxor", "addps", "mulps"])
        x, y = "xmm%d" % rng.randint(0, 7), "xmm%d" % rng.randint(0, 7)
        if rng.random() < 0.5:
            return "%s %s, %s" % (m, x, y)
        return "%s %s, %s" % (m, x, self.mem())

    # -- data ----------------------------------------------------------------

    def string(self):
        rng = self.rng
        body = "".join(rng.choice("abcXYZ019 .,") for _ in range(rng.randint(1, 6)))
        r = rng.random()
        if r < 0.4:
            return "'%s'" % body
        if r < 0.7:
            return '"%s"' % body
        return "`%s\\n\\t\\x41`" % body

    def data_item(self, size):
        rng = self.rng
        r = rng.random()
        if r < 0.15 and size == 8:
            return self.string()
        if r < 0.25 and size >= 16:
            return self.string()
        # A symbol goes in a field the format has a relocation for: 32 bits
        # everywhere, 64 only where the target is. (NASM takes `dq sym` in a
        # 32-bit object, warns, and writes a 32-bit relocation zero-extended
        # into the field; rsasm refuses it: NOT GENERATED 11.)
        if r < 0.4 and (size == 32 or (size == 64 and self.bits == 64)):
            sym = self.label("cdb")
            if sym != "0":
                if self.elf and sym in self.externs and rng.random() < 0.4:
                    return "%s wrt %s" % (sym, rng.choice(
                        ["..got", "..sym"] + (["..gotoff"] if size == 64 else [])))
                if self.fmt == "win64" and size == 32 and rng.random() < 0.4:
                    return "%s wrt ..imagebase" % sym
                return sym
        # A distance is only written where it fits: NASM warns and truncates
        # one that does not, and rsasm refuses it (NOT GENERATED 10).
        if r < 0.5 and size >= 32 and len(self.code) >= 2:
            return "%s - %s" % (self.code[0], self.code[1])
        if r < 0.55 and size >= 32:
            return "$ - $$"
        return self.spell(self.number(size))

    def data_line(self):
        rng = self.rng
        size = rng.choice([8, 8, 16, 32, 32, 64])
        items = [self.data_item(size) for _ in range(rng.randint(1, 4))]
        return "%s %s" % (DATA_KEYWORD[size], ", ".join(items))

    # -- whole programs ------------------------------------------------------

    def preamble(self):
        rng = self.rng
        out = []
        if self.fmt == "bin":
            out.append("bits %d" % self.bits)
            if rng.random() < 0.3:
                out.append("org %s" % rng.choice(["0x7c00", "0x100", "0"]))
        elif rng.random() < 0.3:
            out.append("bits %d" % self.bits)
        if self.rel:
            out.append("default rel")
        for name in self.externs:
            out.append("extern %s" % name)
        for name in self.commons:
            out.append("common %s %d" % (name, rng.choice([4, 8, 16])))
        if self.obj:
            for name in sorted(self.exported):
                if self.elf and rng.random() < 0.3:
                    out.append("global %s:%s" % (name, "function" if name in self.code else "data"))
                else:
                    out.append("global %s" % name)
        for name in self.equs:
            out.append("%s equ %s" % (name, self.spell(rng.randint(0, 0x1000))))
        if rng.random() < 0.3:
            out += self.macro_definition()
        if rng.random() < 0.25:
            self.strucs.append("rec%d" % len(self.strucs))
            out.append("struc %s" % self.strucs[-1])
            for field in ("a", "b", "c"):
                out.append(".%s: %s 1" % (field, RES_KEYWORD[rng.choice([8, 16, 32, 64])]))
            out.append("endstruc")
        return out

    def macro_definition(self):
        rng = self.rng
        name = "m%d" % rng.randint(0, 3)
        self.macro = name
        kind = rng.random()
        if kind < 0.4:
            self.macro_args = 2
            return ["%%macro %s 2" % name,
                    "db %1", "db %2", "%endmacro"]
        if kind < 0.7:
            self.macro_args = 1
            return ["%%macro %s 1-2 0x55" % name,
                    "db %0, %1, %2", "%endmacro"]
        self.macro_args = 1
        # COFF has no 2-byte relocation, and NASM writes a 4-byte one into
        # the 2-byte field rather than say so, so the label is referred to
        # through a doubleword there.
        return ["%%macro %s 1" % name,
                "%%%%local_%s: db %%1" % name,
                "%s %%%%local_%s" % ("dd" if self.coff else "dw", name), "%endmacro"]

    def preprocessor(self):
        """A run of preprocessor lines that stands on its own wherever data
        may go."""
        rng = self.rng
        r = rng.random()
        if r < 0.25:
            name = "D%d" % rng.randint(0, 3)
            return ["%%define %s %s" % (name, self.spell(rng.randint(0, 0xFF))),
                    "db %s" % name]
        if r < 0.45:
            return ["%assign counter 0",
                    "%%rep %d" % rng.randint(1, 5),
                    "db counter",
                    "%assign counter counter+1",
                    "%endrep"]
        if r < 0.6:
            return ["%%if %d %s %d" % (rng.randint(0, 3), rng.choice(["==", "<", ">", "!="]),
                                       rng.randint(0, 3)),
                    "db 0x11",
                    "%else",
                    "db 0x22",
                    "%endif"]
        if r < 0.7:
            return ["%define HAVE 1", "%ifdef HAVE", "db 0x33", "%endif",
                    "%ifndef NOPE", "db 0x44", "%endif"]
        if r < 0.8 and getattr(self, "macro", None):
            args = ", ".join(self.spell(rng.randint(0, 0xFF)) for _ in range(self.macro_args))
            return ["%s %s" % (self.macro, args)]
        if r < 0.9:
            return ["%define twice(x) ((x) * 2)", "db twice(%d)" % rng.randint(0, 40)]
        return ["%%strlen slen %s" % self.string(), "db slen"]

    def section_line(self, spec):
        """`section <name> <attributes>`, with the attributes only the first
        time the section is opened. Re-declaring one with `align=` resets the
        alignment an `align` inside it had raised, in COFF (NOT GENERATED 9),
        and real source names a section's attributes once."""
        name = spec.split()[0]
        if name in self.declared:
            return "section %s" % name
        self.declared.add(name)
        return "section %s" % spec

    def text_block(self, section):
        rng = self.rng
        out = [self.section_line(section)]
        for _ in range(rng.randint(1, 8)):
            r = rng.random()
            if r < 0.12 and self.code:
                name = rng.choice([n for n in self.code if n not in self.defined] or self.code)
                if name not in self.defined:
                    self.defined.add(name)
                    self.owner = name
                    out.append("%s:" % name)
                    continue
            if r < 0.2 and getattr(self, "owner", None):
                local = ".l%d" % len(self.locals.setdefault(self.owner, []))
                self.locals[self.owner].append(local)
                out.append("%s:" % local)
                continue
            if r < 0.28:
                out.append("times %d db 0x90" % rng.choice(PADDINGS))
                continue
            if r < 0.33:
                out.append("align %d" % rng.choice([2, 4, 8, 16]))
                continue
            if r < 0.38:
                out.append(self.data_line())
                continue
            if r < 0.44:
                out += self.preprocessor()
                continue
            out.append(self.instruction())
        return out

    def data_block(self, section):
        rng = self.rng
        out = [self.section_line(section)]
        for _ in range(rng.randint(1, 6)):
            r = rng.random()
            if r < 0.2 and self.data:
                name = rng.choice([n for n in self.data if n not in self.defined] or self.data)
                if name not in self.defined:
                    self.defined.add(name)
                    self.owner = name
                    out.append("%s:" % name)
                    if rng.random() < 0.2 and self.equs:
                        # An `equ` does not take the local labels after it:
                        # they still belong to the label before, in both
                        # assemblers.
                        out.append("%s_len equ $ - %s" % (name, name))
                    continue
            if r < 0.3 and self.strucs:
                which = rng.choice(self.strucs)
                out.append("istruc %s" % which)
                for field in ("a", "c"):
                    out.append("at %s.%s, db 0x%02x" % (which, field, rng.randint(0, 255)))
                out.append("iend")
                continue
            if r < 0.38:
                out.append(rng.choice(["align %d" % rng.choice([2, 4, 8]),
                                       "alignb %d" % rng.choice([2, 4, 8])]))
                continue
            if r < 0.45:
                out.append("times %d %s" % (rng.randint(1, 6), self.data_line()))
                continue
            if r < 0.55:
                out += self.preprocessor()
                continue
            out.append(self.data_line())
        return out

    def bss_block(self):
        rng = self.rng
        out = [self.section_line(".bss")]
        for _ in range(rng.randint(1, 4)):
            if self.bss and rng.random() < 0.5:
                name = rng.choice([n for n in self.bss if n not in self.defined] or self.bss)
                if name not in self.defined:
                    self.defined.add(name)
                    # Every label a local one may hang off, wherever it is.
                    self.owner = name
                    out.append("%s:" % name)
                    continue
            if rng.random() < 0.2:
                out.append("alignb %d" % rng.choice([4, 8, 16]))
                continue
            size = rng.choice([8, 16, 32, 64])
            out.append("%s %d" % (RES_KEYWORD[size], rng.randint(1, 64)))
        return out

    def mutation(self, lines):
        """One statement that ought to be refused, somewhere in the program."""
        rng = self.rng
        bits = self.bits
        wrong = []
        wrong.append("mov %s, %s" % (self.reg(32), self.reg(8)))
        # A plain base register, not a symbol: a mutation may land in a data
        # section, and a rip-relative reference from one to a label in it is
        # resolved by NASM and relocated by rsasm (NOT GENERATED 8).
        plain = {16: "[bx]", 32: "[ebx]", 64: "[rbx]"}[bits]
        wrong.append("mov byte %s, 0x1234" % plain)
        wrong.append("mov %s, 1" % plain)                # no size to go on
        wrong.append("add %s, %s" % (self.reg(8), self.spell(self.number(32))))
        wrong.append("times -1 db 0")
        if bits != 64:
            wrong.append("mov rax, rbx")
            wrong.append("push r8")
            wrong.append("mov %s, [rip+4]" % self.reg(32))
        else:
            wrong.append("push eax")
            wrong.append("mov rax, [bx+si]")
        if self.defined:
            # A byte first, so that the second definition is at an address of
            # its own: NASM takes a label defined twice at the *same* address
            # (NOT GENERATED 12), and only a real move is refused by both.
            wrong.append("db 0\n%s: db 0" % sorted(self.defined)[0])
        if getattr(self, "macro", None):
            wrong.append("%s 1, 2, 3, 4, 5" % self.macro)
        wrong.append("%if 1")                            # never closed
        wrong.append("resb 4")                           # in a progbits section
        wrong.append("%undefined_directive 1")
        choice = rng.choice(wrong)
        self.mutations.append(choice)
        # Not into a `.bss` block: rsasm refuses an instruction there and
        # NASM lets it through, which would hide what the mutation is for.
        places = [i for i in range(1, len(lines) + 1)
                  if not self.in_bss(lines, i)]
        at = rng.choice(places) if places else len(lines)
        return lines[:at] + [choice] + lines[at:]

    @staticmethod
    def in_bss(lines, at):
        for line in reversed(lines[:at]):
            if line.startswith("section "):
                return line.split()[1] == ".bss"
        return False

    def source(self):
        rng = self.rng
        self.plan()
        lines = self.preamble()
        text_sections = [".text"]
        data_sections = [".rdata" if self.coff else ".rodata", ".data"]
        if self.obj and rng.random() < 0.2:
            named = ".s%d" % rng.randint(0, 3)
            attr = rng.choice(["", " align=8", " data align=4" if self.coff else
                               " progbits alloc noexec write align=16"])
            data_sections.append(named + attr)
        if self.fmt == "bin":
            # A flat binary is written in one section. Where a program has
            # more, NASM's `bin` writer lays each one out at a multiple of 4
            # and leaves `.bss` out of the file altogether, while rsasm puts
            # them end to end and writes `.bss` out as zeroes -- a difference
            # this fuzzer is not about: NOT GENERATED 5.
            text_sections = data_sections = [".text"]
        blocks = []
        for _ in range(rng.randint(2, 6)):
            r = rng.random()
            if r < 0.5:
                blocks.append(self.text_block(rng.choice(text_sections)))
            elif r < 0.85 or not self.bss:
                blocks.append(self.data_block(rng.choice(data_sections)))
            else:
                blocks.append(self.bss_block())
        for block in blocks:
            lines += block
        # Whatever was planned but never placed is defined now, so that no
        # reference is left dangling.
        tail = []
        for name in self.code:
            if name not in self.defined:
                tail += ["section %s" % text_sections[0], "%s:" % name, "ret"]
        for name in self.data:
            if name not in self.defined:
                tail += ["section %s" % (".text" if self.fmt == "bin" else ".data"),
                         "%s:" % name, "dd 0"]
        for name in self.bss:
            if name not in self.defined:
                tail += ["section .bss", "%s:" % name, "resb 8"]
        lines += tail
        # NASM writes an `extern` into the object only where something refers
        # to it, and rsasm writes every one; a program that declares a symbol
        # it never uses would differ for that reason alone, so each one gets
        # a reference. The difference itself is NOT GENERATED 4.
        text = "\n".join(l for l in lines
                         if not l.startswith(("extern ", "common ", "global ")))
        for name in self.externs + self.commons:
            if not re.search(r"(?<![\w.$#@~?])%s(?![\w.$#@~?])" % re.escape(name), text):
                lines += ["section %s" % (".data" if self.obj else ".text"),
                          "%s %s" % (DATA_KEYWORD[self.bits if self.bits != 16 else 32], name)]
        if self.mutate:
            lines = self.mutation(lines)
        body = "\n".join(("        " + l if not l.endswith(":") and not l.startswith("%")
                          else l) for l in lines)
        return body + "\n"


def make(seed, fmt, mutate):
    gen = Gen(random.Random(seed), fmt, mutate)
    return gen.source(), gen


# --- running a case ----------------------------------------------------------


def one(job):
    seed, fmt, mutate = job
    source, gen = make(seed, fmt, mutate)
    with tempfile.TemporaryDirectory() as d:
        ref, ours = assemble(source, fmt, d)
    cls, detail = classify(ref, ours)
    return dict(seed=seed, fmt=fmt, cls=cls, detail=detail, source=source,
                mutation="; ".join(gen.mutations), ref=ref, ours=ours,
                refused=ref[0] == "ERROR")


def show(result, limit=30):
    r = result
    print("### %s [%s] seed %d%s"
          % (r["detail"] or r["cls"], r["fmt"], r["seed"],
             " (mutation: %s)" % r["mutation"] if r["mutation"] else ""))
    print("    |" + r["source"].rstrip("\n").replace("\n", "\n    |"))
    if r["ref"][0] == "ERROR":
        print("  nasm:  ERROR %s" % r["ref"][1])
    if r["ours"][0] == "ERROR":
        print("  rsasm: ERROR %s" % r["ours"][1])
    if r["ref"][0] == "OK" and r["ours"][0] == "OK":
        diff = list(difflib.unified_diff(r["ref"][1], r["ours"][1], "nasm", "rsasm",
                                         n=0, lineterm=""))
        print("\n".join("  " + l for l in diff[2:limit]))


def fuzz(args):
    formats = [args.format] if args.format else sorted(FORMATS)
    rng = random.Random(args.seed)
    jobs = [(rng.getrandbits(48), rng.choice(formats), rng.random() < args.mutations)
            for _ in range(args.count)]
    counts = collections.Counter()
    by_format = collections.Counter()
    deviations = collections.Counter()
    findings = []
    refused = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as ex:
        for r in ex.map(one, jobs, chunksize=4):
            counts[r["cls"]] += 1
            by_format[r["fmt"]] += 1
            refused += r["cls"] == "agree" and r["refused"]
            if r["cls"] == "deviation":
                deviations[r["detail"]] += 1
            elif r["cls"] == "rsasm":
                findings.append(r)
    print("formats: " + "  ".join("%s %d" % kv for kv in sorted(by_format.items())))
    print("classes: " + "  ".join("%s %d" % kv for kv in sorted(counts.items()))
          + "  (%d of the agreements are both refusing the program)" % refused)
    if deviations:
        print("deviations: " + "  ".join("%s %d" % kv for kv in deviations.most_common()))
    findings.sort(key=lambda r: (r["detail"], len(r["source"])))
    for r in findings[:args.limit]:
        show(r)
    if len(findings) > args.limit:
        print("... %d more finding(s)" % (len(findings) - args.limit))
    # The last line is the one tools/fuzz/run.sh reads.
    print("--- nasm: %d case(s) compared, %d finding(s)" % (sum(counts.values()), len(findings)))
    return 1 if findings else 0


def check(args):
    with open(args.file) as fh:
        source = fh.read()
    with tempfile.TemporaryDirectory() as d:
        ref, ours = assemble(source, args.format, d)
    cls, detail = classify(ref, ours)
    result = dict(seed=0, fmt=args.format, cls=cls, detail=detail, source=source,
                  mutation="", ref=ref, ours=ours)
    if cls == "agree":
        print("agree [%s]" % args.format)
        return 0
    show(result, limit=200)
    return 1 if cls == "rsasm" else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    fz = sub.add_parser("fuzz", help="generate random programs and compare output")
    fz.add_argument("--seed", type=int, default=1)
    fz.add_argument("--count", type=int, default=600)
    fz.add_argument("--format", choices=sorted(FORMATS), help="default: all of them")
    fz.add_argument("--mutations", type=float, default=0.25)
    fz.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    fz.add_argument("--limit", type=int, default=20, help="findings shown")
    ck = sub.add_parser("check", help="compare one program")
    ck.add_argument("file")
    ck.add_argument("--format", choices=sorted(FORMATS), default="bin")
    args = ap.parse_args()
    # A missing reference is a failure, not a reason to pass quietly: the
    # whole point of the run is that the two were compared.
    if not os.path.exists(NASM):
        sys.exit("no NASM at %s; run tools/oracles/build.sh nasm" % NASM)
    code, version = run([NASM, "-v"], ".")
    if code != 0 or "version 2.16.03" not in version:
        sys.exit("REF-MISSING: %s is not NASM 2.16.03 (%s)" % (NASM, version.strip()))
    if not os.path.exists(RSASM):
        sys.exit("no rsasm at %s; cargo build --all-features --bin rsasm" % RSASM)
    # tools/coff-diff/canon.sh reads a COFF object with llvm-readobj.
    if args.format is None or args.format.startswith("win"):
        if run(["llvm-readobj", "--version"], ".")[0] != 0:
            sys.exit("llvm-readobj is not on the PATH; the COFF objects need it")
    return fuzz(args) if args.cmd == "fuzz" else check(args)


if __name__ == "__main__":
    sys.exit(main())
