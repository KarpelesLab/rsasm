# Prints what two assemblers' objects have to agree on, apart from section
# contents and relocations, which run.sh adds.
#
#   llvm-readobj --file-headers --sections --symbols o.o | awk -f object.awk
#
# One line for `e_flags`, one per allocated section with a size, and one per
# symbol, sorted, since neither a linker nor a disassembler cares about the
# order of either:
#
#   flags 0x5000000
#   section .text SHT_PROGBITS ALLOC,EXECINSTR size=8 align=4
#   symbol $t 0x0 size=0 None Local .text
#
# Section and file symbols are left out: which sections get one is a detail
# of each assembler, and a linker finds a section by its header. So is the
# `.ARM.attributes` section, which rsasm does not write.

function field(line,    s) {
    s = line
    sub(/^[^:]*: ?/, "", s)
    sub(/ ?\([0-9a-fA-Fx]+\)$/, "", s)
    return s
}

/^ElfHeader \{/ { in_header = 1 }
in_header && $1 == "Flags" {
    s = $0
    sub(/.*\(/, "", s)
    sub(/\).*/, "", s)
    print "flags", s
    in_header = 0
}

$1 == "Section" && $2 == "{" { in_section = 1; name = ""; flags = ""; next }
in_section && $1 == "Name:" { name = field($0) }
in_section && $1 == "Type:" { type = $2 }
in_section && $1 ~ /^SHF_/ {
    f = $1
    sub(/^SHF_/, "", f)
    flags = flags (flags == "" ? "" : ",") f
}
in_section && $1 == "Size:" { size = $2 }
in_section && $1 == "AddressAlignment:" { align = $2 }
in_section && $1 == "}" {
    in_section = 0
    if (flags ~ /ALLOC/ && size != 0 && name != ".ARM.attributes")
        lines[n++] = sprintf("section %s %s %s size=%d align=%d", name, type, flags, size, align)
}

$1 == "Symbol" && $2 == "{" { in_symbol = 1; next }
in_symbol && $1 == "Name:" { sname = field($0) }
in_symbol && $1 == "Value:" { svalue = $2 }
in_symbol && $1 == "Size:" { ssize = $2 }
in_symbol && $1 == "Binding:" { sbind = $2 }
in_symbol && $1 == "Type:" { stype = $2 }
in_symbol && $1 == "Section:" { ssect = field($0) }
in_symbol && $1 == "}" {
    in_symbol = 0
    if (sname != "" && stype != "Section" && stype != "File")
        lines[n++] = sprintf("symbol %s %s size=%s %s %s %s", sname, svalue, ssize, stype, sbind, ssect)
}

END {
    # A plain insertion sort: POSIX awk has no sort function, and the objects
    # in a corpus are small. Sections sort before symbols, and each by name.
    for (i = 1; i < n; i++) {
        v = lines[i]
        for (j = i - 1; j >= 0 && lines[j] > v; j--)
            lines[j + 1] = lines[j]
        lines[j + 1] = v
    }
    for (i = 0; i < n; i++)
        print lines[i]
}
