//! Per-target GNU as conventions the core applies on a backend's say-so:
//! what `.align n` counts, and whether a section's end is rounded up to its
//! alignment. Every expectation is what the target's GNU as (cross binutils
//! 2.47) or llvm-mc produced for the same source.

mod common;
#[allow(unused_imports)]
use common::*;

/// Asserts `.data` bytes for `.byte 1; .align 2, 0; .byte 2` on a target.
#[allow(dead_code)]
fn align_2(arch: &str) -> String {
    hex(&section(
        &assemble_for(arch, ".data\n.byte 1\n.align 2, 0\n.byte 2\n"),
        ".data",
    ))
}

#[allow(dead_code)]
fn size_of(asm: &rsasm::assembler::Assembler, name: &str) -> u64 {
    asm.sections
        .iter()
        .find(|s| asm.interner.get(s.name) == name)
        .unwrap_or_else(|| panic!("no section named `{name}`"))
        .size
}

macro_rules! align_counts {
    ($($feature:literal, $test:ident, $arch:literal => $bytes:literal;)*) => {$(
        #[cfg(feature = $feature)]
        #[test]
        fn $test() {
            assert_eq!(align_2($arch), $bytes);
        }
    )*};
}

// Bytes: x86 ELF, SPARC, RX. Powers of two: the rest.
align_counts! {
    "x86", align_counts_bytes_on_x86_64, "x86-64" => "01 00 02";
    "sparc", align_counts_bytes_on_sparc, "sparc" => "01 00 02";
    "rx", align_counts_bytes_on_rx, "rx" => "01 00 02 00";
    "arm", align_is_a_power_of_two_on_arm, "arm" => "01 00 00 00 02";
    "arm", align_is_a_power_of_two_on_thumb, "thumb" => "01 00 00 00 02";
    "aarch64", align_is_a_power_of_two_on_aarch64, "aarch64" => "01 00 00 00 02";
    "riscv", align_is_a_power_of_two_on_riscv, "riscv64" => "01 00 00 00 02";
    "mips", align_is_a_power_of_two_on_mips, "mips" => "01 00 00 00 02";
    "powerpc", align_is_a_power_of_two_on_powerpc, "powerpc" => "01 00 00 00 02";
    "rl78", align_is_a_power_of_two_on_rl78, "rl78" => "01 00 00 00 02 00 00 00";
    "v850", align_is_a_power_of_two_on_v850, "v850" => "01 00 00 00 02 00 00 00";
    "superh", align_is_a_power_of_two_on_superh, "sh" => "01 00 00 00 02";
}

#[allow(dead_code)]
const TAIL: &str = ".byte 1\n.balign 4\n.byte 2\n\
                    .data\n.byte 3\n.balign 4\n.byte 4\n\
                    .bss\n.skip 1\n.balign 4\n.skip 1\n";

macro_rules! tails {
    ($($feature:literal, $test:ident, $arch:literal =>
        $text:literal, $data:literal, $bss:literal;)*) => {$(
        #[cfg(feature = $feature)]
        #[test]
        fn $test() {
            let asm = assemble_for($arch, TAIL);
            assert_eq!(hex(&section(&asm, ".text")), $text);
            assert_eq!(hex(&section(&asm, ".data")), $data);
            assert_eq!(size_of(&asm, ".bss"), $bss);
        }
    )*};
}

tails! {
    "rl78", rl78_rounds_every_section, "rl78" =>
        "01 00 00 00 02 00 00 00", "03 00 00 00 04 00 00 00", 8;
    "rx", rx_rounds_every_section_padding_code_with_no_ops, "rx" =>
        "01 fc 13 00 02 fc 13 00", "03 00 00 00 04 00 00 00", 8;
    "v850", v850_rounds_every_section, "v850" =>
        "01 00 00 00 02 00 00 00", "03 00 00 00 04 00 00 00", 8;
    "superh", superh_rounds_only_code_sections, "sh" =>
        "01 00 00 09 02 00 00 09", "03 00 00 00 04", 5;
    // llvm-mc's padding: GNU as pads after a data-only fragment with
    // `90 66 90` instead, though after an instruction it agrees.
    "x86", x86_64_rounds_nothing, "x86-64" =>
        "01 0f 1f 00 02", "03 00 00 00 04", 5;
    "sparc", sparc_rounds_nothing, "sparc" =>
        "01 00 00 00 02", "03 00 00 00 04", 5;
}
