//! SuperH encoding tests.
//!
//! Every expected byte string here came out of GNU as: `sh-elf-as` (binutils
//! 2.47) for `sh`, and `sh-elf-as -little` for `shl`, the references that
//! `tools/xas-diff/run.sh sh shl` compares against. Nothing in this file is
//! an encoding rsasm invented for itself.

#![cfg(feature = "superh")]

mod common;
use common::*;

/// Asserts that `src` assembles for big-endian SH to `want`.
#[track_caller]
fn be(src: &str, want: &str) {
    let got = hex(&text_for("sh", src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

/// Asserts that `src` assembles for little-endian SH to `want`.
#[track_caller]
fn le(src: &str, want: &str) {
    let got = hex(&text_for("shl", src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

/// Asserts that `src` assembles for big-endian SH, and that the bytes start
/// with `head` and end with `tail` around `len` bytes in all: for programs
/// whose middle is `.space`.
#[track_caller]
fn be_around(src: &str, head: &str, tail: &str, len: usize) {
    let b = text_for("sh", src);
    let got = hex(&b);
    assert_eq!(b.len(), len, "\nsource: {src}\n   got: {got}");
    assert!(
        got.starts_with(head) && got.ends_with(tail),
        "\nsource: {src}\n  head: {head}\n  tail: {tail}\n   got: {got}"
    );
}

// ---- data transfer ----------------------------------------------------------

#[test]
fn the_confirmed_starting_points() {
    be("mov #1, r0", "e0 01");
    le("mov #1, r0", "01 e0");
    be("rts", "00 0b");
    be("nop", "00 09");
}

#[test]
fn register_moves_and_register_spellings() {
    be("mov r3, r4", "64 33");
    // `sp` is r15; GNU as also takes the SH-DSP names `ix` for r8.
    be("mov sp, r0", "60 f3");
    be("mov ix, r0", "60 83");
    // Mnemonics and register names ignore case.
    be("CMP/EQ r1, r2", "32 10");
    be("Mov.L @R1+, R2", "62 16");
}

#[test]
fn eight_bit_immediates_take_either_spelling_of_a_byte() {
    be("mov #-1, r2", "e2 ff");
    be("mov #255, r3", "e3 ff");
    be("mov #'A', r6", "e6 41");
    be("add #-4, r15", "7f fc");
    be("cmp/eq #0x55, r0", "88 55");
    be("and #0xf0, r0", "c9 f0");
    be("tst.b #4, @(r0,gbr)", "cc 04");
    be("trapa #34", "c3 22");
}

#[test]
fn indirect_increment_decrement_and_indexed_modes() {
    be("mov.b @r1, r2", "62 10");
    be("mov.w r1, @r2", "22 11");
    be("mov.l @r1+, r2", "62 16");
    be("mov.l r2, @-r15", "2f 26");
    be("mov.l @(r0,r3), r4", "04 3e");
    be("mov.l r5, @(r0,r6)", "06 56");
}

#[test]
fn displacements_are_counted_in_units_of_the_operand_size() {
    // Four bits of count: 15 bytes, 30 bytes or 60 bytes of reach.
    be("mov.b @(15,r3), r0", "84 3f");
    be("mov.w @(30,r3), r0", "85 3f");
    be("mov.l @(60,r6), r7", "57 6f");
    be("mov.l r9, @(60,r10)", "1a 9f");
    be("mov.b r0, @(1,r1)", "80 11");
    be("mov.w r0, @(28,r2)", "81 2e");
    // Eight bits of count from GBR.
    be("mov.b @(200,gbr), r0", "c4 c8");
    be("mov.w @(400,gbr), r0", "c5 c8");
    be("mov.l @(1000,gbr), r0", "c6 fa");
    be("mov.l r0, @(1020,gbr)", "c2 ff");
}

#[test]
fn a_displacement_that_the_field_cannot_hold_names_its_limit() {
    let e = errors_for("sh", "mov.l @(64,r1), r2");
    assert!(e.contains("0 to 60"), "{e}");
    let e = errors_for("sh", "mov.l @(62,r1), r2");
    assert!(e.contains("not a multiple of 4"), "{e}");
    let e = errors_for("sh", "mov.w @(31,r1), r0");
    assert!(e.contains("not a multiple of 2"), "{e}");
    let e = errors_for("sh", "mov.b @(16,r1), r0");
    assert!(e.contains("0 to 15"), "{e}");
    let e = errors_for("sh", "mov.l @(1024,gbr), r0");
    assert!(e.contains("0 to 1020"), "{e}");
    // The fields are unsigned.
    let e = errors_for("sh", "mov.l @(-4,r1), r2");
    assert!(e.contains("0 to 60"), "{e}");
    let e = errors_for("sh", "mov #256, r0");
    assert!(e.contains("-128 to 255"), "{e}");
}

#[test]
fn only_r0_reaches_the_byte_and_word_displacement_forms() {
    let e = errors_for("sh", "mov.b @(4,r1), r2");
    assert!(
        e.contains("r0,@(disp,rm)") || e.contains("@(disp,rm),r0"),
        "{e}"
    );
}

#[test]
fn label_differences_and_equates_fill_immediates_and_displacements() {
    be(
        "mov #b-a, r1\nmov.l @(b-a,r2), r3\na: nop\nnop\nb: nop\nnop",
        "e1 04 53 21 00 09 00 09 00 09 00 09",
    );
    be(
        ".equ OFF, 8\n.set IMM, -3\nmov.l @(OFF,r1), r2\nmov #IMM, r3\n\
         mov.w @(OFF*2,gbr), r0\ntrapa #OFF",
        "52 12 e3 fd c5 08 c3 08",
    );
}

// ---- arithmetic, logic, shifts ----------------------------------------------

#[test]
fn slash_mnemonics_are_rejoined_from_the_lexer_tokens() {
    be("cmp/eq r1, r2", "32 10");
    be("cmp/hs r3, r4", "34 32");
    be("cmp/ge r5, r6", "36 53");
    be("cmp/hi r7, r8", "38 76");
    be("cmp/gt r9, r10", "3a 97");
    be("cmp/pz r11", "4b 11");
    be("cmp/pl r12", "4c 15");
    be("cmp/str r13, r14", "2e dc");
    be("fcmp/gt dr2, dr4", "f4 25");
    be("bf/s 0x100", "8f 7e");
}

#[test]
fn a_mnemonic_with_a_space_around_its_slash_is_not_one() {
    // GNU as reads a mnemonic up to the first space, so all three fail there.
    for src in ["cmp / eq r1, r2", "cmp/ eq r1, r2", "cmp /eq r1, r2"] {
        let _ = errors_for("sh", src);
    }
    let e = errors_for("sh", "cmp/xx r1, r2");
    assert!(e.contains("unknown instruction `cmp/xx`"), "{e}");
}

#[test]
fn arithmetic_and_multiply() {
    be("dt r1", "41 10");
    be("div0s r1, r2", "22 17");
    be("div0u", "00 19");
    be("div1 r1, r2", "32 14");
    be("dmuls.l r1, r2", "32 1d");
    be("dmulu.l r1, r2", "32 15");
    be("mul.l r1, r2", "02 17");
    be("muls.w r1, r2", "22 1f");
    be("mulu.w r1, r2", "22 1e");
    be("neg r1, r2", "62 1b");
    be("negc r1, r2", "62 1a");
    be("exts.b r1, r2", "62 1e");
    be("extu.w r1, r2", "62 1d");
    be("swap.b r1, r2", "62 18");
    be("swap.w r1, r2", "62 19");
    be("xtrct r1, r2", "22 1d");
    be("movt r5", "05 29");
    be("not r1, r2", "62 17");
}

#[test]
fn shifts() {
    be("shll2 r1", "41 08");
    be("shlr8 r1", "41 19");
    be("shll16 r1", "41 28");
    be("rotcl r1", "41 24");
    be("rotcr r1", "41 25");
    be("shad r1, r2", "42 1c");
    be("shld r3, r4", "44 3d");
}

// ---- system and control registers ---------------------------------------------

#[test]
fn control_register_loads_and_stores() {
    be("ldc r4, r0_bank", "44 8e");
    be("stc.l r6_bank, @-r15", "4f e3");
    be("ldc r1, ssr", "41 3e");
    be("stc sgr, r1", "01 3a");
    be("ldc r1, dbr", "41 fa");
    be("sts.l pr, @-r15", "4f 22");
    be("lds.l @r15+, pr", "4f 26");
    be("lds r1, fpul", "41 5a");
    be("sts.l fpscr, @-r1", "41 62");
}

#[test]
fn no_operand_instructions() {
    be("sleep", "00 1b");
    be("clrmac", "00 28");
    be("clrt", "00 08");
    be("sett", "00 18");
    be("clrs", "00 48");
    be("sets", "00 58");
    be("ldtlb", "00 38");
    be("synco", "00 ab");
    be("rts ; nop", "00 0b 00 09");
}

#[test]
fn sh4_and_sh4a_additions() {
    be("movca.l r0, @r1", "01 c3");
    be("movli.l @r1, r0", "01 63");
    be("movco.l r0, @r1", "01 73");
    be("movua.l @r1+, r0", "41 e9");
}

// ---- floating point -----------------------------------------------------------

#[test]
fn fpu_instructions() {
    be("fadd fr2, fr4", "f4 20");
    // A `dr` register is written with its first `fr` register's number.
    be("fmov dr2, dr4", "f4 2c");
    be("fmov.s @r1, fr2", "f2 18");
    be("fmov.d dr2, @-r15", "ff 2b");
    be("fipr fv4, fv8", "f9 ed");
    be("ftrv xmtrx, fv4", "f5 fd");
    be("fmac fr0, fr1, fr2", "f2 1e");
    be("fsca fpul, dr2", "f2 fd");
    be("fcnvds dr2, fpul", "f2 bd");
    be("frchg", "fb fd");
    be("fschg", "f3 fd");
    be("fpchg", "f7 fd");
}

#[test]
fn a_restricted_variant_refuses_what_its_cpu_lacks() {
    let e = errors_for("sh2", "fadd fr2, fr4");
    assert!(e.contains("FPU"), "{e}");
    let e = errors_for("sh1", "dt r1");
    assert!(e.contains("SH-2"), "{e}");
    let e = errors_for("sh3", "movca.l r0, @r1");
    assert!(e.contains("SH-4"), "{e}");
    let e = errors_for("sh4", "movli.l @r1, r0");
    assert!(e.contains("SH-4A"), "{e}");
    // What the CPU has still assembles, and `.arch` can widen it again.
    assert_eq!(hex(&text_for("sh2", "dt r1")), "41 10");
    assert_eq!(hex(&text_for("sh1", ".arch sh4\nfadd fr2, fr4")), "f4 20");
}

// ---- comments ----------------------------------------------------------------

#[test]
fn bang_comments_anywhere_and_hash_only_at_the_start_of_a_line() {
    be("nop ! a comment", "00 09");
    be("nop!no space", "00 09");
    be("  # a comment after indentation\nnop", "00 09");
    be("mov.l @(4,r1),r2 /* block */", "52 11");
}

// ---- branches -----------------------------------------------------------------

#[test]
fn branches_count_words_from_the_instruction_plus_four() {
    // A number is an address in the section, as a label there would be.
    be("bra 4098", "a7 ff");
    be("bra -4092", "a8 00");
    be("bt 0x102", "89 7f");
    be("bt -0xfc", "89 80");
    be("bt.s 8", "8d 02");
    be(
        "start:\nbt next\nnop\nnext: bf start\nbra start\nnop\nbsr next\nnop",
        "89 00 00 09 8b fc af fb 00 09 bf fb 00 09",
    );
    be("jmp @r0", "40 2b");
    be("jsr @r15", "4f 0b");
    be("braf r3", "03 23");
    be("bsrf r4", "04 03");
}

#[test]
fn bra_and_bsr_reach_twelve_bits_of_words() {
    let b = text_for(
        "sh",
        "bra far\nnop\n.space 4090\nfar: bsr back\nnop\n.space 4092\nback: nop",
    );
    assert_eq!(hex(&b[..4]), "a7 fd 00 09");
    assert_eq!(hex(&b[4094..4098]), "b7 fe 00 09");
    assert_eq!(hex(&b[b.len() - 2..]), "00 09");
    assert_eq!(b.len(), 8192);
    let e = errors_for("sh", "bra far\nnop\n.space 4096\nfar: nop");
    assert!(e.contains("out of range") && e.contains("-4096"), "{e}");
}

#[test]
fn an_out_of_reach_bt_becomes_the_opposite_branch_over_a_bra() {
    // Within reach: the plain two-byte form.
    be_around("bt far\n.space 254\nfar: nop", "89 7e 00", "00 00 09", 258);
    // One word past it: `bf .+6; bra far; nop`, exactly as GNU as does it.
    be_around(
        "bt far\n.space 258\nfar: nop",
        "8b 01 a0 81 00 09 00",
        "00 00 09",
        266,
    );
    // A delayed branch keeps its own slot instruction for the `bra`.
    be_around(
        "bt/s far\nmov r1, r2\n.space 300\nfar: nop",
        "8b 00 a0 96 62 13 00",
        "00 00 09",
        308,
    );
    // Backward too.
    be_around(
        "far: nop\n.space 400\nbf/s far\nadd #1, r1",
        "00 09 00",
        "00 89 00 af 34 71 01",
        408,
    );
}

#[test]
fn a_relaxed_branch_can_push_an_earlier_one_out_of_reach() {
    let b = text_for("sh", "bt b\nbt c\n.space 252\nb: nop\n.space 300\nc: nop");
    assert_eq!(hex(&b[..12]), "8b 01 a0 81 00 09 8b 01 a1 15 00 09");
    assert_eq!(b.len(), 12 + 252 + 2 + 300 + 2);
}

#[test]
fn a_branch_beyond_even_the_relaxed_form_is_an_error() {
    let e = errors_for("sh", "bt far\n.space 5000\nfar: nop");
    assert!(e.contains("out of range"), "{e}");
}

#[test]
fn a_branch_to_an_odd_address_is_an_error_not_a_truncation() {
    let e = errors_for("sh", "bra odd\n.byte 1\nodd: nop");
    assert!(e.contains("not a multiple of 2"), "{e}");
}

#[test]
fn the_delay_slot_is_left_as_written() {
    be(
        "jsr @r1\nmov #0, r4\nbra 1f\nadd #1, r4\n1: rts\nmov r4, r0",
        "41 0b e4 00 a0 00 74 01 00 0b 60 43",
    );
}

// ---- PC-relative loads ----------------------------------------------------------

#[test]
fn mov_l_counts_longs_from_pc_plus_four_rounded_down() {
    // On a four-byte boundary the base is here + 4 ...
    be(
        "mov.l lit, r1\njmp @r1\nnop\nnop\nlit: .long 0x12345678",
        "d1 01 41 2b 00 09 00 09 12 34 56 78",
    );
    // ... and two bytes past one it is here + 2, so the field is the same.
    be(
        "nop\nmov.l lit, r1\njmp @r1\nnop\nlit: .long 0x89abcdef",
        "00 09 d1 01 41 2b 00 09 89 ab cd ef",
    );
    be(
        "nop\nmova tbl, r0\nmov.l tbl, r2\nrts\nnop\n.balign 4\ntbl: .long 1\n.long 2",
        "00 09 c7 02 d2 01 00 0b 00 09 00 09 00 00 00 01 00 00 00 02",
    );
    be_around(
        "mov.l lit, r0\nnop\n.space 1016\nlit: .long 7",
        "d0 fe 00 09 00",
        "00 00 00 00 07",
        1024,
    );
}

#[test]
fn a_relaxed_delayed_branch_can_move_a_load_to_the_other_boundary() {
    // The `bt/s` grows by two bytes after the load's first layout, which
    // flips the boundary the load sits on; GNU as and rsasm both follow.
    let b = text_for(
        "sh",
        "nop\nbt/s far\nnop\nmov.l lit, r1\nnop\n.balign 4\nlit: .long 5\n\
         .space 300\nfar: nop\nnop",
    );
    assert_eq!(
        hex(&b[..16]),
        "00 09 8b 00 a0 9a 00 09 d1 00 00 09 00 00 00 05"
    );
}

#[test]
fn mov_w_counts_words_from_pc_plus_four() {
    be(
        "mov.w w1, r1\nmov.w w2, r2\nrts\nnop\nw1: .word 0x1234\nw2: .word -2",
        "91 02 92 02 00 0b 00 09 12 34 ff fe",
    );
    be_around(
        "mov.w lit, r0\n.space 508\nlit: .word 7",
        "90 fd 00",
        "00 00 07",
        512,
    );
}

#[test]
fn at_disp_pc_is_an_offset_from_the_instruction() {
    be("mov.l @(4,pc), r2", "d2 00");
    be("mov.l @(1024,pc), r2", "d2 ff");
    be("mov.w @(514,pc), r2", "92 ff");
    be("mova @(8,pc), r0", "c7 01");
    let e = errors_for("sh", "mov.l @(1028,pc), r2");
    assert!(e.contains("4 to 1024"), "{e}");
    let e = errors_for("sh", "mov.w @(516,pc), r2");
    assert!(e.contains("4 to 514"), "{e}");
    // `. + 8` from address 2 is not on a four-byte boundary.
    let e = errors_for("sh", "nop\nmov.l @(8,pc), r2");
    assert!(e.contains("not a multiple of 4"), "{e}");
}

#[test]
fn at_label_pc_is_the_deprecated_spelling_of_label() {
    let asm = assemble_for("sh", "mov.l @(lit,pc), r1\nnop\nlit: .long 5");
    assert!(!asm.diags.has_errors());
    assert!(
        asm.diags.render(&asm.sm, false).contains("deprecated"),
        "GNU as warns about this spelling, and so should rsasm"
    );
    assert_eq!(
        hex(&asm.section_bytes(rsasm::section::SectionId(0))),
        "d1 00 00 09 00 00 00 05"
    );
}

#[test]
fn a_misaligned_literal_is_an_error_not_a_rounding() {
    let e = errors_for("sh", "mov.l lit, r1\nnop\n.byte 0\nlit: .long 1");
    assert!(e.contains("not a multiple of 4"), "{e}");
    let e = errors_for("sh", "nop\nmov.l lit, r1\n.byte 0\nlit: .long 1");
    assert!(e.contains("not a multiple of 4"), "{e}");
}

#[test]
fn a_literal_out_of_reach_names_the_limit() {
    let e = errors_for("sh", "mov.l lit, r0\nnop\n.space 1024\nlit: .long 7");
    assert!(e.contains("out of range"), "{e}");
    let e = errors_for("sh", "mov.w lit, r0\n.space 514\nlit: .word 7");
    assert!(e.contains("out of range"), "{e}");
}

// ---- byte order ---------------------------------------------------------------

#[test]
fn sh_and_shl_emit_the_same_words_byte_swapped() {
    let sources = [
        "mov #1, r0",
        "mov.l @(60,r6), r7",
        "cmp/str r13, r14",
        "bt 0x102",
        "bra -4092",
        "mov.l @(1024,pc), r2",
        "ldc r4, r0_bank",
        "fipr fv4, fv8",
        "rts ; nop",
        "start:\nbt next\nnop\nnext: bf start\nbra start\nnop\nbsr next\nnop",
    ];
    for src in sources {
        let big = text_for("sh", src);
        let mut swapped = text_for("shl", src);
        assert_eq!(big.len() % 2, 0, "{src}");
        for pair in swapped.chunks_mut(2) {
            pair.swap(0, 1);
        }
        assert_eq!(hex(&big), hex(&swapped), "{src}");
    }
}

#[test]
fn little_endian_words_and_data() {
    le("rts", "0b 00");
    le("mov.l r2, @-r15", "26 2f");
    le("fpchg", "fd f7");
    le(
        "mov.l x, r0\nrts\nnop\nnop\nx: .long 0x01020304\n.word 0x0506\n.byte 7, 8",
        "01 d0 0b 00 09 00 09 00 04 03 02 01 06 05 07 08",
    );
    le(
        "bt/s far\nmov r1, r2\n.space 300\nfar: nop",
        &format!("00 8b 96 a0 13 62 {}09 00", "00 ".repeat(300)),
    );
}

// ---- padding and object properties ----------------------------------------------

#[test]
fn code_alignment_pads_with_nops_after_a_zero_byte_for_an_odd_gap() {
    be(
        ".byte 1\n.balign 4\nnop\nnop\nnop\nnop",
        "01 00 00 09 00 09 00 09 00 09 00 09",
    );
    le(
        ".byte 1\n.balign 4\nnop\nnop\nnop\nnop",
        "01 00 09 00 09 00 09 00 09 00 09 00",
    );
}

#[test]
fn code_is_not_aligned_for_you() {
    // GNU as puts this `nop` at offset 1, and so does rsasm.
    be(".byte 1\nnop", "01 00 09");
}

#[test]
fn object_level_properties() {
    for name in ["sh", "shl"] {
        let a = rsasm::arch::lookup(name).expect("backend present");
        assert_eq!(a.name(), name);
        assert_eq!(a.elf_machine(), 42, "{name}"); // EM_SH
        assert_eq!(a.data_reloc(4, false), Some(1), "{name}"); // R_SH_DIR32
        assert_eq!(a.data_reloc(4, true), Some(2), "{name}"); // R_SH_REL32
        assert_eq!(a.data_reloc(2, false), Some(33), "{name}"); // R_SH_DIR16
        assert_eq!(a.data_reloc(1, false), Some(34), "{name}"); // R_SH_DIR8
        assert_eq!(a.modifier_reloc("GOT", 4, false), Some(160), "{name}");
        assert_eq!(a.modifier_reloc("PLT", 4, false), Some(161), "{name}");
        assert_eq!(a.modifier_reloc("GOTOFF", 4, false), Some(166), "{name}");
        assert_eq!(a.modifier_reloc("TPOFF", 4, false), Some(148), "{name}");
        assert_eq!(a.pointer_bytes(&a.initial_state()), 4);
        assert_eq!(a.word_bytes(), 2);
        assert_eq!(a.align_unit(), 1);
    }
    assert_eq!(
        rsasm::arch::lookup("sh").unwrap().endian(),
        rsasm::arch::Endian::Big
    );
    assert_eq!(
        rsasm::arch::lookup("shl").unwrap().endian(),
        rsasm::arch::Endian::Little
    );
}

#[test]
fn an_external_long_gets_r_sh_dir32() {
    let asm = assemble_for("sh", "nop\n.p2align 2\n.long x");
    assert!(!asm.diags.has_errors());
    assert_eq!(asm.relocs.len(), 1);
    assert_eq!(asm.relocs[0].kind, 1);
    assert_eq!(asm.relocs[0].offset, 4);
}

// ---- diagnostics ----------------------------------------------------------------

#[test]
fn bad_operands_are_diagnosed() {
    let e = errors_for("sh", "mov 1, r0");
    assert!(e.contains("needs a `#`"), "{e}");
    let e = errors_for("sh", "jmp r1");
    assert!(e.contains("jmp @rn"), "{e}");
    let e = errors_for("sh", "mova lit, r1\nlit: .long 0");
    assert!(e.contains("mova label,r0"), "{e}");
    let e = errors_for("sh", "mov.l @(r1,r2), r3");
    assert!(e.contains("@(r0,"), "{e}");
    let e = errors_for("sh", "mov.l @-sr, r3");
    assert!(e.contains("r0`-`r15"), "{e}");
    let e = errors_for("sh", "mov.l tbr, r0");
    assert!(e.contains("SH-2A"), "{e}");
    let e = errors_for("sh", "bra");
    assert!(e.contains("bra label"), "{e}");
}

const BAD: &[&str] = &[
    "",
    "@",
    ",",
    "mov",
    "mov ,",
    "mov r1,",
    "mov , r1",
    "mov #",
    "mov #, r0",
    "mov @",
    "mov.l @(",
    "mov.l @()",
    "mov.l @(,)",
    "mov.l @(4",
    "mov.l @(4,",
    "mov.l @(4,r1",
    "mov.l @(4 r1), r2",
    "mov.l @(r0",
    "mov.l @(r0,",
    "mov.l @(r0,4), r1",
    "mov.l @(4,sr), r1",
    "mov.l @-, r1",
    "mov.l @+r1, r2",
    "mov.l @r1++, r2",
    "mov.l @r16, r2",
    "cmp/",
    "cmp//eq r1, r2",
    "cmp/1 r1, r2",
    "/eq",
    "bt",
    "bt/s",
    "bt/s/x 4",
    "bra #",
    "bra @r1",
    "bra 1",
    "bt 3",
    "bt undefined_symbol",
    "mov.l undefined_symbol, r0",
    "mov.w undefined_symbol, r0",
    "mov.l @(undefined_symbol,pc), r0",
    "mov.l @(a-b,pc), r0\na: b:",
    "mov.l @(99999999999,pc), r0",
    "mov.l @(-99999999999,r1), r0",
    "mov #0x7fffffffffffffff, r0",
    "trapa #-9223372036854775807",
    "mov.l @(1f,r1), r0\n1:",
    "fmov fr16, fr1",
    "fipr fv1, fv2",
    "ldc r1, r9_bank",
    "ldc.l @r1+, pc",
    "stc pc, r1",
    "mov.b #1, @(r0,gbr)",
    "xor.b #1, @(r1,gbr)",
    "and #1, r1",
    "mov a0, r0",
    "\u{1F600}",
    "mov r1, \u{1F600}",
];

#[test]
fn malformed_input_never_panics() {
    for arch in ["sh", "shl", "sh1"] {
        for src in BAD {
            // Either outcome is fine; a panic or a hang is not.
            let _ = try_text_for(arch, src);
        }
    }
}

#[test]
fn malformed_input_is_reported() {
    for arch in ["sh", "shl"] {
        for src in &BAD[1..] {
            assert!(
                try_text_for(arch, src).is_err(),
                "`{src}` should not assemble for {arch}"
            );
        }
    }
}

#[test]
fn a_flat_image_at_a_real_load_address_lays_out_the_same() {
    // The boundary checks look at the absolute address, which on a
    // four-byte-aligned base agrees with the section offset GNU as uses.
    let src = "nop\nmov.l lit, r1\njmp @r1\nnop\nlit: .long 0x89abcdef";
    let asm = assemble_flat_for("sh", src, 0x8c01_0000);
    assert!(
        !asm.diags.has_errors(),
        "{}",
        asm.diags.render(&asm.sm, false)
    );
    assert_eq!(
        hex(&asm.section_bytes(rsasm::section::SectionId(0))),
        "00 09 d1 01 41 2b 00 09 89 ab cd ef"
    );
}

#[test]
fn addends_live_in_the_field_except_for_dir16() {
    // sh-elf-as: DIR32 `x + 0` over field 8, DIR16 `x + 3` over a zero field,
    // DIR8 `x + 0` over field 1, REL32 `x + 0` over field 4.
    let asm = assemble_for(
        "sh",
        ".data\n.long x+8\n.word x+3\n.byte x+1\n.byte 0\n.long x-.+4\n",
    );
    assert!(
        !asm.diags.has_errors(),
        "{}",
        asm.diags.render(&asm.sm, false)
    );
    let got: Vec<(u64, u32, i64)> = asm
        .relocs
        .iter()
        .map(|r| (r.offset, r.kind, r.addend))
        .collect();
    assert_eq!(got, vec![(0, 1, 0), (4, 33, 3), (6, 34, 0), (8, 2, 0)]);
    assert_eq!(
        hex(&section(&asm, ".data")),
        "00 00 00 08 00 00 01 00 00 00 00 04"
    );
}
