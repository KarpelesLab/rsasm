//! APX encoding tests: the registers `r16`-`r31`, the REX2 prefix and the
//! extended EVEX forms.
//!
//! Every expected byte string here was produced by GNU as 2.47, the pinned
//! reference `tools/gas-diff` uses, and never by rsasm itself. Where GNU as
//! and llvm-mc 22 disagree -- two-operand `cfcmov`, `setcc` with a register
//! wider than a byte, `xchg` with an extended register -- this file follows
//! GNU as, as the rest of the x86 backend does, and the split is recorded in
//! `tools/fuzz/x86.py`. The corpora in tools/gas-diff and tools/mc-diff cover
//! far more; this file pins the cases that exercise a distinct field of the
//! prefix, so a regression names the field that broke.
#![cfg(feature = "x86")]

mod common;
use common::*;

/// Asserts that `src` assembles to `want`, written as space-separated hex.
#[track_caller]
fn enc(src: &str, want: &str) {
    let got = hex(&text(src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

/// The same, in Intel syntax.
#[track_caller]
fn intel(src: &str, want: &str) {
    let full = format!(".intel_syntax noprefix\n{src}");
    let got = hex(&text(&full));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

/// Asserts that `src` is rejected with a diagnostic containing `needle`.
#[track_caller]
fn rejects(src: &str, needle: &str) {
    let e = errors(src);
    assert!(
        e.contains(needle),
        "\nsource: {src}\nwanted: {needle}\n   got: {e}"
    );
}

/// The same, in 32-bit mode, where none of this exists.
#[track_caller]
fn rejects32(src: &str, needle: &str) {
    let e = errors_for("i386", src);
    assert!(
        e.contains(needle),
        "\nsource: {src}\nwanted: {needle}\n   got: {e}"
    );
}

#[test]
fn the_rex2_prefix_carries_the_fourth_register_number_bit() {
    // REX2 is `D5` and a byte whose high nibble holds the fourth bit of each
    // register field and the opcode map, and whose low nibble is REX's own.
    enc("movq %r16, %r31", "d5 59 89 c7");
    enc("movq %rax, %r16", "d5 18 89 c0");
    enc("movq %r16, %rax", "d5 48 89 c0");
    enc("addl %r16d, %r17d", "d5 50 01 c1");
    enc("addw %r20w, %r21w", "66 d5 50 01 e5");
    enc("addb %r20b, %r21b", "d5 50 00 e5");
    enc("movq (%r16), %rax", "d5 18 8b 00");
    enc("movq (%r16,%r17,4), %rax", "d5 38 8b 04 88");
    enc("movq -1(%r31), %r16", "d5 59 8b 47 ff");
    enc("leaq (%r16,%r17,8), %r18", "d5 78 8d 14 c8");
    enc("pushq %r16", "d5 10 50");
    enc("popq %r16", "d5 10 58");
    enc("sete %r16b", "d5 90 94 c0");
    enc("bswapq %r31", "d5 99 cf");
    enc("movq %r16, %cr0", "d5 90 22 c0");
    enc("incq %r16", "d5 18 ff c0");
    enc(
        "movabsq $0x123456789, %r16",
        "d5 18 b8 89 67 45 23 01 00 00 00",
    );
    enc("addb %spl, %r16b", "d5 10 00 e0");
}

#[test]
fn the_hinted_and_paired_stack_instructions() {
    // `pushp` and `popp` are `push` and `pop` with REX2.W, the hint that the
    // two will be matched; the paired forms write the second register in `vvvv`.
    enc("pushp %rax", "d5 08 50");
    enc("pushp %rsp", "d5 08 54");
    enc("popp %rsp", "d5 08 5c");
    enc("popp %rax", "d5 08 58");
    enc("pushp %r16", "d5 18 50");
    enc("popp %r31", "d5 19 5f");
    enc("push2 %rax, %rbx", "62 f4 64 18 ff f0");
    enc("pop2 %rax, %rbx", "62 f4 64 18 8f c0");
    enc("push2p %r16, %r17", "62 fc f4 10 ff f0");
    enc("pop2p %r24, %r25", "62 dc b4 10 8f c0");
    enc("push2 %r31, %r30", "62 dc 0c 10 ff f7");
    enc("jmpabs $0x1234567890", "d5 00 a1 90 78 56 34 12 00 00 00");
}

#[test]
fn a_new_destination_register_in_vvvv() {
    // The extended EVEX prefix carries a destination register in `vvvv` with
    // `ND` set, which leaves the sources alone.
    enc("addq %rax, %rbx, %rcx", "62 f4 f4 18 01 c3");
    enc("addq $7, %rbx, %rcx", "62 f4 f4 18 83 c3 07");
    enc("addq 8(%rax), %rbx, %rcx", "62 f4 f4 18 03 58 08");
    enc("addq $1, 8(%rax), %rcx", "62 f4 f4 18 83 40 08 01");
    enc("addb $7, %bl, %cl", "62 f4 74 18 80 c3 07");
    enc("addw %r28w, %cx, %r30w", "62 64 0d 10 01 e1");
    enc("incq %rax, %rbx", "62 f4 e4 18 ff c0");
    enc("decq %r24, %r25", "62 dc b4 10 ff c8");
    enc("notq %rax, %rbx", "62 f4 e4 18 f7 d0");
    enc("negq %rax, %rbx", "62 f4 e4 18 f7 d8");
    enc("shlq $3, %rax, %rbx", "62 f4 e4 18 c1 e0 03");
    enc("rorq $1, %rax, %rbx", "62 f4 e4 18 d1 c8");
    enc("sarq %cl, %rax, %rbx", "62 f4 e4 18 d3 f8");
    enc("shldq $3, %rax, %rbx, %rcx", "62 f4 f4 18 24 c3 03");
    enc("shrdq %cl, %r24, %r25, %r26", "62 4c ac 10 ad c1");
    enc("imulq %rax, %rbx, %rcx", "62 f4 f4 18 af d8");
    enc("cmovneq %rax, %rbx, %rcx", "62 f4 f4 18 45 d8");
    enc("cmovneq 8(%rax), %rbx, %rcx", "62 f4 f4 18 45 58 08");
    enc("addq (%r24,%r25,2), %r26, %r27", "62 0c a0 10 03 14 48");
}

#[test]
fn the_no_flags_forms() {
    // `{nf}` picks the encoding that leaves the flags as they were, which is
    // `EVEX.NF`; it combines with the new destination register.
    enc("{nf} addq %rax, %rbx", "62 f4 fc 0c 01 c3");
    enc("{nf} addq %rax, %rbx, %rcx", "62 f4 f4 1c 01 c3");
    enc("{nf} subq $1, %rax", "62 f4 fc 0c 83 e8 01");
    enc("{nf} imulq %rax, %rbx", "62 f4 fc 0c af d8");
    enc("{nf} negq %rax", "62 f4 fc 0c f7 d8");
    enc("{nf} idivq %r24", "62 dc fc 0c f7 f8");
    enc("{nf} shldq $3, %rax, %rbx", "62 f4 fc 0c 24 c3 03");
    enc("{nf} lzcntq %rax, %rbx", "62 f4 fc 0c f5 d8");
    enc("{nf} popcntq %rax, %rbx", "62 f4 fc 0c 88 d8");
    enc("{nf} andnq %rax, %rbx, %rcx", "62 f2 e4 0c f2 c8");
    enc("{nf} blsiq %rax, %rbx", "62 f2 e4 0c f3 d8");
    enc("{nf} sarq %cl, %r16, %r17", "62 fc f4 14 d3 f8");
    enc("{evex} {nf} addq %rax, %rbx", "62 f4 fc 0c 01 c3");
}

#[test]
fn the_pseudo_prefixes_pick_an_encoding() {
    // `{evex}` asks for the promoted form where a legacy one would be
    // shorter, `{rex2}` and `{rex}` for a prefix the operands do not need.
    enc("{evex} addq %rax, %rbx", "62 f4 fc 08 01 c3");
    enc("{evex} addq 8(%rax), %rbx", "62 f4 fc 08 03 58 08");
    enc(
        "{evex} addq 1016(%rax), %rbx",
        "62 f4 fc 08 03 98 f8 03 00 00",
    );
    enc("{evex} notq 8(%rax)", "62 f4 fc 08 f7 50 08");
    enc("{evex} sete %al", "62 f4 7f 08 44 c0");
    enc("{evex} imulq $3, %rax, %rbx", "62 f4 fc 08 6b d8 03");
    enc("{evex} shldq %cl, %rax, %rbx", "62 f4 fc 08 a5 c3");
    enc("{rex2} movq %rax, %rbx", "d5 08 89 c3");
    enc("{rex2} nop", "d5 00 90");
    enc("{rex2} lock addq %rax, (%rbx)", "f0 d5 08 01 03");
    enc("{rex} movl %eax, %ebx", "40 89 c3");
    enc("{rex} movq %rax, %rbx", "48 89 c3");
}

#[test]
fn the_conditional_compares_and_their_flag_mask() {
    // `ccmp` and `ctest` hold the condition where AVX-512 keeps the
    // writemask, and the flags to assume when it is false in `vvvv`.
    enc("ccmpeq %rax, %rbx", "62 f4 84 04 39 c3");
    enc("ccmpe {dfv=of} %rax, %rbx", "62 f4 c4 04 39 c3");
    enc("ccmpeq {dfv=of,sf,zf,cf} %rax, %rbx", "62 f4 fc 04 39 c3");
    enc("ccmpeq {dfv=cf} $1, %rax", "62 f4 8c 04 83 f8 01");
    enc("ccmpew {dfv=zf} %ax, %bx", "62 f4 15 04 39 c3");
    enc("ccmpeb {dfv=zf} %al, %bl", "62 f4 14 04 38 c3");
    enc("ccmpeq {dfv=zf} 8(%rax), %rbx", "62 f4 94 04 3b 58 08");
    enc("ccmpt {dfv=zf} %rax, %rbx", "62 f4 94 0a 39 c3");
    enc("ccmpf {dfv=zf} %rax, %rbx", "62 f4 94 0b 39 c3");
    enc("ctestzq {dfv=} %rax, %rbx", "62 f4 84 04 85 c3");
    enc("ctestzq {dfv=zf} $1, %rax", "62 f4 94 04 f7 c0 01 00 00 00");
    enc("ctestsq {dfv=cf} %r24, %r25", "62 4c 8c 08 85 c1");
    enc(
        "ccmpeq {dfv=of,sf,zf,cf} 8(%r16,%r17,4), %r18",
        "62 ec f8 04 3b 54 88 08",
    );
    enc("{evex} cmpq %rax, %rbx", "62 f4 84 0a 39 c3");
    enc("{evex} testq %rax, %rbx", "62 f4 84 0a 85 c3");
}

#[test]
fn the_conditionally_faulting_moves() {
    // `cfcmov` faults on neither side when its condition is false, so it has
    // a store form as well as a load one; `EVEX.NF` is what tells them apart.
    enc("cfcmovneq %rax, %rbx", "62 f4 fc 08 45 d8");
    enc("cfcmovneq 8(%rax), %rbx", "62 f4 fc 08 45 58 08");
    enc("cfcmovneq %rbx, 8(%rax)", "62 f4 fc 0c 45 58 08");
    enc("cfcmovneq %rax, %rbx, %rcx", "62 f4 f4 1c 45 d8");
    enc("cfcmovoq %r24, %r25, %r26", "62 4c ac 14 40 c8");
}

#[test]
fn the_forms_that_zero_the_upper_half() {
    // `setzucc` and `imulzu` clear the rest of the register they write; GNU
    // as also spells the first as `setcc` with a wider register.
    enc("setzue %al", "62 f4 7f 18 44 c0");
    enc("setzue %r16b", "62 fc 7f 18 44 c0");
    enc("setzuno %r31b", "62 dc 7f 18 41 c7");
    enc("setb %edx", "62 f4 7f 18 42 c2");
    enc("setl %rcx", "62 f4 ff 18 4c c1");
    enc("imulzu $3, %ax, %bx", "62 f4 7d 18 6b d8 03");
    enc("imulzu $300, %r16w, %r17w", "62 ec 7d 18 69 c8 2c 01");
    enc("imulzu $3, %bx", "62 f4 7d 18 6b db 03");
}

#[test]
fn the_instructions_promoted_into_map_4() {
    // A legacy opcode in the `0F 38` map is out of REX2's reach, so an
    // extended register there needs the promoted form; several were renumbered.
    enc("movbeq (%r16), %rbx", "62 fc fc 08 60 18");
    enc("{evex} movbeq %rbx, (%rax)", "62 f4 fc 08 61 18");
    enc("crc32q %r16, %rbx", "62 fc fc 08 f1 d8");
    enc("{evex} crc32b %al, %ebx", "62 f4 7c 08 f0 d8");
    enc("adcxq %r16, %rbx", "62 fc fd 08 66 d8");
    enc("adoxl %eax, %ebx", "f3 0f 38 f6 d8");
    enc("movdiri %r16d, (%rbx)", "62 e4 7c 08 f9 03");
    enc("movdir64b (%r16), %rbx", "62 fc 7d 08 f8 18");
    enc("enqcmd (%r16), %rbx", "62 fc 7f 08 f8 18");
    enc("invpcid (%r16), %rbx", "62 fc 7e 08 f2 18");
    enc("wrssq %r16, (%rbx)", "62 e4 fc 08 66 03");
    enc("movrsq (%r16), %rbx", "62 fc fc 08 8b 18");
    enc("{evex} lzcntw %ax, %bx", "62 f4 7d 08 f5 d8");
    enc("{evex} tzcntl %eax, %ebx", "62 f4 7c 08 f4 d8");
    enc("{evex} popcntq %rax, %rbx", "62 f4 fc 08 88 d8");
}

#[test]
fn the_vex_rows_repeated_under_the_extended_evex_prefix() {
    // BMI, the opmask moves, AMX's tile loads and CMPccXADD keep their map,
    // opcode and `W`; only the prefix changes.
    enc("andnq %r16, %rbx, %rcx", "62 fa e4 08 f2 c8");
    enc("bzhiq %r16, %rbx, %rcx", "62 f2 fc 00 f5 cb");
    enc("mulxq %r16, %rbx, %rcx", "62 fa e7 08 f6 c8");
    enc("rorxq $3, %r16, %rbx", "62 fb ff 08 f0 d8 03");
    enc("blsiq %r16, %rbx", "62 fa e4 08 f3 d8");
    enc("sarxq %r16, %rbx, %rcx", "62 f2 fe 00 f7 cb");
    enc("kmovq %r16, %k1", "62 f9 ff 08 92 c8");
    enc("kmovq %k1, %r16", "62 e1 ff 08 93 c1");
    enc("ldtilecfg (%r16)", "62 fa 7c 08 49 00");
    enc("tileloadd (%r16,%rbx), %tmm0", "62 fa 7f 08 4b 04 18");
    enc("cmpexadd %rdx, %rax, (%r16)", "62 fa ed 08 e4 00");
    enc("{evex} andnq %rax, %rbx, %rcx", "62 f2 e4 08 f2 c8");
}

#[test]
fn apx_in_intel_syntax() {
    // The same forms with the operands the other way round, the destination
    // first.
    intel("mov r16, r31", "d5 5c 89 f8");
    intel("add rcx, rbx, rax", "62 f4 f4 18 01 c3");
    intel("shld rcx, rbx, rax, 3", "62 f4 f4 18 24 c3 03");
    intel("cfcmovne rcx, rbx, rax", "62 f4 f4 1c 45 d8");
    intel("ccmpe {dfv=of,sf} rbx, rax", "62 f4 e4 04 39 c3");
    intel("ctestz {dfv=zf} rbx, rax", "62 f4 94 04 85 c3");
    intel("setzue al", "62 f4 7f 18 44 c0");
    intel("push2 rax, rbx", "62 f4 7c 18 ff f3");
    intel("pop2p r24, r25", "62 dc bc 10 8f c1");
    intel("pushp rax", "d5 08 50");
    intel("jmpabs 0x1234", "d5 00 a1 34 12 00 00 00 00 00 00");
    intel("imulzu bx, ax, 3", "62 f4 7d 18 6b d8 03");
    intel("movbe rbx, qword ptr [r16]", "62 fc fc 08 60 18");
    intel("{nf} add rbx, rax", "62 f4 fc 0c 01 c3");
    intel("{rex2} mov rax, rbx", "d5 08 89 d8");
}

#[test]
fn what_the_references_refuse() {
    // `ah` and its siblings have no encoding under REX2 or either EVEX
    // layout, which took their register numbers.
    rejects(
        "addb %ah, %r16b",
        "cannot be used in an instruction that needs a REX",
    );
    rejects("addb %ah, %bl, %cl", "needs an EVEX or REX2 prefix");
    rejects("setzue %bh", "needs an EVEX or REX2 prefix");
    rejects("ccmpeb {dfv=zf} %bh, %cl", "needs an EVEX or REX2 prefix");
    // The extended state saves address memory with `rbx` as well as the
    // register written, and APX leaves them out although REX2 could reach
    // them; `pextrb`'s `0F 3A` map it could not reach either way, and neither
    // instruction has a promoted form to fall back on.
    rejects("xsave (%r16)", "no REX2 encoding");
    rejects("pextrb $1, %xmm0, %r16d", "no REX2 encoding");
    // `{rex2}` asks for a prefix, not for a different encoding family.
    rejects(
        "{rex2} vaddps %xmm0, %xmm1, %xmm2",
        "has no legacy encoding",
    );
    rejects("{rex2} addq %rax, %rbx, %rcx", "has no legacy encoding");
    rejects("{rex2} movbeq (%rax), %rbx", "no REX2 encoding");
    // Not everything was promoted: `mov`, `push` and the two-operand `cmov`
    // have no map-4 opcode.
    rejects("{evex} movq %rax, %rbx", "has no EVEX encoding");
    rejects("{evex} pushq %rax", "has no EVEX encoding");
    rejects("{evex} cmovneq %rax, %rbx", "has no EVEX encoding");
    // Nor does everything have a no-flags form: an operation that reads the
    // flags, or whose only result is flags, cannot leave them alone.
    for src in [
        "{nf} notq %rax",
        "{nf} adcq %rax, %rbx",
        "{nf} rclq $1, %rax",
        "{nf} cmpq %rax, %rbx",
        "{nf} push2 %rax, %rbx",
        "{nf} setzue %al",
        "{nf} cfcmovneq %rax, %rbx",
    ] {
        rejects(src, "has no `{nf}` form");
    }
    // The paired forms move the stack pointer themselves, and `pop2` writes
    // both its registers.
    rejects("push2 %rsp, %rax", "cannot be one of a paired push");
    rejects("push2 %rax, %rsp", "cannot be one of a paired push");
    rejects("pop2 %rax, %rax", "must be different");
    // A condition `{dfv=...}` cannot supply a flag for, and the decorator on
    // an instruction with no condition to compare it against.
    rejects("ccmpp {dfv=zf} %rax, %rbx", "unknown instruction");
    rejects(
        "ccmpe {dfv=af} %rax, %rbx",
        "not one of `of`, `sf`, `zf` and `cf`",
    );
    rejects("ccmpe {dfv=zf,zf} %rax, %rbx", "named twice");
    rejects("addq {dfv=zf} %rax, %rbx", "takes no `{dfv=...}`");
    // GNU as refuses `lock` on everything APX promoted.
    rejects(
        "lock addq %rax, (%rbx), %rcx",
        "cannot be combined with `lock`",
    );
    // A shift with a new destination still has to say what to shift by.
    rejects("rolq %rax, %rbx", "no form of `rolq`");
}

#[test]
fn none_of_it_exists_outside_long_mode() {
    rejects32("movl %r16d, %eax", "only available in 64-bit mode");
    rejects32("addl %eax, %ebx, %ecx", "only available in 64-bit mode");
    rejects32("push2 %eax, %ebx", "no form of `push2`");
    rejects32("{rex2} movl %eax, %ebx", "requires 64-bit mode");
    rejects32("{nf} addl %eax, %ebx", "has no `{nf}` form");
}
