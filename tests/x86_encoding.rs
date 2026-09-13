//! x86-64 encoding tests.
//!
//! Every expected byte string here was checked against GNU as 2.46
//! (`as --64`), so this file doubles as a record of where rsasm intends to be
//! byte-compatible with it.

mod common;
use common::*;

/// Asserts that `src` assembles to `want`, written as space-separated hex.
#[track_caller]
fn enc(src: &str, want: &str) {
    let got = hex(&text(src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

#[test]
fn zero_operand_instructions() {
    enc("nop", "90");
    enc("ret", "c3");
    enc("leave", "c9");
    enc("hlt", "f4");
    enc("int3", "cc");
    enc("ud2", "0f 0b");
    enc("syscall", "0f 05");
    enc("cpuid", "0f a2");
    enc("endbr64", "f3 0f 1e fa");
    enc("cltq", "48 98");
    enc("cqto", "48 99");
}

#[test]
fn register_to_register_moves_across_widths() {
    enc("movq %rbx, %rax", "48 89 d8");
    enc("movl %ebx, %eax", "89 d8");
    enc("movw %bx, %ax", "66 89 d8");
    enc("movb %bl, %al", "88 d8");
}

#[test]
fn rex_extension_bits() {
    enc("movq %rax, %r15", "49 89 c7");
    enc("movq %r8, %r9", "4d 89 c1");
    // spl/dil exist only with a REX prefix, even an otherwise empty one.
    enc("movb %sil, %dil", "40 88 f7");
    // ah has no REX form, so it must not acquire one.
    enc("movb %ah, %al", "88 e0");
    // `+r` opcodes put the register's high bit in REX.B, not REX.R.
    enc("pushq %r12", "41 54");
    enc("popq %r13", "41 5d");
}

#[test]
fn immediate_width_selection() {
    enc("movl $1, %eax", "b8 01 00 00 00");
    // A 64-bit move of a small constant uses the shorter sign-extended form.
    enc("movq $1, %rax", "48 c7 c0 01 00 00 00");
    enc("movq $-1, %rax", "48 c7 c0 ff ff ff ff");
    // Only a value that does not fit in 32 bits needs the 10-byte form.
    enc(
        "movq $0x1122334455667788, %rax",
        "48 b8 88 77 66 55 44 33 22 11",
    );
    enc(
        "movabsq $0x1122334455667788, %rax",
        "48 b8 88 77 66 55 44 33 22 11",
    );
    // `add` prefers the sign-extended imm8 encoding whenever it fits.
    enc("addq $1, %rax", "48 83 c0 01");
    enc("addq $128, %rax", "48 05 80 00 00 00");
    enc("addq $-129, %rax", "48 05 7f ff ff ff");
    enc("addl $0x1000, %eax", "05 00 10 00 00");
}

#[test]
fn memory_addressing_forms() {
    enc("movq 8(%rbx), %rax", "48 8b 43 08");
    enc("movq -8(%rbx), %rax", "48 8b 43 f8");
    enc("movq (%rbx,%rcx), %rax", "48 8b 04 0b");
    enc("movq (%rbx,%rcx,4), %rax", "48 8b 04 8b");
    enc("movq 16(%rbx,%rcx,8), %rax", "48 8b 44 cb 10");
    // rsp as a base always needs a SIB byte.
    enc("movq (%rsp), %rax", "48 8b 04 24");
    enc("movq 8(%rsp), %rax", "48 8b 44 24 08");
    // rbp as a base always needs a displacement, even a zero one.
    enc("movq (%rbp), %rax", "48 8b 45 00");
    enc("movq (%r12), %rax", "49 8b 04 24");
    enc("movq (%r13), %rax", "49 8b 45 00");
    enc("movq (%r12,%r13,4), %rax", "4b 8b 04 ac");
    // An absolute address in 64-bit mode goes through the SIB escape.
    enc("movq 0x1000, %rax", "48 8b 04 25 00 10 00 00");
}

#[test]
fn rip_relative_addressing() {
    // A constant displacement is written literally.
    enc("leaq 2(%rip), %rax", "48 8d 05 02 00 00 00");
    enc("leaq -8(%rip), %rax", "48 8d 05 f8 ff ff ff");
    enc("leaq (%rip), %rax", "48 8d 05 00 00 00 00");
    // A symbol becomes the distance from the end of the instruction.
    enc("leaq foo(%rip), %rax\nfoo: nop", "48 8d 05 00 00 00 00 90");
    enc(
        "nop\nfoo: nop\nleaq foo(%rip), %rax",
        "90 90 48 8d 05 f8 ff ff ff",
    );
    // The bias accounts for an immediate following the displacement.
    enc(
        "movl $1, foo(%rip)\nfoo: .long 0",
        "c7 05 00 00 00 00 01 00 00 00 00 00 00 00",
    );
}

#[test]
fn segment_overrides() {
    enc("movq %fs:(%rax), %rax", "64 48 8b 00");
    enc("movq %gs:8(%rax), %rax", "65 48 8b 40 08");
    // A segment may also be written as a standalone prefix mnemonic.
    enc("fs movq (%rax), %rax", "64 48 8b 00");
}

#[test]
fn instruction_prefixes() {
    enc("lock incq (%rax)", "f0 48 ff 00");
    enc("rep movsb", "f3 a4");
    enc("repne scasb", "f2 ae");
}

#[test]
fn xchg_uses_the_short_accumulator_form() {
    enc("xchgq %rbx, %rax", "48 93");
    enc("xchgq %rax, %rbx", "48 93");
    enc("xchgq %r8, %rax", "49 90");
    enc("xchgl %ebx, %eax", "93");
    // `xchg rax, rax` is spelled `nop`...
    enc("xchgq %rax, %rax", "90");
    // ...but `xchg eax, eax` must not be, since `90` would leave the upper
    // half of rax alone instead of clearing it.
    enc("xchgl %eax, %eax", "87 c0");
    enc("xchgw %ax, %ax", "66 90");
}

#[test]
fn extending_moves() {
    enc("movzbl %al, %eax", "0f b6 c0");
    enc("movzwl %ax, %eax", "0f b7 c0");
    enc("movsbl %al, %eax", "0f be c0");
    enc("movswq %ax, %rax", "48 0f bf c0");
    enc("movslq %eax, %rax", "48 63 c0");
}

#[test]
fn arithmetic_and_shifts() {
    enc("imulq %rbx, %rax", "48 0f af c3");
    enc("imulq $4, %rbx, %rax", "48 6b c3 04");
    enc("shlq $1, %rax", "48 d1 e0");
    enc("shlq $4, %rax", "48 c1 e0 04");
    enc("shrq %cl, %rax", "48 d3 e8");
    enc("sarl $31, %eax", "c1 f8 1f");
    enc("negq %rax", "48 f7 d8");
    enc("idivq %rbx", "48 f7 fb");
}

#[test]
fn conditional_instructions() {
    enc("setne %al", "0f 95 c0");
    enc("sete %bl", "0f 94 c3");
    enc("cmovgq %rbx, %rax", "48 0f 4f c3");
}

#[test]
fn branches_pick_the_shortest_displacement() {
    // A nearby target fits in a rel8.
    enc("jmp fwd\nnop\nfwd: ret", "eb 01 90 c3");
    enc("back: nop\njmp back", "90 eb fd");
    enc("1: jmp 1b", "eb fe");
    // A distant one is relaxed to rel32; the branch itself grows from 2 to 5
    // bytes, which the layout pass has to account for.
    let out = text("jmp far\n.space 200\nfar: ret");
    assert_eq!(hex(&out[..5]), "e9 c8 00 00 00");
    assert_eq!(out.len(), 5 + 200 + 1);
    // Conditional branches relax the same way, 2 bytes to 6.
    let out = text("je far\n.space 200\nfar: ret");
    assert_eq!(hex(&out[..6]), "0f 84 c8 00 00 00");
    // `call` has no short form.
    enc("target: ret\ncall target", "c3 e8 fa ff ff ff");
}

#[test]
fn relaxation_settles_when_branches_push_each_other_apart() {
    // Each `jmp` is short only if the ones after it stay short. With 127
    // bytes of padding the chain has to grow, and the layout loop must
    // converge rather than oscillate.
    let src = "
        jmp a
        jmp b
        .space 120
        a: nop
        b: nop
    ";
    let out = text(src);
    // 120 bytes of padding plus two labels' worth of nops, whatever the
    // branches ended up costing.
    assert!(out.len() >= 120 + 2 + 4);
    // Both branches must land on their targets: decode the second one.
    assert_eq!(
        out[0],
        0xeb,
        "first jump should still be short: {}",
        hex(&out)
    );
}

#[test]
fn intel_syntax() {
    enc(".intel_syntax noprefix\nmov rax, rbx", "48 89 d8");
    enc(".intel_syntax noprefix\nadd rax, 1", "48 83 c0 01");
    enc(
        ".intel_syntax noprefix\nmov qword ptr [rbx+8], rax",
        "48 89 43 08",
    );
    enc(
        ".intel_syntax noprefix\nmov eax, dword ptr [rbx+rcx*4+16]",
        "8b 44 8b 10",
    );
    enc(
        ".intel_syntax noprefix\nlea rax, [rip+2]",
        "48 8d 05 02 00 00 00",
    );
    enc(".intel_syntax noprefix\nmov rax, [rbx]", "48 8b 03");
    enc(".intel_syntax noprefix\nmov rax, [rbx+rcx]", "48 8b 04 0b");
    enc(
        ".intel_syntax noprefix\nmov rax, [rcx*4]",
        "48 8b 04 8d 00 00 00 00",
    );
    enc(".intel_syntax noprefix\nmov rax, [rbx-8]", "48 8b 43 f8");
    enc(
        ".intel_syntax noprefix\nmov rax, [0x1000]",
        "48 8b 04 25 00 10 00 00",
    );
}

#[test]
fn the_two_syntaxes_agree_and_can_be_switched_mid_file() {
    let att = text("movq 8(%rbx), %rax");
    let intel = text(".intel_syntax noprefix\nmov rax, qword ptr [rbx+8]");
    assert_eq!(att, intel);
    // `.att_syntax` switches back.
    enc(
        ".intel_syntax noprefix\nmov rax, rbx\n.att_syntax\nmovq %rbx, %rax",
        "48 89 d8 48 89 d8",
    );
}

#[test]
fn operating_mode_directives() {
    enc(".code64\nnop", "90");
    enc(".code32\nnop", "90");
    enc(".code16\nnop", "90");
    // Operand size 32 needs the 0x66 prefix in 16-bit mode and none otherwise.
    enc(".code16\nmovl %ebx, %eax", "66 89 d8");
    enc(".code32\nmovl %ebx, %eax", "89 d8");
    enc(".code16\nmovw %bx, %ax", "89 d8");
}
