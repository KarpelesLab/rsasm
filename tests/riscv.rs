//! RISC-V encoding tests.
//!
//! Every expected byte string here came from `llvm-mc -mattr=+m,+a,+f,+d,+c`
//! (LLVM 22), via `tools/mc-diff`. Because `+c` is on, the expectations also
//! pin down which instructions llvm-mc chose to compress.

#![cfg(feature = "riscv")]

mod common;
use common::*;

#[track_caller]
fn enc64(src: &str, want: &str) {
    let got = hex(&text_for("riscv64", src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

#[track_caller]
fn enc32(src: &str, want: &str) {
    let got = hex(&text_for("riscv32", src));
    assert_eq!(got, want, "\nsource: {src}\n  want: {want}\n   got: {got}");
}

#[track_caller]
fn table64(cases: &[(&str, &str)]) {
    for (src, want) in cases {
        enc64(src, want);
    }
}

#[test]
fn r_type() {
    table64(&[
        ("add a0, a1, a2", "33 85 c5 00"),
        ("sub a0, a1, a2", "33 85 c5 40"),
        ("sll a0, a1, a2", "33 95 c5 00"),
        ("slt a0, a1, a2", "33 a5 c5 00"),
        ("sltu a0, a1, a2", "33 b5 c5 00"),
        ("xor a0, a1, a2", "33 c5 c5 00"),
        ("srl a0, a1, a2", "33 d5 c5 00"),
        ("sra a0, a1, a2", "33 d5 c5 40"),
        ("or a0, a1, a2", "33 e5 c5 00"),
        ("and a0, a1, a2", "33 f5 c5 00"),
    ]);
}

#[test]
fn i_type() {
    table64(&[
        ("addi a0, a1, -2048", "13 85 05 80"),
        ("slti a0, a1, 100", "13 a5 45 06"),
        ("sltiu a0, a1, 100", "13 b5 45 06"),
        ("xori a0, a1, 255", "13 c5 f5 0f"),
        ("ori a0, a1, -1", "13 e5 f5 ff"),
        ("andi a0, a1, 2047", "13 f5 f5 7f"),
        ("jalr a0, a1, 4", "67 85 45 00"),
        // RV64 shift amounts are six bits, which borrows bit 25 from funct7.
        ("slli a0, a1, 63", "13 95 f5 03"),
        ("srli a0, a1, 1", "13 d5 15 00"),
        ("srai a0, a1, 31", "13 d5 f5 41"),
    ]);
}

#[test]
fn loads_and_stores() {
    table64(&[
        ("lb a0, 0(a1)", "03 85 05 00"),
        ("lh a0, 2(a1)", "03 95 25 00"),
        ("lbu a0, -1(a1)", "03 c5 f5 ff"),
        ("lhu a0, 2047(a1)", "03 d5 f5 7f"),
        ("sb a0, 0(a1)", "23 80 a5 00"),
        ("sh a0, 2(a1)", "23 91 a5 00"),
        // An S-type immediate is split around the rd field.
        ("sw a0, -2048(a1)", "23 a0 a5 80"),
    ]);
}

#[test]
fn b_type_immediates_scatter_across_the_word() {
    table64(&[
        ("beq a0, a1, 8", "63 04 b5 00"),
        ("bne a0, a1, -8", "e3 1c b5 fe"),
        ("blt a0, a1, 4092", "e3 4e b5 7e"),
        ("bge a0, a1, -4096", "63 50 b5 80"),
        ("bltu a0, a1, 16", "63 68 b5 00"),
        ("bgeu a0, a1, 16", "63 78 b5 00"),
    ]);
}

#[test]
fn u_and_j_type() {
    table64(&[
        ("lui a0, 32", "37 05 02 00"),
        ("auipc ra, 1048575", "97 f0 ff ff"),
        ("jal a0, 16", "6f 05 00 01"),
    ]);
}

#[test]
fn abi_and_numbered_register_names_are_interchangeable() {
    for (a, b) in [
        ("add x10, x11, x12", "add a0, a1, a2"),
        ("add x8, x9, x18", "add s0, s1, s2"),
        ("add fp, s1, s2", "add s0, s1, s2"),
        ("fadd.s f10, f11, f12", "fadd.s fa0, fa1, fa2"),
        ("fadd.s f8, f0, f31", "fadd.s fs0, ft0, ft11"),
    ] {
        assert_eq!(
            text_for("riscv64", a),
            text_for("riscv64", b),
            "`{a}` and `{b}` differ"
        );
    }
    table64(&[
        ("add s0, s1, s2", "33 84 24 01"),
        ("fadd.s fs0, ft0, ft11", "53 74 f0 01"),
        ("add zero, ra, sp", "33 80 20 00"),
        ("add gp, tp, t6", "b3 01 f2 01"),
    ]);
}

#[test]
fn compression_follows_llvm_choices() {
    table64(&[
        // `c.add` has a form for either operand order.
        ("add a0, a0, a1", "2e 95"),
        ("add a0, a1, a0", "2e 95"),
        ("add sp, sp, a0", "2a 91"),
        // `c.sub` and `c.xor` only reach x8-x15.
        ("sub a0, a0, a1", "0d 8d"),
        ("xor a0, a1, a0", "2d 8d"),
        // `addi` has six compressed spellings; the value picks one.
        ("addi a0, a0, 1", "05 05"),
        ("addi a0, a0, 32", "13 05 05 02"),
        ("addi a0, zero, 5", "15 45"),
        ("addi a0, a0, 0", "2a 85"),
        ("addi sp, sp, 16", "41 01"),
        ("addi sp, sp, -64", "39 71"),
        ("addi a0, sp, 16", "08 08"),
        ("slli a0, a0, 3", "0e 05"),
        ("srai a0, a0, 3", "0d 85"),
        ("andi a0, a0, -32", "01 99"),
        ("lw a0, 4(a1)", "c8 41"),
        ("lw a0, 4(sp)", "12 45"),
        ("lw a0, 124(a5)", "e8 5f"),
        ("lw a0, 128(a5)", "03 a5 07 08"),
        ("ld a0, 504(sp)", "7e 75"),
        ("sd ra, 8(sp)", "06 e4"),
        ("lui a0, 1048575", "7d 75"),
        // `c.lui` cannot load into sp, which is `c.addi16sp`'s encoding.
        ("lui sp, 4", "37 41 00 00"),
        ("jalr a0", "02 95"),
        ("ebreak", "02 90"),
        ("unimp", "00 00"),
        ("fld fa0, 8(sp)", "22 25"),
        // `c.flwsp` exists only on RV32.
        ("flw fa0, 8(sp)", "07 25 81 00"),
    ]);
    enc32("flw fa0, 8(sp)", "22 65");
    enc32("fsw fa0, 4(a1)", "c8 e1");
}

#[test]
fn rv64_only_instructions() {
    table64(&[
        ("lwu a0, 4(a1)", "03 e5 45 00"),
        ("ld a0, 8(a1)", "88 65"),
        ("sd a0, 8(a1)", "88 e5"),
        ("addiw a0, a1, 1", "1b 85 15 00"),
        ("addiw a0, a0, 1", "05 25"),
        ("slliw a0, a1, 31", "1b 95 f5 01"),
        ("srliw a0, a1, 1", "1b d5 15 00"),
        ("sraiw a0, a1, 31", "1b d5 f5 41"),
        ("addw a0, a1, a2", "3b 85 c5 00"),
        ("subw a0, a1, a2", "3b 85 c5 40"),
        ("sllw a0, a1, a2", "3b 95 c5 00"),
        ("srlw a0, a1, a2", "3b d5 c5 00"),
        ("sraw a0, a1, a2", "3b d5 c5 40"),
    ]);
}

#[test]
fn rv64_only_instructions_are_rejected_on_rv32() {
    for src in [
        "ld a0, 0(a1)",
        "addw a0, a1, a2",
        "sext.w a0, a1",
        "lr.d a0, (a1)",
    ] {
        let e = errors_for("riscv32", src);
        assert!(e.contains("RV64"), "`{src}`: {e}");
    }
}

#[test]
fn pseudo_instructions() {
    table64(&[
        ("nop", "01 00"),
        ("mv a0, a1", "2e 85"),
        ("not a0, a1", "13 c5 f5 ff"),
        ("neg a0, a1", "33 05 b0 40"),
        ("negw a0, a1", "3b 05 b0 40"),
        ("sext.w a0, a1", "1b 85 05 00"),
        ("seqz a0, a1", "13 b5 15 00"),
        ("snez a0, a1", "33 35 b0 00"),
        ("sltz a0, a1", "33 a5 05 00"),
        ("sgtz a0, a1", "33 25 b0 00"),
        ("beqz a0, 8", "01 c5"),
        ("bnez a0, 8", "01 e5"),
        ("blez a0, 8", "63 54 a0 00"),
        ("bgez a0, 8", "63 54 05 00"),
        ("bltz a0, 8", "63 44 05 00"),
        ("bgtz a0, 8", "63 44 a0 00"),
        ("bgt a0, a1, 8", "63 c4 a5 00"),
        ("ble a0, a1, 8", "63 d4 a5 00"),
        ("bgtu a0, a1, 8", "63 e4 a5 00"),
        ("bleu a0, a1, 8", "63 f4 a5 00"),
        ("j 64", "81 a0"),
        ("jr a0", "02 85"),
        ("ret", "82 80"),
        ("call sym", "97 00 00 00 e7 80 00 00"),
        ("tail sym", "17 03 00 00 67 00 03 00"),
        ("fmv.w.x fa0, a1", "53 85 05 f0"),
        ("fneg.d fa0, fa1", "53 95 b5 22"),
        ("fabs.s fa0, fa1", "53 a5 b5 20"),
    ]);
}

#[test]
fn li_picks_the_same_sequence_as_llvm() {
    table64(&[
        ("li a0, 5", "15 45"),
        ("li a0, 2047", "13 05 f0 7f"),
        // `li 1; slli 11` beats `lui+addi` because both halves compress.
        ("li a0, 2048", "05 45 2e 05"),
        ("li a0, 4096", "05 65"),
        ("li a0, 0x12345678", "37 55 34 12 13 05 85 67"),
        ("li a0, -0x80000000", "37 05 00 80"),
        ("li a0, 0xffffffff", "7d 55 01 91"),
        ("li a0, 0x100000000", "05 45 02 15"),
        (
            "li a0, 0x123456789abcdef",
            "37 25 09 00 13 05 b5 a2 32 05 13 05 55 3c 36 05 13 05 d5 ab 32 05 13 05 f5 de",
        ),
        (
            "li a0, -0x123456789abcdef",
            "37 55 97 db 13 05 f5 30 36 05 13 05 15 95 3a 05 13 05 05 80 13 05 15 a1",
        ),
        ("li a0, 0x7fffffffffffffff", "7d 55 05 81"),
        ("li a0, -0x8000000000000000", "7d 55 7e 15"),
    ]);
    enc32("li a0, 0x12345678", "37 55 34 12 13 05 85 67");
    // On RV32 an unsigned 32-bit constant wraps to the same register value.
    enc32("li a0, 0xffffffff", "7d 55");
    enc32("li a0, 0x80000000", "37 05 00 80");
    enc32("li a0, -2049", "7d 75 13 05 f5 7f");
}

#[test]
fn m_extension() {
    table64(&[
        ("mul a0, a1, a2", "33 85 c5 02"),
        ("mulh a0, a1, a2", "33 95 c5 02"),
        ("mulhsu a0, a1, a2", "33 a5 c5 02"),
        ("mulhu a0, a1, a2", "33 b5 c5 02"),
        ("div a0, a1, a2", "33 c5 c5 02"),
        ("divu a0, a1, a2", "33 d5 c5 02"),
        ("rem a0, a1, a2", "33 e5 c5 02"),
        ("remu a0, a1, a2", "33 f5 c5 02"),
        ("mulw a0, a1, a2", "3b 85 c5 02"),
        ("divw a0, a1, a2", "3b c5 c5 02"),
        ("divuw a0, a1, a2", "3b d5 c5 02"),
        ("remw a0, a1, a2", "3b e5 c5 02"),
        ("remuw a0, a1, a2", "3b f5 c5 02"),
    ]);
}

#[test]
fn a_extension_with_ordering_suffixes() {
    table64(&[
        ("lr.w a0, (a1)", "2f a5 05 10"),
        ("lr.d a0, (a1)", "2f b5 05 10"),
        ("sc.w a0, a1, (a2)", "2f 25 b6 18"),
        ("sc.w.aq a0, a1, (a2)", "2f 25 b6 1c"),
        ("amoswap.w.rl a0, a1, (a2)", "2f 25 b6 0a"),
        ("amoadd.d.aqrl a0, a1, (a2)", "2f 35 b6 06"),
        ("amomaxu.d a0, a1, (a2)", "2f 35 b6 e0"),
    ]);
}

#[test]
fn f_and_d_extensions() {
    table64(&[
        ("flw fa0, 4(a1)", "07 a5 45 00"),
        ("fsd fa0, 8(a1)", "88 a5"),
        ("fsub.d fa0, fa1, fa2", "53 f5 c5 0a"),
        ("fsqrt.d fa0, fa1", "53 f5 05 5a"),
        ("fmadd.d fa0, fa1, fa2, fa3", "43 f5 c5 6a"),
        ("feq.d a0, fa1, fa2", "53 a5 c5 a2"),
        ("fclass.d a0, fa1", "53 95 05 e2"),
        ("fmv.x.d a0, fa1", "53 85 05 e2"),
        // The rounding mode defaults to `dyn` and can be overridden.
        ("fcvt.w.s a0, fa0", "53 75 05 c0"),
        ("fcvt.w.s a0, fa0, rne", "53 05 05 c0"),
        ("fadd.s fa0, fa1, fa2, rtz", "53 95 c5 00"),
        ("fcvt.s.d fa0, fa1", "53 f5 15 40"),
        // Widening conversions are exact and have no rounding mode at all.
        ("fcvt.d.s fa0, fa1", "53 85 05 42"),
        ("fcvt.d.w fa0, a0", "53 05 05 d2"),
    ]);
}

#[test]
fn csr_and_system() {
    table64(&[
        ("csrr a0, mstatus", "73 25 00 30"),
        ("csrw mstatus, a0", "73 10 05 30"),
        ("csrrwi a0, fcsr, 7", "73 d5 33 00"),
        ("csrrs a0, 0x340, a1", "73 a5 05 34"),
        ("ecall", "73 00 00 00"),
        ("fence", "0f 00 f0 0f"),
        ("fence r, w", "0f 00 10 02"),
        ("fence.i", "0f 10 00 00"),
    ]);
}

#[test]
fn relocation_modifiers_leave_zeroed_fields() {
    enc64(
        "lui a0, %hi(sym)\naddi a0, a0, %lo(sym)\nsw a1, %lo(sym)(a0)",
        "37 05 00 00 13 05 05 00 23 20 b5 00",
    );
    enc64(
        "1: auipc a0, %pcrel_hi(sym)\naddi a0, a0, %pcrel_lo(1b)",
        "17 05 00 00 13 05 05 00",
    );
}

#[test]
fn relocation_modifiers_select_relocation_types() {
    let asm = assemble_for(
        "riscv64",
        "lui a0, %hi(sym)\naddi a0, a0, %lo(sym)\nsw a1, %lo(sym)(a0)\ncall sym\n",
    );
    assert!(!asm.diags.has_errors());
    let kinds: Vec<(u64, u32)> = asm.relocs.iter().map(|r| (r.offset, r.kind)).collect();
    // R_RISCV_HI20, R_RISCV_LO12_I, R_RISCV_LO12_S, R_RISCV_CALL.
    assert_eq!(kinds, vec![(0, 26), (4, 27), (8, 28), (12, 18)]);

    let asm = assemble_for("riscv64", "call sym@plt\nj sym\nbeqz a0, sym\n");
    assert!(!asm.diags.has_errors());
    let kinds: Vec<(u64, u32)> = asm.relocs.iter().map(|r| (r.offset, r.kind)).collect();
    // R_RISCV_CALL_PLT, then R_RISCV_JAL and R_RISCV_BRANCH: a reference the
    // linker resolves takes the full-width form.
    assert_eq!(kinds, vec![(0, 19), (8, 17), (12, 16)]);
}

#[test]
fn branches_to_labels() {
    enc64(
        "start:\nadd a0, a0, a1\naddi a1, a1, -1\nbnez a1, start\nret",
        "2e 95 fd 15 f5 fd 82 80",
    );
    // A local call and tail resolve without a relocation.
    enc64(
        "target:\nret\ncall target\ntail target",
        "82 80 97 00 00 00 e7 80 e0 ff 17 03 00 00 67 00 63 ff",
    );
    enc64(
        "la a0, value\nlla a1, value\nvalue:\nret",
        "17 05 00 00 13 05 05 01 97 05 00 00 93 85 85 00 82 80",
    );
    // `c.jal` exists only on RV32.
    enc32("jal target\nnop\ntarget:\nret", "11 20 01 00 82 80");
}

/// Checks a relaxed branch by its first and last bytes; the padding between
/// them is zeros.
#[track_caller]
fn relaxed(arch: &str, src: &str, head: &str, tail: &str, len: usize) {
    let out = text_for(arch, src);
    assert_eq!(out.len(), len, "{src}");
    let h = hex(&out[..4]);
    let t = hex(&out[out.len() - tail.split(' ').count()..]);
    assert_eq!((h.as_str(), t.as_str()), (head, tail), "{src}");
}

#[test]
fn compressed_branches_grow_when_the_target_is_out_of_reach() {
    // c.beqz reaches +-256 bytes; beq is chosen once the target is further.
    relaxed(
        "riscv64",
        "beqz a0, far\n.space 300\nfar:\nret",
        "63 08 05 12",
        "82 80",
        306,
    );
    // c.j reaches +-2 KiB.
    relaxed(
        "riscv64",
        "j ahead\n.space 4000\nnop\nahead:\nret",
        "6f 00 70 7a",
        "01 00 82 80",
        4008,
    );
    relaxed(
        "riscv32",
        "jal target\n.space 3000\ntarget:\nret",
        "ef 00 d0 3b",
        "82 80",
        3006,
    );
}

#[test]
fn option_rvc_and_push_pop() {
    enc64(
        ".option norvc\nadd a0, a0, a1\nmv a1, a2\nret\n.option rvc\nadd a0, a0, a1",
        "33 05 b5 00 93 05 06 00 67 80 00 00 2e 95",
    );
    enc64(
        "add a0, a0, a1\n.option push\n.option norvc\nadd a0, a0, a1\n.option pop\nadd a0, a0, a1",
        "2e 95 33 05 b5 00 2e 95",
    );
}

#[test]
fn alignment_pads_with_real_no_ops() {
    enc64(
        "add a0, a0, a1\n.p2align 3\nadd a0, a0, a1\n.p2align 2\nret",
        "2e 95 01 00 13 00 00 00 2e 95 01 00 82 80",
    );
}

// ---- diagnostics ------------------------------------------------------------

#[track_caller]
fn rejects(arch: &str, src: &str, needle: &str) {
    let e = errors_for(arch, src);
    assert!(
        e.contains(needle),
        "`{src}` should mention `{needle}`:\n{e}"
    );
}

#[test]
fn immediates_out_of_range_name_the_limit() {
    rejects("riscv64", "addi a0, a0, 2048", "12-bit");
    rejects("riscv64", "lw a0, -2049(a1)", "12-bit");
    rejects("riscv64", "lui a0, 0x100000", "20-bit");
    rejects("riscv64", "slli a0, a0, 64", "between 0 and 63");
    rejects("riscv32", "slli a0, a0, 32", "between 0 and 31");
    rejects("riscv64", "slliw a0, a0, 32", "between 0 and 31");
    rejects("riscv64", "csrrwi a0, 0x300, 32", "between 0 and 31");
    rejects("riscv32", "li a0, 0x100000000", "32 bits");
}

#[test]
fn branches_out_of_range_are_reported() {
    let src = "beq a0, a1, far\n.space 5000\nfar: ret";
    assert!(try_text_for("riscv64", src).is_err());
    // An odd displacement cannot be encoded at all.
    assert!(try_text_for("riscv64", "beq a0, a1, 3").is_err());
    assert!(try_text_for("riscv64", "j 3").is_err());
}

#[test]
fn operand_shape_errors() {
    rejects("riscv64", "add a0, a1", "3 operand");
    rejects("riscv64", "add a0, a1, fa2", "integer register");
    rejects("riscv64", "fadd.s fa0, fa1, a2", "floating-point register");
    rejects("riscv64", "lw a0, a1", "offset(reg)");
    rejects("riscv64", "lw a0, 4(fa1)", "integer register");
    rejects("riscv64", "lui a0, %lo(sym)", "low half");
    rejects("riscv64", "addi a0, a0, %hi(sym)", "12-bit");
    rejects(
        "riscv64",
        "addi a0, a0, %nope(sym)",
        "unknown relocation modifier",
    );
    rejects("riscv64", "frobnicate a0", "unknown instruction");
    rejects("riscv64", "lr.w a0, 4(a1)", "no offset");
    rejects("riscv64", "fence x, w", "iorw");
    rejects("riscv64", ".option nonsense", "unknown `.option");
    rejects("riscv64", ".option pop", "no `.option push`");
    rejects(
        "riscv64",
        ".option push\n.option pop\n.option pop",
        "no `.option push`",
    );
}

/// Every one of these is wrong in some way. The only requirement is that the
/// backend reports something and returns.
const MALFORMED: &[&str] = &[
    "add",
    "add ,",
    "add a0,",
    "add ,a0",
    "add a0,,a1",
    "add a0 a1 a2",
    "add a0, a1, a2, a3",
    "addi a0, a1,",
    "addi a0, a1, (",
    "addi a0, a1, )",
    "addi a0, a1, %",
    "addi a0, a1, %lo",
    "addi a0, a1, %lo(",
    "addi a0, a1, %lo()",
    "addi a0, a1, %lo(sym",
    "addi a0, a1, %lo(sym))",
    "addi a0, a1, %lo(sym)(",
    "addi a0, a1, 1 2",
    "lw a0,",
    "lw a0, (",
    "lw a0, ()",
    "lw a0, )",
    "lw a0, 4(",
    "lw a0, 4()",
    "lw a0, 4(a1",
    "lw a0, 4(a1, a2)",
    "lw a0, 4((a1))",
    "lw a0, ((((",
    "lw a0, ))))",
    "lw a0, %lo(sym)(a1)(a2)",
    "sw , 4(a1)",
    "beq a0, a1",
    "beq a0, a1, %hi(x)",
    "beqz",
    "bnez a0",
    "j",
    "j a0, a1",
    "jal",
    "jal a0, a1, a2",
    "jalr",
    "jalr a0, a1, a2, a3",
    "jalr (a1)",
    "jalr 4(",
    "jr",
    "ret a0",
    "call",
    "call a0, a1, a2",
    "tail",
    "li",
    "li a0",
    "li a0,",
    "li 5, a0",
    "li a0, sym",
    "la",
    "la a0",
    "lr.w",
    "lr.w a0",
    "sc.w a0, a1",
    "amoadd.w.aq a0, a1, a2",
    "amoadd.w.aqrl.aq a0, a1, (a2)",
    "fadd.s fa0, fa1",
    "fadd.s fa0, fa1, fa2, nearest",
    "fadd.s fa0, fa1, fa2, rtz, rtz",
    "fcvt.w.s a0",
    "fcvt.w.s a0, fa0, a1",
    "fmadd.s fa0, fa1, fa2",
    "fmv.s fa0",
    "csrr a0",
    "csrr a0, nosuch",
    "csrw mstatus",
    "csrrw a0, 5000, a1",
    "csrrwi a0, mstatus, -1",
    "fence r",
    "fence r, w, x",
    "fence 1, 2",
    "ecall a0",
    "nop nop",
    "x99",
    "a0",
    "add x32, x0, x0",
    "add f32, x0, x0",
    ".option",
    ".option 1",
    ".option push, pop",
    ".option pop\n.option pop\n.option pop",
    "slli a0, a0, -1",
    "slli a0, a0, sym",
    "lui a0, -0x80001",
    "addi a0, a0, 0x7fffffffffffffff",
    "li a0, 0xffffffffffffffffffff",
    "beq a0, a1, .+0x100000",
    "j .+0x100000000",
    "call .+0x100000000",
];

#[test]
fn malformed_input_never_panics() {
    for arch in ["riscv32", "riscv64"] {
        for src in MALFORMED {
            let _ = try_text_for(arch, src);
        }
    }
}

#[test]
fn backend_names_resolve() {
    for name in ["riscv32", "riscv64", "rv32", "rv64", "riscv"] {
        assert!(rsasm::arch::lookup(name).is_some(), "{name}");
    }
    let rv32 = rsasm::arch::lookup("rv32").map(|a| a.name());
    assert_eq!(rv32, Some("riscv32"));
    let rv64 = rsasm::arch::lookup("rv64").map(|a| a.name());
    assert_eq!(rv64, Some("riscv64"));
}

#[test]
fn data_relocations_use_riscv_numbers() {
    let a = rsasm::arch::lookup("riscv64").expect("backend present");
    assert_eq!(a.elf_machine(), 243);
    assert_eq!(a.data_reloc(4, false), Some(1));
    assert_eq!(a.data_reloc(8, false), Some(2));
    assert_eq!(a.data_reloc(4, true), Some(57));
    assert_eq!(a.data_reloc(1, false), None);
}
