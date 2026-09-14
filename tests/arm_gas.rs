//! ARM and Thumb features whose reference is GNU as: literal pools, mapping
//! symbols, `adr`, interworking and `it` blocks.
//!
//! Every expected value here was taken from `arm-none-eabi-as -march=armv7-a`
//! 2.47, the reference `tools/xas-diff/run.sh arm thumb` compares whole
//! objects against; the cases are the corpora's, or cut down from them.

#![cfg(feature = "arm")]

mod common;
use common::*;

/// The mapping symbols of an assembled source, as `(section, offset, name)`.
fn mapping(arch: &str, src: &str) -> Vec<(String, u64, &'static str)> {
    let asm = assemble_for(arch, src);
    assert!(
        !asm.diags.has_errors(),
        "{}",
        asm.diags.render(&asm.sm, false)
    );
    asm.mapping_symbols
        .iter()
        .map(|m| {
            let name = asm.interner.get(asm.section(m.section).name).to_string();
            (name, m.offset, m.name)
        })
        .collect()
}

fn text(entries: &[(u64, &'static str)]) -> Vec<(String, u64, &'static str)> {
    entries
        .iter()
        .map(|&(o, n)| (".text".to_string(), o, n))
        .collect()
}

// ---- literal pools -----------------------------------------------------------

/// A pool collects the literals since the last `.ltorg`; equal numbers share
/// an entry, a number a `mov` or `mvn` can hold is moved instead, and a pool
/// still open at the end of the section is written there.
#[test]
fn arm_literal_pools() {
    let src = "f:      ldr     r0, =0x12345678
        mov     r0, r1
        .ltorg
        ldr     r0, =0x12345678
        ldreq   r1, =0x87654321
        ldrne   r2, =0x100
        ldr     r3, =f
        bx      lr
";
    assert_eq!(
        hex(&text_for("arm", src)),
        "00 00 1f e5 01 00 a0 e1 78 56 34 12 0c 00 9f e5 0c 10 9f 05 01 2c a0 13 \
         08 30 9f e5 1e ff 2f e1 78 56 34 12 21 43 65 87 00 00 00 00"
    );
    assert_eq!(
        mapping("arm", src),
        text(&[(0, "$a"), (8, "$d"), (0xc, "$a"), (0x20, "$d")])
    );
    // The entry for a label is relocated against its section.
    let asm = assemble_for("arm", src);
    assert_eq!(asm.relocs.len(), 1);
    assert_eq!((asm.relocs[0].offset, asm.relocs[0].kind), (0x28, 2));
}

/// Thumb moves a number with a 32-bit `mov.w`, `mvn.w` or `movw`, never a
/// flag-setting 16-bit `movs`, and aligns its pool with zeros, marking the
/// padding as data as well as the pool.
#[test]
fn thumb_literal_pools() {
    let src = "f:      ldr     r0, =0x12345678
        movs    r0, r0
        bx      lr
        .ltorg
        ldr     r1, =0xff
        ldr     r2, =0xffffff00
        ldr     r3, =0x1234
        ldr     r4, =0x12345678
        ldr.w   r5, =0x12345678
";
    assert_eq!(
        hex(&text_for("thumb", src)),
        "01 48 00 00 70 47 00 00 78 56 34 12 4f f0 ff 01 6f f0 ff 02 41 f2 34 23 \
         01 4c df f8 04 50 00 00 78 56 34 12"
    );
    assert_eq!(
        mapping("thumb", src),
        text(&[
            (0, "$t"),
            (6, "$d"),
            (8, "$d"),
            (0xc, "$t"),
            (0x1e, "$d"),
            (0x20, "$d")
        ])
    );
}

/// A 16-bit load reaches 1020 bytes forward; past that, or when the code
/// before the pool grows, layout takes the 32-bit form.
#[test]
fn thumb_literal_loads_grow_out_of_reach() {
    let near = text_for("thumb", "ldr r0, =0x12345678\n.space 1018\n.ltorg\n");
    assert_eq!(hex(&near[..2]), "fe 48");
    let nearest = text_for("thumb", "ldr r0, =0x12345678\n.space 1022\n.ltorg\n");
    assert_eq!(hex(&nearest[..2]), "ff 48");
    let far = text_for("thumb", "ldr r0, =0x12345678\n.space 1024\n.ltorg\n");
    assert_eq!(hex(&far[..4]), "df f8 00 04");
    let grown = text_for(
        "thumb",
        "ldr r0, =0x12345678\nldr r1, =0x12345679\n.space 1014\nb far\n.ltorg\n\
         .space 2048\nfar: bx lr\n",
    );
    assert_eq!(hex(&grown[..6]), "ff 48 df f8 00 14");
}

#[test]
fn a_pool_out_of_reach_is_refused() {
    let e = errors_for("arm", "ldr r0, =0x12345678\n.space 4096\nbx lr\n");
    assert!(e.contains("-4095 to 4095"), "{e}");
    assert!(e.contains("put an `.ltorg` nearer"), "{e}");
    let e = errors_for("thumb", "ldr.n r0, =0x12345678\n.space 1026\n.ltorg\n");
    assert!(e.contains("0 to 1020"), "{e}");
    assert!(errors_for("arm", "ldrb r0, =1").contains("only `ldr` can"));
    assert!(errors_for("arm", "ldr r0, =0x100000000").contains("32-bit word"));
}

// ---- adr and adrl ----------------------------------------------------------------

/// ARM `adr` is an `add` or `sub` from the PC; `adrl` adds a second one, or a
/// no-op where one reaches.
#[test]
fn arm_adr_and_adrl() {
    assert_eq!(
        hex(&text_for(
            "arm",
            "back: nop\nadr r0, back\nadr r1, fwd\nadreq r2, fwd\nadr lr, back + 4\nfwd: bx lr\n"
        )),
        "00 f0 20 e3 0c 00 4f e2 04 10 8f e2 00 20 8f 02 14 e0 4f e2 1e ff 2f e1"
    );
    let far = text_for(
        "arm",
        "back: adrl r0, near\nadrl r1, far\nadrl r2, back\nnear: nop\n.space 0x10000\n\
         far: adrl r3, back\nadrlne r4, near\nbx lr\n",
    );
    assert_eq!(
        hex(&far[..24]),
        "10 00 8f e2 00 00 a0 e1 0c 10 8f e2 01 18 81 e2 18 20 4f e2 00 00 a0 e1"
    );
    assert_eq!(
        hex(&far[0x1001c..0x1002c]),
        "24 30 4f e2 01 38 43 e2 14 40 4f 12 01 48 44 12"
    );
    let e = errors_for("arm", "adr r0, far\n.space 1014\nfar: bx lr\n");
    assert!(e.contains("try `adrl`"), "{e}");
}

/// Thumb `adr` is 16 bits for a low register and a word-aligned label up to
/// 1020 bytes ahead, and `addw`/`subw` from the PC otherwise.
#[test]
fn thumb_adr() {
    assert_eq!(
        hex(&text_for(
            "thumb",
            "back: nop\nadr r0, back\nadr r1, fwd\nadr r8, fwd\nadr.w r2, fwd\n\
             adr r3, odd\n.p2align 2, 0\nfwd: bx lr\nodd: bx lr\n"
        )),
        "00 bf af f2 04 00 03 a1 0f f2 08 08 0f f2 04 02 0f f2 02 03 70 47 70 47"
    );
}

// ---- mapping symbols -----------------------------------------------------------

/// Every change between code and data is marked, alignment padding with no-ops
/// is code, and an odd remainder of it is data.
#[test]
fn mapping_symbols_mark_code_and_data() {
    let src = "f:      mov     r0, r1
        .word   1, 2
        .byte   3
        .p2align 2
        mov     r1, r2
        .ascii  \"ab\"
        .balign 4, 0xaa
        bx      lr
";
    assert_eq!(
        hex(&text_for("arm", src)),
        "01 00 a0 e1 01 00 00 00 02 00 00 00 03 00 00 00 02 10 a0 e1 61 62 aa aa \
         1e ff 2f e1"
    );
    assert_eq!(
        mapping("arm", src),
        text(&[
            (0, "$a"),
            (4, "$d"),
            (0xd, "$d"),
            (0x10, "$a"),
            (0x14, "$d"),
            (0x18, "$a")
        ])
    );
}

/// Data before any code is marked from the start of the section once code
/// follows, but not in a section that never has code.
#[test]
fn data_before_code_is_marked_from_the_start() {
    assert_eq!(
        mapping("arm", ".byte 1\n.p2align 1\nmov r0, r0\n.data\n.word 1\n"),
        text(&[(0, "$d"), (1, "$d"), (2, "$a")])
    );
}
