//! The base integer instruction set: the 8086 through x86-64 core.
//!
//! Everything here predates SIMD; the vector families live in sibling modules.

use super::{
    CONDITIONS, DEF64, Def, IMM64, ModRm, NO_REX_W, NO64, NOTACC, ONLY64, Op, PLUSREG, WIDTHS, add,
    d, opsize_bits,
};
use std::collections::HashMap;

/// `add`-style group: eight instructions sharing one opcode layout.
fn alu_group(table: &mut HashMap<&'static str, Vec<Def>>, mnem: &'static str, base: u8, ext: u8) {
    let mut defs = Vec::new();

    // 8-bit forms.
    defs.push(d(vec![Op::Rm(1), Op::R(1)], &[base], ModRm::Reg, 8));
    defs.push(d(vec![Op::R(1), Op::Rm(1)], &[base + 2], ModRm::Reg, 8));

    for w in WIDTHS {
        let bits = opsize_bits(w);
        defs.push(d(vec![Op::Rm(w), Op::R(w)], &[base + 1], ModRm::Reg, bits));
        defs.push(d(vec![Op::R(w), Op::Rm(w)], &[base + 3], ModRm::Reg, bits));
    }

    // Immediate forms. The 8-bit accumulator form (`add al, imm8`) is a byte
    // shorter than the ModRM one and has no sign-extended rival, so it comes
    // first; GNU as and NASM both prefer it.
    defs.push(d(
        vec![Op::Fixed("al"), Op::Imm(1)],
        &[base + 4],
        ModRm::None,
        8,
    ));
    defs.push(d(vec![Op::Rm(1), Op::Imm(1)], &[0x80], ModRm::Ext(ext), 8));
    // The wider sign-extended `imm8` encodings come first so the matcher
    // prefers them whenever the value fits.
    for w in WIDTHS {
        let bits = opsize_bits(w);
        defs.push(d(
            vec![Op::Rm(w), Op::Imm8s],
            &[0x83],
            ModRm::Ext(ext),
            bits,
        ));
    }
    // `op eAX, imm32` is one byte shorter than the ModRM form, so it is tried
    // before it but after the imm8-sign-extended forms.
    defs.push(d(
        vec![Op::Fixed("ax"), Op::Imm(2)],
        &[base + 5],
        ModRm::None,
        16,
    ));
    defs.push(d(
        vec![Op::Fixed("eax"), Op::Imm(4)],
        &[base + 5],
        ModRm::None,
        32,
    ));
    defs.push(d(
        vec![Op::Fixed("rax"), Op::Imm(4)],
        &[base + 5],
        ModRm::None,
        64,
    ));
    for w in WIDTHS {
        let bits = opsize_bits(w);
        let imm = if w == 2 { 2 } else { 4 };
        defs.push(d(
            vec![Op::Rm(w), Op::Imm(imm)],
            &[0x81],
            ModRm::Ext(ext),
            bits,
        ));
    }

    table.insert(mnem, defs);
}

/// `shl`-style group: shifts and rotates.
fn shift_group(table: &mut HashMap<&'static str, Vec<Def>>, mnems: &[&'static str], ext: u8) {
    let mut defs = Vec::new();
    defs.push(d(vec![Op::Rm(1), Op::One], &[0xd0], ModRm::Ext(ext), 8));
    defs.push(d(
        vec![Op::Rm(1), Op::Fixed("cl")],
        &[0xd2],
        ModRm::Ext(ext),
        8,
    ));
    defs.push(d(vec![Op::Rm(1), Op::Imm(1)], &[0xc0], ModRm::Ext(ext), 8));
    for w in WIDTHS {
        let bits = opsize_bits(w);
        defs.push(d(vec![Op::Rm(w), Op::One], &[0xd1], ModRm::Ext(ext), bits));
        defs.push(d(
            vec![Op::Rm(w), Op::Fixed("cl")],
            &[0xd3],
            ModRm::Ext(ext),
            bits,
        ));
        defs.push(d(
            vec![Op::Rm(w), Op::Imm(1)],
            &[0xc1],
            ModRm::Ext(ext),
            bits,
        ));
    }
    // A shift with no count means "by one".
    defs.push(d(vec![Op::Rm(1)], &[0xd0], ModRm::Ext(ext), 8));
    for w in WIDTHS {
        defs.push(d(vec![Op::Rm(w)], &[0xd1], ModRm::Ext(ext), opsize_bits(w)));
    }
    for m in mnems {
        table.insert(m, defs.clone());
    }
}

/// `not`/`neg`/`mul`/`div`-style unary group: `F6`/`F7 /digit`.
fn unary_group(table: &mut HashMap<&'static str, Vec<Def>>, mnem: &'static str, ext: u8) {
    let mut defs = vec![d(vec![Op::Rm(1)], &[0xf6], ModRm::Ext(ext), 8)];
    for w in WIDTHS {
        defs.push(d(vec![Op::Rm(w)], &[0xf7], ModRm::Ext(ext), opsize_bits(w)));
    }
    table.insert(mnem, defs);
}

pub fn install(t: &mut HashMap<&'static str, Vec<Def>>) {
    alu_group(t, "add", 0x00, 0);
    alu_group(t, "or", 0x08, 1);
    alu_group(t, "adc", 0x10, 2);
    alu_group(t, "sbb", 0x18, 3);
    alu_group(t, "and", 0x20, 4);
    alu_group(t, "sub", 0x28, 5);
    alu_group(t, "xor", 0x30, 6);
    alu_group(t, "cmp", 0x38, 7);

    shift_group(t, &["rol"], 0);
    shift_group(t, &["ror"], 1);
    shift_group(t, &["rcl"], 2);
    shift_group(t, &["rcr"], 3);
    shift_group(t, &["shl", "sal"], 4);
    shift_group(t, &["shr"], 5);
    shift_group(t, &["sar"], 7);

    unary_group(t, "not", 2);
    unary_group(t, "neg", 3);
    unary_group(t, "mul", 4);
    unary_group(t, "div", 6);
    unary_group(t, "idiv", 7);

    // `test` has no `r, r/m` direction and no sign-extended immediate.
    {
        let mut defs = vec![
            d(vec![Op::Rm(1), Op::R(1)], &[0x84], ModRm::Reg, 8),
            d(vec![Op::Fixed("al"), Op::Imm(1)], &[0xa8], ModRm::None, 8),
            d(vec![Op::Rm(1), Op::Imm(1)], &[0xf6], ModRm::Ext(0), 8),
        ];
        for w in WIDTHS {
            let bits = opsize_bits(w);
            defs.push(d(vec![Op::Rm(w), Op::R(w)], &[0x85], ModRm::Reg, bits));
        }
        defs.push(d(
            vec![Op::Fixed("ax"), Op::Imm(2)],
            &[0xa9],
            ModRm::None,
            16,
        ));
        defs.push(d(
            vec![Op::Fixed("eax"), Op::Imm(4)],
            &[0xa9],
            ModRm::None,
            32,
        ));
        defs.push(d(
            vec![Op::Fixed("rax"), Op::Imm(4)],
            &[0xa9],
            ModRm::None,
            64,
        ));
        for w in WIDTHS {
            let bits = opsize_bits(w);
            let imm = if w == 2 { 2 } else { 4 };
            defs.push(d(
                vec![Op::Rm(w), Op::Imm(imm)],
                &[0xf7],
                ModRm::Ext(0),
                bits,
            ));
        }
        t.insert("test", defs);
    }

    // mov
    {
        let mut defs = vec![
            d(vec![Op::Rm(1), Op::R(1)], &[0x88], ModRm::Reg, 8),
            d(vec![Op::R(1), Op::Rm(1)], &[0x8a], ModRm::Reg, 8),
        ];
        for w in WIDTHS {
            let bits = opsize_bits(w);
            defs.push(d(vec![Op::Rm(w), Op::R(w)], &[0x89], ModRm::Reg, bits));
            defs.push(d(vec![Op::R(w), Op::Rm(w)], &[0x8b], ModRm::Reg, bits));
        }
        // `B0+r`/`B8+r` load an immediate straight into a register.
        defs.push(d(vec![Op::R(1), Op::Imm(1)], &[0xb0], ModRm::None, 8).flags(PLUSREG));
        defs.push(d(vec![Op::R(2), Op::Imm(2)], &[0xb8], ModRm::None, 16).flags(PLUSREG));
        defs.push(d(vec![Op::R(4), Op::Imm(4)], &[0xb8], ModRm::None, 32).flags(PLUSREG));
        // C7 /0 sign-extends imm32 to 64 bits and is shorter than movabs, so
        // it is preferred whenever the value fits.
        defs.push(d(vec![Op::Rm(8), Op::Imm(4)], &[0xc7], ModRm::Ext(0), 64));
        defs.push(d(vec![Op::R(8), Op::Imm(8)], &[0xb8], ModRm::None, 64).flags(PLUSREG | IMM64));
        defs.push(d(vec![Op::Rm(1), Op::Imm(1)], &[0xc6], ModRm::Ext(0), 8));
        defs.push(d(vec![Op::Rm(2), Op::Imm(2)], &[0xc7], ModRm::Ext(0), 16));
        defs.push(d(vec![Op::Rm(4), Op::Imm(4)], &[0xc7], ModRm::Ext(0), 32));
        t.insert("mov", defs);

        // `movabs` always takes the full-width immediate form.
        t.insert(
            "movabs",
            vec![
                d(vec![Op::R(8), Op::Imm(8)], &[0xb8], ModRm::None, 64).flags(PLUSREG | IMM64),
                d(vec![Op::R(4), Op::Imm(4)], &[0xb8], ModRm::None, 32).flags(PLUSREG),
            ],
        );
    }

    // Sign- and zero-extending moves.
    for (mnem, op) in [("movzx", 0xb6u8), ("movsx", 0xbeu8)] {
        let mut defs = Vec::new();
        for dst in [2u8, 4, 8] {
            defs.push(d(
                vec![Op::R(dst), Op::Rm(1)],
                &[0x0f, op],
                ModRm::Reg,
                opsize_bits(dst),
            ));
        }
        for dst in [4u8, 8] {
            defs.push(d(
                vec![Op::R(dst), Op::Rm(2)],
                &[0x0f, op + 1],
                ModRm::Reg,
                opsize_bits(dst),
            ));
        }
        t.insert(mnem, defs);
    }
    // 32-to-64 sign extension has its own opcode.
    t.insert(
        "movsxd",
        vec![d(vec![Op::R(8), Op::Rm(4)], &[0x63], ModRm::Reg, 64).flags(ONLY64)],
    );

    t.insert("lea", {
        WIDTHS
            .iter()
            .map(|&w| {
                d(
                    vec![Op::R(w), Op::M(0)],
                    &[0x8d],
                    ModRm::Reg,
                    opsize_bits(w),
                )
            })
            .collect()
    });

    t.insert("xchg", {
        // `xchg rax, rax` is spelled `nop`, and `xchg ax, ax` is `66 90`;
        // both are shorter than the ModRM forms, so they come first.
        let mut defs = vec![
            d(
                vec![Op::Fixed("rax"), Op::Fixed("rax")],
                &[0x90],
                ModRm::None,
                64,
            )
            .flags(NO_REX_W),
            d(
                vec![Op::Fixed("ax"), Op::Fixed("ax")],
                &[0x90],
                ModRm::None,
                16,
            ),
        ];
        // `xchg rAX, r` has a one-byte encoding.
        for (w, acc) in [(2u8, "ax"), (4, "eax"), (8, "rax")] {
            let bits = opsize_bits(w);
            defs.push(
                d(vec![Op::Fixed(acc), Op::R(w)], &[0x90], ModRm::None, bits)
                    .flags(PLUSREG | NOTACC),
            );
            defs.push(
                d(vec![Op::R(w), Op::Fixed(acc)], &[0x90], ModRm::None, bits)
                    .flags(PLUSREG | NOTACC),
            );
        }
        defs.push(d(vec![Op::Rm(1), Op::R(1)], &[0x86], ModRm::Reg, 8));
        defs.push(d(vec![Op::R(1), Op::Rm(1)], &[0x86], ModRm::Reg, 8));
        for w in WIDTHS {
            defs.push(d(
                vec![Op::Rm(w), Op::R(w)],
                &[0x87],
                ModRm::Reg,
                opsize_bits(w),
            ));
            defs.push(d(
                vec![Op::R(w), Op::Rm(w)],
                &[0x87],
                ModRm::Reg,
                opsize_bits(w),
            ));
        }
        defs
    });

    // imul has three shapes: one-operand (into rDX:rAX), two-operand, and
    // three-operand with an immediate.
    t.insert("imul", {
        let mut defs = vec![d(vec![Op::Rm(1)], &[0xf6], ModRm::Ext(5), 8)];
        for w in WIDTHS {
            let bits = opsize_bits(w);
            let imm = if w == 2 { 2 } else { 4 };
            defs.push(d(
                vec![Op::R(w), Op::Rm(w), Op::Imm8s],
                &[0x6b],
                ModRm::Reg,
                bits,
            ));
            defs.push(d(
                vec![Op::R(w), Op::Rm(w), Op::Imm(imm)],
                &[0x69],
                ModRm::Reg,
                bits,
            ));
            defs.push(d(
                vec![Op::R(w), Op::Rm(w)],
                &[0x0f, 0xaf],
                ModRm::Reg,
                bits,
            ));
            defs.push(d(vec![Op::Rm(w)], &[0xf7], ModRm::Ext(5), bits));
        }
        defs
    });

    for (mnem, ext) in [("inc", 0u8), ("dec", 1)] {
        let mut defs = vec![d(vec![Op::Rm(1)], &[0xfe], ModRm::Ext(ext), 8)];
        // The one-byte `40+r`/`48+r` forms exist only outside long mode, where
        // those opcodes became the REX prefixes; they are shorter, so they win
        // for a bare register there. In 64-bit mode only the ModRM form is
        // encodable.
        for w in [2u8, 4] {
            defs.push(
                d(
                    vec![Op::R(w)],
                    &[0x40 + ext * 8],
                    ModRm::None,
                    opsize_bits(w),
                )
                .flags(PLUSREG | NO64),
            );
        }
        for w in WIDTHS {
            defs.push(d(vec![Op::Rm(w)], &[0xff], ModRm::Ext(ext), opsize_bits(w)));
        }
        t.insert(mnem, defs);
    }

    t.insert(
        "push",
        vec![
            d(vec![Op::Imm8s], &[0x6a], ModRm::None, 0),
            d(vec![Op::R(8)], &[0x50], ModRm::None, 64).flags(PLUSREG | DEF64),
            d(vec![Op::R(2)], &[0x50], ModRm::None, 16).flags(PLUSREG | DEF64),
            d(vec![Op::Imm(4)], &[0x68], ModRm::None, 0),
            d(vec![Op::Rm(8)], &[0xff], ModRm::Ext(6), 64).flags(DEF64),
            d(vec![Op::Rm(2)], &[0xff], ModRm::Ext(6), 16).flags(DEF64),
        ],
    );
    t.insert(
        "pop",
        vec![
            d(vec![Op::R(8)], &[0x58], ModRm::None, 64).flags(PLUSREG | DEF64),
            d(vec![Op::R(2)], &[0x58], ModRm::None, 16).flags(PLUSREG | DEF64),
            d(vec![Op::Rm(8)], &[0x8f], ModRm::Ext(0), 64).flags(DEF64),
            d(vec![Op::Rm(2)], &[0x8f], ModRm::Ext(0), 16).flags(DEF64),
        ],
    );

    // Control transfer. `jmp`'s two relative forms differ in size, which is
    // what drives branch relaxation in the layout pass.
    t.insert(
        "jmp",
        vec![
            d(vec![Op::Rel(1)], &[0xeb], ModRm::None, 0),
            d(vec![Op::Rel(4)], &[0xe9], ModRm::None, 0),
            d(vec![Op::IndirectRm(2)], &[0xff], ModRm::Ext(4), 16).flags(NO64),
            d(vec![Op::IndirectRm(4)], &[0xff], ModRm::Ext(4), 32).flags(NO64),
            d(vec![Op::IndirectRm(8)], &[0xff], ModRm::Ext(4), 0).flags(DEF64),
        ],
    );
    t.insert(
        "call",
        vec![
            d(vec![Op::Rel(4)], &[0xe8], ModRm::None, 0),
            d(vec![Op::IndirectRm(2)], &[0xff], ModRm::Ext(2), 16).flags(NO64),
            d(vec![Op::IndirectRm(4)], &[0xff], ModRm::Ext(2), 32).flags(NO64),
            d(vec![Op::IndirectRm(8)], &[0xff], ModRm::Ext(2), 0).flags(DEF64),
        ],
    );
    t.insert(
        "ret",
        vec![
            d(vec![], &[0xc3], ModRm::None, 0),
            d(vec![Op::Imm(2)], &[0xc2], ModRm::None, 0),
        ],
    );

    for &(suffix, tttn) in CONDITIONS {
        let jcc: &'static str = Box::leak(format!("j{suffix}").into_boxed_str());
        t.insert(
            jcc,
            vec![
                d(vec![Op::Rel(1)], &[0x70 + tttn], ModRm::None, 0),
                d(vec![Op::Rel(4)], &[0x0f, 0x80 + tttn], ModRm::None, 0),
            ],
        );
        let setcc: &'static str = Box::leak(format!("set{suffix}").into_boxed_str());
        t.insert(
            setcc,
            vec![d(vec![Op::Rm(1)], &[0x0f, 0x90 + tttn], ModRm::Ext(0), 8)],
        );
        let cmovcc: &'static str = Box::leak(format!("cmov{suffix}").into_boxed_str());
        t.insert(
            cmovcc,
            WIDTHS
                .iter()
                .map(|&w| {
                    d(
                        vec![Op::R(w), Op::Rm(w)],
                        &[0x0f, 0x40 + tttn],
                        ModRm::Reg,
                        opsize_bits(w),
                    )
                })
                .collect(),
        );
    }

    // Zero-operand instructions.
    for (mnem, bytes) in [
        ("nop", &[0x90u8] as &[u8]),
        ("leave", &[0xc9]),
        ("hlt", &[0xf4]),
        ("int3", &[0xcc]),
        ("ud2", &[0x0f, 0x0b]),
        ("syscall", &[0x0f, 0x05]),
        ("sysret", &[0x0f, 0x07]),
        ("cpuid", &[0x0f, 0xa2]),
        ("rdtsc", &[0x0f, 0x31]),
        ("pause", &[0xf3, 0x90]),
        ("cld", &[0xfc]),
        ("std", &[0xfd]),
        ("cli", &[0xfa]),
        ("sti", &[0xfb]),
        ("clc", &[0xf8]),
        ("stc", &[0xf9]),
        ("cmc", &[0xf5]),
        ("endbr64", &[0xf3, 0x0f, 0x1e, 0xfa]),
        ("endbr32", &[0xf3, 0x0f, 0x1e, 0xfb]),
        ("cwtl", &[0x98]),
        ("cltq", &[0x98]),
        ("cqto", &[0x99]),
        ("cltd", &[0x99]),
        ("movsb", &[0xa4]),
        ("movsq", &[0xa5]),
        ("stosb", &[0xaa]),
        ("stosq", &[0xab]),
        ("lodsb", &[0xac]),
        ("lodsq", &[0xad]),
        ("scasb", &[0xae]),
        ("scasq", &[0xaf]),
        ("cmpsb", &[0xa6]),
        ("cmpsq", &[0xa7]),
    ] {
        // `cltq`/`cqto` and the 64-bit string ops need REX.W.
        let opsize = match mnem {
            "cltq" | "cqto" | "movsq" | "stosq" | "lodsq" | "scasq" | "cmpsq" => 64,
            _ => 0,
        };
        t.insert(mnem, vec![d(vec![], bytes, ModRm::None, opsize)]);
    }
    t.insert("int", vec![d(vec![Op::Imm(1)], &[0xcd], ModRm::None, 0)]);

    // `nop` with an operand is the canonical multi-byte no-op.
    if let Some(defs) = t.get_mut("nop") {
        for w in [2u8, 4] {
            defs.push(d(
                vec![Op::Rm(w)],
                &[0x0f, 0x1f],
                ModRm::Ext(0),
                opsize_bits(w),
            ));
        }
    }

    install_more(t);
}

/// The rest of the integer instruction set: the forms real-mode and
/// 32-bit code lean on that the 64-bit-only corpora never exercised. Every
/// encoding here was checked byte for byte against NASM 2.16.03; see
/// `tools/nasm-diff`.
fn install_more(t: &mut HashMap<&'static str, Vec<Def>>) {
    // ---- push / pop, in every width and the segment registers ----------
    // 32-bit register push/pop exist only outside long mode; the 16- and
    // 64-bit forms are already in the table.
    if let Some(defs) = t.get_mut("push") {
        defs.push(d(vec![Op::R(4)], &[0x50], ModRm::None, 32).flags(PLUSREG | NO64));
        defs.push(d(vec![Op::Rm(4)], &[0xff], ModRm::Ext(6), 32).flags(NO64));
    }
    if let Some(defs) = t.get_mut("pop") {
        defs.push(d(vec![Op::R(4)], &[0x58], ModRm::None, 32).flags(PLUSREG | NO64));
        defs.push(d(vec![Op::Rm(4)], &[0x8f], ModRm::Ext(0), 32).flags(NO64));
    }
    // The segment pushes and pops: one-byte opcodes for the low four, a `0F`
    // pair for `fs`/`gs`. The low four are gone in long mode.
    for (seg, push, pop) in [
        ("es", 0x06u8, 0x07u8),
        ("cs", 0x0e, 0x00),
        ("ss", 0x16, 0x17),
        ("ds", 0x1e, 0x1f),
    ] {
        add(
            t,
            "push",
            vec![d(vec![Op::Fixed(seg)], &[push], ModRm::None, 0).flags(NO64)],
        );
        if pop != 0 {
            add(
                t,
                "pop",
                vec![d(vec![Op::Fixed(seg)], &[pop], ModRm::None, 0).flags(NO64)],
            );
        }
    }
    for (seg, hi) in [("fs", 0xa0u8), ("gs", 0xa8)] {
        add(
            t,
            "push",
            vec![d(vec![Op::Fixed(seg)], &[0x0f, hi], ModRm::None, 0)],
        );
        add(
            t,
            "pop",
            vec![d(vec![Op::Fixed(seg)], &[0x0f, hi + 1], ModRm::None, 0)],
        );
    }

    // ---- flags and registers en masse ----------------------------------
    for (mnem, op, opsize, flags) in [
        ("pusha", 0x60u8, 0u8, NO64),
        ("pushad", 0x60, 32, NO64),
        ("pushaw", 0x60, 16, NO64),
        ("popa", 0x61, 0, NO64),
        ("popad", 0x61, 32, NO64),
        ("popaw", 0x61, 16, NO64),
        ("pushf", 0x9c, 0, 0),
        ("pushfd", 0x9c, 32, NO64),
        ("pushfw", 0x9c, 16, 0),
        ("pushfq", 0x9c, 0, ONLY64),
        ("popf", 0x9d, 0, 0),
        ("popfd", 0x9d, 32, NO64),
        ("popfw", 0x9d, 16, 0),
        ("popfq", 0x9d, 0, ONLY64),
    ] {
        t.insert(
            mnem,
            vec![d(vec![], &[op], ModRm::None, opsize).flags(flags)],
        );
    }

    // ---- sign-extension of the accumulator ------------------------------
    for (mnem, op, opsize) in [
        ("cbw", 0x98u8, 16u8),
        ("cwde", 0x98, 32),
        ("cdqe", 0x98, 64),
        ("cwd", 0x99, 16),
        ("cdq", 0x99, 32),
        ("cqo", 0x99, 64),
    ] {
        add(t, mnem, vec![d(vec![], &[op], ModRm::None, opsize)]);
    }

    // ---- string operations, word and dword forms ------------------------
    // The byte and quadword forms are already installed; `movsd`/`cmpsd`
    // with no operands are the string moves, distinct from the SSE rows.
    for (base, op) in [
        ("movs", 0xa4u8),
        ("cmps", 0xa6),
        ("stos", 0xaa),
        ("lods", 0xac),
        ("scas", 0xae),
    ] {
        for (suffix, opsize) in [("w", 16u8), ("d", 32)] {
            let name: &'static str = Box::leak(format!("{base}{suffix}").into_boxed_str());
            add(t, name, vec![d(vec![], &[op + 1], ModRm::None, opsize)]);
        }
    }

    // ---- port I/O -------------------------------------------------------
    for (acc, w) in [("al", 8u8), ("ax", 16), ("eax", 32)] {
        let (op_imm, op_dx) = if w == 8 {
            (0xe4u8, 0xecu8)
        } else {
            (0xe5, 0xed)
        };
        add(
            t,
            "in",
            vec![d(
                vec![Op::Fixed(acc), Op::Imm(1)],
                &[op_imm],
                ModRm::None,
                w,
            )],
        );
        add(
            t,
            "in",
            vec![d(
                vec![Op::Fixed(acc), Op::Fixed("dx")],
                &[op_dx],
                ModRm::None,
                w,
            )],
        );
        let (op_imm, op_dx) = if w == 8 {
            (0xe6u8, 0xeeu8)
        } else {
            (0xe7, 0xef)
        };
        add(
            t,
            "out",
            vec![d(
                vec![Op::Imm(1), Op::Fixed(acc)],
                &[op_imm],
                ModRm::None,
                w,
            )],
        );
        add(
            t,
            "out",
            vec![d(
                vec![Op::Fixed("dx"), Op::Fixed(acc)],
                &[op_dx],
                ModRm::None,
                w,
            )],
        );
    }

    // ---- bit test and scan ----------------------------------------------
    for (mnem, rr, ext) in [
        ("bt", 0xa3u8, 4u8),
        ("bts", 0xab, 5),
        ("btr", 0xb3, 6),
        ("btc", 0xbb, 7),
    ] {
        let mut defs = Vec::new();
        for w in WIDTHS {
            defs.push(d(
                vec![Op::Rm(w), Op::R(w)],
                &[0x0f, rr],
                ModRm::Reg,
                opsize_bits(w),
            ));
        }
        for w in WIDTHS {
            defs.push(d(
                vec![Op::Rm(w), Op::Imm(1)],
                &[0x0f, 0xba],
                ModRm::Ext(ext),
                opsize_bits(w),
            ));
        }
        t.insert(mnem, defs);
    }
    for (mnem, op) in [("bsf", 0xbcu8), ("bsr", 0xbd)] {
        let defs = WIDTHS
            .iter()
            .map(|&w| {
                d(
                    vec![Op::R(w), Op::Rm(w)],
                    &[0x0f, op],
                    ModRm::Reg,
                    opsize_bits(w),
                )
            })
            .collect();
        t.insert(mnem, defs);
    }
    // `bswap` only has 32- and 64-bit forms.
    t.insert(
        "bswap",
        vec![
            d(vec![Op::R(4)], &[0x0f, 0xc8], ModRm::None, 32).flags(PLUSREG),
            d(vec![Op::R(8)], &[0x0f, 0xc8], ModRm::None, 64).flags(PLUSREG),
        ],
    );

    // ---- atomic and double-shift ---------------------------------------
    for (mnem, op8) in [("cmpxchg", 0xb0u8), ("xadd", 0xc0)] {
        let mut defs = vec![d(vec![Op::Rm(1), Op::R(1)], &[0x0f, op8], ModRm::Reg, 8)];
        for w in WIDTHS {
            defs.push(d(
                vec![Op::Rm(w), Op::R(w)],
                &[0x0f, op8 + 1],
                ModRm::Reg,
                opsize_bits(w),
            ));
        }
        t.insert(mnem, defs);
    }
    for (mnem, imm_op, cl_op) in [("shld", 0xa4u8, 0xa5u8), ("shrd", 0xac, 0xad)] {
        let mut defs = Vec::new();
        for w in WIDTHS {
            defs.push(d(
                vec![Op::Rm(w), Op::R(w), Op::Imm(1)],
                &[0x0f, imm_op],
                ModRm::Reg,
                opsize_bits(w),
            ));
            defs.push(d(
                vec![Op::Rm(w), Op::R(w), Op::Fixed("cl")],
                &[0x0f, cl_op],
                ModRm::Reg,
                opsize_bits(w),
            ));
        }
        t.insert(mnem, defs);
    }

    // ---- interrupt return, far return, stack frame ----------------------
    // `iret` follows the operating mode; `iretw`/`iretd`/`iretq` pin a width.
    add(t, "iret", vec![d(vec![], &[0xcf], ModRm::None, 0)]);
    t.insert("iretd", vec![d(vec![], &[0xcf], ModRm::None, 32)]);
    t.insert("iretw", vec![d(vec![], &[0xcf], ModRm::None, 16)]);
    t.insert("iretq", vec![d(vec![], &[0xcf], ModRm::None, 64)]);
    t.insert(
        "retf",
        vec![
            d(vec![], &[0xcb], ModRm::None, 0),
            d(vec![Op::Imm(2)], &[0xca], ModRm::None, 0),
        ],
    );
    t.insert(
        "enter",
        vec![d(vec![Op::Imm(2), Op::Imm(1)], &[0xc8], ModRm::None, 0)],
    );

    // ---- loops and the ecx-conditional jump -----------------------------
    for (mnem, op) in [
        ("loop", 0xe2u8),
        ("loope", 0xe1),
        ("loopz", 0xe1),
        ("loopne", 0xe0),
        ("loopnz", 0xe0),
        ("jecxz", 0xe3),
        ("jrcxz", 0xe3),
        ("jcxz", 0xe3),
    ] {
        t.insert(mnem, vec![d(vec![Op::Rel(1)], &[op], ModRm::None, 0)]);
    }

    // ---- descriptor tables and the machine-status word ------------------
    for (mnem, ext) in [
        ("sgdt", 0u8),
        ("sidt", 1),
        ("lgdt", 2),
        ("lidt", 3),
        ("smsw", 4),
        ("lmsw", 6),
    ] {
        let width = if matches!(mnem, "smsw") { 2 } else { 0 };
        t.insert(
            mnem,
            vec![d(vec![Op::M(width)], &[0x0f, 0x01], ModRm::Ext(ext), 0)],
        );
    }

    // ---- segment, control and debug register moves ----------------------
    if let Some(defs) = t.get_mut("mov") {
        // Segment moves ignore REX.W; storing honours the operand-size
        // prefix, loading does not.
        defs.push(d(vec![Op::Rm(2), Op::SReg], &[0x8c], ModRm::Reg, 16));
        defs.push(d(vec![Op::SReg, Op::Rm(2)], &[0x8e], ModRm::Reg, 0));
        // Control and debug registers: r32 outside long mode, r64 within.
        // The general register is the r/m operand (mod=11); the special
        // register fills ModRM.reg. r32 outside long mode, r64 within.
        for (reg_op, from_cr, to_cr) in [(Op::CReg, 0x20u8, 0x22u8), (Op::DReg, 0x21, 0x23)] {
            defs.push(d(vec![Op::Rm(4), reg_op], &[0x0f, from_cr], ModRm::Reg, 0).flags(NO64));
            defs.push(d(vec![reg_op, Op::Rm(4)], &[0x0f, to_cr], ModRm::Reg, 0).flags(NO64));
            defs.push(d(vec![Op::Rm(8), reg_op], &[0x0f, from_cr], ModRm::Reg, 0).flags(ONLY64));
            defs.push(d(vec![reg_op, Op::Rm(8)], &[0x0f, to_cr], ModRm::Reg, 0).flags(ONLY64));
        }
    }

    // ---- the BCD and miscellaneous one-byte opcodes ---------------------
    for (mnem, bytes, flags) in [
        ("aaa", &[0x37u8] as &[u8], NO64),
        ("daa", &[0x27], NO64),
        ("aas", &[0x3f], NO64),
        ("das", &[0x2f], NO64),
        ("into", &[0xce], NO64),
        ("xlatb", &[0xd7], 0),
        ("xlat", &[0xd7], 0),
        ("salc", &[0xd6], NO64),
        ("lahf", &[0x9f], 0),
        ("sahf", &[0x9e], 0),
        ("iretq", &[0xcf], ONLY64),
        ("wait", &[0x9b], 0),
        ("fwait", &[0x9b], 0),
        ("emms", &[0x0f, 0x77], 0),
        ("rdmsr", &[0x0f, 0x32], 0),
        ("wrmsr", &[0x0f, 0x30], 0),
        ("rdpmc", &[0x0f, 0x33], 0),
        ("sysenter", &[0x0f, 0x34], 0),
        ("sysexit", &[0x0f, 0x35], 0),
        ("clts", &[0x0f, 0x06], 0),
        ("invd", &[0x0f, 0x08], 0),
        ("wbinvd", &[0x0f, 0x09], 0),
    ] {
        add(t, mnem, vec![d(vec![], bytes, ModRm::None, 0).flags(flags)]);
    }
    // `aam`/`aad` take an optional base, defaulting to ten.
    for (mnem, op) in [("aam", 0xd4u8), ("aad", 0xd5)] {
        t.insert(
            mnem,
            vec![
                d(vec![], &[op, 0x0a], ModRm::None, 0).flags(NO64),
                d(vec![Op::Imm(1)], &[op], ModRm::None, 0).flags(NO64),
            ],
        );
    }
    // `int1`/`icebp`, and `ud2` is already present.
    add(t, "int1", vec![d(vec![], &[0xf1], ModRm::None, 0)]);
    add(t, "icebp", vec![d(vec![], &[0xf1], ModRm::None, 0)]);
}
