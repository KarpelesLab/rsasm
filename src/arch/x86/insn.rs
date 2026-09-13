//! The x86 instruction table.
//!
//! Operand patterns are written in **Intel order** (destination first). The
//! AT&T front end reverses its operands before matching, so there is only one
//! table.

use std::collections::HashMap;
use std::sync::OnceLock;

/// What an operand slot accepts. Widths are in bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Op {
    /// Register or memory of the given width.
    Rm(u8),
    /// Register only.
    R(u8),
    /// Memory only; width 0 means "any, size irrelevant" (as for `lea`).
    M(u8),
    /// Immediate encoded in this many bytes.
    Imm(u8),
    /// One immediate byte, sign-extended to the operation width.
    Imm8s,
    /// Branch displacement of this many bytes.
    Rel(u8),
    /// A specific register, by name.
    Fixed(&'static str),
    /// The literal constant 1, as in `shl $1, %eax`.
    One,
    /// Register or memory operand used indirectly (`jmp *%rax`).
    IndirectRm(u8),
}

impl Op {
    pub fn width(self) -> u8 {
        match self {
            Op::Rm(w) | Op::R(w) | Op::M(w) | Op::Imm(w) | Op::IndirectRm(w) => w,
            Op::Imm8s => 1,
            Op::Rel(w) => w,
            Op::One => 0,
            Op::Fixed(_) => 0,
        }
    }
}

/// How ModRM is formed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ModRm {
    /// No ModRM byte.
    None,
    /// `/r`: the reg field holds a register operand.
    Reg,
    /// `/digit`: the reg field is a fixed opcode extension.
    Ext(u8),
}

pub const PLUSREG: u16 = 1 << 0;
/// Operand size defaults to 64 bits in long mode (push, pop, jmp, call, ret).
pub const DEF64: u16 = 1 << 1;
/// Only encodable in 64-bit mode.
pub const ONLY64: u16 = 1 << 2;
/// Not encodable in 64-bit mode.
pub const NO64: u16 = 1 << 3;
/// The immediate is an absolute 64-bit value (`movabs`).
pub const IMM64: u16 = 1 << 4;
/// Not usable when every register operand is the accumulator. `xchg` needs
/// this: `xchg eax, eax` must not encode as `90`, which is `nop` and does not
/// clear the upper half of `rax`.
pub const NOTACC: u16 = 1 << 5;
/// A 64-bit form that needs no REX.W, because the plain opcode already means
/// what the source asked for. `xchg rax, rax` is the one case: it is spelled
/// `90`, the canonical `nop`.
pub const NO_REX_W: u16 = 1 << 6;

#[derive(Clone, Debug)]
pub struct Def {
    pub ops: Vec<Op>,
    /// Mandatory prefix emitted before REX: 0x66, 0xF2 or 0xF3.
    pub pfx: u8,
    pub opcode: Vec<u8>,
    pub modrm: ModRm,
    /// Operation width in bits: 0 (irrelevant), 8, 16, 32 or 64. Drives the
    /// 0x66 prefix and REX.W.
    pub opsize: u8,
    pub flags: u16,
}

impl Def {
    fn new(ops: Vec<Op>, opcode: Vec<u8>, modrm: ModRm, opsize: u8) -> Def {
        Def {
            ops,
            pfx: 0,
            opcode,
            modrm,
            opsize,
            flags: 0,
        }
    }

    fn flags(mut self, f: u16) -> Def {
        self.flags |= f;
        self
    }
}

fn d(ops: Vec<Op>, opcode: &[u8], modrm: ModRm, opsize: u8) -> Def {
    Def::new(ops, opcode.to_vec(), modrm, opsize)
}

/// The 16 condition codes, in `tttn` order, with every accepted spelling.
#[rustfmt::skip]
pub const CONDITIONS: &[(&str, u8)] = &[
    ("o", 0x0),
    ("no", 0x1),
    ("b", 0x2), ("c", 0x2), ("nae", 0x2),
    ("ae", 0x3), ("nb", 0x3), ("nc", 0x3),
    ("e", 0x4), ("z", 0x4),
    ("ne", 0x5), ("nz", 0x5),
    ("be", 0x6), ("na", 0x6),
    ("a", 0x7), ("nbe", 0x7),
    ("s", 0x8),
    ("ns", 0x9),
    ("p", 0xa), ("pe", 0xa),
    ("np", 0xb), ("po", 0xb),
    ("l", 0xc), ("nge", 0xc),
    ("ge", 0xd), ("nl", 0xd),
    ("le", 0xe), ("ng", 0xe),
    ("g", 0xf), ("nle", 0xf),
];

/// Widths that the generic "r/m, r" style patterns are generated for.
const WIDTHS: [u8; 3] = [2, 4, 8];

fn opsize_bits(w: u8) -> u8 {
    w * 8
}

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

    // Immediate forms. The sign-extended `imm8` encodings come first so the
    // matcher prefers them whenever the value fits.
    defs.push(d(vec![Op::Rm(1), Op::Imm(1)], &[0x80], ModRm::Ext(ext), 8));
    for w in WIDTHS {
        let bits = opsize_bits(w);
        defs.push(d(
            vec![Op::Rm(w), Op::Imm8s],
            &[0x83],
            ModRm::Ext(ext),
            bits,
        ));
    }
    // `op al, imm8` and `op eAX, imm32` are one byte shorter than the ModRM
    // forms, so they are tried before them but after imm8-sign-extended.
    defs.push(d(
        vec![Op::Fixed("al"), Op::Imm(1)],
        &[base + 4],
        ModRm::None,
        8,
    ));
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

fn build() -> HashMap<&'static str, Vec<Def>> {
    let mut t: HashMap<&'static str, Vec<Def>> = HashMap::new();

    alu_group(&mut t, "add", 0x00, 0);
    alu_group(&mut t, "or", 0x08, 1);
    alu_group(&mut t, "adc", 0x10, 2);
    alu_group(&mut t, "sbb", 0x18, 3);
    alu_group(&mut t, "and", 0x20, 4);
    alu_group(&mut t, "sub", 0x28, 5);
    alu_group(&mut t, "xor", 0x30, 6);
    alu_group(&mut t, "cmp", 0x38, 7);

    shift_group(&mut t, &["rol"], 0);
    shift_group(&mut t, &["ror"], 1);
    shift_group(&mut t, &["rcl"], 2);
    shift_group(&mut t, &["rcr"], 3);
    shift_group(&mut t, &["shl", "sal"], 4);
    shift_group(&mut t, &["shr"], 5);
    shift_group(&mut t, &["sar"], 7);

    unary_group(&mut t, "not", 2);
    unary_group(&mut t, "neg", 3);
    unary_group(&mut t, "mul", 4);
    unary_group(&mut t, "div", 6);
    unary_group(&mut t, "idiv", 7);

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
            d(vec![Op::IndirectRm(8)], &[0xff], ModRm::Ext(4), 0).flags(DEF64),
        ],
    );
    t.insert(
        "call",
        vec![
            d(vec![Op::Rel(4)], &[0xe8], ModRm::None, 0),
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

    t
}

pub fn table() -> &'static HashMap<&'static str, Vec<Def>> {
    static TABLE: OnceLock<HashMap<&'static str, Vec<Def>>> = OnceLock::new();
    TABLE.get_or_init(build)
}

pub fn lookup(mnemonic: &str) -> Option<&'static [Def]> {
    table().get(mnemonic).map(|v| v.as_slice())
}

/// True if `name` names an instruction, ignoring AT&T size suffixes.
pub fn is_mnemonic(name: &str) -> bool {
    table().contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_covers_the_expected_groups() {
        for m in [
            "add", "sub", "mov", "lea", "jmp", "je", "setne", "cmovg", "imul", "shl", "ret",
        ] {
            assert!(is_mnemonic(m), "missing `{m}`");
        }
        assert!(!is_mnemonic("nosuchinsn"));
    }

    #[test]
    fn jmp_offers_a_short_and_a_near_form() {
        let defs = lookup("jmp").unwrap();
        assert!(defs.iter().any(|x| x.ops == [Op::Rel(1)]));
        assert!(defs.iter().any(|x| x.ops == [Op::Rel(4)]));
    }

    #[test]
    fn alu_prefers_sign_extended_imm8() {
        let defs = lookup("add").unwrap();
        let i8_pos = defs
            .iter()
            .position(|x| x.ops == [Op::Rm(4), Op::Imm8s])
            .unwrap();
        let i32_pos = defs
            .iter()
            .position(|x| x.ops == [Op::Rm(4), Op::Imm(4)])
            .unwrap();
        assert!(i8_pos < i32_pos, "imm8 form must be matched first");
    }
}
