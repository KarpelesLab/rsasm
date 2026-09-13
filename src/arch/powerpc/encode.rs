//! Turning a matched instruction definition into its 32-bit word.
//!
//! Everything here works on one word. Bit positions are given the way the
//! PowerPC manuals give them — numbered from the most significant bit, so
//! "bits 16:20" is the five-bit field whose least significant bit is word bit
//! 11 — and `at` does that conversion once, so the rest of the file can name
//! fields the way the manual does.

use super::insn::{Def, F, OPT1, OPTL, Resolved, Rot, Rot2};
use super::operand::{Mem, Operand, OperandKind, Value};
use super::reg::{RegClass, describe};
use super::reloc;
use crate::arch::{AsmCtx, Endian};
use crate::expr::{ExprKind, ExprRef};
use crate::section::{Fixup, FixupKind, Variant};
use crate::source::Span;

/// The shift that puts a field whose manual bit range ends at `last` — counted
/// from the most significant bit of the word — in the right place.
const fn at(last: u32) -> u32 {
    31 - last
}

const RT: u32 = at(10); // RT / RS / BO / TO / crbD
const RA: u32 = at(15); // RA / BI / crbA
const RB: u32 = at(20); // RB / SH / crbB
const FRC: u32 = at(25); // FRC, and MB of an M-form rotate
const ME: u32 = at(30);
const CRFD: u32 = at(8);
const CRFS: u32 = at(13);
const L_BIT: u32 = at(10);
const BH: u32 = at(20); // two bits at 19:20
const CRM: u32 = at(19); // eight bits at 12:19
const FLM: u32 = at(14); // eight bits at 7:14
const SPRF: u32 = at(20); // ten bits at 11:20
const LEV: u32 = at(26); // seven bits at 20:26

/// The `o` suffix sets OE, bit 21.
const OE_BIT: u32 = 1 << at(21);

pub struct Encoder<'c, 'a> {
    cx: &'c mut AsmCtx<'a>,
    endian: Endian,
    word: u32,
    fixups: Vec<Fixup>,
    failed: bool,
}

impl<'c, 'a> Encoder<'c, 'a> {
    pub fn new(cx: &'c mut AsmCtx<'a>, endian: Endian) -> Encoder<'c, 'a> {
        Encoder {
            cx,
            endian,
            word: 0,
            fixups: Vec::new(),
            failed: false,
        }
    }

    /// Encodes one instruction, or reports why it cannot be encoded.
    pub fn encode(mut self, r: &Resolved, ops: &[Operand], span: Span) -> Option<Variant> {
        self.word = r.def.word;
        if r.rc {
            self.word |= 1;
        }
        if r.oe {
            self.word |= OE_BIT;
        }

        let groups = self.split_operands(r.def, ops, span)?;
        for (f, group) in groups {
            self.field(f, group);
        }
        if self.failed {
            return None;
        }
        Some(Variant {
            bytes: self.endian.bytes(self.word as u64, 4),
            fixups: self.fixups,
        })
    }

    /// Hands each pattern field the operands it consumes, honouring the forms
    /// whose first or last operand may be left out.
    fn split_operands<'o>(
        &mut self,
        def: &Def,
        ops: &'o [Operand],
        span: Span,
    ) -> Option<Vec<(F, &'o [Operand])>> {
        let full: usize = def.ops.iter().copied().map(arity).sum();
        let short = full.saturating_sub(1);
        let pat = if ops.len() == full {
            def.ops
        } else if ops.len() == short && def.flags & OPT1 != 0 {
            def.ops.split_first().map_or(&[][..], |(_, rest)| rest)
        } else if ops.len() == short && def.flags & OPTL != 0 {
            def.ops.split_last().map_or(&[][..], |(_, rest)| rest)
        } else {
            let want = if def.flags & (OPT1 | OPTL) != 0 {
                format!("{short} or {full}")
            } else {
                full.to_string()
            };
            self.cx.error(
                span,
                format!(
                    "`{}` takes {want} operand(s), but {} were given",
                    def.name,
                    ops.len()
                ),
            );
            return None;
        };

        let mut out = Vec::with_capacity(pat.len());
        let mut rest = ops;
        for f in pat {
            let (group, tail) = rest.split_at(arity(*f).min(rest.len()));
            out.push((*f, group));
            rest = tail;
        }
        Some(out)
    }

    fn field(&mut self, f: F, group: &[Operand]) {
        let Some(op) = group.first() else {
            // `split_operands` guarantees the counts line up.
            return;
        };
        match f {
            F::Rt => {
                let v = self.gpr(op);
                self.put(RT, v);
            }
            F::Ra => {
                let v = self.gpr(op);
                self.put(RA, v);
            }
            F::Rb => {
                let v = self.gpr(op);
                self.put(RB, v);
            }
            F::RtRb => {
                let v = self.gpr(op);
                self.put(RT, v);
                self.put(RB, v);
            }
            F::Ft => {
                let v = self.fpr(op);
                self.put(RT, v);
            }
            F::Fa => {
                let v = self.fpr(op);
                self.put(RA, v);
            }
            F::Fb => {
                let v = self.fpr(op);
                self.put(RB, v);
            }
            F::Fc => {
                let v = self.fpr(op);
                self.put(FRC, v);
            }
            F::Simm => self.imm16(op, Range16::Signed),
            F::SimmU => self.imm16(op, Range16::Either),
            F::Uimm => self.imm16(op, Range16::Unsigned),
            F::NegSimm => match self.constant(op, "immediate") {
                // `subi rD, rA, v` is `addi rD, rA, -v`, so the range is the
                // signed one mirrored.
                Some(v) if (-32767..=32768).contains(&v) => self.word |= (-v) as u32 & 0xffff,
                Some(v) => self.reject(
                    op,
                    format!("immediate {v} is out of range: must be -32767 to 32768"),
                ),
                None => {}
            },
            F::Sh5 => {
                let v = self.small(op, 31, "shift count");
                self.put(RB, v);
            }
            F::Mb5 => {
                let v = self.small(op, 31, "mask begin");
                self.put(FRC, v);
            }
            F::Me5 => {
                let v = self.small(op, 31, "mask end");
                self.put(ME, v);
            }
            F::Sh6 => {
                if let Some(v) = self.small(op, 63, "shift count") {
                    self.word |= md_sh(v);
                }
            }
            F::M6 => {
                if let Some(v) = self.small(op, 63, "mask bound") {
                    self.word |= md_m(v);
                }
            }
            F::CrfD => {
                let v = self.crf(op);
                self.put(CRFD, v);
            }
            F::CrfS => {
                let v = self.crf(op);
                self.put(CRFS, v);
            }
            F::CrbD => {
                let v = self.small(op, 31, "CR bit");
                self.put(RT, v);
            }
            F::CrbA => {
                let v = self.small(op, 31, "CR bit");
                self.put(RA, v);
            }
            F::CrbB => {
                let v = self.small(op, 31, "CR bit");
                self.put(RB, v);
            }
            F::CrbAB => {
                let v = self.small(op, 31, "CR bit");
                self.put(RA, v);
                self.put(RB, v);
            }
            F::CrbAll => {
                let v = self.small(op, 31, "CR bit");
                self.put(RT, v);
                self.put(RA, v);
                self.put(RB, v);
            }
            // The definition already holds the BI of the condition *within* a
            // CR field; naming a field moves it up by four bits per field.
            F::CrfBi => {
                if let Some(n) = self.crf(op) {
                    self.word |= (n * 4) << RA;
                }
            }
            F::Bo => {
                let v = self.small(op, 31, "BO");
                self.put(RT, v);
            }
            F::Bi => {
                let v = self.small(op, 31, "BI");
                self.put(RA, v);
            }
            F::Bh => {
                let v = self.small(op, 3, "branch hint");
                self.put(BH, v);
            }
            F::To => {
                let v = self.small(op, 31, "trap condition");
                self.put(RT, v);
            }
            F::Crm => {
                let v = self.small(op, 255, "CR mask");
                self.put(CRM, v);
            }
            F::Flm => {
                let v = self.small(op, 255, "FPSCR field mask");
                self.put(FLM, v);
            }
            F::L => {
                let v = self.small(op, 1, "comparison width");
                self.put(L_BIT, v);
            }
            F::Lev => {
                let v = self.small(op, 127, "system call level");
                self.put(LEV, v);
            }
            F::Spr => {
                if let Some(n) = self.spr(op) {
                    // The ten-bit SPR number is stored with its two five-bit
                    // halves swapped, a quirk inherited from POWER.
                    self.word |= (((n & 0x1f) << 5) | (n >> 5)) << SPRF;
                }
            }
            F::MemD => self.mem(op, false),
            F::MemDS => self.mem(op, true),
            F::Rel24 => self.branch(op, 26, true),
            F::Abs24 => self.branch(op, 26, false),
            F::Rel14 => self.branch(op, 16, true),
            F::Abs14 => self.branch(op, 16, false),
            F::RotN(kind) => {
                if let Some(n) = self.constant(op, "shift count") {
                    let r = rot1(kind, n);
                    self.rotate(op, r);
                }
            }
            F::RotNB(kind) => {
                let (Some(n), Some(b)) = (
                    self.constant(op, "field width"),
                    group
                        .get(1)
                        .and_then(|o| self.constant(o, "starting bit position")),
                ) else {
                    return;
                };
                let r = rot2(kind, n, b);
                self.rotate(op, r);
            }
        }
    }

    fn put(&mut self, shift: u32, value: Option<u32>) {
        if let Some(v) = value {
            self.word |= v << shift;
        }
    }

    fn rotate(&mut self, op: &Operand, r: Result<RotFields, String>) {
        match r {
            Ok(RotFields::M { sh, mb, me }) => {
                self.word |= (sh << RB) | (mb << FRC) | (me << ME);
            }
            Ok(RotFields::Md { sh, m }) => self.word |= md_sh(sh) | md_m(m),
            Err(msg) => self.reject(op, msg),
        }
    }

    // ---- operand readers --------------------------------------------------

    fn reject(&mut self, op: &Operand, msg: impl Into<String>) {
        self.cx.error(op.span, msg);
        self.failed = true;
    }

    fn expected(&mut self, op: &Operand, what: &str) {
        let found = op.describe();
        self.reject(op, format!("expected {what}, found {found}"));
    }

    /// The plain value of an operand; a memory reference has none.
    fn plain(op: &Operand) -> Option<Value> {
        match op.kind {
            OperandKind::Value(v) => Some(v),
            OperandKind::Mem(_) => None,
        }
    }

    /// A register operand, written either as a name of `class` or as the bare
    /// number that PowerPC assembly usually uses.
    fn reg_in(&mut self, op: &Operand, class: RegClass, what: &str) -> Option<u32> {
        match Self::plain(op) {
            Some(Value::Reg(r)) if r.class == class => Some(r.num as u32),
            Some(Value::Reg(r)) => {
                let name = describe(r);
                self.reject(op, format!("`{name}` is not {what}"));
                None
            }
            Some(Value::Expr(e)) => match self.cx.constant(e) {
                Some(v) if (0..=31).contains(&v) => Some(v as u32),
                Some(v) => {
                    self.reject(
                        op,
                        format!("register number {v} is out of range: must be 0 to 31"),
                    );
                    None
                }
                None => {
                    self.reject(op, format!("expected {what}"));
                    None
                }
            },
            None => {
                self.expected(op, what);
                None
            }
        }
    }

    fn gpr(&mut self, op: &Operand) -> Option<u32> {
        self.reg_in(op, RegClass::Gpr, "a general-purpose register")
    }

    fn fpr(&mut self, op: &Operand) -> Option<u32> {
        self.reg_in(op, RegClass::Fpr, "a floating-point register")
    }

    /// A CR field number, written `cr3` or `3`.
    fn crf(&mut self, op: &Operand) -> Option<u32> {
        match Self::plain(op) {
            Some(Value::Reg(r)) if r.class == RegClass::Cr => Some(r.num as u32),
            Some(Value::Expr(e)) => match self.cx.constant(e) {
                Some(v) if (0..=7).contains(&v) => Some(v as u32),
                Some(v) => {
                    self.reject(
                        op,
                        format!("condition register field {v} is out of range: must be 0 to 7"),
                    );
                    None
                }
                None => {
                    self.reject(op, "expected a condition register field");
                    None
                }
            },
            _ => {
                self.expected(op, "a condition register field");
                None
            }
        }
    }

    /// An SPR number, written `lr`, `ctr`, `xer` or as a number.
    fn spr(&mut self, op: &Operand) -> Option<u32> {
        match Self::plain(op) {
            Some(Value::Reg(r)) if r.class == RegClass::Spr => Some(r.num as u32),
            Some(Value::Expr(e)) => match self.cx.constant(e) {
                Some(v) if (0..=1023).contains(&v) => Some(v as u32),
                Some(v) => {
                    self.reject(
                        op,
                        format!("special-purpose register {v} is out of range: must be 0 to 1023"),
                    );
                    None
                }
                None => {
                    self.reject(op, "expected a special-purpose register");
                    None
                }
            },
            _ => {
                self.expected(op, "a special-purpose register");
                None
            }
        }
    }

    /// A small unsigned constant field.
    fn small(&mut self, op: &Operand, max: i64, what: &str) -> Option<u32> {
        match self.constant(op, what) {
            Some(v) if (0..=max).contains(&v) => Some(v as u32),
            Some(v) => {
                self.reject(
                    op,
                    format!("{what} {v} is out of range: must be 0 to {max}"),
                );
                None
            }
            None => None,
        }
    }

    fn constant(&mut self, op: &Operand, what: &str) -> Option<i64> {
        match Self::plain(op) {
            Some(Value::Expr(e)) => match self.cx.constant(e) {
                Some(v) => Some(v),
                None => {
                    self.reject(op, format!("{what} must be a constant"));
                    None
                }
            },
            _ => {
                self.expected(op, &format!("a constant {what}"));
                None
            }
        }
    }

    // ---- immediates, displacements and branch targets ---------------------

    /// A 16-bit immediate in bits 16:31, resolved now or left to a fixup.
    fn imm16(&mut self, op: &Operand, range: Range16) {
        let Some(Value::Expr(e)) = Self::plain(op) else {
            self.expected(op, "an immediate");
            return;
        };
        match self.halfword_value(op, e) {
            Folded::Invalid => {}
            Folded::Truncated(v) => self.word |= v as u32 & 0xffff,
            Folded::Symbolic => self.halfword_fixup(e, op.span, false),
            Folded::Plain(v) if range.bounds().contains(&v) => self.word |= v as u32 & 0xffff,
            Folded::Plain(v) => {
                let b = range.bounds();
                self.reject(
                    op,
                    format!(
                        "immediate {v} is out of range: must be {} to {}",
                        b.start(),
                        b.end()
                    ),
                );
            }
        }
    }

    /// A `d(rA)` reference: the base into RA, the displacement into the low
    /// halfword. A DS-form displacement owns only 14 of those 16 bits, so it
    /// must be a multiple of four and is merged rather than overwritten.
    fn mem(&mut self, op: &Operand, ds: bool) {
        let OperandKind::Mem(Mem {
            disp,
            base,
            base_span,
        }) = op.kind
        else {
            self.expected(op, "a memory operand of the form `d(rA)`");
            return;
        };
        let base_op = Operand {
            kind: OperandKind::Value(base),
            span: base_span,
        };
        let v = self.gpr(&base_op);
        self.put(RA, v);

        let Some(e) = disp else { return };
        let v = match self.halfword_value(op, e) {
            Folded::Invalid => return,
            Folded::Symbolic => return self.halfword_fixup(e, op.span, ds),
            Folded::Plain(v) if !Range16::Signed.bounds().contains(&v) => {
                return self.reject(
                    op,
                    format!("displacement {v} is out of range: must be -32768 to 32767"),
                );
            }
            Folded::Plain(v) | Folded::Truncated(v) => v,
        };
        if ds && v % 4 != 0 {
            return self.reject(
                op,
                format!("displacement {v} must be a multiple of 4 in a DS-form instruction"),
            );
        }
        self.word |= v as u32 & 0xffff;
    }

    /// Reads a value destined for the low halfword, applying an `@l`, `@h` or
    /// `@ha` written on a constant.
    ///
    /// The core treats relocation modifiers as annotations that only choose
    /// a relocation, so a constant reaches the backend unmodified; without
    /// this, `lis 3, 0x12348000@ha` would be rejected and `lis 3, 0x8000@ha`
    /// silently encoded as 0x8000 rather than 1.
    fn halfword_value(&mut self, op: &Operand, e: ExprRef) -> Folded {
        let top = match &self.cx.exprs.get(e).kind {
            ExprKind::Modifier(n, inner) => Some((self.cx.name(*n).to_ascii_lowercase(), *inner)),
            _ => None,
        };
        let Some((name, inner)) = top else {
            return match self.cx.constant(e) {
                // A modifier buried inside arithmetic on a constant has no
                // meaning the linker could supply either.
                Some(_) if self.modifier(e).is_some() => {
                    self.reject(op, "a relocation modifier must apply to the whole operand");
                    Folded::Invalid
                }
                Some(v) => Folded::Plain(v),
                None => Folded::Symbolic,
            };
        };
        let Some(v) = self.cx.constant(inner) else {
            return Folded::Symbolic;
        };
        let half = match name.as_str() {
            "l" => v,
            "h" | "hi" => v >> 16,
            // `@ha` pre-compensates for the low half being sign-extended when
            // it is added back, which is what `lis` + `addi` pairs need.
            "ha" | "h_a" => v.wrapping_add(0x8000) >> 16,
            other => {
                self.reject(
                    op,
                    format!("relocation modifier `@{other}` is not supported here"),
                );
                return Folded::Invalid;
            }
        };
        Folded::Truncated(half & 0xffff)
    }

    /// A relocation against the low halfword of the instruction word.
    ///
    /// ELF puts `r_offset` on the halfword itself rather than on the
    /// instruction, so on a big-endian target the fixup starts two bytes in
    /// and on a little-endian one at the instruction's first byte.
    fn halfword_fixup(&mut self, e: ExprRef, span: Span, ds: bool) {
        let reloc = match (self.modifier(e).as_deref(), ds) {
            (None, false) => reloc::ADDR16,
            (None, true) => reloc::ADDR16_DS,
            (Some("l"), false) => reloc::ADDR16_LO,
            (Some("l"), true) => reloc::ADDR16_LO_DS,
            (Some("h" | "hi"), false) => reloc::ADDR16_HI,
            (Some("ha" | "h_a"), false) => reloc::ADDR16_HA,
            (Some(other), _) => {
                self.cx.error(
                    span,
                    format!("relocation modifier `@{other}` is not supported here"),
                );
                self.failed = true;
                return;
            }
        };
        let mut kind = FixupKind::data(2).with_reloc(reloc);
        // A DS-form halfword cannot be overwritten whole: its low two bits
        // belong to the opcode.
        if ds {
            kind = kind.with_field(16, 4).scatter(ds_field);
        }
        self.fixups.push(Fixup {
            offset: if self.endian == Endian::Big { 2 } else { 0 },
            expr: e,
            kind,
            span,
        });
    }

    /// A branch target. The fixup covers the whole instruction word, since the
    /// AA and LK bits share the displacement field's bytes.
    fn branch(&mut self, op: &Operand, bits: u8, pcrel: bool) {
        let Some(Value::Expr(e)) = Self::plain(op) else {
            self.expected(op, "a branch target");
            return;
        };
        // The core would quietly fall back to REL24 for a modifier it does
        // not know, and `bl foo@plt` meaning a plain REL24 is exactly the kind
        // of wrong answer that links and then fails at run time.
        if let Some(m) = self.modifier(e) {
            self.reject(
                op,
                format!("relocation modifier `@{m}` is not supported on a branch target"),
            );
            return;
        }
        let (scatter, rel, abs): (fn(u64, i64) -> u64, u32, u32) = if bits == 26 {
            (i_form, reloc::REL24, reloc::ADDR24)
        } else {
            (b_form, reloc::REL14, reloc::ADDR14)
        };
        let kind = if pcrel {
            FixupKind::pcrel(4, 0).with_reloc(rel)
        } else {
            FixupKind::data(4).signed().with_reloc(abs)
        };
        self.fixups.push(Fixup {
            offset: 0,
            expr: e,
            kind: kind.with_field(bits, 4).scatter(scatter),
            span: op.span,
        });
    }

    /// The `@`-modifier applied anywhere in an expression, lowercased.
    fn modifier(&self, e: ExprRef) -> Option<String> {
        match &self.cx.exprs.get(e).kind {
            ExprKind::Modifier(n, _) => Some(self.cx.name(*n).to_ascii_lowercase()),
            ExprKind::Unary(_, a) => self.modifier(*a),
            ExprKind::Binary(_, a, b) => self.modifier(*a).or_else(|| self.modifier(*b)),
            _ => None,
        }
    }
}

/// How many operands a pattern field consumes. Only the two-immediate rotate
/// mnemonics take more than one.
fn arity(f: F) -> usize {
    match f {
        F::RotNB(_) => 2,
        _ => 1,
    }
}

/// A halfword operand after constant folding.
enum Folded {
    /// An ordinary constant, still subject to the field's range check.
    Plain(i64),
    /// A constant cut down to 16 bits by `@l`/`@h`/`@ha`, which fits by
    /// construction.
    Truncated(i64),
    /// Not known until link time: needs a relocation.
    Symbolic,
    /// Already diagnosed.
    Invalid,
}

/// Which spellings a 16-bit immediate field accepts.
#[derive(Copy, Clone)]
enum Range16 {
    Signed,
    Unsigned,
    /// Either reading. `lis 3, 0xffff` and `lis 3, -1` are the same word, and
    /// sources loading the high half of an address rely on the unsigned
    /// spelling; GNU as and llvm-mc both accept it there and only there.
    Either,
}

impl Range16 {
    fn bounds(self) -> std::ops::RangeInclusive<i64> {
        match self {
            Range16::Signed => -32768..=32767,
            Range16::Unsigned => 0..=65535,
            Range16::Either => -32768..=65535,
        }
    }
}

/// I-form: a 24-bit field of word offsets in bits 6:29, leaving the AA and LK
/// bits at the bottom of the word untouched.
fn i_form(word: u64, v: i64) -> u64 {
    (word & 0xfc00_0003) | (((v >> 2) as u64 & 0x00ff_ffff) << 2)
}

/// B-form: the same idea with a 14-bit field in bits 16:29, so the BO and BI
/// fields above it survive as well.
fn b_form(word: u64, v: i64) -> u64 {
    (word & 0xffff_0003) | (((v >> 2) as u64 & 0x3fff) << 2)
}

/// DS-form displacement: 14 bits of a halfword whose low two bits are opcode.
fn ds_field(half: u64, v: i64) -> u64 {
    (half & 0x3) | (v as u64 & 0xfffc)
}

/// The six-bit SH of an MD- or XS-form rotate is split in two: its low five
/// bits go where the M-form's whole SH goes (16:20), and its top bit lands
/// alone in bit 30, immediately above Rc.
fn md_sh(sh: u32) -> u32 {
    ((sh & 0x1f) << RB) | ((sh >> 5) << ME)
}

/// The six-bit MB or ME of an MD-form rotate is split the other way round: its
/// low five bits occupy 21:25 and its top bit sits in bit 26. Read as plain
/// binary the field is therefore `m[1:5] || m[0]`, not `m`.
fn md_m(m: u32) -> u32 {
    ((m & 0x1f) << FRC) | ((m >> 5) << at(26))
}

/// The rotate fields an extended mnemonic expands to.
enum RotFields {
    /// 32-bit rotates: SH, MB and ME, five bits each.
    M { sh: u32, mb: u32, me: u32 },
    /// 64-bit rotates: SH and the one mask bound the form has, six bits each.
    Md { sh: u32, m: u32 },
}

/// Expands an extended rotate that takes a single shift amount.
///
/// Each of these is one `rlwinm`, `rldicl` or `rldicr` whose mask is a
/// function of the shift: `slwi rA, rS, n` keeps the bits that did not fall
/// off the left end, `clrlwi` rotates by nothing and masks, and so on. Which
/// base instruction is used is fixed by the table entry; this only computes
/// the fields.
fn rot1(kind: Rot, n: i64) -> Result<RotFields, String> {
    use Rot::*;
    let wide = matches!(kind, Sldi | Srdi | Clrldi | Clrrdi | Rotldi | Rotrdi);
    let w: i64 = if wide { 64 } else { 32 };
    if !(0..w).contains(&n) {
        return Err(format!(
            "shift count {n} is out of range: must be 0 to {}",
            w - 1
        ));
    }
    let (n, w) = (n as u32, w as u32);
    Ok(match kind {
        // A left shift by n is a rotate by n keeping bits 0..=31-n; the mask
        // is what stops the bits that rotated round from coming back in.
        Slwi => RotFields::M {
            sh: n,
            mb: 0,
            me: 31 - n,
        },
        // A right shift is a left rotate by 32-n. The modulo matters only for
        // n = 0, where a rotate by 32 does not fit the five-bit field.
        Srwi => RotFields::M {
            sh: (32 - n) % 32,
            mb: n,
            me: 31,
        },
        Clrlwi => RotFields::M {
            sh: 0,
            mb: n,
            me: 31,
        },
        Clrrwi => RotFields::M {
            sh: 0,
            mb: 0,
            me: 31 - n,
        },
        Rotlwi => RotFields::M {
            sh: n,
            mb: 0,
            me: 31,
        },
        Rotrwi => RotFields::M {
            sh: (32 - n) % 32,
            mb: 0,
            me: 31,
        },
        // The 64-bit forms carry only one mask bound. Whether it is read as MB
        // or as ME is decided by the opcode the table entry names: `rldicl`
        // masks from the left, `rldicr` from the right.
        Sldi => RotFields::Md { sh: n, m: 63 - n },
        Srdi => RotFields::Md {
            sh: (w - n) % w,
            m: n,
        },
        Clrldi => RotFields::Md { sh: 0, m: n },
        Clrrdi => RotFields::Md { sh: 0, m: 63 - n },
        Rotldi => RotFields::Md { sh: n, m: 0 },
        Rotrdi => RotFields::Md {
            sh: (w - n) % w,
            m: 0,
        },
    })
}

/// Expands an extended rotate that names a field of `n` bits starting at bit
/// `b`, counting from the most significant bit as the ISA does.
fn rot2(kind: Rot2, n: i64, b: i64) -> Result<RotFields, String> {
    use Rot2::*;
    let wide = matches!(kind, Extldi | Extrdi | Insrdi);
    let w: i64 = if wide { 64 } else { 32 };
    if !(1..=w).contains(&n) {
        return Err(format!("field width {n} is out of range: must be 1 to {w}"));
    }
    if !(0..w).contains(&b) {
        return Err(format!(
            "bit position {b} is out of range: must be 0 to {}",
            w - 1
        ));
    }
    if n + b > w {
        return Err(format!(
            "a {n}-bit field starting at bit {b} runs past the end of a {w}-bit register"
        ));
    }
    let (n, b, w) = (n as u32, b as u32, w as u32);
    Ok(match kind {
        Extlwi => RotFields::M {
            sh: b,
            mb: 0,
            me: n - 1,
        },
        Extrwi => RotFields::M {
            sh: (b + n) % 32,
            mb: 32 - n,
            me: 31,
        },
        Inslwi => RotFields::M {
            sh: (32 - b) % 32,
            mb: b,
            me: b + n - 1,
        },
        Insrwi => RotFields::M {
            sh: (32 - (b + n)) % 32,
            mb: b,
            me: b + n - 1,
        },
        Extldi => RotFields::Md { sh: b, m: n - 1 },
        Extrdi => RotFields::Md {
            sh: (b + n) % w,
            m: 64 - n,
        },
        Insrdi => RotFields::Md {
            sh: (w - (b + n)) % w,
            m: b,
        },
    })
}

/// Padding for `.align` in code: PowerPC's canonical no-op is `ori 0, 0, 0`.
///
/// A run of padding that is not a whole number of words can only arise after
/// sub-word data, so the odd bytes are the tail of a partial word and go
/// first, as zeros; the whole words that follow are real no-ops and stay
/// executable.
pub fn nop_bytes(endian: Endian, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len % 4];
    let word = endian.bytes(0x6000_0000, 4);
    while out.len() + 4 <= len {
        out.extend_from_slice(&word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md_fields_split_the_way_the_isa_describes() {
        // `rldicl 3, 4, 40, 33`: SH 40 is 0b101000, MB 33 is 0b100001.
        assert_eq!(md_sh(40), (8 << 11) | 2);
        assert_eq!(md_m(33), (1 << 6) | (1 << 5));
        // Values below 32 keep the plain layout of the 32-bit forms.
        assert_eq!(md_sh(5), 5 << 11);
        assert_eq!(md_m(6), 6 << 6);
    }

    #[test]
    fn branch_scatter_keeps_the_opcode_and_link_bits() {
        // `bl` is 0x48000001; a +4096 displacement must not disturb LK.
        assert_eq!(i_form(0x4800_0001, 4096), 0x4800_1001);
        assert_eq!(i_form(0x4800_0000, -4), 0x4bff_fffc);
        // `beq` is 0x41820000; BO and BI must survive.
        assert_eq!(b_form(0x4182_0000, 256), 0x4182_0100);
        assert_eq!(b_form(0x4182_0000, -8), 0x4182_fff8);
    }

    #[test]
    fn ds_displacement_leaves_the_opcode_bits_alone() {
        // `ldu` carries a 1 in the low two bits of its displacement halfword.
        assert_eq!(ds_field(0x0001, 16), 0x0011);
        assert_eq!(ds_field(0x0001, -8), 0xfff9);
    }

    #[test]
    fn nop_padding_is_whole_words_of_ori_zero() {
        assert_eq!(
            nop_bytes(Endian::Big, 8),
            vec![0x60, 0, 0, 0, 0x60, 0, 0, 0]
        );
        assert_eq!(nop_bytes(Endian::Little, 4), vec![0, 0, 0, 0x60]);
        // An odd tail belongs to the partial word before it, so it leads.
        assert_eq!(nop_bytes(Endian::Big, 2), vec![0, 0]);
        assert_eq!(nop_bytes(Endian::Big, 7), vec![0, 0, 0, 0x60, 0, 0, 0]);
    }

    #[test]
    fn extended_rotates_match_their_definitions() {
        // `slwi 3, 4, 5` is `rlwinm 3, 4, 5, 0, 26`.
        let RotFields::M { sh, mb, me } = rot1(Rot::Slwi, 5).expect("valid") else {
            panic!("32-bit form")
        };
        assert_eq!((sh, mb, me), (5, 0, 26));
        // `srdi 3, 4, 5` is `rldicl 3, 4, 59, 5`.
        let RotFields::Md { sh, m } = rot1(Rot::Srdi, 5).expect("valid") else {
            panic!("64-bit form")
        };
        assert_eq!((sh, m), (59, 5));
        // `insrdi 3, 4, 5, 6` is `rldimi 3, 4, 53, 6`.
        let RotFields::Md { sh, m } = rot2(Rot2::Insrdi, 5, 6).expect("valid") else {
            panic!("64-bit form")
        };
        assert_eq!((sh, m), (53, 6));
        assert!(rot1(Rot::Slwi, 32).is_err());
        assert!(rot2(Rot2::Extlwi, 0, 0).is_err());
        assert!(rot2(Rot2::Extlwi, 8, 28).is_err());
    }
}
