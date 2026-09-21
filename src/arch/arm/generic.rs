//! The table-driven encoder, for every instruction the two hand-written
//! encoders do not: the saturating and packing group, the parallel
//! arithmetic, the bitfield moves, the load/store exclusives, the halfword
//! and dual multiplies, the divides, the hint and barrier space, the
//! coprocessor instructions and the system forms.
//!
//! Each mnemonic is a run of [`Form`]s from [`super::table`], which is
//! generated from GNU's own disassembler tables. A form is an opcode word
//! and a list of [`Op`]s saying what its operands are and where their bits
//! go, so encoding is a walk down that list. The forms of one mnemonic are
//! sorted narrow Thumb first, then wide Thumb, then A32, and the first that
//! fits wins — which is what picks a Thumb instruction's width, and what
//! `.n` and `.w` narrow the choice of.

use super::insn::{AL, Width};
use super::operand::{Index, MemOffset, Operand, OperandKind, Shift, ShiftAmt};
use super::reg::{self, Reg};
use super::table::{self, Field, Form, Op, Set};
use super::{Insn, THUMB_BITS};
use crate::arch::AsmCtx;
use crate::section::Variant;

/// The forms of a mnemonic, following the spellings GNU as shares.
pub fn forms(name: &str) -> Option<&'static [Form]> {
    let name = match table::SPELLINGS.binary_search_by(|(a, _)| (*a).cmp(name)) {
        Ok(i) => table::SPELLINGS[i].1,
        Err(_) => name,
    };
    let lo = table::FORMS.partition_point(|f| f.name < name);
    let hi = table::FORMS.partition_point(|f| f.name <= name);
    (lo < hi).then(|| &table::FORMS[lo..hi])
}

/// Assembles `ins` from its table forms, or reports why none of them fit.
pub fn assemble(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, at: u16) -> Option<Vec<Variant>> {
    let all = forms(table::FORMS[at as usize].name)?;
    let thumb = cx.state.bits == THUMB_BITS;
    let mut best: Option<(&Form, usize)> = None;
    for form in all {
        if !wanted(form.set, thumb, ins.width) {
            continue;
        }
        match encode(cx, ins, form, false) {
            Ok(word) => return Some(emit(form, word)),
            Err(used) => {
                if best.is_none_or(|(_, n)| used > n) {
                    best = Some((form, used));
                }
            }
        }
    }
    // The diagnostic comes from the form that read the most of what was
    // written, which is the one the source most nearly spells.
    match best {
        Some((form, _)) => {
            let _ = encode(cx, ins, form, true);
        }
        None => {
            let what = match (thumb, ins.width) {
                (true, Width::Narrow) => " as a 16-bit instruction",
                (true, Width::Wide) => " as a 32-bit instruction",
                (true, _) => " in Thumb",
                _ => " in ARM",
            };
            cx.error(ins.span, format!("`{}` cannot be encoded{what}", ins.text));
        }
    }
    None
}

/// Whether a form's instruction set is the one being assembled, and its
/// width the one a `.n` or `.w` asked for.
fn wanted(set: Set, thumb: bool, width: Width) -> bool {
    match set {
        Set::Arm => !thumb,
        Set::T16 => thumb && width != Width::Wide,
        Set::T32 => thumb && width != Width::Narrow,
    }
}

fn emit(form: &Form, word: u32) -> Vec<Variant> {
    let bytes = match form.set {
        Set::T16 => (word as u16).to_le_bytes().to_vec(),
        // A 32-bit Thumb instruction is two little-endian halfwords, the
        // first on top of the word the table holds.
        Set::T32 => {
            let mut v = ((word >> 16) as u16).to_le_bytes().to_vec();
            v.extend_from_slice(&(word as u16).to_le_bytes());
            v
        }
        Set::Arm => word.to_le_bytes().to_vec(),
    };
    vec![Variant::new(bytes)]
}

/// Puts `value` into `field`, whose pieces run from the value's low bits up.
fn place(word: &mut u32, field: Field, value: u32) {
    let mut left = value;
    for (lsb, width) in field {
        let mask = (1u32 << width) - 1;
        *word |= (left & mask) << lsb;
        left >>= width;
    }
}

/// The number of bits a field holds.
fn width_of(field: Field) -> u32 {
    field.iter().map(|(_, w)| u32::from(*w)).sum()
}

/// The state of one attempt to fit the written operands to a form.
struct Walk<'a, 'b, 'c> {
    cx: &'a mut AsmCtx<'b>,
    ins: &'a Insn<'c>,
    word: u32,
    /// The next written operand to read.
    at: usize,
    /// The operand read last, for `!` and for a register pair's second half.
    prev: Option<usize>,
    /// A shift written on the register just read, which the next `Op` must
    /// be the one that takes it.
    shift: Option<(Shift, u32)>,
    /// The `#lsb` of a bitfield instruction, which its `#width` is measured
    /// from.
    lsb: u32,
    /// Whether to report the first thing that does not fit.
    report: bool,
    failed: bool,
}

impl Walk<'_, '_, '_> {
    fn op(&self) -> Option<&Operand> {
        self.ins.ops.get(self.at)
    }

    fn fail<T>(&mut self, msg: impl FnOnce() -> String) -> Option<T> {
        if self.report && !self.failed {
            let span = self.op().map_or(self.ins.span, |o| o.span);
            self.cx.error(span, msg());
        }
        self.failed = true;
        None
    }

    fn take(&mut self) {
        self.prev = Some(self.at);
        self.at += 1;
    }

    /// The constant value of the operand about to be read.
    fn constant(&mut self) -> Option<i64> {
        let Some(op) = self.op().cloned() else {
            return self.fail(|| "expected an immediate".into());
        };
        let (OperandKind::Imm(e) | OperandKind::Braced(e)) = op.kind else {
            let what = op.describe();
            return self.fail(|| format!("expected an immediate, found {what}"));
        };
        match self.cx.constant(e) {
            Some(v) => Some(v),
            None => self.fail(|| "this immediate must be a constant expression".into()),
        }
    }

    /// A register operand, taking a shift written on it for the `Op` after.
    fn register(&mut self, bits: u8) -> Option<Reg> {
        let Some(op) = self.op().cloned() else {
            return self.fail(|| "expected a register".into());
        };
        let r = match op.kind {
            OperandKind::Reg(r) => r,
            OperandKind::Shifted { rm, shift, amount } => {
                let n = match amount {
                    ShiftAmt::Imm(n) => n,
                    ShiftAmt::None => 0,
                    ShiftAmt::Reg(_) => {
                        return self.fail(|| {
                            "this instruction cannot take a register shift amount".into()
                        });
                    }
                };
                self.shift = Some((shift, n));
                rm
            }
            _ => {
                let what = op.describe();
                return self.fail(|| format!("expected a register, found {what}"));
            }
        };
        if u32::from(r) >= 1 << bits {
            let name = reg::name_of(r);
            return self.fail(|| format!("`{name}` is not one of r0-r7 here"));
        }
        self.take();
        Some(r)
    }

    /// Puts an immediate into a field, checking its range the way the field
    /// and its scale allow.
    fn immediate(&mut self, field: Field, scale: u8, bias: u8) -> Option<()> {
        let v = self.constant()?;
        let scale = i64::from(scale);
        let bias = i64::from(bias);
        let hi = ((1i64 << width_of(field)) - 1 + bias) * scale;
        if v < bias * scale || v > hi || v % scale != 0 {
            let step = if scale == 1 {
                String::new()
            } else {
                format!(" in steps of {scale}")
            };
            return self.fail(|| {
                format!(
                    "immediate {v} is out of range ({} to {hi}{step})",
                    bias * scale
                )
            });
        }
        place(&mut self.word, field, (v / scale - bias) as u32);
        self.take();
        Some(())
    }

    /// A bare word operand — a coprocessor register, a barrier option, the
    /// interrupt flags — as it was written.
    fn word_operand(&mut self) -> Option<String> {
        match self.op().and_then(|o| o.word.clone()) {
            Some(w) => Some(w),
            None => self.fail(|| "expected a keyword operand".into()),
        }
    }

    /// The shift written on the register just read, if any.
    fn pending_shift(&mut self) -> Option<(Shift, u32)> {
        self.shift.take()
    }
}

/// Fits the written operands to `form`, returning the encoded word or how
/// many of them were read before it stopped fitting.
fn encode(cx: &mut AsmCtx<'_>, ins: &Insn<'_>, form: &Form, report: bool) -> Result<u32, usize> {
    let mut w = Walk {
        cx,
        ins,
        word: form.word,
        at: 0,
        prev: None,
        shift: None,
        lsb: 0,
        report,
        failed: false,
    };
    let ok = (|| {
        // A32 keeps the condition in the top four bits; a form that has none
        // has them filled in already, and cannot be predicated.
        if form.set == Set::Arm {
            if form.cond {
                w.word |= u32::from(ins.cond) << 28;
            } else if ins.cond_written && ins.cond != AL {
                let text = ins.text;
                w.fail(|| format!("`{text}` cannot be conditional"))?;
            }
        } else if ins.cond_written && ins.cond != AL {
            let text = ins.text;
            w.fail(|| format!("`{text}` is conditional, which in Thumb takes an `it` block"))?;
        }
        if ins.set_flags {
            let text = ins.text;
            w.fail(|| format!("`{text}` cannot set the flags"))?;
        }
        for op in form.ops {
            step(&mut w, *op)?;
        }
        if w.shift.is_some() {
            w.fail(|| "this instruction cannot take a shift".into())?;
        }
        if !form
            .ops
            .iter()
            .any(|o| matches!(o, Op::Writeback(_) | Op::SpBase(..)))
            && ins.ops.iter().any(|o| o.writeback)
        {
            let text = ins.text;
            w.fail(|| format!("`{text}` does not write a base register back"))?;
        }
        if w.at != ins.ops.len() {
            let extra = ins.ops.len();
            let text = ins.text;
            w.fail(|| format!("`{text}` does not take {extra} operands"))?;
        }
        Some(())
    })();
    match ok {
        Some(()) => Ok(w.word),
        None => Err(w.at),
    }
}

fn step(w: &mut Walk<'_, '_, '_>, op: Op) -> Option<()> {
    match op {
        Op::Reg(lsb, bits) => {
            let r = w.register(bits)?;
            w.word |= u32::from(r) << lsb;
        }
        Op::RegTwice(a, b) => {
            let r = w.register(4)?;
            w.word |= (u32::from(r) << a) | (u32::from(r) << b);
        }
        Op::Base(lsb, bits) => {
            let r = base_register(w)?;
            if u32::from(r) >= 1 << bits {
                let name = reg::name_of(r);
                return w.fail(|| format!("`{name}` cannot be a base register here"));
            }
            w.word |= u32::from(r) << lsb;
        }
        // The second half of a register pair carries no bits, and GNU as
        // takes the spelling that leaves it out.
        Op::Next => {
            let want = w
                .prev
                .and_then(|i| w.ins.ops[i].reg())
                .map(|r| r.wrapping_add(1));
            if let Some(r) = w.op().and_then(|o| o.reg())
                && Some(r) == want
            {
                w.take();
            }
        }
        Op::Imm(field, scale, bias) => w.immediate(field, scale, bias)?,
        Op::OptImm(field) => {
            if w.at < w.ins.ops.len() {
                w.immediate(field, 1, 0)?;
            }
        }
        Op::Hint(field) => {
            if w.at < w.ins.ops.len() {
                if !matches!(w.op().map(|o| &o.kind), Some(OperandKind::Braced(_))) {
                    return w.fail(|| "a hint number is written in braces".into());
                }
                w.immediate(field, 1, 0)?;
            }
        }
        Op::Lsb(field) => {
            let v = w.constant()?;
            if !(0..32).contains(&v) {
                return w.fail(|| format!("bit position {v} is out of range (0 to 31)"));
            }
            w.lsb = v as u32;
            place(&mut w.word, field, w.lsb);
            w.take();
        }
        Op::Msb(field) => {
            let v = w.constant()?;
            let lsb = w.lsb;
            let last = i64::from(lsb) + v - 1;
            if v < 1 || last > 31 {
                return w.fail(|| format!("a field of {v} bits does not fit above bit {lsb}"));
            }
            place(&mut w.word, field, last as u32);
            w.take();
        }
        Op::Width(field) => {
            let v = w.constant()?;
            let lsb = w.lsb;
            if v < 1 || i64::from(lsb) + v > 32 {
                return w.fail(|| format!("a field of {v} bits does not fit above bit {lsb}"));
            }
            place(&mut w.word, field, (v - 1) as u32);
            w.take();
        }
        Op::Rotate(lsb) => {
            if let Some((shift, n)) = w.pending_shift() {
                if shift != Shift::Ror || n % 8 != 0 || n > 24 {
                    return w.fail(|| "the only rotation here is `ror` by 8, 16 or 24".into());
                }
                w.word |= (n / 8) << lsb;
            }
        }
        Op::SatShift(lsb, bits, asr, lsb2, bits2) => sat_shift(w, lsb, bits, asr, lsb2, bits2)?,
        Op::Coproc(lsb) => {
            let name = w.word_operand()?;
            let Some(n) = name.strip_prefix('p').and_then(|d| d.parse::<u32>().ok()) else {
                return w.fail(|| format!("expected a coprocessor number, found `{name}`"));
            };
            if n > 15 {
                return w.fail(|| format!("there is no coprocessor `p{n}`"));
            }
            w.word |= n << lsb;
            w.take();
        }
        Op::CReg(lsb) => {
            let name = w.word_operand()?;
            let Some(n) = name
                .strip_prefix("cr")
                .or(name.strip_prefix('c'))
                .and_then(|d| d.parse::<u32>().ok())
            else {
                return w.fail(|| format!("expected a coprocessor register, found `{name}`"));
            };
            if n > 15 {
                return w.fail(|| format!("there is no coprocessor register `c{n}`"));
            }
            w.word |= n << lsb;
            w.take();
        }
        Op::ApsrNzcv => {
            let name = w.word_operand()?;
            if !name.eq_ignore_ascii_case("apsr_nzcv") {
                return w.fail(|| format!("expected `APSR_nzcv`, found `{name}`"));
            }
            w.take();
        }
        Op::Barrier => {
            if w.at < w.ins.ops.len() {
                let name = w.word_operand()?;
                let Some(v) = barrier_option(&name) else {
                    return w.fail(|| format!("`{name}` is not a barrier option"));
                };
                w.word |= v;
                w.take();
            } else {
                // No option written is a full system barrier.
                w.word |= 15;
            }
        }
        Op::Writeback(lsb) => {
            if w.prev.is_some_and(|i| w.ins.ops[i].writeback) {
                w.word |= 1 << lsb;
            }
        }
        Op::SpBase(lsb, wb) => {
            w.word |= u32::from(reg::SP) << lsb;
            if let Some(r) = w.op().and_then(|o| o.reg()) {
                if r != reg::SP {
                    return w.fail(|| "the base register of `srs` must be `sp`".into());
                }
                if w.ins.ops[w.at].writeback {
                    w.word |= 1 << wb;
                }
                w.take();
            }
        }
        Op::IntFlags(lsb) => {
            let name = w.word_operand()?;
            let mut bits = 0;
            for ch in name.chars() {
                bits |= match ch {
                    'f' => 1,
                    'i' => 2,
                    'a' => 4,
                    _ => return w.fail(|| format!("`{name}` is not a list of `a`, `i` and `f`")),
                };
            }
            if bits == 0 {
                return w.fail(|| "expected at least one of `a`, `i` and `f`".into());
            }
            w.word |= bits << lsb;
            w.take();
        }
        Op::Endian(lsb) => {
            let name = w.word_operand()?;
            match name.as_str() {
                "le" => {}
                "be" => w.word |= 1 << lsb,
                _ => return w.fail(|| format!("expected `be` or `le`, found `{name}`")),
            }
            w.take();
        }
        Op::IdxMem(base, index, shift) => table_branch(w, base, index, shift)?,
        Op::OffMem(base, field, scale) => offset_mem(w, base, field, scale)?,
        Op::CoprocMem => coproc_mem(w)?,
    }
    Some(())
}

/// The base register of a `[rn]` operand, which must have nothing else in it.
fn base_register(w: &mut Walk<'_, '_, '_>) -> Option<Reg> {
    let Some(op) = w.op().cloned() else {
        return w.fail(|| "expected `[rn]`".into());
    };
    let OperandKind::Mem(mem) = op.kind else {
        let what = op.describe();
        return w.fail(|| format!("expected `[rn]`, found {what}"));
    };
    if !matches!(mem.offset, MemOffset::None) || mem.index != Index::Offset || op.writeback {
        return w.fail(|| "this instruction addresses `[rn]` with no offset".into());
    }
    w.take();
    Some(mem.base)
}

/// `ssat`, `usat`, `pkhbt` and `pkhtb`'s optional shift: `lsl` or `asr` by a
/// constant, with the kind in one bit where both are allowed.
fn sat_shift(
    w: &mut Walk<'_, '_, '_>,
    lsb: u8,
    bits: u8,
    asr: u8,
    lsb2: u8,
    bits2: u8,
) -> Option<()> {
    let Some((shift, n)) = w.pending_shift() else {
        return Some(());
    };
    let is_asr = match shift {
        Shift::Lsl if asr != 255 => false,
        Shift::Asr if asr != 254 => true,
        _ => {
            let want = match asr {
                254 => "`lsl`",
                255 => "`asr`",
                _ => "`lsl` or `asr`",
            };
            return w.fail(|| format!("the only shift here is {want}"));
        }
    };
    // `asr #32` is written out but encoded as zero, as it is everywhere else
    // in the instruction set.
    let n = if is_asr && n == 32 { 0 } else { n };
    let total = u32::from(bits) + if lsb2 == 255 { 0 } else { u32::from(bits2) };
    if n >= 1 << total {
        return w.fail(|| format!("shift amount {n} is out of range"));
    }
    if is_asr && asr < 32 {
        w.word |= 1 << asr;
    }
    w.word |= (n & ((1 << bits) - 1)) << lsb;
    if lsb2 != 255 {
        w.word |= (n >> bits) << lsb2;
    }
    Some(())
}

/// `tbb [rn, rm]` and `tbh [rn, rm, lsl #1]`.
fn table_branch(w: &mut Walk<'_, '_, '_>, base: u8, index: u8, shift: u8) -> Option<()> {
    let Some(op) = w.op().cloned() else {
        return w.fail(|| "expected `[rn, rm]`".into());
    };
    let OperandKind::Mem(mem) = op.kind else {
        let what = op.describe();
        return w.fail(|| format!("expected `[rn, rm]`, found {what}"));
    };
    let MemOffset::Reg {
        rm,
        add: true,
        shift: kind,
        amount,
    } = mem.offset
    else {
        return w.fail(|| "expected an index register".into());
    };
    if mem.index != Index::Offset || kind != Shift::Lsl || amount != u32::from(shift) {
        let want = if shift == 0 { "" } else { ", lsl #1" };
        return w.fail(|| format!("this instruction addresses `[rn, rm{want}]`"));
    }
    w.word |= u32::from(mem.base) << base;
    w.word |= u32::from(rm) << index;
    w.take();
    Some(())
}

/// `[rn]` or `[rn, #imm]` with a scaled unsigned offset, the Thumb-2
/// exclusive loads' addressing.
fn offset_mem(w: &mut Walk<'_, '_, '_>, base: u8, field: Field, scale: u8) -> Option<()> {
    let Some(op) = w.op().cloned() else {
        return w.fail(|| "expected a memory operand".into());
    };
    let OperandKind::Mem(mem) = op.kind else {
        let what = op.describe();
        return w.fail(|| format!("expected a memory operand, found {what}"));
    };
    let off = match mem.offset {
        MemOffset::None => 0,
        MemOffset::Imm(v) => v,
        _ => return w.fail(|| "this instruction takes no index register".into()),
    };
    let scale = i64::from(scale);
    let hi = ((1i64 << width_of(field)) - 1) * scale;
    if mem.index != Index::Offset || op.writeback {
        return w.fail(|| "this instruction does not write the base register back".into());
    }
    if off < 0 || off > hi || off % scale != 0 {
        return w.fail(|| format!("offset {off} is out of range (0 to {hi} in steps of {scale})"));
    }
    w.word |= u32::from(mem.base) << base;
    place(&mut w.word, field, (off / scale) as u32);
    w.take();
    Some(())
}

/// `ldc` and `stc`'s addressing: `[rn, #±imm8*4]` with or without writeback,
/// `[rn], #±imm8*4`, and the unindexed `[rn], {imm8}` that hands the byte to
/// the coprocessor.
fn coproc_mem(w: &mut Walk<'_, '_, '_>) -> Option<()> {
    let Some(op) = w.op().cloned() else {
        return w.fail(|| "expected a memory operand".into());
    };
    let OperandKind::Mem(mem) = op.kind else {
        let what = op.describe();
        return w.fail(|| format!("expected a memory operand, found {what}"));
    };
    w.word |= u32::from(mem.base) << 16;
    if let MemOffset::Unindexed(v) = mem.offset {
        if !(0..=255).contains(&v) {
            return w.fail(|| format!("option {v} does not fit in a byte"));
        }
        // P clear, W clear, U set: the offset field is the coprocessor's.
        w.word |= (1 << 23) | (v as u32);
        w.take();
        return Some(());
    }
    let off = match mem.offset {
        MemOffset::None => 0,
        MemOffset::Imm(v) => v,
        _ => return w.fail(|| "this instruction takes no index register".into()),
    };
    if off % 4 != 0 || off.unsigned_abs() > 1020 {
        return w.fail(|| format!("offset {off} is out of range (-1020 to 1020 in steps of 4)"));
    }
    match mem.index {
        Index::Offset => w.word |= 1 << 24,
        Index::PreIndex => w.word |= (1 << 24) | (1 << 21),
        Index::PostIndex => w.word |= 1 << 21,
    }
    if off >= 0 {
        w.word |= 1 << 23;
    }
    w.word |= (off.unsigned_abs() / 4) as u32;
    w.take();
    Some(())
}

/// The memory-barrier options, as their 4-bit encodings.
pub fn barrier_option(name: &str) -> Option<u32> {
    Some(match name {
        "sy" => 15,
        "st" => 14,
        "ish" => 11,
        "ishst" => 10,
        "nsh" | "un" => 7,
        "nshst" | "unst" => 6,
        "osh" => 3,
        "oshst" => 2,
        _ => return None,
    })
}
