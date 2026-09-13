//! Instruction assembly: bit fields, displacements, and immediates whose
//! width depends on their value.
//!
//! RX instructions are a few base bytes with packed bit fields, followed by
//! displacement and immediate bytes. [`Enc`] builds exactly that, with the
//! field numbering GNU as uses (bit 0 is the most significant bit of the first
//! byte), so each encoding reads like the line of `rx-parse.y` it was checked
//! against.
//!
//! # Size classes
//!
//! Most of RX's variable length comes from two places:
//!
//! - **Displacements** are 0, 8 or 16 bits, chosen from the value, and are
//!   stored *divided by the operand size*: `mov.l 8[r1], r2` stores 2. They
//!   must be constants when the instruction is read; GNU as rejects anything
//!   else, and so does this backend.
//! - **Immediates** are 8, 16, 24 or 32 bits, with a two-bit length code
//!   (`li`) in the opcode, where `00` means 32. Several instructions also have
//!   a shorter form for small unsigned values (`mov #uimm4, r1`, `cmp #uimm8,
//!   r1`), picked before the general one.
//!
//! GNU as decides all of this while it parses, from whether the operand is a
//! constant *at that moment*. That is not the same thing as whether it is a
//! constant eventually, and matching the reference means following it:
//!
//! - a constant takes the shortest form that fits;
//! - a difference of two labels that are both already defined, in the same
//!   section, has been folded to a constant by GNU as's expression parser, so
//!   it too takes the shortest form — but only layout knows its value, so
//!   every candidate is offered and layout picks;
//! - any other difference of symbols is relaxed by GNU as among the general
//!   form's 8/16/24/32-bit immediates, never the short forms;
//! - anything else referring to a symbol is a 32-bit immediate with a
//!   relocation, even if the symbol turns out to be nearby.
//!
//! The second rule is an approximation. GNU as folds only when no relaxable
//! instruction or alignment lies between the two labels, which a backend
//! cannot see; see [`classify`].

use super::reg::Size;
use super::reloc;
use crate::arch::AsmCtx;
use crate::expr::{BinOp, ExprKind, ExprRef, SymbolEnv, UnOp, Value};
use crate::section::{Fixup, FixupKind, Variant};
use crate::source::Span;
use crate::symbol::SymbolValue;

/// An instruction under construction.
#[derive(Clone, Debug)]
pub struct Enc {
    pub bytes: Vec<u8>,
    pub fixups: Vec<Fixup>,
}

impl Enc {
    pub fn new(base: &[u8]) -> Enc {
        Enc {
            bytes: base.to_vec(),
            fixups: Vec::new(),
        }
    }

    /// ORs `val` into the `sz`-bit field starting `pos` bits from the most
    /// significant bit of the first byte. Bits of `val` above `sz` are
    /// dropped; callers range-check first.
    pub fn field(&mut self, val: u32, pos: u32, sz: u32) -> &mut Enc {
        for i in 0..sz {
            if (val >> (sz - 1 - i)) & 1 == 1 {
                let p = pos + i;
                self.bytes[(p / 8) as usize] |= 0x80 >> (p % 8);
            }
        }
        self
    }

    /// Appends `n` little-endian bytes of `v`. Operand bytes are always
    /// little-endian on RX, whatever the data byte order.
    pub fn push(&mut self, v: i64, n: usize) -> &mut Enc {
        for i in 0..n {
            self.bytes.push((v >> (8 * i)) as u8);
        }
        self
    }

    /// Appends `kind.size` placeholder bytes to be filled from `expr`.
    pub fn fixup(&mut self, expr: ExprRef, kind: FixupKind, span: Span) -> &mut Enc {
        self.fixup_at(self.bytes.len(), expr, kind, span);
        self.bytes
            .extend(std::iter::repeat_n(0, kind.size as usize));
        self
    }

    /// Records a fixup over bytes that already exist.
    pub fn fixup_at(&mut self, offset: usize, expr: ExprRef, kind: FixupKind, span: Span) {
        self.fixups.push(Fixup {
            offset: offset as u32,
            expr,
            kind,
            span,
        });
    }

    pub fn variant(self) -> Variant {
        Variant {
            bytes: self.bytes,
            fixups: self.fixups,
        }
    }

    pub fn one(self) -> Option<Vec<Variant>> {
        Some(vec![self.variant()])
    }
}

/// Folds `e` to a number, or reports `what` must be a constant.
pub fn constant(cx: &mut AsmCtx<'_>, e: ExprRef, span: Span, what: &str) -> Option<i64> {
    match cx.constant(e) {
        Some(v) => Some(v),
        None => {
            cx.error(span, format!("{what} must be a constant"));
            None
        }
    }
}

/// A constant in `lo..=hi`, or a diagnostic naming that range.
pub fn constant_in(
    cx: &mut AsmCtx<'_>,
    e: ExprRef,
    span: Span,
    what: &str,
    lo: i64,
    hi: i64,
) -> Option<i64> {
    let v = constant(cx, e, span, what)?;
    if v < lo || v > hi {
        cx.error(span, format!("{what} {v} is out of range ({lo} to {hi})"));
        return None;
    }
    Some(v)
}

// ---- displacements --------------------------------------------------------

/// Appends a displacement for an operand of size `size`, writing its length
/// code (0: none, 1: 8-bit, 2: 16-bit) into the two-bit field at `pos`.
///
/// A zero displacement, written or not, takes no bytes. Otherwise the stored
/// value is the displacement divided by the operand size, which is why a
/// `.l` operand reaches 262140 bytes and must be a multiple of 4.
pub fn disp(
    cx: &mut AsmCtx<'_>,
    enc: &mut Enc,
    pos: u32,
    disp: Option<ExprRef>,
    size: Size,
    span: Span,
) -> Option<()> {
    let Some(e) = disp else {
        return Some(());
    };
    let Some(v) = cx.constant(e) else {
        cx.error(
            span,
            "displacements must be constants; GNU as reads them before any label is placed",
        );
        return None;
    };
    if v == 0 {
        return Some(());
    }
    if v < 0 {
        cx.error(
            span,
            format!("displacement {v} is negative; RX displacements are unsigned"),
        );
        return None;
    }
    let scale = size.scale();
    if v % scale != 0 {
        cx.error(
            span,
            format!(
                "displacement {v} is not a multiple of {scale}, the size of a `{}` operand",
                [".b", ".w", ".l"][size as usize]
            ),
        );
        return None;
    }
    let units = v / scale;
    if units <= 0xff {
        enc.field(1, pos, 2).push(units, 1);
    } else if units <= 0xffff {
        enc.field(2, pos, 2).push(units, 2);
    } else {
        cx.error(
            span,
            format!(
                "displacement {v} is too large (the limit for this operand size is {})",
                0xffff * scale
            ),
        );
        return None;
    }
    Some(())
}

/// The five-bit scaled displacement of the short `mov`/`movu` forms, if `disp`
/// has one: a written constant from 0 up to 31 units, aligned to the operand
/// size. A missing displacement does not count, because GNU as's grammar
/// sends `[reg]` to the long form.
pub fn disp5(cx: &AsmCtx<'_>, disp: Option<ExprRef>, size: Size) -> Option<u32> {
    let v = cx.constant(disp?)?;
    let scale = size.scale();
    (v >= 0 && v % scale == 0 && v / scale <= 31).then_some((v / scale) as u32)
}

// ---- immediates -----------------------------------------------------------

/// What is known about an immediate when the instruction is read.
#[derive(Copy, Clone, Debug)]
pub enum Val {
    Const(i64),
    /// A difference of labels GNU as would have folded to a constant.
    Folded(ExprRef),
    /// A difference GNU as leaves to its own relaxation.
    Relax(ExprRef),
    /// Anything else: a relocation.
    Sym(ExprRef),
}

/// Classifies an immediate the way GNU as's parser would see it.
///
/// A difference of two labels that are already defined in the same section
/// is taken to be one GNU as folded. The reference also requires that nothing
/// between them changes size during relaxation — no unsized branch, no
/// symbolic immediate, no displacement-bearing instruction and no `.align` —
/// which a backend has no way to see, so such a difference is assembled here
/// with the short forms available where GNU as would use the long ones.
pub fn classify(cx: &AsmCtx<'_>, e: ExprRef) -> Val {
    if let Some(c) = cx.constant(e) {
        return Val::Const(c);
    }
    if let Some(v) = SymbolEnv::new(cx.exprs, cx.symbols).value(e)
        && let (Some(p), Some(m)) = (v.plus, v.minus)
    {
        let sec = |id| match cx.symbols.get(id).value {
            SymbolValue::Label { section, .. } => Some(section),
            _ => None,
        };
        if sec(p).is_some() && sec(p) == sec(m) {
            return Val::Folded(e);
        }
        return Val::Relax(e);
    }
    if is_difference(cx, e) {
        Val::Relax(e)
    } else {
        Val::Sym(e)
    }
}

/// Whether `e` is, syntactically, `a - b` with symbols on both sides, give
/// or take added constants — what GNU as calls `O_subtract`.
fn is_difference(cx: &AsmCtx<'_>, e: ExprRef) -> bool {
    match cx.exprs.get(e).kind {
        ExprKind::Binary(BinOp::Sub, l, r) => mentions_symbol(cx, l) && mentions_symbol(cx, r),
        ExprKind::Binary(BinOp::Add, l, r) => {
            match (mentions_symbol(cx, l), mentions_symbol(cx, r)) {
                (true, false) => is_difference(cx, l),
                (false, true) => is_difference(cx, r),
                _ => false,
            }
        }
        ExprKind::Unary(UnOp::Plus, x) => is_difference(cx, x),
        _ => false,
    }
}

fn mentions_symbol(cx: &AsmCtx<'_>, e: ExprRef) -> bool {
    match cx.exprs.get(e).kind {
        ExprKind::Int(_) => false,
        ExprKind::Sym(_)
        | ExprKind::SymId(_)
        | ExprKind::LocalRef(..)
        | ExprKind::Here
        | ExprKind::SectionStart => cx.constant(e).is_none(),
        ExprKind::Unary(_, x) | ExprKind::Modifier(_, x) => mentions_symbol(cx, x),
        ExprKind::Binary(_, l, r) => mentions_symbol(cx, l) || mentions_symbol(cx, r),
    }
}

/// The values a field accepts.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Range {
    /// Two's complement: -128..=127 for a byte.
    Signed,
    /// 0..=255 for a byte.
    Unsigned,
    /// Either reading: -128..=255 for a byte.
    Either,
}

impl Range {
    fn bounds(self, bits: u32) -> (i64, i64) {
        let half = 1i64 << (bits - 1);
        match self {
            Range::Signed => (-half, half - 1),
            Range::Unsigned => (0, 2 * half - 1),
            Range::Either => (-half, 2 * half - 1),
        }
    }
}

/// Where an immediate goes in one candidate encoding.
#[derive(Copy, Clone, Debug)]
pub enum Place {
    /// An unsigned four-bit field at bit `pos` of the opcode.
    Nibble(u32),
    /// `n` trailing bytes, relocated with `reloc` when symbolic.
    Bytes { n: u8, range: Range, reloc: u32 },
    /// GNU as's `IMM`: one to four trailing bytes, with the length code at bit
    /// `li` of the opcode. `bits` is the operand width, 8, 16 or 32, which
    /// limits the value and decides how a constant is sign-folded: `mov.b
    /// #255` stores one byte, `ff`, as does `mov #0xffffffff`.
    Imm { li: u32, bits: u32 },
}

/// One candidate encoding of an instruction with an immediate.
#[derive(Clone, Debug)]
pub struct Rung {
    pub enc: Enc,
    pub place: Place,
    /// The value is stored negated: `sub #n` is `add #-n`.
    pub negate: bool,
    /// GNU as uses this form for a non-constant immediate.
    pub symbolic: bool,
    /// GNU as never relaxes this form's immediate below 32 bits.
    pub wide_when_symbolic: bool,
}

impl Rung {
    pub fn new(enc: Enc, place: Place) -> Rung {
        Rung {
            enc,
            place,
            negate: false,
            symbolic: !matches!(place, Place::Nibble(_)),
            wide_when_symbolic: false,
        }
    }

    /// Marks an immediate that follows a displacement.
    ///
    /// GNU as records the displacement as a relaxation too, and its relaxation
    /// pass then looks for the immediate's expression in the wrong slot, finds
    /// nothing it can evaluate, and settles on 32 bits. Checked: `mov.w #e-s,
    /// 4[r2]` with `e - s` a forward 5 is `f9 21 02 05 00 00 00`.
    pub fn after_displacement(mut self) -> Rung {
        self.wide_when_symbolic = true;
        self
    }

    /// A form GNU as only picks for a constant: the short immediate forms.
    pub fn const_only(mut self) -> Rung {
        self.symbolic = false;
        self
    }

    pub fn negated(mut self) -> Rung {
        self.negate = true;
        self
    }
}

/// The byte length an `IMM` needs for `v`, after GNU as's sign fold.
fn imm_len(v: i64, bits: u32) -> Option<u8> {
    let (lo, hi) = Range::Either.bounds(bits);
    if v < lo || v > hi {
        return None;
    }
    // A value in the upper half of the operand width is its negative
    // reading: `mov.w #0xffff` is `mov.w #-1`.
    let half = 1i64 << (bits - 1);
    let v = if v >= half { v - 2 * half } else { v };
    Some(match v {
        -0x80..=0x7f => 1,
        -0x8000..=0x7fff => 2,
        -0x80_0000..=0x7f_ffff => 3,
        _ => 4,
    })
}

/// The `li` code for an `n`-byte immediate: 32 bits is 0.
fn li_code(n: u8) -> u32 {
    (n % 4) as u32
}

/// Assembles an instruction whose candidate encodings are `rungs`, in the
/// order GNU as tries them, for the immediate `e`.
pub fn immediate(
    cx: &mut AsmCtx<'_>,
    rungs: Vec<Rung>,
    e: ExprRef,
    span: Span,
) -> Option<Vec<Variant>> {
    match classify(cx, e) {
        Val::Const(c) => const_immediate(cx, rungs, c, span).map(|v| vec![v]),
        Val::Folded(e) => Some(folded(cx, rungs, e, span)),
        Val::Relax(e) => symbolic(cx, rungs, e, span, true),
        Val::Sym(e) => symbolic(cx, rungs, e, span, false),
    }
}

/// Picks the first rung a constant fits, or explains the widest one's limit.
pub fn const_immediate(
    cx: &mut AsmCtx<'_>,
    rungs: Vec<Rung>,
    c: i64,
    span: Span,
) -> Option<Variant> {
    let mut limit = (0, 0);
    for Rung {
        mut enc,
        place,
        negate,
        ..
    } in rungs
    {
        let v = if negate { c.wrapping_neg() } else { c };
        match place {
            Place::Nibble(pos) => {
                if (0..=15).contains(&v) {
                    enc.field(v as u32, pos, 4);
                    return Some(enc.variant());
                }
                limit = (0, 15);
            }
            Place::Bytes { n, range, .. } => {
                let (lo, hi) = range.bounds(8 * n as u32);
                if (lo..=hi).contains(&v) {
                    enc.push(v, n as usize);
                    return Some(enc.variant());
                }
                limit = (lo, hi);
            }
            Place::Imm { li, bits } => {
                if let Some(n) = imm_len(v, bits) {
                    enc.field(li_code(n), li, 2).push(v, n as usize);
                    return Some(enc.variant());
                }
                limit = Range::Either.bounds(bits);
                if negate {
                    limit = (-limit.1, -limit.0);
                }
            }
        }
    }
    cx.error(
        span,
        format!("immediate {c} is out of range ({} to {})", limit.0, limit.1),
    );
    None
}

// Folded differences need a fixup that accepts exactly a rung's range, so
// layout moves past a rung whenever GNU as's constant test would have. Signed
// ranges are what a fixup checks natively; an unsigned one is checked as a
// signed range around its midpoint, by fixing up `e - mid` and adding `mid`
// back when writing.

fn hi_nibble_plus8(word: u64, v: i64) -> u64 {
    (word & 0x0f) | ((((v + 8) as u64) & 0xf) << 4)
}

fn lo_nibble_plus8(word: u64, v: i64) -> u64 {
    (word & 0xf0) | (((v + 8) as u64) & 0xf)
}

fn byte_plus128(_word: u64, v: i64) -> u64 {
    ((v + 128) as u64) & 0xff
}

fn negate4(_word: u64, v: i64) -> u64 {
    (v.wrapping_neg() as u64) & 0xffff_ffff
}

fn offset_expr(cx: &mut AsmCtx<'_>, e: ExprRef, by: u64, span: Span) -> ExprRef {
    let k = cx.exprs.int(by, span);
    cx.exprs.alloc(ExprKind::Binary(BinOp::Sub, e, k), span)
}

/// The fixup for an `n`-byte immediate field accepting `range`.
fn byte_kind(n: u8, range: Range, reloc: u32) -> FixupKind {
    let k = FixupKind::data(n).with_reloc(reloc);
    match range {
        Range::Signed => k.signed(),
        Range::Unsigned | Range::Either => k,
    }
}

/// Every rung, as a variant, for a difference only layout can evaluate.
fn folded(cx: &mut AsmCtx<'_>, rungs: Vec<Rung>, e: ExprRef, span: Span) -> Vec<Variant> {
    // `-(a - b)` has no value until layout, and the shared evaluator will not
    // negate a relocatable value, so the negation is spelled `b - a`.
    let neg = |cx: &mut AsmCtx<'_>| negated_difference(cx, e, span);
    let mut out = Vec::new();
    for Rung {
        enc, place, negate, ..
    } in rungs
    {
        let val = if negate { neg(cx) } else { e };
        match place {
            Place::Nibble(pos) => {
                let mut enc = enc;
                let scatter = if pos % 8 == 0 {
                    hi_nibble_plus8
                } else {
                    lo_nibble_plus8
                };
                let kind = FixupKind::data(1)
                    .signed()
                    .with_field(4, 1)
                    .scatter(scatter);
                let shifted = offset_expr(cx, val, 8, span);
                enc.fixup_at((pos / 8) as usize, shifted, kind, span);
                out.push(enc.variant());
            }
            Place::Bytes { n, range, reloc } => {
                let mut enc = enc;
                if range == Range::Unsigned && n == 1 {
                    let kind = FixupKind::data(1).signed().scatter(byte_plus128);
                    let shifted = offset_expr(cx, val, 128, span);
                    enc.fixup(shifted, kind, span);
                } else {
                    enc.fixup(val, byte_kind(n, range, reloc), span);
                }
                out.push(enc.variant());
            }
            Place::Imm { li, bits } => {
                let ladder: &[(u8, Range)] = match bits {
                    8 => &[(1, Range::Either)],
                    16 => &[(1, Range::Signed), (2, Range::Either)],
                    _ => &[
                        (1, Range::Signed),
                        (2, Range::Signed),
                        (3, Range::Signed),
                        (4, Range::Either),
                    ],
                };
                for &(n, range) in ladder {
                    let mut enc = enc.clone();
                    enc.field(li_code(n), li, 2);
                    enc.fixup(val, byte_kind(n, range, imm_reloc(n)), span);
                    out.push(enc.variant());
                }
            }
        }
    }
    out
}

/// `-e` for a difference of labels `e`, written as the reverse difference.
fn negated_difference(cx: &mut AsmCtx<'_>, e: ExprRef, span: Span) -> ExprRef {
    let v = SymbolEnv::new(cx.exprs, cx.symbols).value(e);
    let Some(Value {
        addend,
        plus: Some(p),
        minus: Some(m),
    }) = v
    else {
        return cx.exprs.alloc(ExprKind::Unary(UnOp::Neg, e), span);
    };
    let m = cx.exprs.alloc(ExprKind::SymId(m), span);
    let p = cx.exprs.alloc(ExprKind::SymId(p), span);
    let diff = cx.exprs.alloc(ExprKind::Binary(BinOp::Sub, m, p), span);
    let k = cx.exprs.int(addend as u64, span);
    cx.exprs.alloc(ExprKind::Binary(BinOp::Sub, diff, k), span)
}

/// The relocation GNU as gives an `n`-byte immediate.
fn imm_reloc(n: u8) -> u32 {
    match n {
        1 => reloc::DIR8S,
        2 => reloc::DIR16,
        3 => reloc::DIR24S,
        _ => reloc::DIR32,
    }
}

/// The forms GNU as uses for a non-constant immediate. `relax` is true for a
/// difference, which it sizes by value; any other symbol gets 32 bits.
fn symbolic(
    cx: &mut AsmCtx<'_>,
    rungs: Vec<Rung>,
    e: ExprRef,
    span: Span,
    relax: bool,
) -> Option<Vec<Variant>> {
    let mut rungs: Vec<Rung> = rungs.into_iter().filter(|r| r.symbolic).collect();
    let Some(last) = rungs.pop() else {
        cx.error(span, "this immediate must be a constant");
        return None;
    };
    let mut out = Vec::new();
    match last.place {
        Place::Imm { li, .. } if last.negate => {
            // The stored value is `-e`: always 32 bits in GNU as. A difference
            // resolves in the file and is negated when written; a symbol would
            // need GNU as's stack-machine relocation (`R_RX_SYM`, `R_RX_OPneg`,
            // `R_RX_ABS32`), which one fixup cannot express.
            if !relax {
                cx.error(
                    span,
                    "a symbolic immediate here would be stored negated, which needs a \
                     relocation expression rsasm cannot emit",
                );
                return None;
            }
            let mut enc = last.enc;
            enc.field(0, li, 2);
            enc.fixup(e, FixupKind::data(4).scatter(negate4), span);
            out.push(enc.variant());
        }
        Place::Imm { li, .. } => {
            let ladder: &[u8] = if relax && !last.wide_when_symbolic {
                &[1, 2, 3, 4]
            } else {
                &[4]
            };
            for &n in ladder {
                let mut enc = last.enc.clone();
                enc.field(li_code(n), li, 2);
                let range = if n == 4 { Range::Either } else { Range::Signed };
                enc.fixup(e, byte_kind(n, range, imm_reloc(n)), span);
                out.push(enc.variant());
            }
        }
        Place::Bytes { n, range, reloc } => {
            let mut enc = last.enc;
            enc.fixup(e, byte_kind(n, range, reloc), span);
            out.push(enc.variant());
        }
        Place::Nibble(_) => {
            cx.error(span, "this immediate must be a constant");
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_count_from_the_most_significant_bit() {
        let mut e = Enc::new(&[0, 0]);
        e.field(0xb, 4, 4);
        assert_eq!(e.bytes, [0x0b, 0]);
        // A field that straddles two bytes.
        let mut e = Enc::new(&[0, 0]);
        e.field(0b101, 7, 3);
        assert_eq!(e.bytes, [0x01, 0x40]);
    }

    #[test]
    fn immediates_are_sign_folded_to_their_operand_width() {
        assert_eq!(imm_len(0xffff_ffff, 32), Some(1));
        assert_eq!(imm_len(0x80, 32), Some(2));
        assert_eq!(imm_len(-129, 32), Some(2));
        assert_eq!(imm_len(0xff, 8), Some(1));
        assert_eq!(imm_len(0x100, 8), None);
        assert_eq!(imm_len(0x8000, 16), Some(2));
        assert_eq!(imm_len(0x1_0000_0000, 32), None);
    }

    #[test]
    fn unsigned_rungs_scatter_back_their_midpoint() {
        assert_eq!(hi_nibble_plus8(0x05, 15 - 8), 0xf5);
        assert_eq!(lo_nibble_plus8(0x50, -8), 0x50);
        assert_eq!(byte_plus128(0, 255 - 128), 0xff);
    }
}
