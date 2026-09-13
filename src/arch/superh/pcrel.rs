//! Branches and PC-relative loads.
//!
//! # The PC base
//!
//! SH executes a branch's delay slot before the branch takes effect, and the
//! program counter a PC-relative field is added to is the address of the
//! instruction plus four: two instructions on, past the delay slot. Every
//! PC-relative field here is therefore a fixup with `adjust = 4`, so the
//! value it receives is `target - (here + 4)` in bytes, and the field stores
//! that divided by the instruction width or the operand size.
//!
//! The longword loads, `mov.l label,rn` and `mova label,r0`, differ in one
//! more way: the CPU clears the low two bits of `PC + 4` first, so the base
//! depends on whether the instruction itself sits on a four-byte boundary.
//! See [`load`].
//!
//! # Delay slots
//!
//! Nothing here moves an instruction into a delay slot or fills one: the
//! instruction after a delayed branch is whatever the source put there. The
//! one change of shape is GNU as's own for a conditional branch that cannot
//! reach its target, described at [`cond_branch`].

use super::encode::{Pending, Words, disp8_by2, disp8_by4};
use super::operand::{Kind, Value};
use crate::arch::{AsmCtx, Endian};
use crate::expr::{BinOp, ExprKind, ExprRef, UnOp};
use crate::section::{FixupKind, Variant};
use crate::source::Span;

const NOP: u16 = 0x0009;
const BRA: u16 = 0xa000;

// ---- branches ---------------------------------------------------------------

/// `bt` / `bf` and their delayed forms: eight bits of signed word count.
fn branch8(word: u64, v: i64) -> u64 {
    (word & !0xff) | ((v >> 1) as u64 & 0xff)
}

/// `bra` / `bsr`: twelve bits of signed word count.
fn branch12(word: u64, v: i64) -> u64 {
    (word & !0xfff) | ((v >> 1) as u64 & 0xfff)
}

/// A conditional branch's field: 8 bits of instructions, so 9 bits of byte
/// offset from PC + 4, reaching -256 to +254.
fn branch8_fixup() -> FixupKind {
    FixupKind::pcrel(2, 4).with_field(9, 2).scatter(branch8)
}

/// `bra` / `bsr`: 12 bits of instructions, -4096 to +4094 bytes.
fn branch12_fixup() -> FixupKind {
    FixupKind::pcrel(2, 4).with_field(13, 2).scatter(branch12)
}

/// `bra` and `bsr`, which have no longer form to grow into.
///
/// No relocation is offered: GNU as does not emit one for a branch to
/// another section or to an undefined symbol either (it reports that the
/// displacement overflows), since an out-of-section 12-bit reach is not
/// something a linker could honour in general.
pub fn branch(word: u16, target: Value, endian: Endian) -> Variant {
    let mut w = Words::new(endian);
    w.push(word, [pending(target, branch12_fixup())]);
    w.finish()
}

/// `bt`, `bf`, `bt/s` and `bf/s`.
///
/// SH has no long conditional branch, so when the target is out of an
/// 8-bit reach GNU as rewrites the branch as the opposite condition jumping
/// over a `bra` — and, since a `bra` has a delay slot of its own, puts a `nop`
/// in that slot:
///
/// ```text
/// bt far        =>   bf 1f
///                    bra far
///                    nop
///                 1:
/// ```
///
/// A delayed `bt/s` keeps its own slot instruction for the `bra` instead, so
/// it becomes `bf 1f; bra far; 1:`, four bytes rather than six: the slot
/// instruction written after `bt/s` runs whichever way the branch goes, just
/// as it did before. The rewrite is offered as a second variant, and layout
/// takes it only when the short form does not fit; the boundaries match
/// GNU as's exactly, which the corpus checks. GNU as warns when it does
/// this; the layout pass has no way to, so the change is silent here.
///
/// If the `bra` cannot reach either, that is the error reported.
pub fn cond_branch(word: u16, target: Value, endian: Endian) -> Vec<Variant> {
    let mut short = Words::new(endian);
    short.push(word, [pending(target, branch8_fixup())]);

    // Bit 9 selects true/false and bit 10 the delay slot.
    let delayed = word & 0x0400 != 0;
    let inverted = (word ^ 0x0200) & !0x0400;
    let mut long = Words::new(endian);
    // Skip the `bra` (and its `nop`): from PC + 4, that is 0 or 1 words.
    long.push(inverted | if delayed { 0 } else { 1 }, []);
    long.push(BRA, [pending(target, branch12_fixup())]);
    if !delayed {
        long.push(NOP, []);
    }
    vec![short.finish(), long.finish()]
}

fn pending(v: Value, kind: FixupKind) -> Pending {
    Pending {
        expr: v.expr,
        kind,
        span: v.span,
    }
}

// ---- PC-relative loads ------------------------------------------------------

/// A PC-relative fixup for an unsigned field: the data loads only reach
/// forward.
fn unsigned_pcrel(adjust: i8) -> FixupKind {
    FixupKind {
        signed: false,
        ..FixupKind::pcrel(2, adjust)
    }
}

/// Keeps the word as it is: for fixups that exist only for their checks.
fn unchanged(word: u64, _: i64) -> u64 {
    word
}

/// A fixup that is satisfied only when the instruction's own address is
/// congruent to `residue` modulo 4.
///
/// The expression is the absolute number `residue`, so the PC-relative value
/// the layout pass computes is `residue - here`, and requiring it to be a
/// multiple of four is exactly the test. It writes nothing.
fn pc_alignment_check(cx: &mut AsmCtx<'_>, residue: u8, span: Span) -> Pending {
    Pending {
        expr: cx.exprs.int(residue as u64, span),
        kind: FixupKind::pcrel(2, 0).with_field(64, 4).scatter(unchanged),
        span,
    }
}

/// `mov.w label,rn`, `mov.l label,rn` and `mova label,r0`, in either
/// spelling: a bare `label`, or `@(disp,pc)`.
///
/// `word` already holds the register. `scale` is the operand size, which is
/// also what the eight-bit field counts in.
pub fn load(
    cx: &mut AsmCtx<'_>,
    mnemonic: &str,
    word: u16,
    scale: u8,
    kind: Kind,
    span: Span,
    endian: Endian,
) -> Option<Vec<Variant>> {
    let target = match kind {
        Kind::Addr(v) => v,
        Kind::PcDisp(v) => {
            if let Some(n) = cx.constant(v.expr) {
                return load_displacement(cx, mnemonic, word, scale, n, v.span, endian);
            }
            // GNU as still reads `@(label,pc)` as plain `label`, warning that
            // the spelling is deprecated; `@(expr,pc)` with a computed `expr`
            // means `. + expr`, which is only supported for constants here.
            if !is_symbol_plus_constant(cx, v.expr) {
                cx.error(
                    v.span,
                    "the displacement in `@(disp,pc)` must be a constant; write the target \
                     label on its own instead",
                );
                return None;
            }
            cx.diags.warning(
                span,
                "`@(label,pc)` is deprecated syntax for a plain `label`",
            );
            v
        }
        // Matching lets nothing else into a PC-relative slot.
        _ => {
            cx.error(span, format!("`{mnemonic}` needs a label here"));
            return None;
        }
    };

    if scale == 2 {
        // `mov.w`: the base is PC + 4 unrounded, so a word literal anywhere
        // on a two-byte boundary within 510 bytes forward is reachable.
        //
        // The field is unsigned, but the fixup's range check cannot express
        // a lower bound of zero: a literal *before* the instruction is not
        // diagnosed by the layout pass.
        let mut w = Words::new(endian);
        w.push(
            word,
            [pending(
                target,
                unsigned_pcrel(4).with_field(9, 2).scatter(disp8_by2),
            )],
        );
        return Some(vec![w.finish()]);
    }

    // `mov.l` / `mova`: the base is (PC + 4) & ~3. The target must itself be
    // on a four-byte boundary, and the distance from the rounded base is then
    // a multiple of four whichever boundary the instruction is on. A fixup
    // is given only `target - (here + adjust)`, never `here`, so the two
    // cases are two variants with the same bytes, each checking its own
    // assumption about the instruction's address:
    //
    //  - on a four-byte boundary, the base is here + 4;
    //  - two bytes past one, the base is here + 2.
    //
    // Layout keeps the first whose checks pass. As with `mov.w`, a negative
    // distance is not caught.
    //
    // Layout never goes back to an earlier variant, but the instruction can
    // move by two bytes after a choice is made: a `bt/s` before it that
    // relaxes grows by two. So the pair is offered several times over, and
    // each such move steps on to the next copy instead of failing.
    let field = |adjust: i8| unsigned_pcrel(adjust).with_field(10, 4).scatter(disp8_by4);
    let mut variants = Vec::with_capacity(2 * LOAD_ROUNDS + 1);
    for _ in 0..LOAD_ROUNDS {
        let mut aligned = Words::new(endian);
        let check = pc_alignment_check(cx, 0, span);
        aligned.push(word, [pending(target, field(4)), check]);
        variants.push(aligned.finish());
        let mut offset = Words::new(endian);
        let check = pc_alignment_check(cx, 2, span);
        offset.push(word, [pending(target, field(2)), check]);
        variants.push(offset.finish());
    }
    // Reached only when every pair failed, so this variant never stands in
    // the output; it exists for its diagnostics, which the pairs' checks
    // would state in terms of whichever boundary they assumed.
    //
    // The first fixup measures from PC + 2. Relative to that, a reachable
    // literal is at most 1022 bytes away from an instruction on a four-byte
    // boundary and 1020 from one two bytes past it, and an unreachable one
    // at least 1026 or 1024: an unsigned 10-bit field's limit of 1023 falls
    // between the two in both cases, so an unreachable literal is reported
    // as out of range. The other two fixups fail for a literal off a
    // four-byte boundary, one for each position the instruction can have,
    // so exactly one of them reports it. An unreachable literal on a
    // boundary also trips one of them; the range error comes first.
    let mut last = Words::new(endian);
    last.push(
        word,
        [
            pending(
                target,
                unsigned_pcrel(2).with_field(10, 2).scatter(unchanged),
            ),
            pending(
                target,
                unsigned_pcrel(0).with_field(64, 4).scatter(unchanged),
            ),
            pending(
                target,
                unsigned_pcrel(2).with_field(64, 4).scatter(unchanged),
            ),
        ],
    );
    variants.push(last.finish());
    Some(variants)
}

/// How many times a longword load offers its pair of variants: enough for
/// that many delayed branches between it and the last alignment directive to
/// relax. Each costs a layout pass only when a target is misaligned or
/// unresolved, which is an error anyway.
const LOAD_ROUNDS: usize = 3;

/// `@(n,pc)` with a constant `n`, which GNU as reads as the address `. + n`.
fn load_displacement(
    cx: &mut AsmCtx<'_>,
    mnemonic: &str,
    word: u16,
    scale: u8,
    n: i64,
    span: Span,
    endian: Endian,
) -> Option<Vec<Variant>> {
    if n % 2 != 0 {
        cx.error(
            span,
            format!("PC-relative displacement {n} is odd; instructions and data are word-aligned"),
        );
        return None;
    }
    let mut w = Words::new(endian);
    if scale == 2 {
        // From PC + 4: 0 to 255 words.
        if !(4..=514).contains(&n) {
            cx.error(
                span,
                format!("PC-relative displacement {n} is out of range for `{mnemonic}` (4 to 514)"),
            );
            return None;
        }
        w.push(word | ((n - 4) / 2) as u16, []);
        return Some(vec![w.finish()]);
    }
    // From (PC + 4) & ~3: the target `. + n` is on a four-byte boundary only
    // if `n` and the instruction's address agree modulo 4, which leaves
    // `n - 4` or `n - 2` as the distance and `(n - 2) / 4` as the field in
    // both cases. Which case applies is known only at layout, so it is
    // checked there.
    let (lo, hi) = if n % 4 == 0 { (4, 1024) } else { (2, 1022) };
    if !(lo..=hi).contains(&n) {
        cx.error(
            span,
            format!("PC-relative displacement {n} is out of range for `{mnemonic}` ({lo} to {hi})"),
        );
        return None;
    }
    let check = pc_alignment_check(cx, (n & 3) as u8, span);
    w.push(word | ((n - 2) >> 2) as u16, [check]);
    Some(vec![w.finish()])
}

/// True for `sym`, `sym + k` and `sym - k`: the shapes GNU as classifies as a
/// symbol reference rather than a computed displacement.
fn is_symbol_plus_constant(cx: &AsmCtx<'_>, e: ExprRef) -> bool {
    match &cx.exprs.get(e).kind {
        ExprKind::Sym(_) | ExprKind::SymId(_) | ExprKind::LocalRef(..) => true,
        ExprKind::Unary(UnOp::Plus, a) => is_symbol_plus_constant(cx, *a),
        ExprKind::Binary(BinOp::Add, a, b) => {
            (is_symbol_plus_constant(cx, *a) && cx.constant(*b).is_some())
                || (cx.constant(*a).is_some() && is_symbol_plus_constant(cx, *b))
        }
        ExprKind::Binary(BinOp::Sub, a, b) => {
            is_symbol_plus_constant(cx, *a) && cx.constant(*b).is_some()
        }
        _ => false,
    }
}
