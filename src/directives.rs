//! Built-in assembler directives.
//!
//! Anything the table here does not claim is offered to the current
//! architecture backend, which is how `.code64` and `.intel_syntax` are
//! handled without the core knowing about x86.

use crate::assembler::{Assembler, Cond};
use crate::cursor::Cursor;
use crate::expr::ExprRef;
use crate::intern::Name;
use crate::lexer::{Punct, TokKind};
use crate::parser::Statement;
use crate::section::{FragKind, Fragment, SectionFlags, SectionKind};
use crate::source::Span;
use crate::symbol::{Binding, SymType, SymbolValue, Visibility};
use std::path::PathBuf;

impl Assembler {
    pub(crate) fn directive(&mut self, stmt: &Statement, name: Name) {
        let text = self.interner.get(name).to_string();
        let mut cur = stmt.arg_cursor();
        let span = stmt.span;

        let handled = match text.as_str() {
            // ---- sections -------------------------------------------------
            ".text" | ".data" | ".bss" | ".rodata" => {
                let id = self.standard_section(&text);
                self.set_section(id);
                true
            }
            ".section" => self.dir_section(&mut cur, span, false),
            ".pushsection" => self.dir_section(&mut cur, span, true),
            ".popsection" => {
                match self.pop_section() {
                    Some(id) => self.cur = id,
                    None => self
                        .diags
                        .error(span, "`.popsection` without a matching `.pushsection`"),
                }
                true
            }
            ".previous" => {
                self.swap_previous();
                true
            }

            // ---- data -----------------------------------------------------
            ".byte" => self.dir_data(&mut cur, 1, span),
            ".short" | ".hword" | ".half" | ".2byte" => self.dir_data(&mut cur, 2, span),
            // `.word` is the one data directive whose width depends on the
            // target, so it asks the backend rather than assuming x86.
            ".word" => {
                let w = self.arch.word_bytes();
                self.dir_data(&mut cur, w, span)
            }
            ".int" | ".long" | ".4byte" => self.dir_data(&mut cur, 4, span),
            // `.dword` (MIPS, RISC-V) and `.xword` (AArch64, SPARC V9) both
            // mean eight bytes; accepting them everywhere is harmless, since
            // neither has a different meaning on any other target.
            ".quad" | ".8byte" | ".dword" | ".xword" => self.dir_data(&mut cur, 8, span),
            ".ascii" => self.dir_ascii(&mut cur, false, span),
            ".asciz" | ".string" | ".asciiz" => self.dir_ascii(&mut cur, true, span),
            ".sleb128" => self.dir_leb(&mut cur, true, span),
            ".uleb128" => self.dir_leb(&mut cur, false, span),
            ".zero" => self.dir_space(&mut cur, span, true),
            ".space" | ".skip" => self.dir_space(&mut cur, span, false),
            ".fill" => self.dir_fill(&mut cur, span),
            ".incbin" => self.dir_incbin(&mut cur, span),

            // ---- layout ---------------------------------------------------
            ".align" | ".balign" => self.dir_align(&mut cur, span, false),
            ".p2align" => self.dir_align(&mut cur, span, true),
            ".org" => {
                if let Some(e) = self.parse_expr(&mut cur) {
                    let fill = self.optional_byte(&mut cur, 0);
                    self.push_frag(
                        FragKind::Org {
                            target: e,
                            fill,
                            size: 0,
                        },
                        span,
                    );
                }
                true
            }

            // ---- symbols --------------------------------------------------
            ".globl" | ".global" => self.dir_binding(&mut cur, Binding::Global, span),
            ".weak" => self.dir_binding(&mut cur, Binding::Weak, span),
            ".local" => self.dir_binding(&mut cur, Binding::Local, span),
            ".hidden" => self.dir_visibility(&mut cur, Visibility::Hidden, span),
            ".protected" => self.dir_visibility(&mut cur, Visibility::Protected, span),
            ".internal" => self.dir_visibility(&mut cur, Visibility::Internal, span),
            // `.set word` with nothing after it is not an assignment: MIPS
            // uses it for assembler options (`.set noreorder`). Only `.set`
            // has that second meaning, so the other spellings go straight
            // to the assignment.
            ".set" if Self::is_set_option(&cur) => false,
            ".set" | ".equ" | ".equiv" => self.dir_set(&mut cur, span, text == ".equiv"),
            ".size" => self.dir_size(&mut cur, span),
            ".type" => self.dir_type(&mut cur, span),
            ".comm" => self.dir_comm(&mut cur, span, false),
            ".lcomm" => self.dir_comm(&mut cur, span, true),

            // ---- conditionals ---------------------------------------------
            ".if" | ".ifeq" | ".ifne" | ".ifdef" | ".ifndef" | ".ifb" | ".ifnb" => {
                self.dir_if(&mut cur, &text, span)
            }
            ".elseif" | ".elif" => self.dir_elseif(&mut cur, span),
            ".else" => {
                self.dir_else(span);
                true
            }
            ".endif" => {
                if self.pop_cond().is_none() {
                    self.diags.error(span, "`.endif` without a matching `.if`");
                }
                true
            }

            // ---- diagnostics ----------------------------------------------
            ".error" | ".err" => {
                let msg = self
                    .optional_string(&mut cur)
                    .unwrap_or_else(|| ".error directive".into());
                self.diags.error(span, msg);
                true
            }
            ".warning" => {
                let msg = self
                    .optional_string(&mut cur)
                    .unwrap_or_else(|| ".warning directive".into());
                self.diags.warning(span, msg);
                true
            }

            // ---- macros ---------------------------------------------------
            // `.macro`, `.endm`, `.exitm`, `.rept`, `.irp`, `.irpc` and
            // `.endr` never reach here: the statement walker intercepts them
            // because they consume the statements that follow. Only `.purgem`
            // is an ordinary directive.
            ".purgem" => self.dir_purgem(&mut cur),

            // ---- files and configuration ----------------------------------
            ".include" => self.dir_include(&mut cur, span),
            ".arch" | ".cpu" => self.dir_arch(&mut cur, span),
            // Recognised and ignored: they carry no information this assembler
            // acts on yet, and rejecting them would break real-world input.
            ".file" | ".ident" | ".version" | ".loc" | ".line" => {
                cur.set_pos(cur.all().len());
                true
            }
            _ if text.starts_with(".cfi_") => {
                cur.set_pos(cur.all().len());
                true
            }
            _ => false,
        };

        if handled {
            self.expect_end(&mut cur);
            return;
        }

        // Give the architecture a chance before reporting it unknown.
        let mut cur = stmt.arg_cursor();
        let Assembler {
            arch,
            interner,
            exprs,
            diags,
            pool,
            symbols,
            arch_state,
            ..
        } = self;
        let mut cx = crate::arch::AsmCtx {
            interner,
            exprs,
            diags,
            pool,
            symbols,
            state: arch_state,
        };
        if arch.directive(&mut cx, &text, &mut cur) {
            self.expect_end(&mut cur);
            return;
        }

        if text == ".set" {
            let opt = match stmt.arg_cursor().rest().first().map(|t| t.kind) {
                Some(TokKind::Ident(n)) => self.interner.get(n).to_string(),
                _ => String::new(),
            };
            self.diags.emit(
                crate::diag::Diagnostic::error(
                    span,
                    format!(
                        "`.set {opt}` is not an option the `{}` backend understands",
                        self.arch.name()
                    ),
                )
                .with_help("to define a symbol, write `.set name, value`"),
            );
            return;
        }
        self.diags
            .error(span, format!("unknown directive `{text}`"));
    }

    // ---- helpers ----------------------------------------------------------

    fn push_frag(&mut self, kind: FragKind, span: Span) {
        self.cur_section().push(Fragment::new(kind, span));
    }

    /// Reads an optional `, expr` trailing byte value.
    fn optional_byte(&mut self, cur: &mut Cursor<'_>, default: u8) -> u8 {
        if cur.eat_punct(Punct::Comma).is_none() {
            return default;
        }
        match self.parse_expr(cur) {
            Some(e) => self
                .eval_absolute(e, "fill value")
                .unwrap_or(default as i64) as u8,
            None => default,
        }
    }

    fn optional_string(&mut self, cur: &mut Cursor<'_>) -> Option<String> {
        let TokKind::Str(i) = cur.peek().kind else {
            return None;
        };
        cur.advance();
        Some(String::from_utf8_lossy(self.pool.get(i)).into_owned())
    }

    fn expect_string(&mut self, cur: &mut Cursor<'_>, what: &str) -> Option<Vec<u8>> {
        let tok = cur.peek();
        let TokKind::Str(i) = tok.kind else {
            self.diags
                .error(tok.span, format!("expected a string {what}"));
            return None;
        };
        cur.advance();
        Some(self.pool.get(i).to_vec())
    }

    fn expect_name(&mut self, cur: &mut Cursor<'_>) -> Option<(Name, Span)> {
        let tok = cur.peek();
        match tok.ident() {
            Some(n) => {
                cur.advance();
                Some((n, tok.span))
            }
            None => {
                self.diags.error(tok.span, "expected a symbol name");
                None
            }
        }
    }

    // ---- data -------------------------------------------------------------

    fn dir_data(&mut self, cur: &mut Cursor<'_>, size: u8, span: Span) -> bool {
        if cur.at_end() {
            return true;
        }
        loop {
            let Some(e) = self.parse_expr(cur) else {
                return true;
            };
            self.emit_value(size, e, span);
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    /// Emits `size` bytes for `e`, as literal bytes when it already folds to a
    /// constant and as a fixup otherwise.
    pub(crate) fn emit_value(&mut self, size: u8, e: ExprRef, span: Span) {
        if self.check_nobits(span) {
            return;
        }
        // Resolve now if it already has a value: a `.set` symbol is a
        // snapshot at each use, so a later redefinition must not reach back
        // and change bytes that were already emitted.
        if let Some(v) = self.eval_ref(e).ok().and_then(|v| v.as_abs()) {
            let kind = crate::section::FixupKind::data(size);
            if !kind.fits(v as i128) {
                let espan = self.exprs.span(e);
                self.diags
                    .error(espan, format!("value {v} does not fit in {size} byte(s)"));
                return;
            }
            let bytes = self.arch.endian().bytes(v as u64, size as usize);
            self.cur_section().emit_bytes(&bytes, span);
            return;
        }
        let mut reloc = self.arch.data_reloc(size, false).unwrap_or(0);
        // A modifier the target does not recognise used to fall back to the
        // plain data relocation, so `.long foo@got` quietly became an
        // absolute reference to `foo`. That is a different program, so it is
        // an error instead.
        if let Some(m) = self.find_modifier(e) {
            let name = self.interner.get(m).to_string();
            match self.arch.modifier_reloc(&name, size, false) {
                Some(r) => reloc = r,
                None => {
                    let espan = self.exprs.span(e);
                    self.diags.error(
                        espan,
                        format!(
                            "`@{name}` is not a relocation modifier the `{}` backend supports \
                             in a {size}-byte data field",
                            self.arch.name()
                        ),
                    );
                    return;
                }
            }
        }
        let kind = crate::section::FixupKind::data(size).with_reloc(reloc);
        let espan = self.exprs.span(e);
        self.cur_section().emit_fixup(size, e, kind, espan);
    }

    fn dir_ascii(&mut self, cur: &mut Cursor<'_>, terminate: bool, span: Span) -> bool {
        if cur.at_end() {
            return true;
        }
        loop {
            let Some(mut bytes) = self.expect_string(cur, "literal") else {
                return true;
            };
            if terminate {
                bytes.push(0);
            }
            self.emit_bytes(&bytes, span);
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    fn dir_leb(&mut self, cur: &mut Cursor<'_>, signed: bool, span: Span) -> bool {
        loop {
            let Some(e) = self.parse_expr(cur) else {
                return true;
            };
            if !self.check_nobits(span) {
                self.push_frag(
                    FragKind::Leb128 {
                        value: e,
                        signed,
                        encoded: vec![0],
                    },
                    span,
                );
            }
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    fn dir_space(&mut self, cur: &mut Cursor<'_>, span: Span, zero_only: bool) -> bool {
        let Some(size) = self.parse_expr(cur) else {
            return true;
        };
        let fill = if zero_only {
            self.exprs.int(0, span)
        } else if cur.eat_punct(Punct::Comma).is_some() {
            match self.parse_expr(cur) {
                Some(e) => e,
                None => return true,
            }
        } else {
            self.exprs.int(0, span)
        };
        self.push_frag(
            FragKind::Space {
                size,
                fill,
                resolved: 0,
            },
            span,
        );
        true
    }

    fn dir_fill(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some(count_e) = self.parse_expr(cur) else {
            return true;
        };
        let Some(count) = self.eval_absolute(count_e, "`.fill` count") else {
            return true;
        };
        let mut size: i64 = 1;
        let mut value: i64 = 0;
        if cur.eat_punct(Punct::Comma).is_some() {
            let Some(e) = self.parse_expr(cur) else {
                return true;
            };
            size = self.eval_absolute(e, "`.fill` size").unwrap_or(1);
            if cur.eat_punct(Punct::Comma).is_some() {
                let Some(e) = self.parse_expr(cur) else {
                    return true;
                };
                value = self.eval_absolute(e, "`.fill` value").unwrap_or(0);
            }
        }
        if count < 0 || size < 0 {
            self.diags
                .error(span, "`.fill` count and size must not be negative");
            return true;
        }
        if !(0..=8).contains(&size) {
            self.diags
                .error(span, "`.fill` size must be between 0 and 8");
            return true;
        }
        let total = (count as u64).saturating_mul(size as u64);
        if total > (1 << 28) {
            self.diags
                .error(span, "`.fill` would emit more than 256 MiB");
            return true;
        }
        let unit = self.arch.endian().bytes(value as u64, size as usize);
        let mut bytes = Vec::with_capacity(total as usize);
        for _ in 0..count {
            bytes.extend_from_slice(&unit);
        }
        self.emit_bytes(&bytes, span);
        true
    }

    fn dir_incbin(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some(name) = self.expect_string(cur, "file name") else {
            return true;
        };
        let name = String::from_utf8_lossy(&name).into_owned();
        let Some(path) = self.find_include(&name) else {
            self.diags.error(span, format!("cannot find `{name}`"));
            return true;
        };
        match std::fs::read(&path) {
            Ok(data) => self.emit_bytes(&data, span),
            Err(e) => self
                .diags
                .error(span, format!("cannot read `{}`: {e}", path.display())),
        }
        true
    }

    // ---- layout -----------------------------------------------------------

    fn dir_align(&mut self, cur: &mut Cursor<'_>, span: Span, power_of_two: bool) -> bool {
        let Some(e) = self.parse_expr(cur) else {
            return true;
        };
        let Some(n) = self.eval_absolute(e, "alignment") else {
            return true;
        };
        if n < 0 || n > 60 && power_of_two {
            self.diags.error(span, "alignment is out of range");
            return true;
        }
        let align: u64 = if power_of_two {
            1u64 << n
        } else {
            if n == 0 {
                return true;
            }
            if !(n as u64).is_power_of_two() {
                self.diags
                    .error(span, format!("alignment {n} is not a power of two"));
                return true;
            }
            n as u64
        };

        let mut fill_expr = None;
        let mut max_skip = None;
        if cur.eat_punct(Punct::Comma).is_some() {
            if !cur.check_punct(Punct::Comma) {
                fill_expr = self.parse_expr(cur);
            }
            if cur.eat_punct(Punct::Comma).is_some()
                && let Some(e) = self.parse_expr(cur)
            {
                max_skip = self
                    .eval_absolute(e, "`.align` maximum skip")
                    .map(|v| v.max(0) as u64);
            }
        }

        // Executable sections pad with real no-ops so the padding stays
        // executable; everything else pads with zeroes.
        let fill = match fill_expr {
            Some(e) => vec![self.eval_absolute(e, "fill value").unwrap_or(0) as u8],
            None if self.section(self.cur).flags.exec => Vec::new(),
            None => vec![0],
        };
        self.push_frag(
            FragKind::Align {
                align,
                fill,
                max_skip,
                pad: 0,
            },
            span,
        );
        self.section_mut(self.cur).align = self.section(self.cur).align.max(align);
        true
    }

    // ---- sections ---------------------------------------------------------

    fn dir_section(&mut self, cur: &mut Cursor<'_>, _span: Span, push: bool) -> bool {
        let tok = cur.peek();
        let name = match tok.kind {
            TokKind::Ident(n) => {
                cur.advance();
                n
            }
            TokKind::Str(i) => {
                cur.advance();
                let s = String::from_utf8_lossy(self.pool.get(i)).into_owned();
                self.interner.intern(&s)
            }
            _ => {
                self.diags.error(tok.span, "expected a section name");
                return true;
            }
        };

        let text = self.interner.get(name).to_string();
        let mut kind = if text.starts_with(".bss") {
            SectionKind::Nobits
        } else {
            SectionKind::Progbits
        };
        let mut flags = default_flags_for(&text);
        let mut entsize = 0u64;

        if cur.eat_punct(Punct::Comma).is_some() {
            if let Some(s) = self.expect_string(cur, "of section flags") {
                flags = parse_flags(&String::from_utf8_lossy(&s));
            }
            // `,@progbits` or `,%progbits`
            if cur.eat_punct(Punct::Comma).is_some() {
                if cur.eat_punct(Punct::At).is_none() {
                    cur.eat_punct(Punct::Percent);
                }
                if let Some((tn, _)) = self.expect_name(cur) {
                    let t = self.interner.get(tn).to_ascii_lowercase();
                    kind = match t.as_str() {
                        "nobits" => SectionKind::Nobits,
                        "note" => SectionKind::Note,
                        _ => SectionKind::Progbits,
                    };
                }
                if cur.eat_punct(Punct::Comma).is_some()
                    && let Some(e) = self.parse_expr(cur)
                {
                    entsize = self
                        .eval_absolute(e, "section entry size")
                        .unwrap_or(0)
                        .max(0) as u64;
                }
            }
        }

        let id = self.get_or_create_section(name, kind, flags, 1);
        self.section_mut(id).entsize = entsize;
        if push {
            self.push_section_stack();
        }
        self.set_section(id);
        true
    }

    // ---- symbols ----------------------------------------------------------

    fn dir_binding(&mut self, cur: &mut Cursor<'_>, binding: Binding, _span: Span) -> bool {
        loop {
            let Some((name, span)) = self.expect_name(cur) else {
                return true;
            };
            let id = self.symbols.intern(name, span);
            self.symbols.get_mut(id).binding = binding;
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    fn dir_visibility(&mut self, cur: &mut Cursor<'_>, vis: Visibility, _span: Span) -> bool {
        loop {
            let Some((name, span)) = self.expect_name(cur) else {
                return true;
            };
            let id = self.symbols.intern(name, span);
            self.symbols.get_mut(id).visibility = vis;
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    /// True for `.set word` — a single identifier and nothing else, which no
    /// assignment can be. Returning `false` from the table sends it on to the
    /// architecture's directive hook.
    fn is_set_option(cur: &Cursor<'_>) -> bool {
        let rest = cur.rest();
        rest.len() == 1 && matches!(rest[0].kind, TokKind::Ident(_))
    }

    fn dir_set(&mut self, cur: &mut Cursor<'_>, span: Span, once_only: bool) -> bool {
        let Some((name, nspan)) = self.expect_name(cur) else {
            return true;
        };
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags.error(span, "expected `,` after the symbol name");
            return true;
        }
        let Some(e) = self.parse_expr(cur) else {
            return true;
        };
        let id = self.symbols.intern(name, nspan);
        if once_only && self.symbols.get(id).is_defined() {
            let prev = self.symbols.get(id).def_span;
            let display = self.display_name(id);
            self.diags.emit(
                crate::diag::Diagnostic::error(span, format!("`{display}` is already defined"))
                    .with_note(prev, "previous definition is here"),
            );
            return true;
        }
        let sym = self.symbols.get_mut(id);
        sym.value = SymbolValue::Expr(e);
        sym.def_span = nspan;
        sym.redefinable = !once_only;
        true
    }

    fn dir_size(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some((name, nspan)) = self.expect_name(cur) else {
            return true;
        };
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags.error(span, "expected `,` after the symbol name");
            return true;
        }
        let Some(e) = self.parse_expr(cur) else {
            return true;
        };
        let id = self.symbols.intern(name, nspan);
        self.symbols.get_mut(id).size = Some(e);
        true
    }

    fn dir_type(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some((name, nspan)) = self.expect_name(cur) else {
            return true;
        };
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags.error(span, "expected `,` after the symbol name");
            return true;
        }
        // The type is written `@function`, `%function` or `STT_FUNC`.
        if cur.eat_punct(Punct::At).is_none() {
            cur.eat_punct(Punct::Percent);
        }
        let Some((tname, tspan)) = self.expect_name(cur) else {
            return true;
        };
        let t = self.interner.get(tname).to_ascii_lowercase();
        let ty = match t.trim_start_matches("stt_") {
            "function" | "func" => SymType::Func,
            "object" => SymType::Object,
            "notype" => SymType::NoType,
            "tls_object" | "tls" => SymType::Tls,
            "common" => SymType::Object,
            other => {
                self.diags
                    .error(tspan, format!("unknown symbol type `{other}`"));
                return true;
            }
        };
        let id = self.symbols.intern(name, nspan);
        self.symbols.get_mut(id).ty = ty;
        let _ = span;
        true
    }

    fn dir_comm(&mut self, cur: &mut Cursor<'_>, span: Span, local: bool) -> bool {
        let Some((name, nspan)) = self.expect_name(cur) else {
            return true;
        };
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags.error(span, "expected `,` and a size");
            return true;
        }
        let Some(e) = self.parse_expr(cur) else {
            return true;
        };
        let Some(size) = self.eval_absolute(e, "`.comm` size") else {
            return true;
        };
        let mut align = 1u64;
        if cur.eat_punct(Punct::Comma).is_some()
            && let Some(e) = self.parse_expr(cur)
        {
            align = self
                .eval_absolute(e, "`.comm` alignment")
                .unwrap_or(1)
                .max(1) as u64;
        }
        if size < 0 {
            self.diags.error(span, "`.comm` size must not be negative");
            return true;
        }
        let id = self.symbols.intern(name, nspan);
        let sym = self.symbols.get_mut(id);
        sym.value = SymbolValue::Common {
            size: size as u64,
            align,
        };
        sym.def_span = nspan;
        sym.ty = SymType::Object;
        if !local {
            sym.binding = Binding::Global;
        }
        true
    }

    // ---- conditionals -----------------------------------------------------

    fn dir_if(&mut self, cur: &mut Cursor<'_>, kind: &str, span: Span) -> bool {
        // A conditional nested inside a false branch is pushed inactive
        // without evaluating its condition, which may not even be resolvable.
        if !self.cond_active() {
            self.push_cond(Cond {
                active: false,
                taken: true,
                seen_else: false,
                span,
            });
            cur.set_pos(cur.all().len());
            return true;
        }
        let value = self.eval_condition(cur, kind);
        self.push_cond(Cond {
            active: value,
            taken: value,
            seen_else: false,
            span,
        });
        true
    }

    fn eval_condition(&mut self, cur: &mut Cursor<'_>, kind: &str) -> bool {
        match kind {
            ".ifdef" | ".ifndef" => {
                let defined = match self.expect_name(cur) {
                    Some((name, _)) => self
                        .symbols
                        .lookup(name)
                        .is_some_and(|id| self.symbols.get(id).is_defined()),
                    None => false,
                };
                if kind == ".ifdef" { defined } else { !defined }
            }
            ".ifb" | ".ifnb" => {
                let blank = cur.at_end() || cur.is_empty();
                cur.set_pos(cur.all().len());
                if kind == ".ifb" { blank } else { !blank }
            }
            _ => {
                let Some(e) = self.parse_expr(cur) else {
                    return false;
                };
                let Some(v) = self.eval_absolute(e, "`.if` condition") else {
                    return false;
                };
                match kind {
                    ".ifeq" => v == 0,
                    ".ifne" => v != 0,
                    _ => v != 0,
                }
            }
        }
    }

    fn dir_elseif(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some(state) = self.cond_top() else {
            self.diags.error(span, "`.elseif` without a matching `.if`");
            cur.set_pos(cur.all().len());
            return true;
        };
        if state.seen_else {
            self.diags.error(span, "`.elseif` after `.else`");
            cur.set_pos(cur.all().len());
            return true;
        }
        if state.taken {
            // An earlier branch already won; skip this condition entirely
            // rather than evaluating something that may not resolve.
            self.set_cond_active(false);
            cur.set_pos(cur.all().len());
            return true;
        }
        // Evaluating the condition needs the enclosing conditional to look
        // active, which it is: `taken` is false only when no branch ran.
        let outer_active = self.enclosing_cond_active();
        let value = outer_active && self.eval_condition(cur, ".if");
        self.set_cond_active(value);
        if value {
            self.mark_cond_taken();
        }
        true
    }

    fn dir_else(&mut self, span: Span) {
        let Some(state) = self.cond_top() else {
            self.diags.error(span, "`.else` without a matching `.if`");
            return;
        };
        if state.seen_else {
            self.diags.error(span, "duplicate `.else`");
            return;
        }
        let taken = state.taken;
        let outer_active = self.enclosing_cond_active();
        self.mark_cond_else();
        self.set_cond_active(outer_active && !taken);
        if !taken {
            self.mark_cond_taken();
        }
    }

    // ---- files ------------------------------------------------------------

    pub(crate) fn find_include(&self, name: &str) -> Option<PathBuf> {
        let direct = PathBuf::from(name);
        if direct.is_absolute() && direct.exists() {
            return Some(direct);
        }
        for dir in &self.options.include_paths {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
        }
        direct.exists().then_some(direct)
    }

    fn dir_purgem(&mut self, cur: &mut Cursor<'_>) -> bool {
        loop {
            let Some((name, span)) = self.expect_name(cur) else {
                return true;
            };
            let lowered = self.interner.get(name).to_ascii_lowercase();
            let key = self.interner.intern(&lowered);
            if self.macros.remove(&key).is_none() {
                self.diags
                    .error(span, format!("no macro named `{lowered}` to purge"));
            }
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
        true
    }

    fn dir_include(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let Some(name) = self.expect_string(cur, "file name") else {
            return true;
        };
        let name = String::from_utf8_lossy(&name).into_owned();
        let Some(path) = self.find_include(&name) else {
            self.diags
                .error(span, format!("cannot find include file `{name}`"));
            return true;
        };
        self.include(&path, span);
        true
    }

    fn dir_arch(&mut self, cur: &mut Cursor<'_>, span: Span) -> bool {
        let tok = cur.peek();
        let name = match tok.kind {
            TokKind::Ident(n) => {
                cur.advance();
                self.interner.get(n).to_string()
            }
            TokKind::Str(i) => {
                cur.advance();
                String::from_utf8_lossy(self.pool.get(i)).into_owned()
            }
            _ => {
                self.diags.error(tok.span, "expected an architecture name");
                return true;
            }
        };
        match crate::arch::lookup(&name) {
            Some(a) => self.switch_arch(a),
            None => {
                let avail = crate::arch::available().join(", ");
                self.diags.emit(
                    crate::diag::Diagnostic::error(span, format!("unknown architecture `{name}`"))
                        .with_help(format!("this build supports: {avail}")),
                );
            }
        }
        true
    }
}

fn default_flags_for(name: &str) -> SectionFlags {
    if name.starts_with(".text") || name == ".init" || name == ".fini" {
        SectionFlags::text()
    } else if name.starts_with(".rodata") {
        SectionFlags::rodata()
    } else if name.starts_with(".data") || name.starts_with(".bss") {
        SectionFlags::data()
    } else {
        SectionFlags::default()
    }
}

fn parse_flags(s: &str) -> SectionFlags {
    let mut f = SectionFlags::default();
    for c in s.chars() {
        match c {
            'a' => f.alloc = true,
            'w' => f.write = true,
            'x' => f.exec = true,
            'M' => f.merge = true,
            'S' => f.strings = true,
            'T' => f.tls = true,
            'G' => f.group = true,
            _ => {}
        }
    }
    f
}
