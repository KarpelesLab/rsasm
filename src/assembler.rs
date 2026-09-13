//! The assembler driver: section state, statement processing, layout and
//! fixup resolution.

use crate::arch::{ArchState, Architecture, AsmCtx, InsnRequest, Syntax};
use crate::cursor::Cursor;
use crate::diag::{DiagBag, Diagnostic};
use crate::dialect;
use crate::expr::{self, EvalCtx, EvalError, ExprArena, ExprKind, ExprRef, Value};
use crate::intern::{Interner, Name};
use crate::lexer::{Dialect, LexConfig, LitPool, LocalDir, Punct};
use crate::macros::{self, MacroDef};
use crate::parser::{Body, LabelDef, Parser, Statement};
use crate::section::{FragKind, Fragment, Section, SectionFlags, SectionId, SectionKind};
use crate::source::{FileId, SourceMap, Span};
use crate::symbol::{SymbolId, SymbolTable, SymbolValue};
use std::collections::HashMap;
use std::path::PathBuf;

/// A relocation the linker must apply.
#[derive(Clone, Debug)]
pub struct Relocation {
    pub section: SectionId,
    /// Offset within the section.
    pub offset: u64,
    /// `None` for a reference to a plain number, which ELF relocates against
    /// symbol 0.
    pub symbol: Option<SymbolId>,
    pub addend: i64,
    /// Architecture-specific relocation type.
    pub kind: u32,
}

#[derive(Clone, Debug)]
pub struct Options {
    /// Produce a relocatable object (emit relocations) rather than resolving
    /// every reference to a final address.
    pub relocatable: bool,
    /// Base address for absolute output.
    pub base_addr: u64,
    /// Directories searched by `.include`.
    pub include_paths: Vec<PathBuf>,
    pub dialect: Dialect,
    pub syntax: Option<Syntax>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            relocatable: true,
            base_addr: 0,
            include_paths: Vec::new(),
            dialect: Dialect::Gas,
            syntax: None,
        }
    }
}

/// The block constructs the statement walker has to recognise before the
/// ordinary directive table sees them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum BlockKind {
    Macro,
    EndMacro,
    ExitMacro,
    Repeat(RepeatKind),
    EndRepeat,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum RepeatKind {
    Rept,
    Irp,
    Irpc,
}

/// One level of `.if` / `.else` / `.endif`.
pub(crate) struct Cond {
    /// Whether code in the current branch is being assembled.
    pub(crate) active: bool,
    /// Whether any branch of this conditional has been taken yet.
    pub(crate) taken: bool,
    pub(crate) seen_else: bool,
    pub(crate) span: Span,
}

pub struct Assembler {
    pub sm: SourceMap,
    pub interner: Interner,
    pub pool: LitPool,
    pub diags: DiagBag,
    pub exprs: ExprArena,
    pub symbols: SymbolTable,
    pub sections: Vec<Section>,
    pub relocs: Vec<Relocation>,
    section_ids: HashMap<Name, SectionId>,
    pub cur: SectionId,
    /// Where `.previous` goes back to.
    previous: Option<SectionId>,
    section_stack: Vec<(SectionId, Option<SectionId>)>,
    pub arch: Box<dyn Architecture>,
    pub arch_state: ArchState,
    pub options: Options,
    /// The anonymous label standing in for `.` in the current statement.
    here_sym: Option<SymbolId>,
    cond: Vec<Cond>,
    /// Guards against runaway `.include` recursion.
    include_depth: u32,
    /// Macros defined so far, keyed by the lowercased name the parser
    /// produces for a mnemonic.
    pub(crate) macros: HashMap<Name, MacroDef>,
    /// Bumped per macro invocation and substituted for `\@`, which is how
    /// macro bodies name labels that must not collide between calls.
    macro_counter: u64,
    macro_depth: u32,
    /// Set by `.exitm`; unwinds the innermost expansion.
    exiting_macro: bool,
    /// Set by a vendor `END`: nothing after it in the source is assembled.
    pub(crate) end_of_source: bool,
    /// While relaxation weighs another size for one fragment: labels in that
    /// section after that fragment, and still at an offset past `pc`, move
    /// by `shift` bytes. Fields: section, fragment index, `pc`, `shift`.
    pub(crate) relax_shift: Option<(SectionId, u32, u64, i64)>,
    /// The alignment fragments put ahead of data that must already be
    /// aligned, which are errors if they pad; see `Assembler::align_data`.
    pub(crate) align_tests: Vec<(SectionId, u32)>,
    /// CC-RH data values written without `#` that were not constants when
    /// read, to be refused at the end if they are labels; see
    /// `Assembler::cc_data`.
    pub(crate) cc_bare_labels: Vec<ExprRef>,
    /// Numbers the symbols a CC-RL/CC-RH `.LOCAL` renames, across the module.
    cc_local_counter: u64,
    /// CC-RX `.DEFINE` strings, by name; see `Assembler::ccrx_apply_defines`.
    pub(crate) ccrx_defines: Vec<(String, String)>,
    /// What CC-RX `.SECTION` and `.ORG` said about each section.
    pub(crate) ccrx_sections: HashMap<SectionId, crate::dialect_cc::RxSection>,
}

impl Assembler {
    pub fn new(arch: Box<dyn Architecture>, options: Options) -> Assembler {
        let mut interner = Interner::new();
        let arch_state = {
            let mut st = arch.initial_state();
            if let Some(s) = options.syntax {
                st.syntax = s;
            }
            st
        };
        let text = interner.intern(".text");
        let mut asm = Assembler {
            sm: SourceMap::new(),
            interner,
            pool: LitPool::new(),
            diags: DiagBag::new(),
            exprs: ExprArena::new(),
            symbols: SymbolTable::new(),
            sections: Vec::new(),
            relocs: Vec::new(),
            section_ids: HashMap::new(),
            cur: SectionId(0),
            previous: None,
            section_stack: Vec::new(),
            arch,
            arch_state,
            options,
            here_sym: None,
            cond: Vec::new(),
            include_depth: 0,
            macros: HashMap::new(),
            macro_counter: 0,
            macro_depth: 0,
            exiting_macro: false,
            end_of_source: false,
            relax_shift: None,
            align_tests: Vec::new(),
            cc_bare_labels: Vec::new(),
            cc_local_counter: 0,
            ccrx_defines: Vec::new(),
            ccrx_sections: HashMap::new(),
        };
        if asm.options.dialect == Dialect::CcRx {
            // The predefined names CC-RX defines whatever the options
            // (R20UT3248EJ0115 Table 5.36, pages 499-500, note 1), except the
            // version number, which would claim a Renesas release.
            for name in ["__ASRX__", "__RENESAS__"] {
                asm.ccrx_defines.push((name.to_string(), "1".to_string()));
            }
        }
        asm.cur = asm.get_or_create_section(text, SectionKind::Progbits, SectionFlags::text(), 1);
        asm
    }

    // ---- sections ---------------------------------------------------------

    pub fn section(&self, id: SectionId) -> &Section {
        &self.sections[id.0 as usize]
    }

    pub fn section_mut(&mut self, id: SectionId) -> &mut Section {
        &mut self.sections[id.0 as usize]
    }

    pub fn cur_section(&mut self) -> &mut Section {
        let id = self.cur;
        &mut self.sections[id.0 as usize]
    }

    pub fn get_or_create_section(
        &mut self,
        name: Name,
        kind: SectionKind,
        flags: SectionFlags,
        align: u64,
    ) -> SectionId {
        if let Some(&id) = self.section_ids.get(&name) {
            return id;
        }
        let id = SectionId(self.sections.len() as u32);
        let mut s = Section::new(id, name, kind, flags);
        s.align = align.max(1);
        self.sections.push(s);
        self.section_ids.insert(name, id);
        id
    }

    /// Switches to `id`, remembering where `.previous` should return to.
    pub(crate) fn set_section(&mut self, id: SectionId) {
        if id != self.cur {
            self.previous = Some(self.cur);
        }
        self.cur = id;
    }

    pub(crate) fn swap_previous(&mut self) {
        if let Some(prev) = self.previous {
            self.previous = Some(self.cur);
            self.cur = prev;
        }
    }

    pub(crate) fn push_section_stack(&mut self) {
        self.section_stack.push((self.cur, self.previous));
    }

    pub(crate) fn pop_section(&mut self) -> Option<SectionId> {
        let (cur, prev) = self.section_stack.pop()?;
        self.previous = prev;
        Some(cur)
    }

    /// Resolves one of the shorthand section directives.
    pub(crate) fn standard_section(&mut self, name: &str) -> SectionId {
        let (kind, flags, align) = match name {
            ".text" => (SectionKind::Progbits, SectionFlags::text(), 1),
            ".data" => (SectionKind::Progbits, SectionFlags::data(), 1),
            ".bss" => (SectionKind::Nobits, SectionFlags::bss(), 1),
            ".rodata" => (SectionKind::Progbits, SectionFlags::rodata(), 1),
            _ => (SectionKind::Progbits, SectionFlags::default(), 1),
        };
        let n = self.interner.intern(name);
        self.get_or_create_section(n, kind, flags, align)
    }

    // ---- symbols ----------------------------------------------------------

    /// Creates an unnamed label pinned to the current position.
    fn anon_label(&mut self, span: Span) -> SymbolId {
        self.cur_section().seal();
        let frag = self.cur_section().next_frag_index();
        let section = self.cur;
        let n = self.symbols.len();
        let name = self.interner.intern(&format!(".L\u{0}anon.{n}"));
        let id = self.symbols.intern(name, span);
        let sym = self.symbols.get_mut(id);
        sym.value = SymbolValue::Label { section, frag };
        sym.def_span = span;
        id
    }

    fn define_label(&mut self, label: &LabelDef) {
        let (id, span) = match *label {
            LabelDef::Named(name, span) => {
                let id = self.symbols.intern(name, span);
                (id, span)
            }
            LabelDef::Numeric(n, span) => {
                let id = self.symbols.local_define_slot(n, span, &mut self.interner);
                (id, span)
            }
        };
        if self.symbols.get(id).is_defined() {
            let prev = self.symbols.get(id).def_span;
            let name = self.display_name(id);
            self.diags.emit(
                Diagnostic::error(span, format!("symbol `{name}` is already defined"))
                    .with_note(prev, "previous definition is here"),
            );
            return;
        }
        self.cur_section().seal();
        let frag = self.cur_section().next_frag_index();
        let section = self.cur;
        let sym = self.symbols.get_mut(id);
        sym.value = SymbolValue::Label { section, frag };
        sym.def_span = span;
    }

    /// The name to show for a symbol in diagnostics.
    pub fn display_name(&self, id: SymbolId) -> String {
        let s = self.symbols.get(id);
        match s.local_number {
            Some(n) => format!("{n}"),
            None => {
                let raw = self.interner.get(s.name);
                match raw.split('\u{0}').next() {
                    Some(prefix) if raw.contains('\u{0}') => format!("{prefix}(anonymous)"),
                    _ => raw.to_string(),
                }
            }
        }
    }

    // ---- driving ----------------------------------------------------------

    pub fn assemble_path(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let file = self.sm.load(path)?;
        self.assemble_file(file);
        Ok(())
    }

    pub fn assemble_str(&mut self, name: &str, src: &str) {
        let file = self.sm.add(name, src);
        self.assemble_file(file);
    }

    pub fn assemble_file(&mut self, file: FileId) {
        self.assemble_file_in(file, true);
    }

    /// Assembles `file`. With `own_conditionals`, a conditional it leaves
    /// open is an error; without, the file is a piece of the one that caused
    /// it, such as one statement rewritten by CC-RX `.DEFINE`, and may open a
    /// conditional that one closes.
    fn assemble_file_in(&mut self, file: FileId, own_conditionals: bool) {
        let mut config = LexConfig::for_dialect(self.options.dialect);
        // GNU-style comment characters are the target's choice, so they come
        // from whichever backend is active when this file starts. A `.arch`
        // switch partway through a file does not re-lex the rest of it — the
        // file is tokenized before its directives run — but it does apply to
        // anything included or expanded after the switch.
        if self.options.dialect == Dialect::Gas {
            let c = self.arch.comments();
            config.line_comment = c.anywhere.to_vec();
            config.line_start_comment = c.line_start.to_vec();
            self.arch.tune_lexer(&mut config);
        }
        // The parser borrows the source map; statements are collected first so
        // the rest of the assembler can take `&mut self` freely.
        let mut statements = Vec::new();
        {
            let sm = &self.sm;
            let mut parser = Parser::new(sm, file, config);
            while let Some(s) =
                parser.next_statement(&mut self.interner, &mut self.pool, &mut self.diags)
            {
                statements.push(s);
                if self.diags.saturated() {
                    break;
                }
            }
        }
        let depth = self.cond.len();
        self.run(&statements);
        // Only the conditionals this file opened are its to close. One a
        // macro left open by `.exitm` ends with the expansion.
        if own_conditionals && self.cond.len() > depth {
            for c in self.cond.split_off(depth) {
                if !self.exiting_macro {
                    self.diags
                        .error(c.span, "unterminated `.if`, expected `.endif`");
                }
            }
        }
    }

    /// Walks a statement list, expanding the block constructs as it goes.
    ///
    /// `.macro` and the repeat directives consume statements that follow
    /// them, so this cannot be a plain `for` loop: the index has to be
    /// reachable from the handlers.
    fn run(&mut self, statements: &[Statement]) {
        let mut i = 0usize;
        while i < statements.len() {
            let stmt = &statements[i];
            i += 1;

            if self.options.dialect == Dialect::CcRx
                && let Some(text) = self.ccrx_apply_defines(stmt)
            {
                if self.macro_depth >= 64 {
                    self.diags.error(
                        stmt.span,
                        "`.DEFINE` replacement nested too deeply; is it recursive?",
                    );
                    return;
                }
                let file = self.sm.add("<.DEFINE>".to_string(), text);
                self.macro_depth += 1;
                self.assemble_file_in(file, false);
                self.macro_depth -= 1;
                if self.exiting_macro || self.end_of_source || self.diags.saturated() {
                    return;
                }
                continue;
            }

            // A block construct inside a false conditional is not a block at
            // all; its statements are skipped one by one like everything else.
            if self.cond_active() {
                match self.block_kind(stmt) {
                    Some(BlockKind::Macro) => {
                        i = self.define_macro(stmt, statements, i);
                        continue;
                    }
                    Some(BlockKind::Repeat(kind)) => {
                        i = self.expand_repeat(stmt, kind, statements, i);
                        continue;
                    }
                    Some(BlockKind::EndMacro) => {
                        self.diags
                            .error(stmt.span, "`.endm` without a matching `.macro`");
                        continue;
                    }
                    Some(BlockKind::EndRepeat) => {
                        self.diags.error(
                            stmt.span,
                            "`.endr` without a matching `.rept`, `.irp` or `.irpc`",
                        );
                        continue;
                    }
                    Some(BlockKind::ExitMacro) => {
                        if self.macro_depth == 0 {
                            self.diags.error(stmt.span, "`.exitm` outside a macro");
                        } else {
                            self.exiting_macro = true;
                        }
                        return;
                    }
                    None => {
                        if self.try_expand_macro(stmt) {
                            if self.exiting_macro || self.end_of_source || self.diags.saturated() {
                                return;
                            }
                            continue;
                        }
                    }
                }
            }

            self.process(stmt);
            if self.exiting_macro || self.end_of_source || self.diags.saturated() {
                return;
            }
        }
    }

    /// The directive a statement names, in GNU as spelling.
    ///
    /// In a vendor dialect a block keyword arrives as a bare word the parser
    /// could not tell from an instruction; it is translated here, so the
    /// statement walker only ever has to know one spelling.
    fn directive_name(&self, stmt: &Statement) -> Option<&str> {
        match &stmt.body {
            Some(Body::Directive { name, .. }) => {
                let text = self.interner.get(*name);
                let bare = text.strip_prefix('.').unwrap_or(text);
                Some(dialect::block_keyword(self.options.dialect, bare).unwrap_or(text))
            }
            Some(Body::Insn { mnemonic, .. }) if self.options.dialect.dotless_directives() => {
                dialect::block_keyword(self.options.dialect, self.interner.get(*mnemonic))
            }
            _ => None,
        }
    }

    /// The directives that open and close a macro body and a repeat block.
    ///
    /// CC-RL and CC-RH close all three with `.ENDM`, so each has to count the
    /// others as nesting too.
    fn block_delimiters(&self, repeat: bool) -> (&'static [&'static str], &'static [&'static str]) {
        match (self.options.dialect.is_cc(), repeat) {
            (true, _) => (&[".macro", ".rept", ".irp"], &[".endm"]),
            (false, false) => (&[".macro"], &[".endm", ".endmacro"]),
            (false, true) => (&[".rept", ".irp", ".irpc"], &[".endr"]),
        }
    }

    fn block_kind(&self, stmt: &Statement) -> Option<BlockKind> {
        Some(match self.directive_name(stmt)? {
            ".macro" => BlockKind::Macro,
            ".endm" | ".endmacro" => BlockKind::EndMacro,
            ".exitm" => BlockKind::ExitMacro,
            ".endr" => BlockKind::EndRepeat,
            ".rept" => BlockKind::Repeat(RepeatKind::Rept),
            ".irp" => BlockKind::Repeat(RepeatKind::Irp),
            ".irpc" => BlockKind::Repeat(RepeatKind::Irpc),
            _ => return None,
        })
    }

    /// Collects the statements of a block, returning its source text and the
    /// index just past its terminator.
    ///
    /// `opens` and `closes` name the directives that nest, so a `.rept` inside
    /// a `.macro` body does not end the macro.
    fn capture_block(
        &mut self,
        statements: &[Statement],
        from: usize,
        opens: &[&str],
        closes: &[&str],
        open_span: Span,
    ) -> Option<(String, usize)> {
        let mut depth = 1usize;
        let mut i = from;
        while i < statements.len() {
            if let Some(name) = self.directive_name(&statements[i]) {
                if opens.contains(&name) {
                    depth += 1;
                } else if closes.contains(&name) {
                    depth -= 1;
                    if depth == 0 {
                        let body = if i > from {
                            // From the start of the first body *line*, not its
                            // first token: in Motorola source the indentation
                            // is what makes `dc.b` an instruction rather than
                            // a label, and the body is re-lexed on expansion.
                            let lo = self.sm.line_start_of(statements[from].span.lo);
                            let hi = statements[i - 1].span.hi;
                            self.sm.span_text(Span::new(lo, hi)).to_string()
                        } else {
                            String::new()
                        };
                        return Some((body, i + 1));
                    }
                }
            }
            i += 1;
        }
        self.diags.error(
            open_span,
            format!("unterminated block, expected `{}`", closes[0]),
        );
        None
    }

    /// The source text of a statement's arguments, which is what the macro
    /// machinery works in.
    fn arg_text(&self, stmt: &Statement) -> String {
        let rest = &stmt.toks[stmt.args.min(stmt.toks.len())..];
        match (rest.first(), rest.last()) {
            (Some(a), Some(b)) => self
                .sm
                .span_text(Span::new(a.span.lo, b.span.hi))
                .to_string(),
            _ => String::new(),
        }
    }

    fn define_macro(&mut self, stmt: &Statement, statements: &[Statement], from: usize) -> usize {
        let header = self.arg_text(stmt);
        let (mut name_text, mut params_text) = macros::split_macro_header(&header);
        let cc = self.options.dialect.renesas_cc();
        // Devpac writes `name macro`, with the name where a label goes.
        // CC-RL, CC-RH and CC-RX write `NAME .MACRO params`, with the name in
        // the symbol field, and CC-RH allows the parameters in parentheses
        // (CC-RL page 527, CC-RH page 460, CC-RX R20UT3248EJ0115 page 486).
        let label_name = match (cc, stmt.symbol, stmt.labels.as_slice()) {
            (true, Some((n, _)), _) => Some(self.interner.get(n).to_string()),
            (false, _, [LabelDef::Named(n, _)]) if name_text.is_empty() => {
                Some(self.interner.get(*n).to_string())
            }
            _ => None,
        };
        if cc {
            name_text = "";
            params_text = header.trim();
            if let Some(inner) = params_text
                .strip_prefix('(')
                .and_then(|p| p.strip_suffix(')'))
            {
                params_text = inner;
            }
        }
        if let Some(n) = &label_name {
            name_text = n;
        }
        let (opens, closes) = self.block_delimiters(false);
        let Some((body, next)) = self.capture_block(statements, from, opens, closes, stmt.span)
        else {
            return statements.len();
        };
        if name_text.is_empty() {
            self.diags.error(stmt.span, "`.macro` needs a name");
            return next;
        }
        let params = match macros::parse_params(params_text) {
            Ok(p) => p,
            Err(msg) => {
                self.diags.error(stmt.span, msg);
                return next;
            }
        };
        let name = self.interner.intern(&name_text.to_ascii_lowercase());
        if let Some(prev) = self.macros.get(&name) {
            let prev_span = prev.def_span;
            self.diags.emit(
                Diagnostic::error(stmt.span, format!("macro `{name_text}` is already defined"))
                    .with_note(prev_span, "previous definition is here")
                    .with_help("use `.purgem` to remove it first"),
            );
            return next;
        }
        self.macros.insert(
            name,
            MacroDef {
                name,
                params,
                body,
                def_span: stmt.span,
            },
        );
        next
    }

    fn expand_repeat(
        &mut self,
        stmt: &Statement,
        kind: RepeatKind,
        statements: &[Statement],
        from: usize,
    ) -> usize {
        let header = self.arg_text(stmt);
        let (opens, closes) = self.block_delimiters(true);
        let Some((body, next)) = self.capture_block(statements, from, opens, closes, stmt.span)
        else {
            return statements.len();
        };

        // Each iteration is substituted separately and the results
        // concatenated, so the whole repeat becomes one expansion.
        let mut text = String::new();
        let cc = self.options.dialect.renesas_cc();
        match kind {
            RepeatKind::Rept => {
                let count = if cc {
                    self.eval_count(stmt)
                } else {
                    self.eval_text_count(&header, stmt.span)
                };
                let Some(count) = count else {
                    return next;
                };
                for n in 0..count {
                    if cc {
                        // CC-RX's `..MACREP` counts the expansions from 1
                        // (R20UT3248EJ0115 page 490).
                        let iteration = [
                            ("..MACREP".to_string(), (n + 1).to_string()),
                            ("..macrep".to_string(), (n + 1).to_string()),
                        ];
                        let bindings = self.cc_local_bindings(&body, &iteration);
                        text.push_str(&self.cc_substitute(&body, &bindings));
                    } else {
                        text.push_str(&body);
                    }
                    text.push('\n');
                }
            }
            RepeatKind::Irp | RepeatKind::Irpc => {
                let (var, rest) = macros::split_macro_header(&header);
                if var.is_empty() {
                    self.diags
                        .error(stmt.span, "`.irp` needs a symbol name and a list of values");
                    return next;
                }
                let rest = rest.trim().trim_start_matches(',').trim();
                let values: Vec<String> = if kind == RepeatKind::Irp {
                    macros::split_args(rest)
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                } else {
                    // `.irpc` walks the characters of its argument, with any
                    // surrounding quotes stripped.
                    let raw = rest.trim_matches('"');
                    raw.chars().map(|c| c.to_string()).collect()
                };
                for v in values {
                    let bindings = vec![(var.to_string(), v)];
                    if cc {
                        let bindings = self.cc_local_bindings(&body, &bindings);
                        text.push_str(&self.cc_substitute(&body, &bindings));
                    } else {
                        text.push_str(&macros::substitute(&body, &bindings, self.macro_counter));
                    }
                    text.push('\n');
                }
            }
        }

        let label = match kind {
            RepeatKind::Rept => "rept",
            RepeatKind::Irp => "irp",
            RepeatKind::Irpc => "irpc",
        };
        self.expand(label, text, stmt.span);
        next
    }

    /// A CC-RL/CC-RH `.REPT` count, which is an absolute expression rather
    /// than a plain number (CC-RL page 529; CC-RH page 463).
    fn eval_count(&mut self, stmt: &Statement) -> Option<i64> {
        let mut cur = stmt.arg_cursor();
        if cur.at_end() {
            self.diags.error(stmt.span, "`.REPT` needs a count");
            return None;
        }
        let e = self.parse_expr(&mut cur)?;
        self.expect_end(&mut cur);
        let n = self.eval_absolute(e, "`.REPT` count")?;
        if n < 0 {
            self.diags
                .error(stmt.span, format!("`.REPT` count {n} is negative"));
            return None;
        }
        Some(n)
    }

    /// Binds each name a CC-RL/CC-RH `.LOCAL` in `body` declares to a fresh
    /// symbol name, after `params` (CC-RL page 528; CC-RH page 462). The
    /// manuals' own generated names start with a dot, which keeps them out of
    /// the way of user symbols; rsasm's do too.
    fn cc_local_bindings(
        &mut self,
        body: &str,
        params: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut out = params.to_vec();
        for name in macros::cc_locals(body) {
            if out.iter().any(|(p, _)| *p == name) {
                continue;
            }
            let fresh = format!(".LL{:08X}", self.cc_local_counter);
            self.cc_local_counter += 1;
            out.push((name, fresh));
        }
        out
    }

    /// Substitutes a CC-RL/CC-RH/CC-RX macro body: whole-word parameters, and
    /// the concatenation symbol, `?` for CC-RL (page 557), `~` for CC-RH (page
    /// 489) and `@` for CC-RX (R20UT3248EJ0115 page 497). CC-RX also replaces
    /// a parameter inside single quotes (page 487).
    fn cc_substitute(&self, body: &str, bindings: &[(String, String)]) -> String {
        let (concat, quoted) = match self.options.dialect {
            Dialect::CcRl => ('?', false),
            Dialect::CcRx => ('@', true),
            _ => ('~', false),
        };
        macros::substitute_words(body, bindings, concat, quoted)
    }

    fn eval_text_count(&mut self, text: &str, span: Span) -> Option<i64> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            self.diags.error(span, "`.rept` needs a count");
            return None;
        }
        match trimmed.parse::<i64>() {
            Ok(n) if n >= 0 => Some(n),
            Ok(_) => {
                self.diags.error(span, "`.rept` count must not be negative");
                None
            }
            Err(_) => {
                self.diags
                    .error(span, "`.rept` count must be a plain number");
                None
            }
        }
    }

    /// Expands `stmt` if its mnemonic names a macro. Returns whether it did.
    fn try_expand_macro(&mut self, stmt: &Statement) -> bool {
        let Some(Body::Insn { mnemonic, span }) = stmt.body else {
            return false;
        };
        if !self.macros.contains_key(&mnemonic) {
            return false;
        }
        // Labels on the invocation line belong to the call site, not to the
        // expansion, so they are defined before anything is substituted.
        for l in &stmt.labels {
            self.define_label(l);
        }
        let def = self.macros[&mnemonic].clone();
        let args = self.arg_text(stmt);
        let Some(bindings) = self.bind_macro_args(&def, &args, span) else {
            return true;
        };
        self.macro_counter += 1;
        let counter = self.macro_counter;
        let positional = self.options.dialect.dotless_directives();
        let text = if self.options.dialect.renesas_cc() {
            let bindings = self.cc_local_bindings(&def.body, &bindings);
            self.cc_substitute(&def.body, &bindings)
        } else {
            macros::substitute_with(&def.body, &bindings, counter, positional)
        };
        let name = self.interner.get(def.name).to_string();
        self.expand(&format!("macro {name}"), text, span);
        true
    }

    /// Matches a call's arguments to a macro's parameters.
    fn bind_macro_args(
        &mut self,
        def: &MacroDef,
        args: &str,
        span: Span,
    ) -> Option<Vec<(String, String)>> {
        let mut bound: Vec<(String, Option<String>)> =
            def.params.iter().map(|p| (p.name.clone(), None)).collect();

        let pieces = macros::split_args(args);

        // The Renesas assemblers bind arguments by position only. CC-RH wants
        // exactly as many as there are parameters (page 460); CC-RL warns
        // about extra ones and leaves missing ones empty (page 527); CC-RX
        // warns about any mismatch, takes an argument in double quotes without
        // them, and counts the arguments in `..MACPARA` (R20UT3248EJ0115
        // pages 487 and 490).
        if self.options.dialect.renesas_cc() {
            let dialect = self.options.dialect;
            let name = self.interner.get(def.name).to_string();
            let (want, got) = (def.params.len(), pieces.len());
            if got != want {
                let msg = format!("macro `{name}` takes {want} argument(s), but {got} were given");
                if dialect == Dialect::CcRh {
                    self.diags.error(span, msg);
                    return None;
                }
                if got > want || dialect == Dialect::CcRx {
                    self.diags.warning(span, msg);
                }
            }
            let mut out: Vec<(String, String)> = def
                .params
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let arg = pieces.get(i).copied().unwrap_or("");
                    let arg = match dialect {
                        Dialect::CcRx => arg
                            .strip_prefix('"')
                            .and_then(|a| a.strip_suffix('"'))
                            .unwrap_or(arg),
                        _ => arg,
                    };
                    (p.name.clone(), arg.to_string())
                })
                .collect();
            if dialect == Dialect::CcRx {
                // Reserved words are not case-sensitive (page 500).
                out.push(("..MACPARA".to_string(), got.to_string()));
                out.push(("..macpara".to_string(), got.to_string()));
            }
            return Some(out);
        }

        // A vendor-dialect macro declared without parameters takes any number
        // of arguments, referred to by position as `\1`, `\2` and so on.
        if def.params.is_empty() && self.options.dialect.dotless_directives() {
            return Some(
                pieces
                    .iter()
                    .enumerate()
                    .map(|(i, p)| ((i + 1).to_string(), (*p).to_string()))
                    .collect(),
            );
        }

        let mut positional = 0usize;
        for (i, piece) in pieces.iter().enumerate() {
            // A `:vararg` parameter swallows the rest of the line verbatim,
            // commas included, so it is matched before anything is split off.
            if let Some(vi) = def.params.iter().position(|p| p.vararg)
                && positional == vi
            {
                bound[vi].1 = Some(pieces[i..].join(", "));
                break;
            }
            match macros::split_named_arg(piece) {
                Some((name, value)) if def.param(name).is_some() => {
                    let idx = def
                        .params
                        .iter()
                        .position(|p| p.name == name)
                        .expect("just checked");
                    bound[idx].1 = Some(value.to_string());
                }
                _ => {
                    if positional >= def.params.len() {
                        self.diags.error(
                            span,
                            format!(
                                "macro `{}` takes {} argument(s), but more were given",
                                self.interner.get(def.name),
                                def.params.len()
                            ),
                        );
                        return None;
                    }
                    bound[positional].1 = Some((*piece).to_string());
                    positional += 1;
                }
            }
        }

        let mut out = Vec::with_capacity(bound.len());
        for (p, (name, value)) in def.params.iter().zip(bound) {
            let value = match value.or_else(|| p.default.clone()) {
                Some(v) => v,
                None if p.required => {
                    self.diags.error(
                        span,
                        format!(
                            "macro `{}` requires an argument for `{name}`",
                            self.interner.get(def.name)
                        ),
                    );
                    return None;
                }
                None => String::new(),
            };
            out.push((name, value));
        }
        Some(out)
    }

    /// Assembles expanded text as if it were an included file.
    ///
    /// It becomes a real entry in the source map, so a diagnostic inside a
    /// macro points at the expanded line and names the macro it came from.
    fn expand(&mut self, what: &str, text: String, span: Span) {
        if self.macro_depth >= 64 {
            self.diags
                .error(span, "macro expansion nested too deeply; is it recursive?");
            return;
        }
        let name = format!("<{what}>");
        let file = self.sm.add(name, text);
        self.macro_depth += 1;
        self.assemble_file(file);
        self.macro_depth -= 1;
        // `.exitm` unwinds exactly one expansion.
        self.exiting_macro = false;
    }

    pub(crate) fn cond_active(&self) -> bool {
        self.cond.last().is_none_or(|c| c.active)
    }

    /// Whether the conditional *enclosing* the innermost one is active. An
    /// `.else` may only turn its branch on if everything around it is on.
    pub(crate) fn enclosing_cond_active(&self) -> bool {
        let n = self.cond.len();
        if n < 2 { true } else { self.cond[n - 2].active }
    }

    pub(crate) fn push_cond(&mut self, c: Cond) {
        self.cond.push(c);
    }

    pub(crate) fn pop_cond(&mut self) -> Option<Cond> {
        self.cond.pop()
    }

    pub(crate) fn cond_top(&self) -> Option<&Cond> {
        self.cond.last()
    }

    pub(crate) fn set_cond_active(&mut self, active: bool) {
        if let Some(c) = self.cond.last_mut() {
            c.active = active;
        }
    }

    pub(crate) fn mark_cond_taken(&mut self) {
        if let Some(c) = self.cond.last_mut() {
            c.taken = true;
        }
    }

    pub(crate) fn mark_cond_else(&mut self) {
        if let Some(c) = self.cond.last_mut() {
            c.seen_else = true;
        }
    }

    /// Assembles another file in place, as `.include` does.
    pub(crate) fn include(&mut self, path: &std::path::Path, span: Span) {
        if self.include_depth > 32 {
            self.diags.error(span, "`.include` nested too deeply");
            return;
        }
        let file = match self.sm.load(path) {
            Ok(f) => f,
            Err(e) => {
                self.diags
                    .error(span, format!("cannot read `{}`: {e}", path.display()));
                return;
            }
        };
        self.include_depth += 1;
        self.assemble_file(file);
        self.include_depth -= 1;
    }

    /// Switches the active architecture backend mid-file.
    pub(crate) fn switch_arch(&mut self, arch: Box<dyn Architecture>) {
        let syntax = self.arch_state.syntax;
        self.arch_state = arch.initial_state();
        // A syntax choice is the user's, not the architecture's, so it carries
        // across a `.arch` switch when the new backend supports it.
        if arch.supports_syntax(syntax) {
            self.arch_state.syntax = syntax;
        }
        self.arch = arch;
    }

    fn process(&mut self, stmt: &Statement) {
        // While a conditional is false, only the directives that can end it
        // are looked at.
        if !self.cond_active() {
            match &stmt.body {
                Some(Body::Directive { name, .. }) => {
                    let text = self.interner.get(*name);
                    if matches!(
                        text,
                        ".if"
                            | ".ifdef"
                            | ".ifndef"
                            | ".ifeq"
                            | ".ifne"
                            | ".else"
                            | ".elseif"
                            | ".endif"
                    ) || (self.options.dialect.renesas_cc()
                        && dialect::is_conditional(
                            self.options.dialect,
                            text.strip_prefix('.').unwrap_or(text),
                        ))
                    {
                        self.directive(stmt, *name);
                    }
                }
                // A vendor `ELSE`/`ENDIF` is a bare word, and has to be seen
                // here too or a false branch could never end.
                Some(Body::Insn { mnemonic, .. }) => {
                    let word = self.interner.get(*mnemonic);
                    if !self.options.dialect.renesas_cc()
                        && dialect::is_conditional(self.options.dialect, word)
                        && let Some(alias) = dialect::lookup(self.options.dialect, word)
                    {
                        self.run_alias(stmt, alias);
                    }
                }
                _ => {}
            }
            return;
        }

        for l in &stmt.labels {
            self.define_label(l);
        }

        // `.` refers to where the statement starts, so the anonymous label
        // standing in for it has to exist before anything is emitted.
        // Every spelling of the location counter the dialect has counts, not
        // just `.`: Motorola writes `*` and Renesas `$`. A `*` that turns out
        // to be multiplication only costs an unused label.
        let d = self.options.dialect;
        if stmt.toks.iter().any(|t| {
            t.is_punct(Punct::Dot)
                || (d.star_is_here() && t.is_punct(Punct::Star))
                || (d.dollar_is_here() && t.is_punct(Punct::Dollar))
        }) || (matches!(stmt.body, Some(Body::Insn { .. }))
            && self
                .arch
                .operands_use_location(&self.interner, stmt.arg_cursor().rest()))
        {
            self.here_sym = Some(self.anon_label(stmt.span));
        }
        let mark = self.exprs.len();

        match &stmt.body {
            None => {}
            Some(Body::Directive { name, span }) => {
                let _ = span;
                self.directive(stmt, *name);
            }
            Some(Body::Insn { mnemonic, span }) => {
                // A bare word may be a vendor directive before it is an
                // instruction; see `dialect::lookup`. Not in CC-RL, CC-RH or
                // CC-RX, whose directives are all dotted and whose `BT` is a
                // branch.
                let alias = if self.options.dialect.renesas_cc() {
                    None
                } else {
                    dialect::lookup(self.options.dialect, self.interner.get(*mnemonic))
                };
                match alias {
                    Some(alias) => self.run_alias(stmt, alias),
                    None => self.instruction(stmt, *mnemonic, *span),
                }
            }
            Some(Body::Assign { name, span }) => {
                let mut cur = stmt.arg_cursor();
                if let Some(mut e) = self.parse_expr(&mut cur) {
                    // A CC-RL/CC-RH `.SET` takes an absolute expression of
                    // symbols already defined (CC-RL page 504, Table 5.12 on
                    // page 483; CC-RH page 435), so it is evaluated where it
                    // stands; that is what lets `CNT .SET CNT + 1` count.
                    let is_set = self.options.dialect.is_cc()
                        && stmt.args >= 1
                        && stmt.toks[stmt.args - 1]
                            .ident()
                            .is_some_and(|w| self.interner.get(w).eq_ignore_ascii_case(".set"));
                    let value = if is_set {
                        self.eval_absolute(e, "a `.SET` value")
                            .map(|v| self.exprs.int(v as u64, self.exprs.span(e)))
                    } else {
                        Some(e)
                    };
                    if let Some(v) = value {
                        e = v;
                        self.set_symbol(*name, e, *span);
                        // Only `.SET` names may be defined again (CC-RL page
                        // 502; CC-RH page 436), and CC-RX has no `.SET`.
                        if self.options.dialect.renesas_cc() && !is_set {
                            let id = self.symbols.intern(*name, *span);
                            self.symbols.get_mut(id).redefinable = false;
                        }
                    }
                }
                self.expect_end(&mut cur);
            }
            Some(Body::Unknown { span }) => {
                self.diags
                    .error(*span, "expected a label, directive or instruction");
            }
            Some(Body::SetLocation { span }) => {
                let mut cur = stmt.arg_cursor();
                if let Some(e) = self.parse_expr(&mut cur) {
                    self.emit_org(e, 0, *span);
                }
                self.expect_end(&mut cur);
            }
        }

        self.bind_positional(mark);
        self.here_sym = None;
    }

    /// Replaces each reference this statement made to a symbol that already
    /// has a constant value with that value.
    ///
    /// A CC-RL/CC-RH `.SET` symbol may be redefined, and every use means the
    /// value it had there (CC-RL page 504; CC-RH page 435). Instruction
    /// operands are otherwise evaluated once the whole file is read, when only
    /// the last value is left.
    fn bind_set_values(&mut self, mark: usize) {
        for i in mark..self.exprs.len() {
            let ExprKind::Sym(name) = self.exprs.nodes[i].kind else {
                continue;
            };
            let Some(id) = self.symbols.lookup(name) else {
                continue;
            };
            if let SymbolValue::Expr(e) = self.symbols.get(id).value
                && let Some(v) = self.eval_ref(e).ok().and_then(|v| v.as_abs())
            {
                self.symbols.get_mut(id).used = true;
                self.exprs.nodes[i].kind = ExprKind::Int(v as u64);
            }
        }
    }

    /// Replaces each reference, among the expression nodes from `mark` on, to
    /// a symbol not defined yet with 0, as CC-RX's `.IF` and `.ELIF` read one
    /// (R20UT3248EJ0115 page 495).
    pub(crate) fn ccrx_undefined_as_zero(&mut self, mark: usize) {
        for i in mark..self.exprs.len() {
            if let ExprKind::Sym(name) = self.exprs.nodes[i].kind
                && !self
                    .symbols
                    .lookup(name)
                    .is_some_and(|id| self.symbols.get(id).is_defined())
            {
                self.exprs.nodes[i].kind = ExprKind::Int(0);
            }
        }
    }

    /// Rewrites `.` and `1f`/`1b` nodes created by this statement into direct
    /// symbol references, now that the statement's position is known.
    fn bind_positional(&mut self, mark: usize) {
        if self.exprs.len() == mark {
            return;
        }
        if self.options.dialect.is_cc() {
            self.bind_set_values(mark);
        }
        let Assembler {
            exprs,
            symbols,
            interner,
            here_sym,
            diags,
            ..
        } = self;
        let here = *here_sym;
        expr::bind_positional(exprs, mark, |kind, span| match kind {
            ExprKind::Here => match here {
                Some(id) => Some(ExprKind::SymId(id)),
                None => {
                    // Only reachable if `.` appeared without a `.` token, which
                    // the pre-scan should have caught.
                    diags.error(span, "`.` is not valid here");
                    None
                }
            },
            ExprKind::LocalRef(n, LocalDir::Forward) => {
                Some(ExprKind::SymId(symbols.local_forward(*n, span, interner)))
            }
            ExprKind::LocalRef(n, LocalDir::Backward) => match symbols.local_backward(*n, span) {
                Some(id) => Some(ExprKind::SymId(id)),
                None => {
                    diags.error(span, format!("no previous local label `{n}:`"));
                    None
                }
            },
            ExprKind::SectionStart => None,
            _ => None,
        });
    }

    // ---- expressions ------------------------------------------------------

    pub fn parse_expr(&mut self, cur: &mut Cursor<'_>) -> Option<ExprRef> {
        let mut p = expr::ExprParser {
            arena: &mut self.exprs,
            interner: &mut self.interner,
            diags: &mut self.diags,
            dollar_is_here: self.options.dialect.dollar_is_here(),
            star_is_here: self.options.dialect.star_is_here(),
            dialect: self.options.dialect,
        };
        p.parse(cur)
    }

    pub fn expect_end(&mut self, cur: &mut Cursor<'_>) {
        if !cur.at_end() && !cur.is_empty() {
            let span = cur.remaining_span();
            self.diags.error(span, "unexpected trailing tokens");
        }
    }

    /// Evaluates an expression against the current symbol table.
    pub fn eval(&mut self, e: ExprRef) -> Result<Value, EvalError> {
        let Assembler { exprs, symbols, .. } = self;
        let mut env = Env {
            exprs,
            symbols,
            depth: 0,
        };
        expr::eval(exprs, e, &mut env)
    }

    /// Evaluates an expression without recording symbol uses, so it can be
    /// called from the output writers, which only have `&Assembler`.
    pub fn eval_ref(&self, e: ExprRef) -> Result<Value, EvalError> {
        let mut env = expr::SymbolEnv::new(&self.exprs, &self.symbols);
        expr::eval(&self.exprs, e, &mut env)
    }

    /// Evaluates an expression to a number, if it resolves to one.
    pub fn eval_const(&self, e: ExprRef) -> Option<i64> {
        self.resolve_value(self.eval_ref(e).ok()?)
    }

    /// The number a symbol stands for, if it has one.
    ///
    /// A difference of two labels counts: `len = end - start` is a constant
    /// even though neither end of it is.
    pub fn symbol_number(&self, id: SymbolId) -> Option<i64> {
        let v = self.eval_ref_symbol(id).ok()?;
        if let Some(n) = v.as_abs() {
            return Some(n);
        }
        self.resolve_value(v)
    }

    /// The section and offset a symbol resolves to, for symbols defined by
    /// `.set` in terms of a label.
    pub fn symbol_target_section(&self, id: SymbolId) -> Option<(SectionId, u64)> {
        let v = self.eval_ref_symbol(id).ok()?;
        let (Some(p), None) = (v.plus, v.minus) else {
            return None;
        };
        let addr = self.symbol_addr(p)?.wrapping_add(v.addend);
        let section = match self.symbols.get(p).value {
            SymbolValue::Label { section, .. } => section,
            _ => return None,
        };
        Some((
            section,
            addr.saturating_sub(self.section(section).addr as i64) as u64,
        ))
    }

    fn eval_ref_symbol(&self, id: SymbolId) -> Result<Value, EvalError> {
        let mut env = expr::SymbolEnv::new(&self.exprs, &self.symbols);
        env.symbol_value(id, Span::DUMMY)
    }

    /// Evaluates an expression that must be a plain number right now.
    pub fn eval_absolute(&mut self, e: ExprRef, what: &str) -> Option<i64> {
        match self.eval(e) {
            Ok(v) => match v.as_abs() {
                Some(n) => Some(n),
                None => {
                    let span = self.exprs.span(e);
                    self.diags
                        .error(span, format!("{what} must be an absolute value"));
                    None
                }
            },
            Err(err) => {
                self.diags.emit(err.into_diagnostic());
                None
            }
        }
    }

    pub(crate) fn set_symbol(&mut self, name: Name, e: ExprRef, span: Span) {
        let id = self.symbols.intern(name, span);
        let sym = self.symbols.get_mut(id);
        if sym.is_defined() && !sym.redefinable {
            let prev = sym.def_span;
            let name = self.display_name(id);
            self.diags.emit(
                Diagnostic::error(span, format!("symbol `{name}` is already defined"))
                    .with_note(prev, "previous definition is here"),
            );
            return;
        }
        let sym = self.symbols.get_mut(id);
        sym.value = SymbolValue::Expr(e);
        sym.def_span = span;
        sym.redefinable = true;
    }

    // ---- emitting ---------------------------------------------------------

    pub fn emit_bytes(&mut self, bytes: &[u8], span: Span) {
        if self.check_nobits(span) {
            return;
        }
        self.cur_section().emit_bytes(bytes, span);
    }

    /// `.bss`-style sections hold no data, so anything but zero fill is an
    /// error rather than being silently dropped.
    pub(crate) fn check_nobits(&mut self, span: Span) -> bool {
        if self.section(self.cur).kind == SectionKind::Nobits {
            let name = self.interner.get(self.section(self.cur).name).to_string();
            self.diags.error(
                span,
                format!("cannot emit data into `{name}`, which allocates no file space"),
            );
            return true;
        }
        false
    }

    pub(crate) fn emit_org(&mut self, target: ExprRef, fill: u8, span: Span) {
        self.cur_section().push(Fragment::new(
            FragKind::Org {
                target,
                fill,
                size: 0,
            },
            span,
        ));
    }

    /// Symbols that were referenced but never given a definition anywhere.
    pub fn report_undefined_locals(&mut self) {
        let missing: Vec<(SymbolId, u32)> = self.symbols.undefined_locals().collect();
        for (id, n) in missing {
            let span = self.symbols.get(id).first_use;
            self.diags
                .error(span, format!("no local label `{n}:` after this point"));
        }
    }

    fn instruction(&mut self, stmt: &Statement, mnemonic: Name, span: Span) {
        let operands = &stmt.toks[stmt.args.min(stmt.toks.len())..];
        let req = InsnRequest {
            mnemonic,
            mnemonic_span: span,
            operands,
            span: stmt.span,
        };
        // Disjoint field borrows keep the architecture object accessible while
        // it mutates the interner, expression arena and diagnostics.
        let Assembler {
            arch,
            interner,
            exprs,
            diags,
            pool,
            symbols,
            arch_state,
            options,
            ..
        } = self;
        let dialect = options.dialect;
        let mut cx = AsmCtx {
            interner,
            exprs,
            diags,
            pool,
            symbols,
            state: arch_state,
            dialect,
        };
        let variants = arch.assemble(&mut cx, &req);
        let Some(variants) = variants else { return };
        // Motorola syntax aligns code as well as data; see `motorola_align`.
        if self.options.dialect == Dialect::Motorola {
            let unit = self.arch.align_unit();
            self.align_to(unit, stmt.span);
        }
        if self.check_nobits(stmt.span) {
            return;
        }
        self.cur_section().emit_variants(variants, stmt.span);
    }
}

/// Expression evaluation environment, borrowing the parts of the assembler
/// evaluation needs.
struct Env<'a> {
    exprs: &'a ExprArena,
    symbols: &'a mut SymbolTable,
    depth: u32,
}

impl EvalCtx for Env<'_> {
    fn lookup_symbol(&mut self, name: Name, span: Span) -> Result<Value, EvalError> {
        let id = self.symbols.intern(name, span);
        self.symbol_value(id, span)
    }

    fn symbol_value(&mut self, id: SymbolId, span: Span) -> Result<Value, EvalError> {
        self.symbols.get_mut(id).used = true;
        match self.symbols.get(id).value.clone() {
            // An `.equ` chain is followed through; anything else stays
            // symbolic until addresses are known.
            SymbolValue::Expr(e) => {
                if self.depth > 64 {
                    return Err(EvalError::new(span, "symbol definition is circular"));
                }
                self.depth += 1;
                let exprs = self.exprs;
                let v = expr::eval(exprs, e, self);
                self.depth -= 1;
                v
            }
            _ => Ok(Value::sym(id, 0)),
        }
    }

    fn here(&mut self, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(span, "`.` cannot be used here"))
    }

    fn section_start(&mut self, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(span, "`$$` is not supported yet"))
    }

    fn local_ref(&mut self, n: u32, _: LocalDir, span: Span) -> Result<Value, EvalError> {
        Err(EvalError::new(
            span,
            format!("local label `{n}` was not resolved"),
        ))
    }

    fn modifier(&mut self, _name: Name, inner: Value, _span: Span) -> Result<Value, EvalError> {
        // Relocation modifiers do not change the value, only the relocation
        // chosen for it, which the fixup resolver handles.
        Ok(inner)
    }
}
