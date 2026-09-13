//! The directives and control instructions of Renesas CC-RL and CC-RH.
//!
//! The two assemblers share one language, and every rule here comes from
//! their user's manuals, cited by section and page:
//!
//! - *CC-RL Compiler User's Manual*, R20UT3123EJ0115 (Rev.1.15, December
//!   2025), chapter 5, "Assembly Language Specifications".
//! - *CC-RH Compiler User's Manual*, R20UT3516EJ0113 (Rev.1.13, June 2026),
//!   chapter 5, of the same name.
//!
//! No Renesas assembler was available to run, so what the manuals describe is
//! all there is to go on; where they leave something open, the comment says
//! what rsasm chose.
//!
//! What cannot be expressed in an ELF object from rsasm is refused with the
//! reason: bit symbols, interrupt vector generation, the linker-evaluated
//! section operators. A directive is accepted and ignored only when it cannot
//! change a byte: debugging information, warning control, the size an
//! `.extern` declares. Absolute placement (`.ORG`, `AT` attributes) is the
//! exception worth knowing about: the section gets the name the manual
//! gives it, but its address is left to the linker, as the CA78K0 dialect
//! already does for `CSEG AT`.

use crate::assembler::Assembler;
use crate::cursor::Cursor;
use crate::dialect::Alias;
use crate::lexer::{Dialect, Punct, TokKind};
use crate::parser::Statement;
use crate::section::{FragKind, Fragment, SectionFlags, SectionKind};
use crate::source::Span;
use crate::symbol::Binding;

/// A CC-RL/CC-RH directive that needs its own handler.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum CcDirective {
    /// `[name] .CSEG [attribute]`.
    Cseg,
    /// `[name] .DSEG [attribute]`.
    Dseg,
    /// `.SECTION name, attribute[, ALIGN=n]`.
    Section,
    /// `.ORG address`.
    Org,
    /// `.ALIGN n` (CC-RH: `.align n[, fill]`).
    Align,
    /// CC-RH `.dshw`: the value shifted right one bit, in two bytes.
    Dshw,
    /// `.PUBLIC name` (CC-RH: `name[, size]`).
    Public,
    /// `.EXTERN name` (CC-RH: `name[, size]`).
    Extern,
    /// CC-RL `.ALIAS alias, symbol`.
    AliasOf,
    /// `$ELSEIFN expression`.
    ElseIfN,
    /// `$INCLUDE (file)` or `$INCLUDE "file"`.
    Include,
    /// `$BINCLUDE (file)`.
    Binclude,
    /// `.LOCAL`, which only means something inside a macro body, where
    /// expansion has already consumed it.
    Local,
    /// A control instruction the architecture backend implements.
    Arch,
    /// Something rsasm cannot express, and why.
    Unsupported(&'static str),
}

const BIT_SYMBOLS: &str = "bit symbols and bit sections are not supported: an ELF symbol \
                           cannot carry a bit position";

/// Looks up `word` — lowercased, without its leading dot, or with the `$` of
/// a control instruction — in the CC-RL or CC-RH table.
pub(crate) fn lookup(dialect: Dialect, word: &str) -> Option<Alias> {
    use Alias::{Cc, Data, Gas, Ignore, Space};
    use CcDirective::*;
    let rl = dialect == Dialect::CcRl;
    Some(match word {
        // ---- section definition: CC-RL §5.2.2, pages 485-500; CC-RH §5.2.2,
        // pages 425-433.
        "cseg" => Cc(Cseg),
        "dseg" => Cc(Dseg),
        "bseg" if rl => Cc(Unsupported(BIT_SYMBOLS)),
        "section" => Cc(Section),
        "org" => Cc(Org),
        // An offset from the start of the section, zero-filled (CC-RL page
        // 500, CC-RH page 433): what GNU as's `.org` is.
        "offset" => Gas(".org"),

        // ---- data: CC-RL §5.2.4, pages 505-512; CC-RH §5.2.5, pages 444-453.
        "db" => Data(1),
        "db2" => Data(2),
        "db4" => Data(4),
        "db8" => Data(8),
        "dhw" if !rl => Data(2),
        "dw" if !rl => Data(4),
        "ddw" if !rl => Data(8),
        "dshw" if !rl => Cc(Dshw),
        "float" | "double" if !rl => Cc(Unsupported(
            "floating-point constants are not supported; write the value's bits with `.dw` or `.ddw`",
        )),
        "ds" => Space(1),
        "align" => Cc(Align),
        "dbit" if rl => Cc(Unsupported(BIT_SYMBOLS)),

        // ---- external definition and reference: CC-RL §5.2.5, pages
        // 513-517; CC-RH §5.2.6, pages 454-458.
        "public" => Cc(Public),
        "extern" => Cc(Extern),
        "weak" => Gas(".weak"),
        "extbit" if rl => Cc(Unsupported(BIT_SYMBOLS)),

        // ---- compiler output: CC-RL §5.2.6, pages 518-525; CC-RH §5.2.4,
        // pages 437-443. Debugging and stack-size information, which no byte
        // depends on.
        "line" | "stack" | "_line_top" | "_line_end" => Ignore,
        "type" if rl => Ignore,
        "file" | "dbl_size" if !rl => Ignore,
        "alias" if rl => Cc(AliasOf),
        "vector" if rl => Cc(Unsupported(
            "`.VECTOR` builds the interrupt vector table in the Renesas linker; \
             write the table with `.DB2` in a section of its own",
        )),

        // ---- macros: CC-RL §5.2.7, pages 526-533; CC-RH §5.2.7, pages
        // 459-467. `.MACRO`, `.REPT`, `.IRP`, `.EXITM` and `.ENDM` are block
        // keywords; see `crate::dialect::block_keyword`.
        "local" => Cc(Local),
        "exitma" => Cc(Unsupported(
            "`.EXITMA` is not supported; `.EXITM` leaves the innermost repeat",
        )),

        // ---- CC-RL's compiler-generated branch directives (§5.2.8, page 535),
        // which the manual says users must not write.
        "bt" | "bf" | "bc" | "bnc" | "bz" | "bnz" | "bh" | "bnh" if rl => Cc(Unsupported(
            "the `.Bcond` directives are compiler output and are not supported; \
             write the branch instructions",
        )),

        // ---- control instructions: CC-RL §5.3, pages 538-555; CC-RH §5.3,
        // pages 468-487.
        "$include" => Cc(Include),
        "$binclude" => Cc(Binclude),
        "$if" => Gas(".if"),
        "$ifn" => Gas(".ifeq"),
        "$ifdef" => Gas(".ifdef"),
        "$ifndef" => Gas(".ifndef"),
        "$elseif" => Gas(".elseif"),
        "$elseifn" => Cc(ElseIfN),
        "$else" => Gas(".else"),
        "$endif" => Gas(".endif"),
        "$nowarning" | "$warning" => Ignore,
        "$mirror" if rl => Cc(Unsupported(
            "`$MIRROR` depends on the device's mirror area, which only the Renesas toolchain knows",
        )),
        // The register mode is a note in the Renesas object file; the code
        // does not change.
        "$reg_mode" if !rl => Ignore,
        "$nomacro" | "$macro" if !rl => Cc(Arch),
        // `$SDATA` promises what rsasm already assumes of every symbol it
        // cannot see, that it is reached with a 16-bit offset; `$DATA` asks
        // for the 32-bit expansion, which needs a relocation the RH850 ABI
        // does not have.
        "$sdata" if !rl => Ignore,
        "$data" if !rl => Cc(Unsupported(
            "`$DATA` asks for 32-bit gp-relative references, which the RH850 ELF ABI cannot express",
        )),
        _ => return None,
    })
}

/// What a section holds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Class {
    Code,
    Const,
    Data,
    Bss,
}

/// A relocation attribute.
#[derive(Copy, Clone, Debug)]
struct Attr {
    /// The section name used when the directive gives none.
    name: &'static str,
    class: Class,
    /// The default alignment condition.
    align: u64,
    /// Takes an absolute address after it.
    at: bool,
    /// Which of `.CSEG` and `.DSEG` accept it; `.SECTION` accepts all.
    seg: Seg,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Seg {
    Code,
    Data,
}

const fn attr(name: &'static str, class: Class, align: u64, seg: Seg) -> Attr {
    Attr {
        name,
        class,
        align,
        at: false,
        seg,
    }
}

/// The relocation attributes CC-RL documents for `.SECTION` (Table 5.15,
/// pages 486-488), `.CSEG` (Table 5.16, pages 490-491) and `.DSEG` (Table
/// 5.17, pages 493-494), with their default names and alignments. The bit
/// attributes are refused before this is consulted.
fn rl_attr(word: &str) -> Option<Attr> {
    use Class::*;
    Some(match word {
        "callt0" => attr(".callt0", Code, 2, Seg::Code),
        "text" => attr(".text", Code, 1, Seg::Code),
        "textf" => attr(".textf", Code, 1, Seg::Code),
        "textf_unit64kp" => attr(".textf_unit64kp", Code, 2, Seg::Code),
        "const" => attr(".const", Const, 2, Seg::Code),
        "constf" => attr(".constf", Const, 2, Seg::Code),
        "opt_byte" => attr(".option_byte", Const, 1, Seg::Code),
        "secur_id" => attr(".security_id", Const, 1, Seg::Code),
        "flash_secur_id" => attr(".flash_security_id", Const, 1, Seg::Code),
        "at" => Attr {
            at: true,
            ..attr(".text", Code, 1, Seg::Code)
        },
        "sdata" => attr(".sdata", Data, 2, Seg::Data),
        "sbss" => attr(".sbss", Bss, 2, Seg::Data),
        "data" => attr(".data", Data, 2, Seg::Data),
        "bss" => attr(".bss", Bss, 2, Seg::Data),
        "dataf" => attr(".dataf", Data, 2, Seg::Data),
        "bssf" => attr(".bssf", Bss, 2, Seg::Data),
        "data_at" => Attr {
            at: true,
            ..attr(".data", Data, 1, Seg::Data)
        },
        "bss_at" => Attr {
            at: true,
            ..attr(".bss", Bss, 1, Seg::Data)
        },
        _ => return None,
    })
}

/// The relocation attributes CC-RH documents for `.cseg` (Table 5.8, pages
/// 426-427) and `.dseg` (Table 5.9, pages 428-430). Every data attribute's
/// default alignment is 4, and whether it holds initial values is in its
/// name.
fn rh_attr(word: &str) -> Option<Attr> {
    use Class::*;
    Some(match word {
        "text" => attr(".text", Code, 2, Seg::Code),
        "pctext" => attr(".pctext", Code, 2, Seg::Code),
        "zconst" => attr(".zconst", Const, 4, Seg::Code),
        "zconst23" => attr(".zconst23", Const, 4, Seg::Code),
        "const" => attr(".const", Const, 4, Seg::Code),
        "pcconst16" => attr(".pcconst16", Const, 4, Seg::Code),
        "pcconst23" => attr(".pcconst23", Const, 4, Seg::Code),
        "pcconst32" => attr(".pcconst32", Const, 4, Seg::Code),
        "sdata" => attr(".sdata", Data, 4, Seg::Data),
        "sbss" => attr(".sbss", Bss, 4, Seg::Data),
        "sdata23" => attr(".sdata23", Data, 4, Seg::Data),
        "sbss23" => attr(".sbss23", Bss, 4, Seg::Data),
        "sdata32" => attr(".sdata32", Data, 4, Seg::Data),
        "sbss32" => attr(".sbss32", Bss, 4, Seg::Data),
        "tdata" => attr(".tdata", Data, 4, Seg::Data),
        "tdata4" => attr(".tdata4", Data, 4, Seg::Data),
        "tbss4" => attr(".tbss4", Bss, 4, Seg::Data),
        "tdata5" => attr(".tdata5", Data, 4, Seg::Data),
        "tbss5" => attr(".tbss5", Bss, 4, Seg::Data),
        "tdata7" => attr(".tdata7", Data, 4, Seg::Data),
        "tbss7" => attr(".tbss7", Bss, 4, Seg::Data),
        "tdata8" => attr(".tdata8", Data, 4, Seg::Data),
        "tbss8" => attr(".tbss8", Bss, 4, Seg::Data),
        "edata" => attr(".edata", Data, 4, Seg::Data),
        "ebss" => attr(".ebss", Bss, 4, Seg::Data),
        "edata23" => attr(".edata23", Data, 4, Seg::Data),
        "ebss23" => attr(".ebss23", Bss, 4, Seg::Data),
        "edata32" => attr(".edata32", Data, 4, Seg::Data),
        "ebss32" => attr(".ebss32", Bss, 4, Seg::Data),
        "zdata" => attr(".zdata", Data, 4, Seg::Data),
        "zbss" => attr(".zbss", Bss, 4, Seg::Data),
        "zdata23" => attr(".zdata23", Data, 4, Seg::Data),
        "zbss23" => attr(".zbss23", Bss, 4, Seg::Data),
        "data" => attr(".data", Data, 4, Seg::Data),
        "bss" => attr(".bss", Bss, 4, Seg::Data),
        _ => return None,
    })
}

impl Assembler {
    /// Runs a CC-RL/CC-RH directive. `stmt`'s arguments start just after it.
    pub(crate) fn run_cc(&mut self, stmt: &Statement, d: CcDirective) {
        let span = stmt.span;
        let mut cur = stmt.arg_cursor();
        match d {
            CcDirective::Cseg => self.cc_segment(stmt, &mut cur, Seg::Code),
            CcDirective::Dseg => self.cc_segment(stmt, &mut cur, Seg::Data),
            CcDirective::Section => self.cc_section(&mut cur, span),
            CcDirective::Org => self.cc_org(&mut cur, span),
            CcDirective::Align => self.cc_align(&mut cur, span),
            CcDirective::Dshw => self.cc_dshw(&mut cur, span),
            CcDirective::Public => self.cc_declare(&mut cur, Some(Binding::Global)),
            CcDirective::Extern => self.cc_declare(&mut cur, None),
            CcDirective::AliasOf => self.cc_alias(&mut cur),
            CcDirective::ElseIfN => {
                self.dir_elseif_kind(&mut cur, span, ".ifeq");
            }
            CcDirective::Include => {
                if let Some(path) = self.cc_file_name(&mut cur, span) {
                    match self.find_include(&path) {
                        Some(p) => self.include(&p, span),
                        None => self
                            .diags
                            .error(span, format!("cannot find include file `{path}`")),
                    }
                }
            }
            CcDirective::Binclude => {
                if let Some(path) = self.cc_file_name(&mut cur, span) {
                    match self.find_include(&path).map(std::fs::read) {
                        Some(Ok(data)) => self.emit_bytes(&data, span),
                        Some(Err(e)) => {
                            self.diags.error(span, format!("cannot read `{path}`: {e}"))
                        }
                        None => self.diags.error(span, format!("cannot find `{path}`")),
                    }
                }
            }
            CcDirective::Local => {
                self.diags.error(
                    span,
                    "`.LOCAL` is only allowed inside a macro, `.REPT` or `.IRP` body",
                );
                cur.set_pos(cur.all().len());
            }
            CcDirective::Arch => {
                let name = match stmt.body {
                    Some(crate::parser::Body::Directive { name, .. }) => {
                        self.interner.get(name).to_string()
                    }
                    _ => String::new(),
                };
                if !self.arch_directive(stmt, &name) {
                    self.diags.error(
                        span,
                        format!(
                            "`{}` is not supported by the `{}` backend",
                            name.to_ascii_uppercase(),
                            self.arch.name()
                        ),
                    );
                }
                return;
            }
            CcDirective::Unsupported(why) => {
                self.diags.error(span, why);
                return;
            }
        }
        self.expect_end(&mut cur);
    }

    /// The attribute table of the current dialect.
    fn cc_attr(&self, word: &str) -> Option<Attr> {
        if self.options.dialect == Dialect::CcRl {
            rl_attr(word)
        } else {
            rh_attr(word)
        }
    }

    /// Reads a relocation attribute and, for the `AT` kinds, its address.
    fn cc_read_attr(
        &mut self,
        cur: &mut Cursor<'_>,
        seg: Option<Seg>,
    ) -> Option<(Attr, Option<i64>)> {
        let tok = cur.peek();
        let Some(n) = tok.ident() else {
            self.diags
                .error(tok.span, "expected a relocation attribute");
            return None;
        };
        cur.advance();
        let word = self.interner.get(n).to_ascii_lowercase();
        if matches!(word.as_str(), "sbss_bit" | "bss_bit" | "bit_at")
            && self.options.dialect == Dialect::CcRl
        {
            self.diags.error(tok.span, BIT_SYMBOLS);
            return None;
        }
        let attr = match self.cc_attr(&word) {
            Some(a) if seg.is_none_or(|s| s == a.seg) => a,
            Some(_) => {
                let dir = if seg == Some(Seg::Code) {
                    ".CSEG"
                } else {
                    ".DSEG"
                };
                self.diags.error(
                    tok.span,
                    format!(
                        "`{}` is not a relocation attribute `{dir}` accepts",
                        word.to_ascii_uppercase()
                    ),
                );
                return None;
            }
            None => {
                self.diags.error(
                    tok.span,
                    format!("unknown relocation attribute `{}`", self.interner.get(n)),
                );
                return None;
            }
        };
        let addr = if attr.at {
            let e = self.parse_expr(cur)?;
            let v = self.eval_absolute(e, "section address")?;
            // CC-RL page 488, note 5.
            if !(0..=0xfffff).contains(&v) {
                let espan = self.exprs.span(e);
                self.diags.error(
                    espan,
                    format!("section address {v:#x} is out of range (0x00000 to 0xFFFFF)"),
                );
                return None;
            }
            Some(v)
        } else {
            None
        };
        Some((attr, addr))
    }

    /// `[name] .CSEG [attribute]` and `[name] .DSEG [attribute]`. Without an
    /// attribute CC-RL assumes `TEXT` and `DATA` (pages 492 and 494); CC-RH's
    /// syntax makes it optional too, and the same defaults are used.
    fn cc_segment(&mut self, stmt: &Statement, cur: &mut Cursor<'_>, seg: Seg) {
        let attr = if cur.at_end() {
            let word = if seg == Seg::Code { "text" } else { "data" };
            (self.cc_attr(word).expect("default attribute exists"), None)
        } else {
            match self.cc_read_attr(cur, Some(seg)) {
                Some(a) => a,
                None => {
                    cur.set_pos(cur.all().len());
                    return;
                }
            }
        };
        let name = stmt.symbol.map(|(n, _)| self.interner.get(n).to_string());
        self.cc_enter(name, attr, None, stmt.span);
    }

    /// `.SECTION name, attribute[, ALIGN=n]` (CC-RL page 486, CC-RH page 431).
    fn cc_section(&mut self, cur: &mut Cursor<'_>, span: Span) {
        let tok = cur.peek();
        let name = match tok.kind {
            TokKind::Ident(n) => self.interner.get(n).to_string(),
            TokKind::Str(i) => String::from_utf8_lossy(self.pool.get(i)).into_owned(),
            _ => {
                self.diags.error(tok.span, "expected a section name");
                cur.set_pos(cur.all().len());
                return;
            }
        };
        cur.advance();
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags
                .error(cur.peek().span, "expected `,` and a relocation attribute");
            cur.set_pos(cur.all().len());
            return;
        }
        let Some(attr) = self.cc_read_attr(cur, None) else {
            cur.set_pos(cur.all().len());
            return;
        };
        let mut align = None;
        while cur.eat_punct(Punct::Comma).is_some() {
            let tok = cur.peek();
            let word = tok
                .ident()
                .map(|n| self.interner.get(n).to_ascii_lowercase());
            match word.as_deref() {
                Some("align") if cur.nth(1).is_punct(Punct::Eq) => {
                    cur.advance();
                    cur.advance();
                    let Some(e) = self.parse_expr(cur) else {
                        return;
                    };
                    let Some(v) = self.eval_absolute(e, "section alignment") else {
                        return;
                    };
                    // 1 or 2 on CC-RL (page 489), 1, 2 or 4 on CC-RH (page
                    // 431), and never for code.
                    let allowed: &[i64] = if self.options.dialect == Dialect::CcRl {
                        &[1, 2]
                    } else {
                        &[1, 2, 4]
                    };
                    if attr.0.class == Class::Code {
                        self.diags
                            .error(tok.span, "`ALIGN` cannot be given for a code section");
                        return;
                    }
                    if !allowed.contains(&v) {
                        self.diags.error(
                            tok.span,
                            format!("section alignment {v} is not one of {allowed:?}"),
                        );
                        return;
                    }
                    align = Some(v as u64);
                }
                Some("comdat") => {
                    self.diags.error(
                        tok.span,
                        "`COMDAT` sections are not supported: rsasm writes no section groups",
                    );
                    cur.set_pos(cur.all().len());
                    return;
                }
                _ => {
                    self.diags.error(
                        tok.span,
                        "expected `ALIGN=n` after the relocation attribute",
                    );
                    cur.set_pos(cur.all().len());
                    return;
                }
            }
        }
        self.cc_enter(Some(name), attr, align, span);
    }

    /// Switches to the section a definition directive names.
    fn cc_enter(
        &mut self,
        name: Option<String>,
        (attr, addr): (Attr, Option<i64>),
        align: Option<u64>,
        span: Span,
    ) {
        let mut name = name.unwrap_or_else(|| attr.name.to_string());
        if let Some(a) = addr {
            // "name" + "_AT" + the address in uppercase hex (CC-RL page 486).
            name = format!("{name}_AT{a:X}");
        }
        let (kind, flags) = match attr.class {
            Class::Code => (SectionKind::Progbits, SectionFlags::text()),
            Class::Const => (SectionKind::Progbits, SectionFlags::rodata()),
            Class::Data => (SectionKind::Progbits, SectionFlags::data()),
            Class::Bss => (SectionKind::Nobits, SectionFlags::bss()),
        };
        self.cc_switch(&name, kind, flags, align.unwrap_or(attr.align), span);
    }

    fn cc_switch(
        &mut self,
        name: &str,
        kind: SectionKind,
        flags: SectionFlags,
        align: u64,
        span: Span,
    ) {
        let n = self.interner.intern(name);
        let existed = self.sections.iter().any(|s| s.name == n);
        let id = self.get_or_create_section(n, kind, flags, align);
        let s = self.section(id);
        // Sections of one name must share one relocation attribute (CC-RL
        // page 485, CC-RH page 425). The initial `.text` counts as `TEXT`.
        if existed && (s.kind != kind || s.flags.exec != flags.exec || s.flags.write != flags.write)
        {
            self.diags.error(
                span,
                format!(
                    "section `{name}` was already defined with a different relocation attribute"
                ),
            );
            return;
        }
        let s = self.section_mut(id);
        s.align = s.align.max(align);
        self.set_section(id);
    }

    /// `.ORG address`: the code after it goes into a section of its own named
    /// after the current one and the address, with the same attribute (CC-RL
    /// page 498; CC-RH page 432, which joins them with `.AT` instead of
    /// `_AT`). The address itself is the linker's to honour.
    fn cc_org(&mut self, cur: &mut Cursor<'_>, span: Span) {
        let Some(e) = self.parse_expr(cur) else {
            cur.set_pos(cur.all().len());
            return;
        };
        let Some(v) = self.eval_absolute(e, "`.ORG` address") else {
            return;
        };
        let rl = self.options.dialect == Dialect::CcRl;
        if (rl && !(0..=0xfffff).contains(&v)) || !(0..=0xffff_ffff).contains(&v) {
            self.diags
                .error(span, format!("`.ORG` address {v:#x} is out of range"));
            return;
        }
        let cur_sec = self.section(self.cur);
        let (kind, flags) = (cur_sec.kind, cur_sec.flags);
        let base = self.interner.get(cur_sec.name).to_string();
        let sep = if rl { "_AT" } else { ".AT" };
        let base = match base.find(sep) {
            Some(i) => base[..i].to_string(),
            None => base,
        };
        self.cc_switch(&format!("{base}{sep}{v:X}"), kind, flags, 1, span);
    }

    /// `.ALIGN n`: an even number from 2 (CC-RL page 512; CC-RH page 453,
    /// which adds a fill byte). The gap is zero-filled in every section,
    /// code included, as both manuals say.
    fn cc_align(&mut self, cur: &mut Cursor<'_>, span: Span) {
        let Some(e) = self.parse_expr(cur) else {
            cur.set_pos(cur.all().len());
            return;
        };
        let Some(n) = self.eval_absolute(e, "alignment") else {
            return;
        };
        if n < 2 || n % 2 != 0 || n >= 1 << 31 {
            self.diags.error(
                span,
                format!("alignment {n} must be an even number from 2 up to 2^31"),
            );
            return;
        }
        if !(n as u64).is_power_of_two() {
            // The manuals take any even number and align the section to the
            // least common multiple; an ELF section's alignment has to be a
            // power of two.
            self.diags.error(
                span,
                format!("alignment {n} is not a power of two, which an ELF section needs"),
            );
            return;
        }
        let mut fill = 0u8;
        if self.options.dialect == Dialect::CcRh && cur.eat_punct(Punct::Comma).is_some() {
            let Some(f) = self.parse_expr(cur) else {
                return;
            };
            let Some(v) = self.eval_absolute(f, "fill value") else {
                return;
            };
            // Only the low byte is used (page 453).
            fill = v as u8;
        }
        let unit = n as u64;
        self.cur_section().push(Fragment::new(
            FragKind::Align {
                align: unit,
                fill: vec![fill],
                max_skip: None,
                pad: 0,
            },
            span,
        ));
        let id = self.cur;
        self.section_mut(id).align = self.section(id).align.max(unit);
    }

    /// `.DB` to `.DB8`, and CC-RH's `.dhw`, `.dw` and `.ddw` for the same
    /// widths. Only `.DB` takes a string (CC-RL page 506, CC-RH page 445).
    ///
    /// CC-RH keeps the low bytes of a value too wide for its field (pages
    /// 445-449), so a constant is truncated here as well. It also gives a
    /// label in data two meanings (Table 5.25, page 497): `#label` and
    /// `!label` are its address, the plain `label` its offset within its
    /// section. The address is what an ELF relocation holds; the offset is
    /// not expressible, and is refused once it is certain the value is a
    /// label and not a constant defined further on.
    pub(crate) fn cc_data(&mut self, cur: &mut Cursor<'_>, width: u8, span: Span) {
        let rh = self.options.dialect == Dialect::CcRh;
        loop {
            if let TokKind::Str(i) = cur.peek().kind
                && width == 1
            {
                cur.advance();
                let bytes = self.pool.get(i).to_vec();
                self.emit_bytes(&bytes, span);
            } else {
                let address = rh && self.cc_address_prefix(cur);
                if self.diags.saturated() {
                    return;
                }
                let Some(e) = self.parse_expr(cur) else {
                    cur.set_pos(cur.all().len());
                    return;
                };
                match self.eval_ref(e).ok().and_then(|v| v.as_abs()) {
                    Some(v) if rh => {
                        let bytes = self.arch.endian().bytes(v as u64, width as usize);
                        self.emit_bytes(&bytes, span);
                    }
                    _ => {
                        if rh && !address {
                            self.cc_bare_labels.push(e);
                        }
                        self.emit_value(width, e, span);
                    }
                }
            }
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
    }

    /// Consumes a CC-RH label-reference prefix in data, returning whether it
    /// asked for an address. `$label` and `%label` are gp- and ep-relative
    /// offsets, for which the RH850 ELF ABI has no data relocation; they are
    /// reported, and the label is then read as if unprefixed.
    fn cc_address_prefix(&mut self, cur: &mut Cursor<'_>) -> bool {
        let tok = cur.peek();
        let next = cur.nth(1);
        if tok.is_punct(Punct::Hash) {
            cur.advance();
            return true;
        }
        // `!` is also the bitwise NOT; before a name that is not a constant it
        // can only be the address reference.
        if tok.is_punct(Punct::Bang)
            && let Some(n) = next.ident()
            && !self.symbols.lookup(n).is_some_and(|id| {
                matches!(
                    self.symbols.get(id).value,
                    crate::symbol::SymbolValue::Expr(_)
                )
            })
        {
            cur.advance();
            return true;
        }
        if (tok.is_punct(Punct::Dollar) || tok.is_punct(Punct::Percent)) && next.ident().is_some() {
            let what = if tok.is_punct(Punct::Dollar) {
                "gp"
            } else {
                "ep"
            };
            self.diags.error(
                tok.span.to(next.span),
                format!("a {what}-relative label reference cannot be data: the RH850 ELF ABI has no relocation for it"),
            );
            cur.advance();
            return true;
        }
        false
    }

    /// Reports the CC-RH data values that turned out to be labels written
    /// without `#`; see [`Assembler::cc_data`]. Run once every symbol is
    /// defined.
    pub(crate) fn check_cc_bare_labels(&mut self) {
        for e in std::mem::take(&mut self.cc_bare_labels) {
            if let Ok(v) = self.eval_ref(e)
                && v.plus.is_some()
                && v.minus.is_none()
            {
                let span = self.exprs.span(e);
                self.diags.emit(
                    crate::diag::Diagnostic::error(
                        span,
                        "in CC-RH data a plain label is its offset within its section, which no ELF relocation can express",
                    )
                    .with_help("write `#label` for the label's address"),
                );
            }
        }
    }

    /// CC-RH `.dshw`: each value shifted right one bit, in two bytes (page
    /// 447). The value must be absolute.
    fn cc_dshw(&mut self, cur: &mut Cursor<'_>, span: Span) {
        loop {
            let Some(e) = self.parse_expr(cur) else {
                cur.set_pos(cur.all().len());
                return;
            };
            let Some(v) = self.eval_absolute(e, "`.dshw` value") else {
                return;
            };
            let bytes = self.arch.endian().bytes((v >> 1) as u64, 2);
            self.emit_bytes(&bytes, span);
            if cur.eat_punct(Punct::Comma).is_none() {
                break;
            }
        }
    }

    /// `.PUBLIC name` and `.EXTERN name`. CC-RH allows a size after the name,
    /// which it ignores too (pages 455 and 457). Undefined symbols are
    /// external already, so `.EXTERN` only records the name.
    fn cc_declare(&mut self, cur: &mut Cursor<'_>, binding: Option<Binding>) {
        let tok = cur.peek();
        let Some(name) = tok.ident() else {
            self.diags.error(tok.span, "expected a symbol name");
            cur.set_pos(cur.all().len());
            return;
        };
        cur.advance();
        let id = self.symbols.intern(name, tok.span);
        if let Some(b) = binding {
            self.symbols.get_mut(id).binding = b;
        }
        if self.options.dialect == Dialect::CcRh && cur.eat_punct(Punct::Comma).is_some() {
            let _ = self.parse_expr(cur);
        }
    }

    /// CC-RL `.ALIAS alias, symbol` (page 524): another name for a symbol
    /// already defined.
    fn cc_alias(&mut self, cur: &mut Cursor<'_>) {
        let tok = cur.peek();
        let Some(alias) = tok.ident() else {
            self.diags.error(tok.span, "expected the alias name");
            cur.set_pos(cur.all().len());
            return;
        };
        cur.advance();
        if cur.eat_punct(Punct::Comma).is_none() {
            self.diags.error(
                cur.peek().span,
                "expected `,` and the symbol the alias names",
            );
            cur.set_pos(cur.all().len());
            return;
        }
        let Some(e) = self.parse_expr(cur) else {
            cur.set_pos(cur.all().len());
            return;
        };
        self.set_symbol(alias, e, tok.span);
    }

    /// The file of `$INCLUDE (file)` or `$INCLUDE "file"`. Inside parentheses
    /// the name is taken as written, since a path does not lex as one token.
    fn cc_file_name(&mut self, cur: &mut Cursor<'_>, span: Span) -> Option<String> {
        let tok = cur.peek();
        if let TokKind::Str(i) = tok.kind {
            cur.advance();
            return Some(String::from_utf8_lossy(self.pool.get(i)).into_owned());
        }
        if tok.is_punct(Punct::LParen) {
            let rest = cur.rest();
            if let Some(close) = rest.iter().rposition(|t| t.is_punct(Punct::RParen))
                && close > 0
            {
                let text = self
                    .sm
                    .span_text(Span::new(rest[0].span.hi, rest[close].span.lo))
                    .trim()
                    .to_string();
                cur.set_pos(cur.pos() + close + 1);
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        self.diags
            .error(span, "expected a file name, as `(file)` or `\"file\"`");
        cur.set_pos(cur.all().len());
        None
    }
}
