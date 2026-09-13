//! The symbol table.

use crate::expr::ExprRef;
use crate::intern::{Interner, Name};
use crate::section::SectionId;
use crate::source::Span;
use std::collections::HashMap;

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SymbolId(pub u32);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Binding {
    Local,
    Global,
    Weak,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SymType {
    #[default]
    NoType,
    Object,
    Func,
    Section,
    File,
    Tls,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Visibility {
    #[default]
    Default,
    Internal,
    Hidden,
    Protected,
}

#[derive(Clone, Debug)]
pub enum SymbolValue {
    /// Referenced but never defined: the linker must supply it.
    Undefined,
    /// A label: the address of fragment `frag` in `section`.
    Label { section: SectionId, frag: u32 },
    /// Defined by `.set` / `.equ` / `=`.
    Expr(ExprRef),
    /// A `.comm` / `.lcomm` tentative definition.
    Common { size: u64, align: u64 },
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: Name,
    pub value: SymbolValue,
    pub binding: Binding,
    pub ty: SymType,
    pub visibility: Visibility,
    pub size: Option<ExprRef>,
    /// Where the symbol was defined; dummy while only referenced.
    pub def_span: Span,
    /// First place the symbol was mentioned, for "undefined symbol" errors.
    pub first_use: Span,
    /// Set for the synthetic symbols behind numeric local labels (`1:`).
    pub local_number: Option<u32>,
    /// `.set` symbols may be redefined; plain labels may not.
    pub redefinable: bool,
    pub used: bool,
}

impl Symbol {
    pub fn is_defined(&self) -> bool {
        !matches!(self.value, SymbolValue::Undefined)
    }
}

#[derive(Default)]
pub struct SymbolTable {
    syms: Vec<Symbol>,
    by_name: HashMap<Name, SymbolId>,
    /// For each numeric local label `N`, the synthetic symbols created for it,
    /// in definition order.
    locals: HashMap<u32, LocalSlots>,
}

#[derive(Default)]
struct LocalSlots {
    /// One entry per `N:` occurrence, created on demand by forward references.
    slots: Vec<SymbolId>,
    /// How many of `slots` have actually been defined so far.
    defined: usize,
}

impl SymbolTable {
    pub fn new() -> SymbolTable {
        SymbolTable::default()
    }

    pub fn len(&self) -> usize {
        self.syms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }

    pub fn get(&self, id: SymbolId) -> &Symbol {
        &self.syms[id.0 as usize]
    }

    pub fn get_mut(&mut self, id: SymbolId) -> &mut Symbol {
        &mut self.syms[id.0 as usize]
    }

    pub fn iter(&self) -> impl Iterator<Item = (SymbolId, &Symbol)> {
        self.syms.iter().enumerate().map(|(i, s)| (SymbolId(i as u32), s))
    }

    pub fn lookup(&self, name: Name) -> Option<SymbolId> {
        self.by_name.get(&name).copied()
    }

    /// Finds `name`, creating an undefined entry if it is new.
    pub fn intern(&mut self, name: Name, span: Span) -> SymbolId {
        if let Some(&id) = self.by_name.get(&name) {
            return id;
        }
        let id = self.push(Symbol {
            name,
            value: SymbolValue::Undefined,
            binding: Binding::Local,
            ty: SymType::NoType,
            visibility: Visibility::Default,
            size: None,
            def_span: Span::DUMMY,
            first_use: span,
            local_number: None,
            redefinable: false,
            used: false,
        });
        self.by_name.insert(name, id);
        id
    }

    /// Creates the symbol that stands for a whole section.
    ///
    /// It is deliberately not registered by name: `.text` as a section symbol
    /// and `.text` as a user-written label are different things.
    pub fn intern_section(&mut self, name: Name, section: SectionId) -> SymbolId {
        self.push(Symbol {
            name,
            value: SymbolValue::Label { section, frag: 0 },
            binding: Binding::Local,
            ty: SymType::Section,
            visibility: Visibility::Default,
            size: None,
            def_span: Span::DUMMY,
            first_use: Span::DUMMY,
            local_number: None,
            redefinable: false,
            used: true,
        })
    }

    fn push(&mut self, s: Symbol) -> SymbolId {
        let id = SymbolId(self.syms.len() as u32);
        self.syms.push(s);
        id
    }

    /// Resolves a backward reference `Nb` to the most recent `N:`.
    pub fn local_backward(&mut self, n: u32, _span: Span) -> Option<SymbolId> {
        let slots = self.locals.get(&n)?;
        if slots.defined == 0 {
            return None;
        }
        Some(slots.slots[slots.defined - 1])
    }

    /// Resolves a forward reference `Nf` to the *next* `N:` to be defined,
    /// creating a placeholder symbol for it if that definition has not been
    /// seen yet.
    pub fn local_forward(&mut self, n: u32, span: Span, interner: &mut Interner) -> SymbolId {
        let idx = self.locals.entry(n).or_default().defined;
        self.local_slot(n, idx, span, interner)
    }

    /// Claims the slot for the next `N:` definition.
    pub fn local_define_slot(&mut self, n: u32, span: Span, interner: &mut Interner) -> SymbolId {
        let idx = self.locals.entry(n).or_default().defined;
        let id = self.local_slot(n, idx, span, interner);
        self.locals.get_mut(&n).expect("slot just created").defined = idx + 1;
        id
    }

    fn local_slot(&mut self, n: u32, idx: usize, span: Span, interner: &mut Interner) -> SymbolId {
        if let Some(&id) = self.locals.get(&n).and_then(|s| s.slots.get(idx)) {
            return id;
        }
        // The NUL byte makes these names unspellable in source, so a synthetic
        // local can never collide with a user symbol.
        let name = interner.intern(&format!(".L\u{0}{n}.{idx}"));
        let id = self.push(Symbol {
            name,
            value: SymbolValue::Undefined,
            binding: Binding::Local,
            ty: SymType::NoType,
            visibility: Visibility::Default,
            size: None,
            def_span: Span::DUMMY,
            first_use: span,
            local_number: Some(n),
            redefinable: false,
            used: false,
        });
        let slots = self.locals.entry(n).or_default();
        debug_assert_eq!(slots.slots.len(), idx, "local label slots must be filled in order");
        slots.slots.push(id);
        id
    }

    /// Numeric local labels that were referenced forward but never defined.
    pub fn undefined_locals(&self) -> impl Iterator<Item = (SymbolId, u32)> + '_ {
        self.locals.iter().flat_map(|(&n, s)| {
            s.slots[s.defined..].iter().map(move |&id| (id, n))
        })
    }
}
