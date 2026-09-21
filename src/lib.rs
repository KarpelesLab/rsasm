//! rsasm — a multi-syntax, multi-architecture assembler.
//!
//! ```
//! # // Hidden: the example needs a backend, and each one is a cargo feature.
//! # #[cfg(feature = "x86")] {
//! use rsasm::{arch, assembler::{Assembler, Options}, section::SectionId};
//!
//! let mut asm = Assembler::new(arch::lookup("x86-64").unwrap(), Options::default());
//! asm.assemble_str("example.s", "movq %rbx, %rax\nret\n");
//! assert!(asm.finish());
//! assert_eq!(asm.section_bytes(SectionId(0)), vec![0x48, 0x89, 0xd8, 0xc3]);
//! # }
//! ```
//!
//! The pipeline is [`lexer`] to [`parser`] to an architecture backend
//! ([`arch`]), which produces [`section`] fragments that [`layout`] resolves
//! into bytes and relocations for [`output`].

pub mod arch;
pub mod assembler;
pub mod cursor;
pub mod diag;
pub mod dialect;
pub mod dialect_cc;
pub mod directives;
pub mod dwarf;
pub mod expr;
pub mod intern;
pub mod layout;
pub mod lexer;
pub mod literals;
pub mod macros;
pub mod mapping;
pub(crate) mod nasm;
pub mod output;
pub mod parser;
// Not API: the classes only describe a relocation between rsasm's own
// modules, and the writers are what a caller uses.
#[doc(hidden)]
pub mod reloc;
pub mod section;
pub mod source;
pub mod symbol;
