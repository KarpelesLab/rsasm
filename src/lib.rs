//! rsasm — a multi-syntax, multi-architecture assembler.
//!
//! ```
//! use rsasm::{arch, assembler::{Assembler, Options}, section::SectionId};
//!
//! let mut asm = Assembler::new(arch::lookup("x86-64").unwrap(), Options::default());
//! asm.assemble_str("example.s", "movq %rbx, %rax\nret\n");
//! assert!(asm.finish());
//! assert_eq!(asm.section_bytes(SectionId(0)), vec![0x48, 0x89, 0xd8, 0xc3]);
//! ```
//!
//! The pipeline is [`lexer`] to [`parser`] to an architecture backend
//! ([`arch`]), which produces [`section`] fragments that [`layout`] resolves
//! into bytes and relocations for [`output`].

pub mod diag;
pub mod intern;
pub mod lexer;
pub mod source;
pub mod cursor;
pub mod expr;
pub mod section;
pub mod symbol;
pub mod arch;
pub mod parser;
pub mod assembler;
pub mod directives;
pub mod layout;
pub mod output;
