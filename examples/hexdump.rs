//! Assembles stdin and prints the `.text` bytes as hex. Used by the
//! differential test script to compare against GNU as.

use rsasm::arch;
use rsasm::assembler::{Assembler, Options};
use rsasm::section::SectionId;
use std::io::Read;

fn main() {
    let mut src = String::new();
    std::io::stdin().read_to_string(&mut src).expect("read stdin");

    let name = std::env::args().nth(1).unwrap_or_else(|| "x86-64".into());
    let Some(arch) = arch::lookup(&name) else {
        eprintln!("unknown architecture `{name}`");
        std::process::exit(2);
    };
    let mut asm = Assembler::new(arch, Options::default());
    asm.assemble_str("<stdin>", &src);
    let ok = asm.finish();
    if !ok || asm.diags.has_errors() {
        print!("RSASM-ERROR: {}", asm.diags.render(&asm.sm, false).replace('\n', " | "));
        println!();
        std::process::exit(1);
    }
    let bytes = asm.section_bytes(SectionId(0));
    println!("{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
}
