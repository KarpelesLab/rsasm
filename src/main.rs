//! The `rsasm` command line driver.

use rsasm::arch;
use rsasm::assembler::{Assembler, Options};
use rsasm::lexer::Dialect;
use rsasm::output::{self, Format};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
rsasm - a multi-syntax, multi-architecture assembler

usage: rsasm [options] <input.s>...

options:
  -o <file>          write output to <file> (default: a.out)
  -a, --arch <name>  target architecture (default: the host, if supported)
  -f, --format <fmt> output format: elf (default) or bin
  -s, --syntax <s>   initial operand syntax: att (default) or intel
  -d, --dialect <d>  source dialect: gas, nasm, motorola, renesas (CA78K0),
                     ccrl (Renesas CC-RL), ccrh (Renesas CC-RH) or
                     ccrx (Renesas CC-RX)
                     (default: the architecture's usual one)
  -I <dir>           add <dir> to the .include search path
  -D <sym>[=<val>]   define <sym> before assembling (default value 1)
      --base <addr>  base address for `bin` output (default 0)
      --hex          print the output as hex instead of writing a file
      --list-arch    list the architectures this build supports
      --no-color     do not colorize diagnostics
  -h, --help         show this message
";

struct Args {
    inputs: Vec<PathBuf>,
    output: PathBuf,
    arch: Option<String>,
    format: Format,
    options: Options,
    defines: Vec<(String, String)>,
    hex: bool,
    color: bool,
    /// Whether `-d` was given; otherwise the architecture picks.
    dialect_given: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(None) => return ExitCode::SUCCESS,
        Ok(Some(a)) => a,
        Err(msg) => {
            eprintln!("rsasm: {msg}");
            eprintln!("try `rsasm --help`");
            return ExitCode::from(2);
        }
    };
    match run(parsed) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("rsasm: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Option<Args>, String> {
    let mut a = Args {
        inputs: Vec::new(),
        output: PathBuf::from("a.out"),
        arch: None,
        format: Format::Elf,
        options: Options::default(),
        defines: Vec::new(),
        hex: false,
        color: std::io::IsTerminal::is_terminal(&std::io::stderr()),
        dialect_given: false,
    };
    let mut i = 0;
    // A value may be written `-o x`, `-ox` or `--out=x`.
    let next = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("`{flag}` needs a value"))
    };
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--list-arch" => {
                for n in arch::available() {
                    println!("{n}");
                }
                return Ok(None);
            }
            "-o" => a.output = PathBuf::from(next(&mut i, "-o")?),
            "-a" | "--arch" => a.arch = Some(next(&mut i, arg)?),
            "-f" | "--format" => {
                let v = next(&mut i, arg)?;
                a.format = Format::from_name(&v).ok_or_else(|| format!("unknown format `{v}`"))?;
            }
            "-s" | "--syntax" => {
                let v = next(&mut i, arg)?;
                a.options.syntax = Some(match v.as_str() {
                    "att" | "at&t" => arch::Syntax::Att,
                    "intel" => arch::Syntax::Intel,
                    _ => return Err(format!("unknown syntax `{v}`")),
                });
            }
            "-d" | "--dialect" => {
                let v = next(&mut i, arg)?;
                a.options.dialect = Dialect::from_name(&v).ok_or_else(|| {
                    format!(
                        "unknown dialect `{v}`; expected gas, nasm, motorola, renesas, ccrl, ccrh or ccrx"
                    )
                })?;
                a.dialect_given = true;
            }
            "-I" => a
                .options
                .include_paths
                .push(PathBuf::from(next(&mut i, "-I")?)),
            "-D" => {
                let v = next(&mut i, "-D")?;
                match v.split_once('=') {
                    Some((k, val)) => a.defines.push((k.to_string(), val.to_string())),
                    None => a.defines.push((v, "1".to_string())),
                }
            }
            "--base" => {
                let v = next(&mut i, "--base")?;
                let n =
                    parse_int(&v).ok_or_else(|| format!("`--base` needs a number, got `{v}`"))?;
                a.options.base_addr = n;
                a.options.relocatable = false;
            }
            "--hex" => a.hex = true,
            "--no-color" => a.color = false,
            _ if arg.starts_with("-I") && arg.len() > 2 => {
                a.options.include_paths.push(PathBuf::from(&arg[2..]))
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                return Err(format!("unknown option `{arg}`"));
            }
            _ => a.inputs.push(PathBuf::from(arg)),
        }
        i += 1;
    }

    if a.inputs.is_empty() {
        return Err("no input files".into());
    }
    // Flat binary output has no relocations to defer to a linker.
    if a.format == Format::Binary {
        a.options.relocatable = false;
    }
    Ok(Some(a))
}

fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn run(args: Args) -> Result<ExitCode, String> {
    let arch = match &args.arch {
        Some(name) => arch::lookup(name).ok_or_else(|| {
            format!(
                "unknown architecture `{name}`; this build supports: {}",
                arch::available().join(", ")
            )
        })?,
        None => arch::default_arch()
            .ok_or_else(|| "this build has no architecture backends enabled".to_string())?,
    };

    let mut options = args.options.clone();
    if !args.dialect_given {
        options.dialect = arch.default_dialect();
    }
    let mut asm = Assembler::new(arch, options);

    // `-D` definitions are assembled as `.set` before the real input, so they
    // behave exactly like a definition at the top of the first file.
    if !args.defines.is_empty() {
        let mut src = String::new();
        for (k, v) in &args.defines {
            src.push_str(&format!(".set {k}, {v}\n"));
        }
        asm.assemble_str("<command line>", &src);
    }

    for input in &args.inputs {
        if let Err(e) = asm.assemble_path(input) {
            return Err(format!("cannot read `{}`: {e}", input.display()));
        }
    }
    let ok = asm.finish();

    let rendered = asm.diags.render(&asm.sm, args.color);
    if !rendered.is_empty() {
        eprint!("{rendered}");
    }
    if !ok || asm.diags.has_errors() {
        let n = asm.diags.error_count();
        eprintln!("rsasm: {n} error{}", if n == 1 { "" } else { "s" });
        return Ok(ExitCode::FAILURE);
    }

    let bytes = match args.format {
        Format::Elf => output::elf::build(&asm).map_err(|e| e.to_string())?,
        Format::Binary => output::raw::build(&asm).map_err(|e| e.to_string())?,
    };

    if args.hex {
        for chunk in bytes.chunks(16) {
            println!(
                "{}",
                chunk
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    std::fs::write(&args.output, &bytes)
        .map_err(|e| format!("cannot write `{}`: {e}", args.output.display()))?;
    Ok(ExitCode::SUCCESS)
}
