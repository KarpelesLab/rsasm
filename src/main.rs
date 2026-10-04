//! The `rsasm` command line driver.

use rsasm::arch;
use rsasm::assembler::{Assembler, ImplicitIt, Options};
use rsasm::lexer::Dialect;
use rsasm::output::{self, Format};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
rsasm - a multi-syntax, multi-architecture assembler

usage: rsasm [options] <input.s>...

options:
  -o <file>          write output to <file> (default: a.out)
  -a, --arch <name>  target architecture (default: the host, if supported),
                     or a target triple: `x86_64-apple-macos` also picks
                     Mach-O output, `x86_64-pc-windows-msvc` PE/COFF
  -f, --format <fmt> output format: elf (default), elf32, elf64, coff,
                     win64, win32, macho, bin or ihex
  -s, --syntax <s>   initial operand syntax: att (default) or intel
  -d, --dialect <d>  source dialect: gas, nasm, motorola, renesas (CA78K0),
                     ccrl (Renesas CC-RL), ccrh (Renesas CC-RH),
                     ccrx (Renesas CC-RX) or 8bit (6502, Z80, 8080, 8051)
                     (default: the architecture's usual one)
      --mimplicit-it=<m>
                     ARM: when a conditional Thumb instruction with no `it`
                     block of its own gets one made up for it -- never, arm
                     (default), thumb or always -- spelled as GNU as spells
                     it, `-mimplicit-it=<m>`, as well
  -I <dir>           add <dir> to the .include search path
  -D <sym>[=<val>]   define <sym> before assembling (default value 1)
      --base <addr>  base address for `bin` and `ihex` output (default 0)
      --hex          print the output as hex instead of writing a file
  -g                 describe the assembly source in DWARF line information
      --gdwarf-<n>   the same, as DWARF version <n> (2 to 5); the version
                     also applies to `.loc` source
      --list-arch    list the architectures this build supports
      --no-color     do not colorize diagnostics
  -h, --help         show this message

linking (`--link`, x86-64 and AArch64 ELF or PE32+ only):
      --link         link the object into a runnable program instead of
                     writing it, and write that to <file>
  -e, --entry <sym>  entry symbol (default: the target's, `_start`)
  -l <name>          link against lib<name>; `-l:<file>` names a file in the
                     search path, which is how `crt1.o` is reached
  -L <dir>           add <dir> to the library search path
      --dynamic-linker <path>
                     record <path> as the program interpreter
      -shared        link a shared library
      -pie           link a position-independent executable
";

/// What `--link` and the options around it asked for.
///
/// The parser accepts them whether or not this build has the `link`
/// feature, so that a build without it can say so plainly rather than
/// report an unknown option.
#[cfg_attr(not(feature = "link"), allow(dead_code))]
#[derive(Default)]
struct Link {
    wanted: bool,
    entry: Option<String>,
    libraries: Vec<String>,
    search_paths: Vec<PathBuf>,
    dynamic_linker: Option<PathBuf>,
    shared: bool,
    pie: bool,
}

struct Args {
    inputs: Vec<PathBuf>,
    output: PathBuf,
    arch: Option<String>,
    format: Format,
    options: Options,
    defines: Vec<(String, String)>,
    hex: bool,
    color: bool,
    link: Link,
    /// Whether `-d` was given; otherwise the architecture picks.
    dialect_given: bool,
    /// The word size `-f elf32`, `-f elf64`, `-f win32` or `-f win64` named,
    /// which picks the architecture when `-a` does not.
    elf_bits: Option<u8>,
    /// Whether `-f` was given; otherwise a Darwin target triple picks Mach-O.
    format_given: bool,
}

/// Applies a builder method to the options in place, since [`Options`]'s
/// builders take and return the whole value.
fn edit(o: &mut Options, f: impl FnOnce(Options) -> Options) {
    *o = f(std::mem::take(o));
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
        options: Options::new(),
        defines: Vec::new(),
        hex: false,
        color: std::io::IsTerminal::is_terminal(&std::io::stderr()),
        link: Link::default(),
        dialect_given: false,
        elf_bits: None,
        format_given: false,
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
                a.format_given = true;
                a.elf_bits = match v.as_str() {
                    "elf32" | "win32" => Some(32),
                    "elf64" | "win64" => Some(64),
                    _ => None,
                };
            }
            "-s" | "--syntax" => {
                let v = next(&mut i, arg)?;
                let syntax = match v.as_str() {
                    "att" | "at&t" => arch::Syntax::Att,
                    "intel" => arch::Syntax::Intel,
                    _ => return Err(format!("unknown syntax `{v}`")),
                };
                edit(&mut a.options, |o| o.with_syntax(syntax));
            }
            "-d" | "--dialect" => {
                let v = next(&mut i, arg)?;
                let dialect = Dialect::from_name(&v).ok_or_else(|| {
                    format!(
                        "unknown dialect `{v}`; expected gas, nasm, motorola, renesas, ccrl, ccrh or ccrx"
                    )
                })?;
                edit(&mut a.options, |o| o.with_dialect(dialect));
                a.dialect_given = true;
            }
            "-I" => {
                let dir = PathBuf::from(next(&mut i, "-I")?);
                edit(&mut a.options, |o| o.with_include_path(dir));
            }
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
                edit(&mut a.options, |o| {
                    o.with_base_addr(n).with_relocatable(false)
                });
            }
            "--hex" => a.hex = true,
            "-g" | "--gen-debug" => edit(&mut a.options, |o| o.with_debug_source(true)),
            "--gdwarf-2" | "--gdwarf-3" | "--gdwarf-4" | "--gdwarf-5" => {
                edit(&mut a.options, |o| o.with_debug_source(true));
                if let Ok(v) = arg[arg.len() - 1..].parse() {
                    edit(&mut a.options, |o| o.with_dwarf_version(v));
                }
            }
            "--no-color" => a.color = false,
            "--link" => a.link.wanted = true,
            "-e" | "--entry" => a.link.entry = Some(next(&mut i, arg)?),
            "-l" => a.link.libraries.push(next(&mut i, "-l")?),
            "-L" => a.link.search_paths.push(PathBuf::from(next(&mut i, "-L")?)),
            "--dynamic-linker" => {
                a.link.dynamic_linker = Some(PathBuf::from(next(&mut i, arg)?));
            }
            "-shared" => a.link.shared = true,
            "-pie" => a.link.pie = true,
            // GNU as's spelling, which is the one build systems pass, with
            // the long form the other options here have.
            _ if arg.starts_with("-mimplicit-it=") || arg.starts_with("--mimplicit-it=") => {
                let v = arg.split_once('=').map(|(_, v)| v).unwrap_or_default();
                let mode = ImplicitIt::from_name(v).ok_or_else(|| {
                    format!("unknown implicit IT mode `{v}`; expected never, arm, thumb or always")
                })?;
                edit(&mut a.options, |o| o.with_implicit_it(mode));
            }
            _ if arg.starts_with("-l") && arg.len() > 2 => {
                a.link.libraries.push(arg[2..].to_string());
            }
            _ if arg.starts_with("-L") && arg.len() > 2 => {
                a.link.search_paths.push(PathBuf::from(&arg[2..]));
            }
            _ if arg.starts_with("-I") && arg.len() > 2 => {
                let dir = PathBuf::from(&arg[2..]);
                edit(&mut a.options, |o| o.with_include_path(dir));
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
    // A target triple names the architecture first and the object format
    // with the rest of it: `arm64-apple-macos` is arm64 in a Mach-O object,
    // `x86_64-pc-windows-msvc` x86-64 in a COFF one.
    if let Some(name) = a.arch.clone()
        && let Some((cpu, rest)) = name.split_once('-')
        && arch::lookup(&name).is_none()
    {
        if !a.format_given {
            a.format = Format::for_target(rest);
        }
        a.arch = Some(cpu.to_string());
    }
    if a.format == Format::MachO {
        edit(&mut a.options, |o| o.with_format(Format::MachO));
    }
    // Flat output has no relocations to defer to a linker.
    if a.format.is_flat() {
        edit(&mut a.options, |o| o.with_relocatable(false));
    }
    #[cfg(not(feature = "link"))]
    if a.link.wanted {
        return Err(
            "`--link` needs the `link` cargo feature, which this build of rsasm was made without"
                .into(),
        );
    }
    if !a.link.wanted
        && (a.link.entry.is_some()
            || !a.link.libraries.is_empty()
            || !a.link.search_paths.is_empty()
            || a.link.dynamic_linker.is_some()
            || a.link.shared
            || a.link.pie)
    {
        return Err(
            "`-e`, `-l`, `-L`, `--dynamic-linker`, `-shared` and `-pie` describe a link, \
             which only `--link` asks for"
                .into(),
        );
    }
    if a.link.shared && a.link.pie {
        return Err("`-shared` and `-pie` ask for different kinds of output".into());
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
        // NASM's defaults: a flat binary starts in 16-bit mode. And an ELF
        // class, however the source is written, names the x86 machine.
        None => match (args.options.dialect(), args.format, args.elf_bits) {
            (Dialect::Nasm, Format::Binary | Format::IntelHex, _) => arch::lookup("i8086"),
            // `-f elf32`, `-f win32` and their 64-bit spellings name the x86
            // machine as well as the format, as they do in NASM.
            (_, Format::Elf | Format::Coff, Some(32)) => arch::lookup("i386"),
            (_, Format::Elf | Format::Coff, Some(64)) => arch::lookup("x86-64"),
            _ => None,
        }
        .or_else(arch::default_arch)
        .ok_or_else(|| "this build has no architecture backends enabled".to_string())?,
    };

    // Refuse a link rsasm cannot hand to qld before assembling anything, so
    // that the answer does not arrive after the work.
    #[cfg(feature = "link")]
    if args.link.wanted && !rsasm::link::supports(args.format, arch.elf_machine()) {
        return Err(format!(
            "`--link` cannot make a program out of {} output for {}; \
             qld links ELF and PE32+ objects for x86-64 and AArch64",
            format_name(args.format),
            arch.name()
        ));
    }

    let mut options = args.options.clone().with_format(args.format);
    if !args.dialect_given {
        options = options.with_dialect(arch.default_dialect());
    }
    let mut asm = Assembler::new(arch, options);

    // `-D` definitions are assembled as `.set` before the real input, so they
    // behave exactly like a definition at the top of the first file.
    if !args.defines.is_empty() {
        let mut src = String::new();
        for (k, v) in &args.defines {
            // NASM's `-D` defines a single-line macro.
            if asm.options.dialect() == Dialect::Nasm {
                src.push_str(&format!("%define {k} {v}\n"));
            } else {
                src.push_str(&format!(".set {k}, {v}\n"));
            }
        }
        asm.assemble_prelude("<command line>", &src);
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

    #[allow(unused_mut)]
    let mut bytes = match args.format {
        Format::Elf => output::elf::build(&asm).map_err(|e| e.to_string())?,
        Format::Coff => output::coff::build(&asm).map_err(|e| e.to_string())?,
        Format::MachO => output::macho::build(&asm).map_err(|e| e.to_string())?,
        Format::Binary => output::raw::build(&asm).map_err(|e| e.to_string())?,
        Format::IntelHex => output::ihex::build(&asm).map_err(|e| e.to_string())?,
        // `Format` is `#[non_exhaustive]`, so a writer this build does not
        // know about needs an arm; `--format` cannot name one.
        _ => return Err(format!("no writer for {:?} output", args.format)),
    };

    // The object goes straight into the linker, so nothing is written
    // between the two steps; what `-o` names is the program.
    #[cfg(feature = "link")]
    if args.link.wanted {
        bytes = link_image(&args, &asm, bytes)?;
    }

    // Intel HEX is already text; `--hex` prints it as it is.
    if args.hex && args.format == Format::IntelHex {
        print!("{}", String::from_utf8_lossy(&bytes));
        return Ok(ExitCode::SUCCESS);
    }
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
    // A program nobody may execute is not much of a program.
    #[cfg(all(unix, feature = "link"))]
    if args.link.wanted {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.output, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot make `{}` executable: {e}", args.output.display()))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// The `-f` name of a format, for a diagnostic to quote.
#[cfg(feature = "link")]
fn format_name(format: Format) -> &'static str {
    match format {
        Format::Elf => "elf",
        Format::Coff => "coff",
        Format::MachO => "macho",
        Format::Binary => "bin",
        Format::IntelHex => "ihex",
        _ => "this",
    }
}

/// Links the assembled object into a program and returns its bytes.
///
/// Whatever qld reports along the way is rendered here, in rsasm's own
/// style, before the failure is handed back; a link that fails is an
/// ordinary error with a non-zero exit, as a refused instruction is.
#[cfg(feature = "link")]
fn link_image(args: &Args, asm: &Assembler, object: Vec<u8>) -> Result<Vec<u8>, String> {
    use rsasm::diag::DiagBag;
    use rsasm::link::{self, Kind};

    let kind = if args.link.shared {
        Kind::Shared
    } else if args.link.pie {
        Kind::Pie
    } else if args.link.dynamic_linker.is_some() {
        Kind::Executable
    } else {
        Kind::StaticExecutable
    };
    let mut options = link::Options::new()
        .with_kind(kind)
        .with_target(args.format, asm.target().elf_machine());
    if let Some(entry) = &args.link.entry {
        options = options.with_entry(entry);
    }
    if let Some(path) = &args.link.dynamic_linker {
        options = options.with_dynamic_linker(path);
    }
    for dir in &args.link.search_paths {
        options = options.with_search_path(dir);
    }
    for library in &args.link.libraries {
        options = options.with_library(library);
    }

    // The object exists only in memory, so it is named after the first
    // source: that is the file it would otherwise have been written to, and
    // the name a diagnostic about it should use.
    let name = args.inputs.first().and_then(|p| p.file_stem()).map_or_else(
        || "a.o".to_string(),
        |s| format!("{}.o", s.to_string_lossy()),
    );

    let mut diags = DiagBag::new();
    let image = link::link(vec![(name, object)], &options, &mut diags);
    let rendered = diags.render(asm.source_map(), args.color);
    if !rendered.is_empty() {
        eprint!("{rendered}");
    }
    image.map_err(|e| format!("link failed: {e}"))
}
