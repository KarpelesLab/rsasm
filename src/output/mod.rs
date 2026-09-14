//! Output writers.

pub mod elf;
pub mod macho;
pub mod ihex;
pub mod raw;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Format {
    /// ELF relocatable object.
    Elf,
    /// Mach-O relocatable object (`MH_OBJECT`).
    MachO,
    /// A flat image of the allocatable sections, with no metadata.
    Binary,
    /// The flat image as Intel HEX records; see [`ihex`].
    IntelHex,
}

impl Format {
    /// Whether the output is an image the assembler lays out itself, with
    /// every address final and nothing left to a linker.
    pub fn is_flat(self) -> bool {
        matches!(self, Format::Binary | Format::IntelHex)
    }

    pub fn from_name(s: &str) -> Option<Format> {
        Some(match s {
            "elf" | "elf32" | "elf64" | "o" | "obj" => Format::Elf,
            "macho" | "macho64" | "mach-o" => Format::MachO,
            "bin" | "binary" | "raw" => Format::Binary,
            "ihex" | "hex" | "intel-hex" => Format::IntelHex,
            _ => return None,
        })
    }

    /// The format a target name asks for: Darwin's triples (`x86_64-apple-macos`,
    /// `arm64-apple-ios`, `*-darwin*`) name Mach-O, everything else ELF.
    pub fn for_target(name: &str) -> Format {
        let name = name.to_ascii_lowercase();
        if name.contains("apple") || name.contains("darwin") || name.contains("macos") {
            Format::MachO
        } else {
            Format::Elf
        }
    }
}

#[derive(Debug)]
pub enum OutputError {
    Unsupported(String),
    Io(std::io::Error),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputError::Unsupported(m) => write!(f, "{m}"),
            OutputError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OutputError {}

impl From<std::io::Error> for OutputError {
    fn from(e: std::io::Error) -> OutputError {
        OutputError::Io(e)
    }
}
