//! Output writers.

pub mod coff;
pub mod elf;
pub mod raw;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Format {
    /// ELF relocatable object.
    Elf,
    /// PE/COFF relocatable object, for Windows.
    Coff,
    /// A flat image of the allocatable sections, with no metadata.
    Binary,
}

impl Format {
    pub fn from_name(s: &str) -> Option<Format> {
        Some(match s {
            "elf" | "elf32" | "elf64" | "o" | "obj" => Format::Elf,
            // `win64` and `win32` are NASM's names for a COFF object, and
            // name the machine as well; see `main`.
            "coff" | "pe" | "win" | "win64" | "win32" => Format::Coff,
            "bin" | "binary" | "raw" => Format::Binary,
            _ => return None,
        })
    }

    /// Whether the format keeps relocation addends in the bytes they
    /// relocate and names its sections and symbols COFF's way.
    pub fn is_coff(self) -> bool {
        self == Format::Coff
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
