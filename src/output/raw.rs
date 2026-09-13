//! Flat binary output: the allocatable sections, concatenated at the
//! addresses layout gave them.

use super::OutputError;
use crate::assembler::Assembler;
use crate::section::{SectionId, SectionKind};

/// Builds a flat image starting at the lowest allocated address.
///
/// Gaps between sections are zero-filled, so the result can be loaded at
/// `base_addr` and every symbol will be where the assembler said it is.
pub fn build(asm: &Assembler) -> Result<Vec<u8>, OutputError> {
    let allocated: Vec<&crate::section::Section> = asm
        .sections
        .iter()
        .filter(|s| s.size > 0 && s.flags.alloc)
        .collect();
    // With no explicitly allocated section, fall back to whatever has content;
    // a bare `.text` file that never says `.section` should still work.
    let chosen: Vec<&crate::section::Section> = if allocated.is_empty() {
        asm.sections.iter().filter(|s| s.size > 0).collect()
    } else {
        allocated
    };
    if chosen.is_empty() {
        return Ok(Vec::new());
    }

    let lo = chosen.iter().map(|s| s.addr).min().expect("non-empty");
    let hi = chosen
        .iter()
        .map(|s| s.addr + s.size)
        .max()
        .expect("non-empty");
    let mut out = vec![0u8; (hi - lo) as usize];
    for s in &chosen {
        if s.kind == SectionKind::Nobits {
            continue;
        }
        let bytes = asm.section_bytes(SectionId(s.id.0));
        let at = (s.addr - lo) as usize;
        out[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(out)
}
