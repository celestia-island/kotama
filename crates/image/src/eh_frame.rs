//! DWARF call frame information (`__eh_frame` / `.eh_frame`) as function ranges.
//!
//! Every non-empty FDE (frame description entry) describes one function: an initial
//! address and a length. That makes the frame section a function table no symbol
//! table has to agree with, and one that survives stripping — the compiler emits it
//! for unwinding, so it is present whether or not names are.
//!
//! It complements `__unwind_info`: the compact unwind index covers functions with a
//! frame worth describing compactly, while `.eh_frame` carries an entry for every
//! function the assembler emitted CFI for. Where both exist they agree; a test
//! asserts that on a real binary.
//!
//! Only the ranges are extracted. The unwind instructions themselves answer "how do
//! I unwind this frame", which this module deliberately does not model.

use gimli::{BaseAddresses, CieOrFde, EhFrame, EndianSlice, LittleEndian, UnwindSection};

/// A function boundary recovered from the frame section.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FunctionRange {
    /// First address covered by the entry.
    pub start: u64,
    /// Number of bytes the entry covers.
    pub length: u64,
}

/// Every function range described by a frame section loaded at `section_address`.
///
/// The section address is not decoration: on both Mach-O and ELF the FDE initial
/// location is encoded PC-relative, so without it every range resolves to a
/// meaningless value or fails outright.
///
/// Entries are deduplicated and sorted by start address, so the result is stable
/// across runs. A malformed entry is skipped rather than failing the whole section:
/// one damaged record should not hide the rest of the table.
#[must_use]
pub fn function_ranges(data: &[u8], section_address: u64) -> Vec<FunctionRange> {
    let eh_frame: EhFrame<EndianSlice<'_, LittleEndian>> = EhFrame::new(data, LittleEndian);
    let mut bases = BaseAddresses::default();
    bases = bases.set_eh_frame(section_address);
    let mut out: Vec<FunctionRange> = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(|_, bases, offset| eh_frame.cie_from_offset(bases, offset))
        else {
            continue;
        };
        let start = fde.initial_address();
        let length = fde.len();
        // A zero address or a zero length is a terminator or padding, not a function.
        if start == 0 || length == 0 {
            continue;
        }
        out.push(FunctionRange { start, length });
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `__eh_frame` section of a real aarch64 Mach-O executable, byte for byte.
    ///
    /// Hand-building a CIE/FDE pair is how the encoding bugs in this repository's
    /// history started, so the test data is compiler output instead.
    const AARCH64_FRAME: &[u8] = &[
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7a, 0x52, 0x00, 0x01, 0x78, 0x1e,
        0x01, 0x10, 0x0c, 0x1f, 0x00, 0x20, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x5c, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x0e, 0x10, 0x70, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x00, 0x00, 0x70, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0e, 0x10, 0x64, 0x0e, 0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x7c, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x68,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0e, 0x10, 0x02, 0x60, 0x0e, 0x00,
        0x2c, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0xc4, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0e, 0x20, 0x48, 0x0c,
        0x1d, 0x10, 0x9e, 0x01, 0x9d, 0x02, 0x02, 0x44, 0x0c, 0x1f, 0x20, 0x48, 0x0e, 0x00, 0xde,
        0xdd, 0x00, 0x00,
    ];

    /// Address the section above is linked at.
    const AARCH64_FRAME_ADDRESS: u64 = 0x1_0000_1670;

    /// The `__eh_frame` of the same program built for x86_64 macOS: a lone CIE.
    const X86_64_FRAME: &[u8] = &[
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7a, 0x52, 0x00, 0x01, 0x78, 0x10,
        0x01, 0x10, 0x0c, 0x07, 0x08, 0x90, 0x01, 0x00, 0x00,
    ];

    #[test]
    fn every_fde_in_a_real_frame_section_becomes_a_range() {
        let ranges = function_ranges(AARCH64_FRAME, AARCH64_FRAME_ADDRESS);
        assert_eq!(ranges.len(), 4, "{ranges:?}");
        let pairs: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start, r.length)).collect();
        assert_eq!(
            pairs,
            vec![
                (0x1_0000_14e8, 0x38),
                (0x1_0000_1520, 0x2c),
                (0x1_0000_154c, 0x68),
                (0x1_0000_15b4, 0x5c),
            ]
        );
    }

    #[test]
    fn the_ranges_tile_the_whole_text_section() {
        // The four functions above are the entire `.text` of that binary, so the
        // lengths must add up to its size exactly. This is what makes the frame
        // section usable as a function table rather than a hint.
        let ranges = function_ranges(AARCH64_FRAME, AARCH64_FRAME_ADDRESS);
        let covered: u64 = ranges.iter().map(|r| r.length).sum();
        assert_eq!(covered, 0x128);
    }

    #[test]
    fn a_frame_section_with_only_a_cie_yields_nothing() {
        // x86_64 macOS unwinds through __unwind_info; its __eh_frame is a CIE and
        // nothing else, which must not be mistaken for a zero-length function.
        assert!(function_ranges(X86_64_FRAME, 0x1_0000_15d0).is_empty());
    }

    #[test]
    fn an_empty_section_yields_nothing() {
        assert!(function_ranges(&[], 0).is_empty());
    }

    #[test]
    fn the_section_address_moves_every_range() {
        // The FDE initial location is PC-relative, so the same bytes at a different
        // link address describe functions at that address. A parser that ignored the
        // argument would return identical starts here.
        let shifted = function_ranges(AARCH64_FRAME, AARCH64_FRAME_ADDRESS + 0x1000);
        assert_eq!(shifted.len(), 4);
        assert_eq!(shifted[0].start, 0x1_0000_14e8 + 0x1000);
        assert_eq!(shifted[0].length, 0x38);
    }

    #[test]
    fn a_truncated_entry_is_skipped_not_fatal() {
        // Cutting the last FDE in half must still yield the earlier ones.
        let cut = &AARCH64_FRAME[..AARCH64_FRAME.len() - 8];
        let ranges = function_ranges(cut, AARCH64_FRAME_ADDRESS);
        assert_eq!(ranges.len(), 3, "{ranges:?}");
    }
}
