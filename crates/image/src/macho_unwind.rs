//! Mach-O compact unwind info (`__unwind_info`) as function boundaries.
//!
//! The compact unwind section is an index of functions with unwind data. Every
//! entry names the offset of a function that has unwind information, which is
//! exactly the set of functions a compiler emitted as real subroutine boundaries.
//! Unlike symbols it is always present in a stripped A64 Mach-O, and unlike a
//! call-target sweep it is exhaustive: it includes leaf functions nothing calls.
//!
//! The layout is the one in `mach-o/compact_unwind_encoding.h`. Only the function
//! offsets are extracted here; the unwind encodings themselves (how to unwind a
//! frame) are not interpreted, because this module answers "where does a function
//! start", not "how do I unwind it".
//!
//! Parsing is deterministic and allocation-bounded by the section size.

/// Section version this parser understands.
pub const UNWIND_SECTION_VERSION: u32 = 1;

/// A regular second-level page (`UNWIND_SECOND_LEVEL_REGULAR`).
const SECOND_LEVEL_REGULAR: u32 = 2;
/// A compressed second-level page (`UNWIND_SECOND_LEVEL_COMPRESSED`).
const SECOND_LEVEL_COMPRESSED: u32 = 3;

/// Size of `unwind_info_section_header` in bytes.
const HEADER_SIZE: usize = 28;
/// Size of one `unwind_info_section_header_index_entry`.
const INDEX_ENTRY_SIZE: usize = 12;
/// Size of one regular second-level entry.
const REGULAR_ENTRY_SIZE: usize = 8;

/// Error from parsing the compact unwind section.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnwindInfoError {
    /// Section shorter than its fixed header.
    Truncated,
    /// `version` is not the one this parser understands.
    UnsupportedVersion(u32),
    /// A page `kind` is neither regular nor compressed.
    UnknownPageKind(u32),
    /// An offset or count leaves the section.
    OutOfBounds,
}

impl std::fmt::Display for UnwindInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("unwind info shorter than its header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported unwind info version {v}"),
            Self::UnknownPageKind(k) => write!(f, "unknown second-level page kind {k:#x}"),
            Self::OutOfBounds => f.write_str("unwind info offset or count leaves the section"),
        }
    }
}

impl std::error::Error for UnwindInfoError {}

/// Read a little-endian `u32` at `offset`, or fail when it leaves `data`.
fn u32_at(data: &[u8], offset: usize) -> Result<u32, UnwindInfoError> {
    let end = offset.checked_add(4).ok_or(UnwindInfoError::OutOfBounds)?;
    let bytes = data.get(offset..end).ok_or(UnwindInfoError::OutOfBounds)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u16` at `offset`, or fail when it leaves `data`.
fn u16_at(data: &[u8], offset: usize) -> Result<u16, UnwindInfoError> {
    let end = offset.checked_add(2).ok_or(UnwindInfoError::OutOfBounds)?;
    let bytes = data.get(offset..end).ok_or(UnwindInfoError::OutOfBounds)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Walk one second-level page and append every function offset it names.
///
/// `base` is the `functionOffset` of the index entry the page belongs to;
/// compressed pages store offsets relative to it.
fn walk_page(
    data: &[u8],
    page: usize,
    base: u64,
    out: &mut Vec<u64>,
) -> Result<(), UnwindInfoError> {
    let kind = u32_at(data, page)?;
    match kind {
        SECOND_LEVEL_REGULAR => {
            let entry_page_offset = u32::from(u16_at(data, page + 4)?);
            let entry_count = u32::from(u16_at(data, page + 6)?);
            let entries = page
                .checked_add(entry_page_offset as usize)
                .ok_or(UnwindInfoError::OutOfBounds)?;
            for index in 0..entry_count as usize {
                let at = entries
                    .checked_add(index * REGULAR_ENTRY_SIZE)
                    .ok_or(UnwindInfoError::OutOfBounds)?;
                let function_offset = u32_at(data, at)?;
                out.push(u64::from(function_offset));
            }
            Ok(())
        }
        SECOND_LEVEL_COMPRESSED => {
            let entry_page_offset = u32::from(u16_at(data, page + 4)?);
            let entry_count = u32::from(u16_at(data, page + 6)?);
            let entries = page
                .checked_add(entry_page_offset as usize)
                .ok_or(UnwindInfoError::OutOfBounds)?;
            for index in 0..entry_count as usize {
                let at = entries
                    .checked_add(index * 4)
                    .ok_or(UnwindInfoError::OutOfBounds)?;
                let entry = u32_at(data, at)?;
                // 24 bits of function offset, relative to the index entry's base.
                let function_offset = u64::from(entry & 0x00ff_ffff);
                out.push(base.wrapping_add(function_offset));
            }
            Ok(())
        }
        other => Err(UnwindInfoError::UnknownPageKind(other)),
    }
}

/// Extract every function offset named by the compact unwind section.
///
/// The result is sorted and deduplicated. Offsets are image-relative, as the
/// section stores them, so the caller adds the image base if it wants VAs.
///
/// # Errors
/// Returns [UnwindInfoError] for a truncated header, an unknown version, an
/// unknown page kind, or any offset that leaves `data`. Nothing is returned
/// on error: a partially parsed index would be a misleading function list.
pub fn function_offsets(data: &[u8]) -> Result<Vec<u64>, UnwindInfoError> {
    if data.len() < HEADER_SIZE {
        return Err(UnwindInfoError::Truncated);
    }
    let version = u32_at(data, 0)?;
    if version != UNWIND_SECTION_VERSION {
        return Err(UnwindInfoError::UnsupportedVersion(version));
    }
    let index_offset = u32_at(data, 20)? as usize;
    let index_count = u32_at(data, 24)?;
    let mut out: Vec<u64> = Vec::new();
    // The last index entry is a sentinel: it names where the covered range ends,
    // not a function, and carries no second-level page. Every earlier entry
    // without a page is a real function whose only entry is the index slot.
    let last = index_count.checked_sub(1);
    for index in 0..index_count as usize {
        let at = index_offset
            .checked_add(index * INDEX_ENTRY_SIZE)
            .ok_or(UnwindInfoError::OutOfBounds)?;
        let function_offset = u64::from(u32_at(data, at)?);
        let second_level = u32_at(data, at + 4)?;
        if Some(index as u32) == last && second_level == 0 {
            break;
        }
        if second_level == 0 {
            out.push(function_offset);
            continue;
        }
        walk_page(data, second_level as usize, function_offset, &mut out)?;
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a compact unwind section with one compressed page.
    ///
    /// `functions` are offsets relative to `base`; the section also gets a
    /// trailing sentinel index entry, as a real linker emits.
    fn compressed_section(base: u32, functions: &[u32]) -> Vec<u8> {
        let mut b = Vec::new();
        let p32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let p16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
        // header: 7 u32
        p32(&mut b, 1); // version
        p32(&mut b, 28); // commonEncodingsArraySectionOffset
        p32(&mut b, 0); // commonEncodingsArrayCount
        p32(&mut b, 28); // personalityArraySectionOffset
        p32(&mut b, 0); // personalityArrayCount
        p32(&mut b, 28); // indexSectionOffset
        p32(&mut b, 2); // indexCount: one real entry + sentinel
                        // index entry 0: {base, page at 52, no lsda}
        p32(&mut b, base);
        p32(&mut b, 52);
        p32(&mut b, 0);
        // index entry 1: sentinel {end, no page, no lsda}
        p32(&mut b, base + 0x1000);
        p32(&mut b, 0);
        p32(&mut b, 0);
        assert_eq!(b.len(), 52);
        // compressed page at 52
        p32(&mut b, 3); // kind = COMPRESSED
        p16(&mut b, 12); // entryPageOffset (relative to page start)
        p16(&mut b, functions.len() as u16);
        p16(&mut b, (12 + 4 * functions.len()) as u16); // encodingsPageOffset
        p16(&mut b, 1); // encodingsCount
        for offset in functions {
            // 24-bit function offset relative to base, 8-bit encoding index 0.
            p32(&mut b, offset & 0x00ff_ffff);
        }
        p32(&mut b, 0); // encoding[0]
        b
    }

    #[test]
    fn a_compressed_page_yields_relative_offsets_plus_base() {
        let data = compressed_section(0x1000, &[0, 0x10, 0x20]);
        assert_eq!(
            function_offsets(&data).unwrap(),
            vec![0x1000, 0x1010, 0x1020]
        );
    }

    #[test]
    fn the_trailing_sentinel_is_not_a_function() {
        // The sentinel names the end of the range; it must never appear.
        let data = compressed_section(0x1000, &[0]);
        assert_eq!(function_offsets(&data).unwrap(), vec![0x1000]);
    }

    #[test]
    fn a_regular_page_yields_absolute_offsets() {
        let mut b = Vec::new();
        let p32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let p16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
        p32(&mut b, 1);
        p32(&mut b, 28);
        p32(&mut b, 0);
        p32(&mut b, 28);
        p32(&mut b, 0);
        p32(&mut b, 28);
        p32(&mut b, 2);
        p32(&mut b, 0x2000); // index entry 0
        p32(&mut b, 52);
        p32(&mut b, 0);
        p32(&mut b, 0x3000); // sentinel
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 2); // kind = REGULAR
        p16(&mut b, 8); // entryPageOffset
        p16(&mut b, 2); // entryCount
                        // regular entries carry absolute function offsets and an encoding each
        p32(&mut b, 0x2000);
        p32(&mut b, 0);
        p32(&mut b, 0x2040);
        p32(&mut b, 0);
        assert_eq!(function_offsets(&b).unwrap(), vec![0x2000, 0x2040]);
    }

    #[test]
    fn results_are_sorted_and_deduplicated() {
        // Deliberately unsorted and with a repeat.
        let data = compressed_section(0x1000, &[0x30, 0x10, 0x30]);
        assert_eq!(function_offsets(&data).unwrap(), vec![0x1010, 0x1030]);
    }

    #[test]
    fn a_truncated_header_is_rejected() {
        assert_eq!(function_offsets(&[0; 27]), Err(UnwindInfoError::Truncated));
        assert!(function_offsets(&[]).is_err());
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut data = compressed_section(0x1000, &[0]);
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            function_offsets(&data),
            Err(UnwindInfoError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn an_unknown_page_kind_is_rejected() {
        let mut data = compressed_section(0x1000, &[0]);
        data[52..56].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            function_offsets(&data),
            Err(UnwindInfoError::UnknownPageKind(7))
        );
    }

    #[test]
    fn an_offset_past_the_section_is_rejected() {
        let mut data = compressed_section(0x1000, &[0]);
        // Point the index at a position beyond the section.
        data[20..24].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert_eq!(function_offsets(&data), Err(UnwindInfoError::OutOfBounds));
    }

    #[test]
    fn the_real_c_uint32_layout_is_assumed() {
        // The header is seven u32 fields and the index entry is three.
        assert_eq!(HEADER_SIZE, 28);
        assert_eq!(INDEX_ENTRY_SIZE, 12);
        assert_eq!(REGULAR_ENTRY_SIZE, 8);
    }
}
