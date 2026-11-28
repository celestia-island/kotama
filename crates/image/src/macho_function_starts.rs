//! Mach-O `LC_FUNCTION_STARTS`: the loader's own list of function entry points.
//!
//! A Mach-O link stores every function start as ULEB128 deltas from the image
//! base, in a load command rather than a section. It is the most direct function
//! boundary source the container has — more so than `__unwind_info`, which
//! indexes only functions that need unwind info — and on a stripped `-s` binary
//! it is often the only one that names leaves.
//!
//! `object` has a `FunctionStartsIterator` but it is `pub(super)` and the
//! symbol-map builder that would consume it is still a TODO, so this reads the
//! load command directly, the same way `pe_export` reads the export directory.
//!
//! Note on fixtures: `zig cc`'s lld does **not** populate `LC_FUNCTION_STARTS`
//! for executables — the command is present with `datasize == 0` — so the
//! cross-compiled Mach-O fixtures exercise the empty case. The ULEB128 decoder
//! is pinned by unit tests on known byte sequences, not by a synthetic binary.

use object::Object as _;

use crate::SymbolInfo;

/// `LC_FUNCTION_STARTS` load command ID.
const LC_FUNCTION_STARTS: u32 = 0x26;

/// Decode one ULEB128 value from `data` at `pos`; returns (value, new position).
fn uleb128(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(pos.checked_add(shift as usize / 7)?)?;
        let index = pos + (shift / 7) as usize;
        let _ = index;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, pos + (shift / 7) as usize + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Function start addresses from a Mach-O image, in image order, as link-time
/// VM addresses (the deltas accumulate from 0 and Mach-O has no relative base).
///
/// Returns empty for a non-Mach-O image, a Mach-O without the command, or one
/// where the command is present but empty (the lld executable shape).
///
/// # Errors
/// Returns a message when the load commands or the ULEB128 stream are malformed;
/// a well-formed image never errors.
pub fn function_starts(data: &[u8]) -> Result<Vec<u64>, String> {
    // Not a parseable image is not this function's question: empty, like a Mach-O
    // without the command. A Mach-O that parses but has a malformed command is
    // an error, because that is a real defect in the input.
    let Ok(file) = object::File::parse(data) else {
        return Ok(Vec::new());
    };
    let is_macho = matches!(file, object::File::MachO32(_) | object::File::MachO64(_));
    if !is_macho {
        return Ok(Vec::new());
    }
    // Walk the load commands by hand: `object` exposes the segments and the
    // symbol tables but not the raw command list, and the data we need is one.
    let header_size = match file.format() {
        object::BinaryFormat::MachO => {
            let magic = u32::from_le_bytes(
                data.get(0..4)
                    .ok_or("short header")?
                    .try_into()
                    .map_err(|_| "slice length")?,
            );
            match magic {
                0xfeed_face | 0xcefa_edfe => 28,
                0xfeed_facf | 0xcffa_edfe => 32,
                _ => return Err(format!("unrecognised Mach-O magic {magic:#x}")),
            }
        }
        _ => return Ok(Vec::new()),
    };
    let little = matches!(
        u32::from_le_bytes(
            data.get(0..4)
                .ok_or("short header")?
                .try_into()
                .map_err(|_| "slice length")?
        ),
        0xfeed_face | 0xfeed_facf
    );
    let read_u32 = |at: usize| -> Result<u32, String> {
        let raw: [u8; 4] = data
            .get(at..at + 4)
            .ok_or_else(|| format!("load command truncated at {at:#x}"))?
            .try_into()
            .map_err(|_| "slice length")?;
        Ok(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    let ncmds = read_u32(16)? as usize;
    let mut offset = header_size;
    for _ in 0..ncmds {
        let cmd = read_u32(offset)?;
        let size = read_u32(offset + 4)? as usize;
        if size < 8 {
            return Err(format!(
                "load command size {size} at {offset:#x} is below the minimum"
            ));
        }
        if cmd == LC_FUNCTION_STARTS {
            let dataoff = read_u32(offset + 8)? as usize;
            let datasize = read_u32(offset + 12)? as usize;
            let bytes = data.get(dataoff..dataoff + datasize).ok_or_else(|| {
                format!("LC_FUNCTION_STARTS data out of range ({dataoff:#x}+{datasize})")
            })?;
            let base = file.relative_address_base();
            let mut out = Vec::new();
            let mut address = 0u64;
            let mut pos = 0usize;
            while pos < bytes.len() {
                let (delta, next) =
                    uleb128(bytes, pos).ok_or("malformed ULEB128 in LC_FUNCTION_STARTS")?;
                pos = next;
                if delta == 0 {
                    break;
                }
                address = address
                    .checked_add(delta)
                    .ok_or("function start overflow")?;
                out.push(base.wrapping_add(address));
            }
            return Ok(out);
        }
        offset = offset
            .checked_add(size)
            .ok_or("load command offset overflow")?;
    }
    Ok(Vec::new())
}

/// Function starts as `SymbolInfo` in the module's own coordinates: the link-time
/// VM address minus `base`, so it lines up with every other `rva` the module
/// carries. No size (the list carries only entry points), no name.
pub fn function_start_symbols(data: &[u8], base: u64) -> Vec<SymbolInfo> {
    function_starts(data)
        .unwrap_or_default()
        .into_iter()
        .map(|address| SymbolInfo {
            rva: address.saturating_sub(base),
            size: 0,
            name: String::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known ULEB128 stream: deltas 0x1000, 0x20, 0x40, terminator. The bytes
    /// are the standard encoding of those values; this pins the decoder, not a
    /// synthetic Mach-O.
    #[test]
    fn uleb128_decodes_the_standard_encodings() {
        // 0x1000 = 0b1_0000_0000_0000 -> 7-bit groups: 0x00, 0x20 -> 0x80 0x20
        // 0x20   -> 0x20 ; 0x40 -> 0x40 ; 0 -> 0x00
        let stream = [0x80u8, 0x20, 0x20, 0x40, 0x00];
        let (a, p1) = uleb128(&stream, 0).unwrap();
        assert_eq!(a, 0x1000);
        let (b, p2) = uleb128(&stream, p1).unwrap();
        assert_eq!(b, 0x20);
        let (c, p3) = uleb128(&stream, p2).unwrap();
        assert_eq!(c, 0x40);
        let (d, _) = uleb128(&stream, p3).unwrap();
        assert_eq!(d, 0);
    }

    /// Multi-byte and edge encodings: a 3-byte value, a 10-byte (64-bit max), and
    /// a truncated stream yields None rather than a wrong number.
    #[test]
    fn uleb128_handles_long_and_truncated_values() {
        // 0x3fff = 0b11_1111_1111_1111 -> 0xff 0x7f
        assert_eq!(uleb128(&[0xff, 0x7f], 0), Some((0x3fff, 2)));
        // u64::MAX: ten 7-bit groups, the last holding 1.
        let max = [0xffu8; 9]
            .iter()
            .copied()
            .chain([0x01])
            .collect::<Vec<_>>();
        assert_eq!(uleb128(&max, 0), Some((u64::MAX, 10)));
        // Continuation bit set but no following byte.
        assert_eq!(uleb128(&[0x80], 0), None);
        // Eleven groups would overflow the shift.
        let too_long = [0xffu8; 10];
        assert_eq!(uleb128(&too_long, 0), None);
    }

    /// `function_start_symbols` puts the starts in the module's coordinates by
    /// taking the base off. This is the one arithmetic step in the module and
    /// the fixture cannot exercise it (empty payload), so it is pinned on its own
    /// with a hand-written Mach-O header carrying a one-entry list.
    ///
    /// mutate: base-not-subtracted (passing 0 for `base` leaves the link-time
    /// address in `rva`, which is off by the image base on every real Mach-O).
    #[test]
    fn symbols_are_in_module_coordinates() {
        // A minimal 64-bit Mach-O: header + one LC_FUNCTION_STARTS whose payload
        // is a single delta of 0x1000 then a terminator. Built here because lld
        // emits an empty command and no system toolchain on this machine fills it.
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes()); // MH_MAGIC_64
        image[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
        image[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        image[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
        image[20..24].copy_from_slice(&16u32.to_le_bytes()); // sizeofcmds
        image[28..32].copy_from_slice(&0u32.to_le_bytes()); // reserved
                                                            // LC_FUNCTION_STARTS { cmd, cmdsize, dataoff, datasize }
        image[32..36].copy_from_slice(&0x26u32.to_le_bytes());
        image[36..40].copy_from_slice(&16u32.to_le_bytes());
        image[40..44].copy_from_slice(&0x40u32.to_le_bytes()); // dataoff
        image[44..48].copy_from_slice(&3u32.to_le_bytes()); // datasize
                                                            // payload: 0x1000 as ULEB128 (0x80 0x20), then terminator 0x00
        image.extend_from_slice(&[0x80, 0x20, 0x00]);
        assert_eq!(function_starts(&image), Ok(vec![0x1000]));
        let symbols = function_start_symbols(&image, 0x1000);
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].rva, 0, "0x1000 - base 0x1000");
        let symbols = function_start_symbols(&image, 0);
        assert_eq!(symbols[0].rva, 0x1000, "base 0 keeps the link-time address");
    }

    /// The terminator ends the list: a delta of zero after a real entry stops
    /// decoding, and anything after it is not read. Pinned here because the
    /// fixture's empty payload never reaches the loop.
    #[test]
    fn a_zero_delta_terminates_the_list() {
        // Same header shape, payload: 0x40, 0x80 (terminator), then 0x7f which
        // must not be read.
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        image[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        image[12..16].copy_from_slice(&2u32.to_le_bytes());
        image[16..20].copy_from_slice(&1u32.to_le_bytes());
        image[20..24].copy_from_slice(&16u32.to_le_bytes());
        image[32..36].copy_from_slice(&0x26u32.to_le_bytes());
        image[36..40].copy_from_slice(&16u32.to_le_bytes());
        image[40..44].copy_from_slice(&0x40u32.to_le_bytes());
        image[44..48].copy_from_slice(&3u32.to_le_bytes());
        image.extend_from_slice(&[0x40, 0x00, 0x7f]);
        assert_eq!(function_starts(&image), Ok(vec![0x40]));
    }

    /// The cross-compiled Mach-O fixture carries the command with an empty payload
    /// (lld does not fill it for executables): empty list, no error.
    #[test]
    fn the_lld_executable_shape_is_empty_not_an_error() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/cross/aarch64-macho/macho");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: Mach-O fixture not built");
            return;
        };
        assert_eq!(function_starts(&data), Ok(Vec::new()));
    }

    /// Non-Mach-O input is empty, not an error.
    #[test]
    fn non_macho_is_empty() {
        assert_eq!(function_starts(b"not a binary"), Ok(Vec::new()));
    }
}
