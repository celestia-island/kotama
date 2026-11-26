//! APT data import-table parser.
//!
//! Layout: optional prefix, `Apt Data:<version>\x1a`, padding, then
//! 16-byte import entries `{movie_offset, name_offset, character, 0}`.
//! Offsets are relative to the start of the Apt Data marker.

use crate::ResourceError;

/// Marker preceding an Apt Data stream.
pub const MARKER: &[u8] = b"Apt Data:";

/// One Apt Data import.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptDataImport {
    /// Movie name.
    pub movie: String,
    /// Symbol name.
    pub name: String,
    /// Character index.
    pub character: u32,
}

/// Parsed Apt Data stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptDataInfo {
    /// Tag text, e.g. `Apt Data:74`.
    pub tag: String,
    /// Imports.
    pub imports: Vec<AptDataImport>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn cstr(bytes: &[u8], offset: usize) -> Option<String> {
    let start = offset;
    let end = bytes[start..].iter().position(|byte| *byte == 0)? + start;
    Some(String::from_utf8_lossy(&bytes[start..end]).to_string())
}

/// True when the bytes contain an Apt Data marker.
#[must_use]
pub fn has_marker(bytes: &[u8]) -> bool {
    bytes.windows(MARKER.len()).any(|window| window == MARKER)
}

/// Parse an Apt Data import table.
///
/// # Errors
/// Returns ResourceError::Invalid when the marker, tag terminator or table is
/// missing.
pub fn parse(bytes: &[u8]) -> Result<AptDataInfo, ResourceError> {
    let marker = bytes
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .ok_or_else(|| ResourceError::Invalid("APT data marker is missing".to_string()))?;
    let tag_end = bytes[marker..]
        .iter()
        .position(|byte| *byte == 0x1A)
        .map(|offset| marker + offset)
        .ok_or_else(|| ResourceError::Invalid("APT data tag terminator is missing".to_string()))?;
    let tag = String::from_utf8_lossy(&bytes[marker..tag_end]).to_string();
    let table_start = tag_end
        .checked_add(5)
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| ResourceError::Invalid("APT data table is outside the file".to_string()))?;
    let mut imports = Vec::new();
    let mut cursor = table_start;
    while let Some(end) = cursor.checked_add(16) {
        let Some(raw) = bytes.get(cursor..end) else {
            break;
        };
        let invalid = || ResourceError::Invalid("APT import record is unreadable".to_string());
        let movie_offset = u32_at(raw, 0).ok_or_else(invalid)?;
        let name_offset = u32_at(raw, 4).ok_or_else(invalid)?;
        let character = u32_at(raw, 8).ok_or_else(invalid)?;
        let reserved = u32_at(raw, 12).ok_or_else(invalid)?;
        if movie_offset == 0
            || name_offset <= movie_offset
            || character == 0
            || character > 64
            || reserved != 0
        {
            break;
        }
        let movie = cstr(bytes, marker + movie_offset as usize)
            .ok_or_else(|| ResourceError::Invalid("APT movie string is invalid".to_string()))?;
        let name = cstr(bytes, marker + name_offset as usize)
            .ok_or_else(|| ResourceError::Invalid("APT name string is invalid".to_string()))?;
        imports.push(AptDataImport {
            movie,
            name,
            character,
        });
        cursor += 16;
    }
    if imports.is_empty() {
        return Err(ResourceError::Invalid(
            "APT data import table is empty".to_string(),
        ));
    }
    Ok(AptDataInfo { tag, imports })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_import_table() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(b"Apt Data:74\x1a\x00\x00\x00\x00");
        bytes.extend_from_slice(&0x30u32.to_le_bytes());
        bytes.extend_from_slice(&0x40u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(0x40, 0);
        bytes.extend_from_slice(b"movie\x00");
        bytes.resize(0x50, 0);
        bytes.extend_from_slice(b"name\x00");
        let info = parse(&bytes).unwrap();
        assert_eq!(info.tag, "Apt Data:74");
        assert_eq!(info.imports.len(), 1);
        assert_eq!(info.imports[0].movie, "movie");
        assert_eq!(info.imports[0].name, "name");
        assert_eq!(info.imports[0].character, 1);
    }
}
