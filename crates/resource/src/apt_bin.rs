//! RA3 .bin aggregate prefix parser.
//!
//! These aggregates start with an opaque prefix, then an Apt Data marker and
//! a numeric type id. Only the prefix facts and printable strings are decoded.

use crate::ResourceError;

/// Marker preceding the Apt Data type id.
pub const MARKER: &[u8] = b"Apt Data";

/// Parsed .bin aggregate prefix facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptBinInfo {
    /// Bytes before the Apt Data marker.
    pub prefix_length: usize,
    /// Numeric type id after the marker.
    pub type_id: String,
    /// Printable strings after the marker.
    pub strings: Vec<String>,
}

/// True when the bytes contain the Apt Data marker near the start.
#[must_use]
pub fn has_marker(bytes: &[u8]) -> bool {
    let limit = bytes.len().min(64);
    bytes.len() >= MARKER.len()
        && bytes[..limit]
            .windows(MARKER.len())
            .any(|window| window == MARKER)
}

/// Parse a .bin aggregate prefix.
///
/// # Errors
/// Returns ResourceError::Invalid when the marker is missing or the type id is
/// unreadable.
pub fn parse(bytes: &[u8]) -> Result<AptBinInfo, ResourceError> {
    let marker = bytes
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .ok_or_else(|| ResourceError::Invalid("BIN aggregate marker is missing".to_string()))?;
    let mut cursor = marker + MARKER.len();
    if bytes.get(cursor) != Some(&b':') {
        return Err(ResourceError::Invalid(
            "BIN aggregate marker is missing ':'".to_string(),
        ));
    }
    cursor += 1;
    let type_start = cursor;
    while bytes.get(cursor).is_some_and(|byte| byte.is_ascii_digit()) {
        cursor += 1;
    }
    if cursor == type_start {
        return Err(ResourceError::Invalid(
            "BIN aggregate type id is empty".to_string(),
        ));
    }
    let type_id = String::from_utf8_lossy(&bytes[type_start..cursor]).to_string();
    let mut strings = Vec::new();
    let mut start: Option<usize> = None;
    for (offset, byte) in bytes.iter().enumerate().skip(cursor) {
        if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(offset);
            }
        } else if let Some(begin) = start {
            if offset - begin >= 4 {
                strings.push(String::from_utf8_lossy(&bytes[begin..offset]).to_string());
            }
            start = None;
        }
    }
    Ok(AptBinInfo {
        prefix_length: marker,
        type_id,
        strings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefix_and_type() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(b"Apt Data:74\x1aREGION\x00Amsterdam_AM\x00");
        assert!(has_marker(&bytes));
        let info = parse(&bytes).unwrap();
        assert_eq!(info.prefix_length, 16);
        assert_eq!(info.type_id, "74");
        assert!(info.strings.contains(&"REGION".to_string()));
        assert!(info.strings.contains(&"Amsterdam_AM".to_string()));
    }
}
