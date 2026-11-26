//! Compiled asset relocation table parser.
//!
//! A `.relo` file is a 4-byte checksum followed by 8-byte relocation
//! entries. Import files currently carry only the checksum when empty.

use crate::ResourceError;

/// One relocation entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelocationEntry {
    /// Relocation kind.
    pub kind: u32,
    /// Relocation offset or sentinel.
    pub offset: u32,
}

/// Parsed relocation table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetRelocation {
    /// Stream checksum.
    pub checksum: u32,
    /// Relocation entries.
    pub entries: Vec<RelocationEntry>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Parse and validate a relocation table.
///
/// # Errors
/// Returns ResourceError::Invalid for a short file or an entry count that is
/// not a whole number of 8-byte records.
pub fn parse(bytes: &[u8]) -> Result<AssetRelocation, ResourceError> {
    if bytes.len() < 4 {
        return Err(ResourceError::Invalid(
            "relocation table is shorter than 4 bytes".to_string(),
        ));
    }
    let checksum = u32_at(bytes, 0)
        .ok_or_else(|| ResourceError::Invalid("relocation checksum is unreadable".to_string()))?;
    let body = &bytes[4..];
    if !body.len().is_multiple_of(8) {
        return Err(ResourceError::Invalid(
            "relocation table has a partial entry".to_string(),
        ));
    }
    let mut entries = Vec::with_capacity(body.len() / 8);
    for chunk in body.as_chunks::<8>().0 {
        entries.push(RelocationEntry {
            kind: u32_at(chunk, 0).ok_or_else(|| {
                ResourceError::Invalid("relocation kind is unreadable".to_string())
            })?,
            offset: u32_at(chunk, 4).ok_or_else(|| {
                ResourceError::Invalid("relocation offset is unreadable".to_string())
            })?,
        });
    }
    Ok(AssetRelocation { checksum, entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entries() {
        let mut bytes = 0x6d1ddbe1u32.to_le_bytes().to_vec();
        for value in [4u32, 0xffff_ffff, 4, 0x1234_5678] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let info = parse(&bytes).unwrap();
        assert_eq!(info.checksum, 0x6d1ddbe1);
        assert_eq!(info.entries.len(), 2);
        assert_eq!(info.entries[0].kind, 4);
        assert_eq!(info.entries[0].offset, 0xffff_ffff);
        assert_eq!(info.entries[1].offset, 0x1234_5678);
    }

    #[test]
    fn rejects_partial_entry() {
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 7]);
        assert!(parse(&bytes).is_err());
    }
}
