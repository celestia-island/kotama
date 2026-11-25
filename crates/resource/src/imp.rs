//! RA3 .imp offset-table parser.
//!
//! Layout: u32 hash, then u32 values separated into groups by 0xFFFFFFFF.

use crate::ResourceError;

/// Sentinel separating offset groups.
pub const GROUP_SEPARATOR: u32 = u32::MAX;

/// Parsed .imp table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImpInfo {
    /// Asset hash.
    pub hash: u32,
    /// Offset groups.
    pub groups: Vec<Vec<u32>>,
}

/// Parse a .imp offset table.
///
/// # Errors
/// Returns ResourceError::Invalid for a file shorter than 4 bytes or a
/// length that is not a multiple of 4.
pub fn parse(bytes: &[u8]) -> Result<ImpInfo, ResourceError> {
    if bytes.len() < 4 {
        return Err(ResourceError::Invalid(
            "IMP table is shorter than 4 bytes".to_string(),
        ));
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(ResourceError::Invalid(
            "IMP table length is not a multiple of 4".to_string(),
        ));
    }
    let mut values = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|raw| u32::from_le_bytes(*raw));
    let hash = values.next().unwrap_or_default();
    let mut groups = Vec::new();
    let mut current = Vec::new();
    for value in values {
        if value == GROUP_SEPARATOR {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
        } else {
            current.push(value);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    Ok(ImpInfo { hash, groups })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_groups() {
        let mut bytes = 0xA49E_1BA9u32.to_le_bytes().to_vec();
        for value in [116u32, 164, 312, GROUP_SEPARATOR, 88, 92, GROUP_SEPARATOR] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let info = parse(&bytes).unwrap();
        assert_eq!(info.hash, 0xA49E_1BA9);
        assert_eq!(info.groups, vec![vec![116, 164, 312], vec![88, 92]]);
    }

    #[test]
    fn parses_hash_only() {
        let info = parse(&0x6D1D_DBE1u32.to_le_bytes()).unwrap();
        assert_eq!(info.hash, 0x6D1D_DBE1);
        assert!(info.groups.is_empty());
    }
}
