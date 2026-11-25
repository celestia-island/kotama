//! RA3 binary asset header parser.
//!
//! Extracted `.asset` files carry a 16-byte identifier, a type name and a
//! `DATA:` XML reference. Property values stay opaque in this module.

use crate::ResourceError;

/// Parsed asset header facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetInfo {
    /// 16-byte asset identifier.
    pub id: [u8; 16],
    /// Unknown u32 at offset 16.
    pub unknown_16: u32,
    /// Property data size.
    pub data_size: u32,
    /// Property count.
    pub property_count: u32,
    /// Unknown u32 at offset 28.
    pub unknown_28: u32,
    /// Asset type name.
    pub type_name: String,
    /// DATA XML reference.
    pub data_path: String,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Parse and validate an asset header.
///
/// # Errors
/// Returns ResourceError::Invalid for a short header, bad type length or a
/// missing DATA reference.
pub fn parse(bytes: &[u8]) -> Result<AssetInfo, ResourceError> {
    if bytes.len() < 36 {
        return Err(ResourceError::Invalid(
            "asset header is shorter than 36 bytes".to_string(),
        ));
    }
    let type_len = u32_at(bytes, 32)
        .ok_or_else(|| ResourceError::Invalid("asset type length is unreadable".to_string()))?
        as usize;
    let type_start: usize = 36;
    let type_end = bytes[type_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|length| type_start + length)
        .unwrap_or(bytes.len());
    if type_end < type_start.saturating_add(type_len) {
        return Err(ResourceError::Invalid(
            "asset type name is shorter than its declared length".to_string(),
        ));
    }
    let type_name = String::from_utf8_lossy(&bytes[type_start..type_end])
        .trim_end_matches(['\0', ' '])
        .to_string();
    if type_name.is_empty() {
        return Err(ResourceError::Invalid(
            "asset type name is empty".to_string(),
        ));
    }
    let tail = &bytes[type_end..];
    let data_start = tail
        .windows(5)
        .position(|window| window == b"DATA:")
        .ok_or_else(|| ResourceError::Invalid("asset DATA reference is missing".to_string()))?;
    let value_start = data_start + 5;
    let value_end = tail[value_start..]
        .iter()
        .position(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'\\' | b'.' | b'_' | b'-' | b':'))
        })
        .map(|length| value_start + length)
        .unwrap_or(tail.len());
    let data_path = String::from_utf8_lossy(&tail[value_start..value_end])
        .trim_end_matches(['\0', ' '])
        .to_string();
    if data_path.is_empty() {
        return Err(ResourceError::Invalid(
            "asset DATA reference is empty".to_string(),
        ));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[..16]);
    Ok(AssetInfo {
        id,
        unknown_16: u32_at(bytes, 16)
            .ok_or_else(|| ResourceError::Invalid("asset field 16 is unreadable".to_string()))?,
        data_size: u32_at(bytes, 20)
            .ok_or_else(|| ResourceError::Invalid("asset data size is unreadable".to_string()))?,
        property_count: u32_at(bytes, 24).ok_or_else(|| {
            ResourceError::Invalid("asset property count is unreadable".to_string())
        })?,
        unknown_28: u32_at(bytes, 28)
            .ok_or_else(|| ResourceError::Invalid("asset field 28 is unreadable".to_string()))?,
        type_name,
        data_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_data_path() {
        let mut bytes = vec![0u8; 36];
        bytes[0..16].copy_from_slice(&[1u8; 16]);
        bytes[20..24].copy_from_slice(&856u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&8u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&37u32.to_le_bytes());
        bytes.extend_from_slice(b"ArmorTemplate:JapanHiveGeneratorArmorA");
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(
            b"DATA:civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml\0",
        );
        let info = parse(&bytes).unwrap();
        assert_eq!(info.id, [1u8; 16]);
        assert_eq!(info.data_size, 856);
        assert_eq!(info.property_count, 8);
        assert_eq!(info.type_name, "ArmorTemplate:JapanHiveGeneratorArmorA");
        assert_eq!(
            info.data_path,
            "civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml"
        );
    }

    #[test]
    fn rejects_short_header_and_missing_data() {
        assert!(parse(&[0u8; 35]).is_err());
        let mut bytes = vec![0u8; 36];
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes.push(b'A');
        assert!(parse(&bytes).is_err());
    }
}
