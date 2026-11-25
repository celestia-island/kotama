//! RA3 binary asset header parser.
//!
//! Extracted `.asset` files carry a 16-byte identifier, a type name and a
//! `DATA:` XML reference. Property values stay opaque in this module.

use crate::ResourceError;

/// One raw asset property record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssetProperty {
    /// Property name hash.
    pub name_hash: u32,
    /// Property type hash.
    pub type_hash: u32,
    /// Value or value-table offset; semantics depend on the type hash.
    pub value_or_offset: u32,
}

/// Parsed asset header facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetInfo {
    /// 16-byte asset identifier.
    pub id: [u8; 16],
    /// Header version (0 or 1).
    pub version: u32,
    /// Type hash (version 1 only).
    pub type_hash: Option<u32>,
    /// Instance hash (version 1 only).
    pub instance_hash: Option<u32>,
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
    /// Offset of the property record table.
    pub property_table_offset: usize,
    /// Non-zero property records.
    pub properties: Vec<AssetProperty>,
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
    let version = u32_at(bytes, 16)
        .ok_or_else(|| ResourceError::Invalid("asset version is unreadable".to_string()))?;
    if version > 1 {
        return Err(ResourceError::Invalid(format!(
            "unsupported asset header version {version}"
        )));
    }
    let (type_len_offset, type_start, type_hash, instance_hash) = if version == 1 {
        (40, 44, u32_at(bytes, 32), u32_at(bytes, 36))
    } else {
        (32, 36, None, None)
    };
    if bytes.len() < type_start {
        return Err(ResourceError::Invalid(
            "asset header is shorter than its type name".to_string(),
        ));
    }
    let type_len = u32_at(bytes, type_len_offset)
        .ok_or_else(|| ResourceError::Invalid("asset type length is unreadable".to_string()))?
        as usize;
    let type_start: usize = type_start;
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
    let property_count = u32_at(bytes, 24)
        .ok_or_else(|| ResourceError::Invalid("asset property count is unreadable".to_string()))?;
    let property_table_offset = type_end + value_end;
    let table_size = property_count as usize;
    if property_table_offset
        .checked_add(table_size * 12)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(ResourceError::Invalid(
            "asset property table is outside the file".to_string(),
        ));
    }
    let mut properties = Vec::new();
    for index in 0..table_size {
        let offset = property_table_offset + index * 12;
        let record = AssetProperty {
            name_hash: u32_at(bytes, offset).ok_or_else(|| {
                ResourceError::Invalid("asset property name is unreadable".to_string())
            })?,
            type_hash: u32_at(bytes, offset + 4).ok_or_else(|| {
                ResourceError::Invalid("asset property type is unreadable".to_string())
            })?,
            value_or_offset: u32_at(bytes, offset + 8).ok_or_else(|| {
                ResourceError::Invalid("asset property value is unreadable".to_string())
            })?,
        };
        if record
            != (AssetProperty {
                name_hash: 0,
                type_hash: 0,
                value_or_offset: 0,
            })
        {
            properties.push(record);
        }
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[..16]);
    Ok(AssetInfo {
        id,
        version,
        type_hash,
        instance_hash,
        data_size: u32_at(bytes, 20)
            .ok_or_else(|| ResourceError::Invalid("asset data size is unreadable".to_string()))?,
        property_count,
        unknown_28: u32_at(bytes, 28)
            .ok_or_else(|| ResourceError::Invalid("asset field 28 is unreadable".to_string()))?,
        type_name,
        data_path,
        property_table_offset,
        properties,
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
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&37u32.to_le_bytes());
        bytes.extend_from_slice(b"ArmorTemplate:JapanHiveGeneratorArmorA");
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(
            b"DATA:civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml",
        );
        for value in [0xffe88740u32, 0x645864f3, 0x2d4] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let info = parse(&bytes).unwrap();
        assert_eq!(info.id, [1u8; 16]);
        assert_eq!(info.data_size, 856);
        assert_eq!(info.property_count, 1);
        assert_eq!(info.type_name, "ArmorTemplate:JapanHiveGeneratorArmorA");
        assert_eq!(
            info.data_path,
            "civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml"
        );
        assert_eq!(info.properties.len(), 1);
        assert_eq!(info.properties[0].name_hash, 0xffe88740);
        assert_eq!(info.properties[0].type_hash, 0x645864f3);
        assert_eq!(info.properties[0].value_or_offset, 0x2d4);
    }

    #[test]
    fn parses_version_1_header() {
        let mut bytes = vec![0u8; 44];
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&2652u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&52u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0xc2b1_a262u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x2ef0_cb34u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&22u32.to_le_bytes());
        bytes.extend_from_slice(b"GameObject:AM_Debris01:");
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(b"DATA:civilian/amsterdam_am/optimized_props/am_debris01.xml");
        for value in [0u32; 52 * 3] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let info = parse(&bytes).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.type_hash, Some(0xc2b1_a262));
        assert_eq!(info.instance_hash, Some(0x2ef0_cb34));
        assert_eq!(info.type_name, "GameObject:AM_Debris01:");
        assert_eq!(
            info.data_path,
            "civilian/amsterdam_am/optimized_props/am_debris01.xml"
        );
        assert_eq!(info.property_count, 52);
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
