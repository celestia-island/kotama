//! BinaryAssetBuilder manifest header parser.
//!
//! The 48-byte header precedes the manifest string buffers. Buffer contents and
//! referenced asset names stay opaque in this module.

use crate::ResourceError;

/// Parsed manifest header facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetManifestInfo {
    /// True when the stream is big-endian.
    pub big_endian: bool,
    /// True when the manifest is linked.
    pub linked: bool,
    /// Format version.
    pub version: u16,
    /// Stream checksum.
    pub stream_checksum: u32,
    /// Hash over all types.
    pub all_types_hash: u32,
    /// Asset count.
    pub asset_count: u32,
    /// Total instance data size.
    pub total_instance_data_size: u32,
    /// Maximum instance chunk size.
    pub max_instance_chunk_size: u32,
    /// Maximum relocation chunk size.
    pub max_relocation_chunk_size: u32,
    /// Maximum imports chunk size.
    pub max_imports_chunk_size: u32,
    /// Asset-reference buffer size.
    pub asset_reference_buffer_size: u32,
    /// Referenced-manifest-name buffer size.
    pub referenced_manifest_name_buffer_size: u32,
    /// Asset-name buffer size.
    pub asset_name_buffer_size: u32,
    /// Source-file-name buffer size.
    pub source_file_name_buffer_size: u32,
    /// NUL-separated printable names found after the header.
    pub names: Vec<String>,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn bool_at(bytes: &[u8], offset: usize) -> Option<bool> {
    bytes.get(offset).and_then(|value| match *value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    })
}

/// Parse and validate a 48-byte manifest header.
///
/// # Errors
/// Returns ResourceError::Invalid for a short header or non-boolean flags.
pub fn parse(bytes: &[u8]) -> Result<AssetManifestInfo, ResourceError> {
    if bytes.len() < 48 {
        return Err(ResourceError::Invalid(
            "asset manifest header is shorter than 48 bytes".to_string(),
        ));
    }
    let mut names = Vec::new();
    let mut start: Option<usize> = None;
    for (offset, byte) in bytes.iter().enumerate().skip(48) {
        if *byte == 0 {
            if let Some(begin) = start {
                if offset - begin >= 3 {
                    if let Ok(text) = std::str::from_utf8(&bytes[begin..offset]) {
                        if text.contains(':')
                            || text.contains('\\')
                            || text.contains('/')
                            || text.contains('.')
                        {
                            names.push(text.to_string());
                        }
                    }
                }
            }
            start = None;
        } else if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(offset);
            }
        } else {
            start = None;
        }
    }
    Ok(AssetManifestInfo {
        big_endian: bool_at(bytes, 0).ok_or_else(|| {
            ResourceError::Invalid("manifest big-endian flag is invalid".to_string())
        })?,
        linked: bool_at(bytes, 1)
            .ok_or_else(|| ResourceError::Invalid("manifest linked flag is invalid".to_string()))?,
        version: u16_at(bytes, 2)
            .ok_or_else(|| ResourceError::Invalid("manifest version is unreadable".to_string()))?,
        stream_checksum: u32_at(bytes, 4)
            .ok_or_else(|| ResourceError::Invalid("manifest checksum is unreadable".to_string()))?,
        all_types_hash: u32_at(bytes, 8).ok_or_else(|| {
            ResourceError::Invalid("manifest type hash is unreadable".to_string())
        })?,
        asset_count: u32_at(bytes, 12).ok_or_else(|| {
            ResourceError::Invalid("manifest asset count is unreadable".to_string())
        })?,
        total_instance_data_size: u32_at(bytes, 16).ok_or_else(|| {
            ResourceError::Invalid("manifest instance size is unreadable".to_string())
        })?,
        max_instance_chunk_size: u32_at(bytes, 20).ok_or_else(|| {
            ResourceError::Invalid("manifest instance chunk size is unreadable".to_string())
        })?,
        max_relocation_chunk_size: u32_at(bytes, 24).ok_or_else(|| {
            ResourceError::Invalid("manifest relocation chunk size is unreadable".to_string())
        })?,
        max_imports_chunk_size: u32_at(bytes, 28).ok_or_else(|| {
            ResourceError::Invalid("manifest imports chunk size is unreadable".to_string())
        })?,
        asset_reference_buffer_size: u32_at(bytes, 32).ok_or_else(|| {
            ResourceError::Invalid("manifest reference buffer size is unreadable".to_string())
        })?,
        referenced_manifest_name_buffer_size: u32_at(bytes, 36).ok_or_else(|| {
            ResourceError::Invalid("manifest name buffer size is unreadable".to_string())
        })?,
        asset_name_buffer_size: u32_at(bytes, 40).ok_or_else(|| {
            ResourceError::Invalid("manifest asset-name buffer size is unreadable".to_string())
        })?,
        source_file_name_buffer_size: u32_at(bytes, 44).ok_or_else(|| {
            ResourceError::Invalid("manifest source-name buffer size is unreadable".to_string())
        })?,
        names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header() {
        let mut bytes = vec![0u8; 48];
        bytes[1] = 1;
        bytes[2..4].copy_from_slice(&6u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&13u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&3_303_040u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&487u32.to_le_bytes());
        bytes.extend_from_slice(b"AptAptData:Foo\0source.xml\0");
        let info = parse(&bytes).unwrap();
        assert!(!info.big_endian);
        assert!(info.linked);
        assert_eq!(info.version, 6);
        assert_eq!(info.asset_count, 13);
        assert_eq!(info.total_instance_data_size, 3_303_040);
        assert_eq!(info.source_file_name_buffer_size, 487);
        assert_eq!(info.names, vec!["AptAptData:Foo", "source.xml"]);
    }

    #[test]
    fn rejects_short_header_and_bad_flag() {
        assert!(parse(&[0u8; 47]).is_err());
        let mut bytes = vec![0u8; 48];
        bytes[0] = 2;
        assert!(parse(&bytes).is_err());
    }
}
