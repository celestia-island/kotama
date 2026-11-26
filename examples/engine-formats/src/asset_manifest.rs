//! BinaryAssetBuilder manifest header parser.
//!
//! The 48-byte header precedes the manifest string buffers. Buffer contents and
//! referenced asset names stay opaque in this module.

use crate::ResourceError;

/// A reference from one asset to another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssetReference {
    /// Referenced type id.
    pub type_id: u32,
    /// Referenced instance id.
    pub instance_id: u32,
}

/// One manifest asset entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetManifestEntry {
    /// Asset type id.
    pub type_id: u32,
    /// Asset instance id.
    pub instance_id: u32,
    /// Type hash.
    pub type_hash: u32,
    /// Instance hash.
    pub instance_hash: u32,
    /// Reference offset relative to the reference buffer.
    pub reference_offset: u32,
    /// Number of references.
    pub reference_count: u32,
    /// Name offset relative to the asset-name buffer.
    pub name_offset: u32,
    /// Source-name offset relative to the source-name buffer.
    pub source_name_offset: u32,
    /// Instance data size.
    pub instance_size: u32,
    /// Relocation data size.
    pub relocation_size: u32,
    /// Imports data size.
    pub imports_size: u32,
    /// Asset name.
    pub name: String,
    /// Source file name.
    pub source_name: String,
    /// References to other assets.
    pub references: Vec<AssetReference>,
}

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
    /// Asset entries from the manifest table.
    pub entries: Vec<AssetManifestEntry>,
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

fn read_cstr(bytes: &[u8], offset: usize) -> Option<String> {
    let start = offset;
    let end = bytes[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|length| start + length)?;
    let text = std::str::from_utf8(&bytes[start..end]).ok()?;
    Some(text.to_string())
}

fn parse_entries(
    bytes: &[u8],
    asset_count: u32,
    reference_base: usize,
    asset_name_base: usize,
    source_name_base: usize,
) -> Result<Vec<AssetManifestEntry>, ResourceError> {
    let mut entries = Vec::new();
    for index in 0..asset_count as usize {
        let offset = 48 + index * 48;
        if offset.checked_add(48).is_none_or(|end| end > bytes.len()) {
            return Err(ResourceError::Invalid(format!(
                "manifest asset entry {index} is outside the file"
            )));
        }
        let reference_offset = u32_at(bytes, offset + 16).ok_or_else(|| {
            ResourceError::Invalid("manifest reference offset is unreadable".to_string())
        })?;
        let reference_count = u32_at(bytes, offset + 20).ok_or_else(|| {
            ResourceError::Invalid("manifest reference count is unreadable".to_string())
        })?;
        let name_offset = u32_at(bytes, offset + 24).ok_or_else(|| {
            ResourceError::Invalid("manifest name offset is unreadable".to_string())
        })?;
        let source_name_offset = u32_at(bytes, offset + 28).ok_or_else(|| {
            ResourceError::Invalid("manifest source-name offset is unreadable".to_string())
        })?;
        let name = read_cstr(bytes, asset_name_base + name_offset as usize).ok_or_else(|| {
            ResourceError::Invalid("manifest asset name is unreadable".to_string())
        })?;
        let source_name = read_cstr(bytes, source_name_base + source_name_offset as usize)
            .ok_or_else(|| {
                ResourceError::Invalid("manifest source name is unreadable".to_string())
            })?;
        let mut references = Vec::new();
        for reference_index in 0..reference_count as usize {
            let reference_at = reference_base + reference_offset as usize + reference_index * 8;
            references.push(AssetReference {
                type_id: u32_at(bytes, reference_at).ok_or_else(|| {
                    ResourceError::Invalid("manifest reference type is unreadable".to_string())
                })?,
                instance_id: u32_at(bytes, reference_at + 4).ok_or_else(|| {
                    ResourceError::Invalid("manifest reference instance is unreadable".to_string())
                })?,
            });
        }
        entries.push(AssetManifestEntry {
            type_id: u32_at(bytes, offset).ok_or_else(|| {
                ResourceError::Invalid("manifest type id is unreadable".to_string())
            })?,
            instance_id: u32_at(bytes, offset + 4).ok_or_else(|| {
                ResourceError::Invalid("manifest instance id is unreadable".to_string())
            })?,
            type_hash: u32_at(bytes, offset + 8).ok_or_else(|| {
                ResourceError::Invalid("manifest type hash is unreadable".to_string())
            })?,
            instance_hash: u32_at(bytes, offset + 12).ok_or_else(|| {
                ResourceError::Invalid("manifest instance hash is unreadable".to_string())
            })?,
            reference_offset,
            reference_count,
            name_offset,
            source_name_offset,
            instance_size: u32_at(bytes, offset + 32).ok_or_else(|| {
                ResourceError::Invalid("manifest instance size is unreadable".to_string())
            })?,
            relocation_size: u32_at(bytes, offset + 36).ok_or_else(|| {
                ResourceError::Invalid("manifest relocation size is unreadable".to_string())
            })?,
            imports_size: u32_at(bytes, offset + 40).ok_or_else(|| {
                ResourceError::Invalid("manifest imports size is unreadable".to_string())
            })?,
            name,
            source_name,
            references,
        });
    }
    Ok(entries)
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
    let asset_count = u32_at(bytes, 12)
        .ok_or_else(|| ResourceError::Invalid("manifest asset count is unreadable".to_string()))?;
    let reference_base = 48usize
        .checked_add(asset_count as usize * 48)
        .ok_or_else(|| ResourceError::Invalid("manifest asset table is too large".to_string()))?;
    let reference_size = u32_at(bytes, 32).ok_or_else(|| {
        ResourceError::Invalid("manifest reference buffer size is unreadable".to_string())
    })? as usize;
    let manifest_name_size = u32_at(bytes, 36).ok_or_else(|| {
        ResourceError::Invalid("manifest name buffer size is unreadable".to_string())
    })? as usize;
    let asset_name_size = u32_at(bytes, 40).ok_or_else(|| {
        ResourceError::Invalid("manifest asset-name buffer size is unreadable".to_string())
    })? as usize;
    let source_name_size = u32_at(bytes, 44).ok_or_else(|| {
        ResourceError::Invalid("manifest source-name buffer size is unreadable".to_string())
    })? as usize;
    let reference_end = reference_base.checked_add(reference_size).ok_or_else(|| {
        ResourceError::Invalid("manifest reference buffer is too large".to_string())
    })?;
    let asset_name_base = reference_end
        .checked_add(manifest_name_size)
        .ok_or_else(|| ResourceError::Invalid("manifest name buffer is too large".to_string()))?;
    let asset_name_end = asset_name_base
        .checked_add(asset_name_size)
        .ok_or_else(|| {
            ResourceError::Invalid("manifest asset-name buffer is too large".to_string())
        })?;
    let source_name_base = asset_name_end;
    if source_name_base
        .checked_add(source_name_size)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(ResourceError::Invalid(
            "manifest source-name buffer is outside the file".to_string(),
        ));
    }
    let entries = parse_entries(
        bytes,
        asset_count,
        reference_base,
        asset_name_base,
        source_name_base,
    )?;
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
        asset_count,
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
        source_file_name_buffer_size: source_name_size as u32,
        names,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_asset_entries() {
        let mut bytes = vec![0u8; 48];
        bytes[1] = 1;
        bytes[2..4].copy_from_slice(&6u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&16u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&8u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&15u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&11u32.to_le_bytes());
        let mut entry = Vec::new();
        for value in [1u32, 2, 3, 4, 0, 1, 0, 0, 16, 8, 4, 0] {
            entry.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&entry);
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(b"AptAptData:Foo\0");
        bytes.extend_from_slice(b"source.xml\0");
        let info = parse(&bytes).unwrap();
        assert!(!info.big_endian);
        assert!(info.linked);
        assert_eq!(info.version, 6);
        assert_eq!(info.asset_count, 1);
        assert_eq!(info.total_instance_data_size, 16);
        assert_eq!(info.asset_name_buffer_size, 15);
        assert_eq!(info.source_file_name_buffer_size, 11);
        assert_eq!(info.names, vec!["AptAptData:Foo", "source.xml"]);
        assert_eq!(info.entries.len(), 1);
        let first = &info.entries[0];
        assert_eq!(first.type_id, 1);
        assert_eq!(first.instance_id, 2);
        assert_eq!(first.name, "AptAptData:Foo");
        assert_eq!(first.source_name, "source.xml");
        assert_eq!(first.instance_size, 16);
        assert_eq!(
            first.references,
            vec![AssetReference {
                type_id: 7,
                instance_id: 8
            }]
        );
    }

    #[test]
    fn rejects_short_header_and_bad_flag() {
        assert!(parse(&[0u8; 47]).is_err());
        let mut bytes = vec![0u8; 48];
        bytes[0] = 2;
        assert!(parse(&bytes).is_err());
    }
}
