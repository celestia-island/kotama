//! APT constant file parser.
//!
//! Layout observed in RA3-era Apt UI data: 17-byte magic "Apt constant file",
//! three padding bytes, u32 AptData entry offset, u32 entry count, u32 header
//! size (32), then typed entries. Strings are absolute NUL-terminated offsets.

use crate::ResourceError;

/// A typed APT constant value.
#[derive(Clone, PartialEq, Debug)]
pub enum AptValue {
    /// No value.
    None,
    /// String constant.
    String(String),
    /// Register index.
    Register(u32),
    /// Boolean value.
    Boolean(bool),
    /// Float value.
    Float(f32),
    /// Signed integer value.
    Integer(i32),
    /// Lookup index.
    Lookup(u32),
    /// Property value (raw u32; semantics not guessed).
    Property(u32),
}

/// One APT constant entry.
#[derive(Clone, PartialEq, Debug)]
pub struct AptConstant {
    /// Raw type ID.
    pub type_id: u32,
    /// Decoded value.
    pub value: AptValue,
}

impl AptConstant {
    /// Conventional type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.type_id {
            1 => "string",
            2 => "property",
            3 => "none",
            4 => "register",
            5 => "boolean",
            6 => "float",
            7 => "integer",
            8 => "lookup",
            _ => "unknown",
        }
    }
}

/// A parsed APT constant file.
#[derive(Clone, PartialEq, Debug)]
pub struct AptConstFile {
    /// Offset of the Apt data entry point.
    pub apt_data_entry_offset: u32,
    /// Entries in file order.
    pub entries: Vec<AptConstant>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    u32_at(bytes, offset).map(|raw| raw as i32)
}

fn f32_at(bytes: &[u8], offset: usize) -> Option<f32> {
    u32_at(bytes, offset).map(f32::from_bits)
}

fn cstr_at(bytes: &[u8], offset: usize) -> Option<String> {
    if offset >= bytes.len() {
        return None;
    }
    let start = offset;
    let end = bytes[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| start + position)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// Parse and validate an APT constant file.
///
/// # Errors
/// Returns ResourceError::Invalid for a wrong magic, bad header, truncated
/// entries or invalid entry types.
pub fn parse(bytes: &[u8]) -> Result<AptConstFile, ResourceError> {
    let base = if bytes.get(..17) == Some(b"Apt constant file".as_slice()) {
        0
    } else if bytes.get(16..33) == Some(b"Apt constant file".as_slice()) {
        16
    } else {
        return Err(ResourceError::UnknownFormat);
    };
    if bytes.len() < base + 32 {
        return Err(ResourceError::Invalid(
            "APT constant file is shorter than its 32-byte header".to_string(),
        ));
    }
    let apt_data_entry_offset = u32_at(bytes, base + 20)
        .ok_or_else(|| ResourceError::Invalid("APT entry offset is unreadable".to_string()))?;
    let count = u32_at(bytes, base + 24)
        .ok_or_else(|| ResourceError::Invalid("APT entry count is unreadable".to_string()))?;
    let header_size = u32_at(bytes, base + 28)
        .ok_or_else(|| ResourceError::Invalid("APT header size is unreadable".to_string()))?;
    if header_size != 32 {
        return Err(ResourceError::Invalid(format!(
            "APT constant header must be 32 bytes, got {header_size}"
        )));
    }
    let mut entries = Vec::new();
    let mut position = base + 32;
    for _ in 0..count {
        let type_id = u32_at(bytes, position).ok_or_else(|| {
            ResourceError::Invalid(format!("APT entry type at {position} is unreadable"))
        })?;
        position += 4;
        let value = match type_id {
            1 => {
                let offset = u32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT string offset at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::String(cstr_at(bytes, offset as usize).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT string offset {offset} is invalid"))
                })?)
            }
            2 => {
                let value = u32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT property at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Property(value)
            }
            3 => AptValue::None,
            4 => {
                let value = u32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT register at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Register(value)
            }
            5 => {
                let value = u32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT boolean at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Boolean(value != 0)
            }
            6 => {
                let value = f32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT float at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Float(value)
            }
            7 => {
                let value = i32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT integer at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Integer(value)
            }
            8 => {
                let value = u32_at(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("APT lookup at {position} is unreadable"))
                })?;
                position += 4;
                AptValue::Lookup(value)
            }
            other => {
                return Err(ResourceError::Invalid(format!(
                    "unsupported APT constant type {other} at {}",
                    position - 4
                )))
            }
        };
        entries.push(AptConstant { type_id, value });
    }
    Ok(AptConstFile {
        apt_data_entry_offset,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_integer_entries() {
        let mut bytes = b"Apt constant file".to_vec();
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&0x50cu32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&48u32.to_le_bytes());
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&42i32.to_le_bytes());
        bytes.extend_from_slice(b"hello\0");
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.apt_data_entry_offset, 0x50c);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].type_name(), "string");
        assert_eq!(
            parsed.entries[0].value,
            AptValue::String("hello".to_string())
        );
        assert_eq!(parsed.entries[1].value, AptValue::Integer(42));
    }

    #[test]
    fn rejects_bad_magic_and_header() {
        assert!(parse(b"not an apt const").is_err());
        let mut bytes = b"Apt constant file".to_vec();
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&31u32.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }
}
