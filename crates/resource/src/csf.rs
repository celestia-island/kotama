//! CSF string table parser.
//!
//! Layout: four CC (CSF), version, label count, string count, zero, language,
//! then LBL records containing a name and STR/STRW records. String values are
//! UTF-16 with each code unit bitwise inverted.

use crate::ResourceError;

/// One localized string.
#[derive(Clone, PartialEq, Debug)]
pub struct CsfString {
    /// Decoded value.
    pub value: String,
    /// Extra ASCII value from STRW, when present.
    pub extra_value: Option<String>,
}

/// One label and its strings.
#[derive(Clone, PartialEq, Debug)]
pub struct CsfLabel {
    /// Label name.
    pub name: String,
    /// Strings under this label.
    pub strings: Vec<CsfString>,
}

/// A parsed CSF file.
#[derive(Clone, PartialEq, Debug)]
pub struct CsfFile {
    /// Format version.
    pub version: u32,
    /// Declared label count.
    pub label_count: u32,
    /// Declared string count.
    pub string_count: u32,
    /// Language ID.
    pub language: u32,
    /// Labels in file order.
    pub labels: Vec<CsfLabel>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn ascii_prefixed(bytes: &[u8], position: usize) -> Option<(String, usize)> {
    let length = u32_at(bytes, position)? as usize;
    let start = position + 4;
    let end = start.checked_add(length)?;
    let raw = bytes.get(start..end)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    Some((
        String::from_utf8_lossy(&raw[..end]).into_owned(),
        start + length,
    ))
}

fn negated_utf16_prefixed(bytes: &[u8], position: usize) -> Option<(String, usize)> {
    let length = u32_at(bytes, position)? as usize;
    let start = position + 4;
    let end = start.checked_add(length.checked_mul(2)?)?;
    let raw = bytes.get(start..end)?;
    let mut units = Vec::with_capacity(length);
    let mut offset = 0;
    while offset + 2 <= raw.len() {
        units.push(!u16::from_le_bytes([raw[offset], raw[offset + 1]]));
        offset += 2;
    }
    Some((String::from_utf16(&units).ok()?, end))
}

fn is_four_cc(bytes: &[u8], position: usize, accepted: &[&[u8; 4]]) -> bool {
    bytes
        .get(position..position + 4)
        .is_some_and(|raw| accepted.iter().any(|candidate| candidate.as_slice() == raw))
}

fn string_tag(bytes: &[u8], position: usize) -> Option<bool> {
    if is_four_cc(bytes, position, &[b"STRW", b"WRTS"]) {
        Some(true)
    } else if is_four_cc(bytes, position, &[b"STR ", b" RTS"]) {
        Some(false)
    } else {
        None
    }
}

/// True when the bytes start with the CSF magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    matches!(bytes.get(..4), Some(b" FSC" | b"CSF "))
}

/// Parse and validate a CSF string table.
///
/// # Errors
/// Returns ResourceError::Invalid for a wrong magic, truncated records or bad
/// label/string chunk tags.
pub fn parse(bytes: &[u8]) -> Result<CsfFile, ResourceError> {
    if !has_magic(bytes) {
        return Err(ResourceError::UnknownFormat);
    }
    let version = u32_at(bytes, 4)
        .ok_or_else(|| ResourceError::Invalid("CSF version is unreadable".to_string()))?;
    let label_count = u32_at(bytes, 8)
        .ok_or_else(|| ResourceError::Invalid("CSF label count is unreadable".to_string()))?;
    let string_count = u32_at(bytes, 12)
        .ok_or_else(|| ResourceError::Invalid("CSF string count is unreadable".to_string()))?;
    let zero = u32_at(bytes, 16)
        .ok_or_else(|| ResourceError::Invalid("CSF reserved field is unreadable".to_string()))?;
    if zero != 0 {
        return Err(ResourceError::Invalid(format!(
            "CSF reserved field is {zero}, expected 0"
        )));
    }
    let language = u32_at(bytes, 20)
        .ok_or_else(|| ResourceError::Invalid("CSF language is unreadable".to_string()))?;
    let mut position = 24usize;
    let mut labels = Vec::new();
    for _ in 0..label_count {
        if !is_four_cc(bytes, position, &[b" LBL", b"LBL "]) {
            return Err(ResourceError::Invalid(format!(
                "CSF label tag at {position} is invalid"
            )));
        }
        position += 4;
        let count = u32_at(bytes, position).ok_or_else(|| {
            ResourceError::Invalid(format!(
                "CSF label string count at {position} is unreadable"
            ))
        })? as usize;
        position += 4;
        let (name, next) = ascii_prefixed(bytes, position).ok_or_else(|| {
            ResourceError::Invalid(format!("CSF label name at {position} is invalid"))
        })?;
        position = next;
        let mut strings = Vec::new();
        for _ in 0..count {
            let wide = string_tag(bytes, position).ok_or_else(|| {
                ResourceError::Invalid(format!("CSF string tag at {position} is invalid"))
            })?;
            position += 4;
            let (value, next) = negated_utf16_prefixed(bytes, position).ok_or_else(|| {
                ResourceError::Invalid(format!("CSF string value at {position} is invalid"))
            })?;
            position = next;
            let extra_value = if wide {
                let (extra, next) = ascii_prefixed(bytes, position).ok_or_else(|| {
                    ResourceError::Invalid(format!("CSF extra value at {position} is invalid"))
                })?;
                position = next;
                Some(extra)
            } else {
                None
            };
            strings.push(CsfString { value, extra_value });
        }
        labels.push(CsfLabel { name, strings });
    }
    Ok(CsfFile {
        version,
        label_count,
        string_count,
        language,
        labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_label_and_negated_string() {
        let mut bytes = b" FSC".to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(b" LBL");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(b"NAME\0");
        bytes.extend_from_slice(b"STR ");
        let value = "HELLO".encode_utf16().map(|unit| !unit).collect::<Vec<_>>();
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        for unit in value {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.labels.len(), 1);
        assert_eq!(parsed.labels[0].name, "NAME");
        assert_eq!(parsed.labels[0].strings[0].value, "HELLO");
    }

    #[test]
    fn rejects_bad_magic_and_tag() {
        assert!(parse(b"not a csf").is_err());
        let mut bytes = b" FSC".to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(b"BAD!");
        assert!(parse(&bytes).is_err());
    }
}
