//! EA BIG archive container (BIGF/BIG4).
//!
//! The table is big-endian: archive size, entry count, first data offset,
//! then offset, size and NUL-terminated name records. Only the container is
//! handled here; entries stay opaque bytes.

use crate::ResourceError;

/// BIG container version.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BigVersion {
    /// Original BIGF.
    BigF,
    /// Later BIG4.
    Big4,
}

impl BigVersion {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::BigF => "bigf",
            Self::Big4 => "big4",
        }
    }
}

/// One archive entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BigEntry<'a> {
    /// Entry name as stored in the archive.
    pub name: &'a str,
    /// Absolute byte offset of the entry payload.
    pub offset: u32,
    /// Entry payload length.
    pub size: u32,
}

/// A parsed BIG archive.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigArchive<'a> {
    /// Original archive bytes.
    pub data: &'a [u8],
    /// Container version.
    pub version: BigVersion,
    /// Declared archive size.
    pub archive_size: u32,
    /// First byte after the entry table.
    pub first_offset: u32,
    /// Entries in table order.
    pub entries: Vec<BigEntry<'a>>,
}

/// True when the bytes start with a supported BIG magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    matches!(bytes.get(..4), Some(b"BIGF" | b"BIG4"))
}

fn be32(bytes: &[u8], offset: usize) -> Result<u32, ResourceError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ResourceError::Invalid("BIG archive is truncated".to_string()))?;
    Ok(u32::from_be_bytes(value.try_into().expect("four bytes")))
}

/// Parse and validate a BIGF/BIG4 archive.
///
/// # Errors
/// Returns ResourceError::Invalid for malformed headers, tables or entry bounds.
pub fn parse(bytes: &[u8]) -> Result<BigArchive<'_>, ResourceError> {
    if bytes.len() < 16 {
        return Err(ResourceError::Invalid(
            "BIG archive is shorter than its 16-byte header".to_string(),
        ));
    }
    let version = match &bytes[..4] {
        b"BIGF" => BigVersion::BigF,
        b"BIG4" => BigVersion::Big4,
        _ => return Err(ResourceError::UnknownFormat),
    };
    let archive_size_be = be32(bytes, 4)?;
    let archive_size_le = u32::from_le_bytes(bytes[4..8].try_into().expect("four bytes"));
    let archive_size = if u64::from(archive_size_be) == bytes.len() as u64 {
        archive_size_be
    } else if u64::from(archive_size_le) == bytes.len() as u64 {
        archive_size_le
    } else {
        return Err(ResourceError::Invalid(format!(
            "BIG archive declares {archive_size_be} or {archive_size_le} bytes but {} are present",
            bytes.len()
        )));
    };
    let count = be32(bytes, 8)?;
    let first_offset = be32(bytes, 12)?;
    let table_end = first_offset as usize;
    if table_end > bytes.len() {
        return Err(ResourceError::Invalid(format!(
            "BIG first offset {table_end} is outside the archive"
        )));
    }
    let mut position = 16usize;
    let mut entries = Vec::new();
    for _ in 0..count {
        if position + 8 > table_end {
            return Err(ResourceError::Invalid(
                "BIG entry table is truncated".to_string(),
            ));
        }
        let offset = be32(bytes, position)?;
        let size = be32(bytes, position + 4)?;
        position += 8;
        let name_start = position;
        let Some(nul) = bytes[name_start..table_end]
            .iter()
            .position(|byte| *byte == 0)
        else {
            return Err(ResourceError::Invalid(
                "BIG entry name is not NUL-terminated".to_string(),
            ));
        };
        let name_end = name_start + nul;
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|_| ResourceError::Invalid("BIG entry name is not UTF-8".to_string()))?;
        position = name_end + 1;
        let end = u64::from(offset) + u64::from(size);
        if offset < first_offset || end > u64::from(archive_size) {
            return Err(ResourceError::Invalid(format!(
                "BIG entry {name:?} lies outside the archive"
            )));
        }
        entries.push(BigEntry { name, offset, size });
    }
    if position > table_end {
        return Err(ResourceError::Invalid(format!(
            "BIG entry table ends at {position}, beyond first offset {table_end}"
        )));
    }
    Ok(BigArchive {
        data: bytes,
        version,
        archive_size,
        first_offset,
        entries,
    })
}

impl BigArchive<'_> {
    /// Look up an entry by name; duplicate names resolve to the last one.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<BigEntry<'_>> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.name == name)
            .copied()
    }

    /// Return an entry payload when its bounds are valid.
    #[must_use]
    pub fn entry_bytes(&self, entry: BigEntry<'_>) -> Option<&'_ [u8]> {
        let start = entry.offset as usize;
        let end = start.checked_add(entry.size as usize)?;
        self.data.get(start..end)
    }

    /// Return an entry payload by name.
    #[must_use]
    pub fn extract(&self, name: &str) -> Option<&'_ [u8]> {
        self.entry_bytes(self.entry(name)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let table_len: usize = entries.iter().map(|(name, _)| 8 + name.len() + 1).sum();
        let data_start = 16 + table_len;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BIG4");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(data_start as u32).to_be_bytes());
        let mut offset = data_start;
        for (name, payload) in entries {
            bytes.extend_from_slice(&(offset as u32).to_be_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            offset += payload.len();
        }
        for (_, payload) in entries {
            bytes.extend_from_slice(payload);
        }
        let total = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&total.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_entries_and_payloads() {
        let bytes = archive(&[("data\\a.bin", b"alpha"), ("data\\b.bin", b"beta")]);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.version, BigVersion::Big4);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "data\\a.bin");
        assert_eq!(parsed.extract("data\\a.bin"), Some(b"alpha".as_slice()));
        assert_eq!(parsed.extract("missing"), None);
    }

    #[test]
    fn accepts_little_endian_archive_size() {
        let mut bytes = archive(&[("x", b"123")]);
        let total = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&total.to_le_bytes());
        assert_eq!(parse(&bytes).unwrap().archive_size, total);
    }

    #[test]
    fn rejects_size_and_table_mismatches() {
        let mut bytes = archive(&[("x", b"123")]);
        bytes[4..8].copy_from_slice(&999u32.to_be_bytes());
        assert!(parse(&bytes).is_err());

        let mut bytes = archive(&[("x", b"123")]);
        bytes[12..16].copy_from_slice(&21u32.to_be_bytes());
        assert!(parse(&bytes).is_err());
    }
}
