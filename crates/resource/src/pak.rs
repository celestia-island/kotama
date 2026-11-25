//! PopCap PAK container parser.
//!
//! The whole file is XOR-ed with `0xF7`. The decrypted stream starts with
//! `0xBAC04AC0` / version 0, followed by a catalog of records and then the
//! file bodies in catalog order.

use crate::ResourceError;

/// XOR mask applied to every PAK byte.
pub const XOR_MASK: u8 = 0xF7;
/// PAK magic after XOR decoding.
pub const MAGIC: u32 = 0xBAC0_4AC0;

/// One PAK entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PakEntry {
    /// Archive path.
    pub name: String,
    /// Body size.
    pub size: u32,
    /// Windows FILETIME.
    pub filetime: u64,
    /// Body offset in the decrypted stream.
    pub offset: usize,
}

/// Parsed PAK container.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PopCapPak {
    /// Catalog entries.
    pub entries: Vec<PakEntry>,
    /// Catalog terminator byte.
    pub catalog_terminator: u8,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset.checked_add(8)?).map(|raw| {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(raw);
        u64::from_le_bytes(buffer)
    })
}

/// True when the bytes decode to the PAK magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0] ^ XOR_MASK == 0xC0
        && bytes[1] ^ XOR_MASK == 0x4A
        && bytes[2] ^ XOR_MASK == 0xC0
        && bytes[3] ^ XOR_MASK == 0xBA
}

/// Parse and validate a PopCap PAK container.
///
/// # Errors
/// Returns ResourceError::Invalid for a short file, bad magic/version, a
/// truncated catalog or a body size mismatch.
pub fn parse(bytes: &[u8]) -> Result<PopCapPak, ResourceError> {
    if bytes.len() < 8 {
        return Err(ResourceError::Invalid(
            "PAK container is shorter than 8 bytes".to_string(),
        ));
    }
    let data: Vec<u8> = bytes.iter().map(|byte| byte ^ XOR_MASK).collect();
    let magic = u32_at(&data, 0)
        .ok_or_else(|| ResourceError::Invalid("PAK magic is unreadable".to_string()))?;
    let version = u32_at(&data, 4)
        .ok_or_else(|| ResourceError::Invalid("PAK version is unreadable".to_string()))?;
    if magic != MAGIC || version != 0 {
        return Err(ResourceError::Invalid(format!(
            "unsupported PAK magic/version {magic:#x}/{version}"
        )));
    }
    let mut cursor = 8usize;
    let mut entries = Vec::new();
    while data.get(cursor) == Some(&0) {
        let length = *data
            .get(cursor + 1)
            .ok_or_else(|| ResourceError::Invalid("PAK name length is unreadable".to_string()))?
            as usize;
        let name_start = cursor + 2;
        let name_end = name_start
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| ResourceError::Invalid("PAK name is outside the file".to_string()))?;
        let name: String = data[name_start..name_end]
            .iter()
            .map(|byte| *byte as char)
            .collect();
        let size = u32_at(&data, name_end)
            .ok_or_else(|| ResourceError::Invalid("PAK entry size is unreadable".to_string()))?;
        let filetime = u64_at(&data, name_end + 4)
            .ok_or_else(|| ResourceError::Invalid("PAK entry time is unreadable".to_string()))?;
        cursor = name_end + 12;
        entries.push(PakEntry {
            name,
            size,
            filetime,
            offset: 0,
        });
    }
    let catalog_terminator = *data.get(cursor).ok_or_else(|| {
        ResourceError::Invalid("PAK catalog terminator is unreadable".to_string())
    })?;
    cursor += 1;
    let catalog_end = cursor;
    let mut body_offset = catalog_end;
    for entry in &mut entries {
        entry.offset = body_offset;
        body_offset = body_offset
            .checked_add(entry.size as usize)
            .ok_or_else(|| ResourceError::Invalid("PAK body offset overflows".to_string()))?;
    }
    if body_offset != data.len() {
        return Err(ResourceError::Invalid(format!(
            "PAK body size {} does not match {}",
            body_offset,
            data.len()
        )));
    }
    Ok(PopCapPak {
        entries,
        catalog_terminator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0);
        data.push(5);
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(0xFF);
        data.extend_from_slice(b"abc");
        let encrypted: Vec<u8> = data.iter().map(|byte| byte ^ XOR_MASK).collect();
        assert!(has_magic(&encrypted));
        let pak = parse(&encrypted).unwrap();
        assert_eq!(pak.entries.len(), 1);
        assert_eq!(pak.entries[0].name, "hello");
        assert_eq!(pak.entries[0].size, 3);
        assert_eq!(pak.entries[0].offset, 8 + 2 + 5 + 12 + 1);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(parse(&[0u8; 8]).is_err());
    }
}
