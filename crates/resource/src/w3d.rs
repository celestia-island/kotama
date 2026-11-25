//! W3D chunk container scanner.
//!
//! A chunk is a little-endian u32 type followed by a u32 size whose high bit
//! marks a container. Chunk payloads stay opaque; this module only produces
//! deterministic offset/size/depth evidence.

use crate::ResourceError;

/// One flattened W3D chunk header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W3dChunk {
    /// Chunk type ID.
    pub type_id: u32,
    /// Byte offset of the chunk header.
    pub offset: u64,
    /// Payload size, excluding the 8-byte header.
    pub size: u32,
    /// Zero for top-level chunks.
    pub depth: u8,
    /// True when the chunk contains sub-chunks.
    pub has_subchunks: bool,
}

/// A parsed W3D chunk tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct W3dFile<'a> {
    /// Original file bytes.
    pub data: &'a [u8],
    /// Chunks in depth-first file order.
    pub chunks: Vec<W3dChunk>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn scan(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: u8,
    chunks: &mut Vec<W3dChunk>,
) -> Result<(), ResourceError> {
    if depth > 32 {
        return Err(ResourceError::Invalid(
            "W3D chunk nesting exceeds 32 levels".to_string(),
        ));
    }
    let mut offset = start;
    while offset < end {
        let Some(header_end) = offset.checked_add(8) else {
            return Err(ResourceError::Invalid(
                "W3D chunk header overflows".to_string(),
            ));
        };
        if header_end > end {
            return Err(ResourceError::Invalid(format!(
                "W3D chunk header at {offset} is truncated"
            )));
        }
        let type_id = u32_at(bytes, offset).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk type at {offset} is unreadable"))
        })?;
        let raw_size = u32_at(bytes, offset + 4).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk size at {offset} is unreadable"))
        })?;
        let has_subchunks = raw_size & 0x8000_0000 != 0;
        let size = raw_size & 0x7fff_ffff;
        let payload_start = header_end;
        let payload_end = payload_start.checked_add(size as usize).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk at {offset} payload overflows"))
        })?;
        if payload_end > end {
            return Err(ResourceError::Invalid(format!(
                "W3D chunk at {offset} payload {size} exceeds its parent"
            )));
        }
        chunks.push(W3dChunk {
            type_id,
            offset: offset as u64,
            size,
            depth,
            has_subchunks,
        });
        if has_subchunks {
            scan(bytes, payload_start, payload_end, depth + 1, chunks)?;
        }
        offset = payload_end;
    }
    Ok(())
}

/// Parse and validate a W3D chunk tree.
///
/// # Errors
/// Returns ResourceError::Invalid for truncated headers, oversized payloads or
/// excessive nesting.
pub fn parse(bytes: &[u8]) -> Result<W3dFile<'_>, ResourceError> {
    let mut chunks = Vec::new();
    scan(bytes, 0, bytes.len(), 0, &mut chunks)?;
    if chunks.is_empty() {
        return Err(ResourceError::Invalid(
            "W3D file contains no chunks".to_string(),
        ));
    }
    Ok(W3dFile {
        data: bytes,
        chunks,
    })
}

impl W3dFile<'_> {
    /// Return a chunk payload when its recorded bounds are valid.
    #[must_use]
    pub fn payload(&self, chunk: W3dChunk) -> Option<&'_ [u8]> {
        let start = chunk.offset.checked_add(8)?;
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(chunk.size as usize)?;
        self.data.get(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(type_id: u32, payload: &[u8], subchunks: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&type_id.to_le_bytes());
        let size = if subchunks {
            0x8000_0000 | payload.len() as u32
        } else {
            payload.len() as u32
        };
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn scans_nested_chunks_and_payloads() {
        let child = chunk(31, b"abcd", false);
        let root = chunk(0, &child, true);
        let parsed = parse(&root).unwrap();
        assert_eq!(parsed.chunks.len(), 2);
        assert_eq!(parsed.chunks[0].type_id, 0);
        assert_eq!(parsed.chunks[0].depth, 0);
        assert!(parsed.chunks[0].has_subchunks);
        assert_eq!(parsed.chunks[1].type_id, 31);
        assert_eq!(parsed.chunks[1].depth, 1);
        assert_eq!(parsed.chunks[1].offset, 8);
        assert_eq!(parsed.payload(parsed.chunks[1]), Some(b"abcd".as_slice()));
    }

    #[test]
    fn rejects_truncated_payload_and_empty_input() {
        let mut bytes = chunk(0, b"abcd", false);
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse(&bytes).is_err());
        assert!(parse(&[]).is_err());
    }
}
