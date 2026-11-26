//! VP6 movie container header parser.
//!
//! MVhd/vp60 files store a small header before MV0K chunks. This module keeps
//! the movie facts and leaves compressed video frames opaque.

use crate::ResourceError;

/// Parsed VP6 movie header facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vp6Info {
    /// Header size in bytes.
    pub header_size: u32,
    /// Codec tag, normally vp60.
    pub codec: String,
    /// Frame width.
    pub width: u16,
    /// Frame height.
    pub height: u16,
    /// Frame count when nonzero.
    pub frame_count: u16,
    /// Remaining header bytes.
    pub tail: Vec<u8>,
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

/// True when the bytes start with the MVhd magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"MVhd".as_slice())
}

/// Parse and validate a VP6 movie header.
///
/// # Errors
/// Returns ResourceError::Invalid for a wrong magic, short header or bad
/// dimensions.
pub fn parse(bytes: &[u8]) -> Result<Vp6Info, ResourceError> {
    if !has_magic(bytes) {
        return Err(ResourceError::UnknownFormat);
    }
    let header_size = u32_at(bytes, 4)
        .ok_or_else(|| ResourceError::Invalid("VP6 header size is unreadable".to_string()))?;
    if header_size < 32 || header_size as usize > bytes.len() {
        return Err(ResourceError::Invalid(format!(
            "VP6 header size {header_size} is outside the file"
        )));
    }
    let codec = bytes
        .get(8..12)
        .ok_or_else(|| ResourceError::Invalid("VP6 codec tag is unreadable".to_string()))?;
    let codec = String::from_utf8_lossy(codec)
        .trim_end_matches(['\0', ' '])
        .to_string();
    let width = u16_at(bytes, 12)
        .ok_or_else(|| ResourceError::Invalid("VP6 width is unreadable".to_string()))?;
    let height = u16_at(bytes, 14)
        .ok_or_else(|| ResourceError::Invalid("VP6 height is unreadable".to_string()))?;
    let frame_count = u16_at(bytes, 16)
        .ok_or_else(|| ResourceError::Invalid("VP6 frame count is unreadable".to_string()))?;
    if width == 0 || height == 0 {
        return Err(ResourceError::Invalid(format!(
            "VP6 dimensions {width}x{height} are invalid"
        )));
    }
    let tail = bytes[20..header_size as usize].to_vec();
    Ok(Vp6Info {
        header_size,
        codec,
        width,
        height,
        frame_count,
        tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_movie_header() {
        let mut bytes = b"MVhd".to_vec();
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(b"vp60");
        bytes.extend_from_slice(&1280u16.to_le_bytes());
        bytes.extend_from_slice(&720u16.to_le_bytes());
        bytes.extend_from_slice(&514u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 14]);
        let info = parse(&bytes).unwrap();
        assert_eq!(info.codec, "vp60");
        assert_eq!(info.width, 1280);
        assert_eq!(info.height, 720);
        assert_eq!(info.frame_count, 514);
    }

    #[test]
    fn rejects_bad_magic_and_dimensions() {
        assert!(parse(b"not vp6").is_err());
        let mut bytes = b"MVhd".to_vec();
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(b"vp60");
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 18]);
        assert!(parse(&bytes).is_err());
    }
}
