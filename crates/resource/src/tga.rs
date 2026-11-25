//! TGA image header parser.
//!
//! Only the 18-byte header is handled; image and color-map payloads stay opaque.

use crate::ResourceError;

/// Parsed TGA header facts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TgaInfo {
    /// ID field length.
    pub id_length: u8,
    /// Color-map type (0 = none, 1 = present).
    pub color_map_type: u8,
    /// Image type (0/1/2/3/9/10/11).
    pub image_type: u8,
    /// First color-map entry index.
    pub color_map_first: u16,
    /// Color-map entry count.
    pub color_map_length: u16,
    /// Color-map entry size in bits.
    pub color_map_entry_size: u8,
    /// X origin.
    pub x_origin: u16,
    /// Y origin.
    pub y_origin: u16,
    /// Image width.
    pub width: u16,
    /// Image height.
    pub height: u16,
    /// Pixel depth in bits.
    pub pixel_depth: u8,
    /// Image descriptor bits.
    pub image_descriptor: u8,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
}

/// Parse and validate a TGA header.
///
/// # Errors
/// Returns ResourceError::Invalid for a header shorter than 18 bytes or an
/// unsupported image/color-map type.
pub fn parse(bytes: &[u8]) -> Result<TgaInfo, ResourceError> {
    if bytes.len() < 18 {
        return Err(ResourceError::Invalid(
            "TGA header is shorter than 18 bytes".to_string(),
        ));
    }
    let info = TgaInfo {
        id_length: bytes[0],
        color_map_type: bytes[1],
        image_type: bytes[2],
        color_map_first: u16_at(bytes, 3).ok_or_else(|| {
            ResourceError::Invalid("TGA color-map first is unreadable".to_string())
        })?,
        color_map_length: u16_at(bytes, 5).ok_or_else(|| {
            ResourceError::Invalid("TGA color-map length is unreadable".to_string())
        })?,
        color_map_entry_size: bytes[7],
        x_origin: u16_at(bytes, 8)
            .ok_or_else(|| ResourceError::Invalid("TGA x origin is unreadable".to_string()))?,
        y_origin: u16_at(bytes, 10)
            .ok_or_else(|| ResourceError::Invalid("TGA y origin is unreadable".to_string()))?,
        width: u16_at(bytes, 12)
            .ok_or_else(|| ResourceError::Invalid("TGA width is unreadable".to_string()))?,
        height: u16_at(bytes, 14)
            .ok_or_else(|| ResourceError::Invalid("TGA height is unreadable".to_string()))?,
        pixel_depth: bytes[16],
        image_descriptor: bytes[17],
    };
    if !matches!(info.image_type, 0 | 1 | 2 | 3 | 9 | 10 | 11) {
        return Err(ResourceError::Invalid(format!(
            "unsupported TGA image type {}",
            info.image_type
        )));
    }
    if !matches!(info.color_map_type, 0 | 1) {
        return Err(ResourceError::Invalid(format!(
            "unsupported TGA color-map type {}",
            info.color_map_type
        )));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_true_color_header() {
        let mut bytes = vec![0u8; 18];
        bytes[2] = 2;
        bytes[12..14].copy_from_slice(&64u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&32u16.to_le_bytes());
        bytes[16] = 24;
        bytes[17] = 0x20;
        let info = parse(&bytes).unwrap();
        assert_eq!(info.image_type, 2);
        assert_eq!(info.width, 64);
        assert_eq!(info.height, 32);
        assert_eq!(info.pixel_depth, 24);
        assert_eq!(info.image_descriptor, 0x20);
    }

    #[test]
    fn rejects_short_header_and_bad_type() {
        assert!(parse(&[0u8; 17]).is_err());
        let mut bytes = vec![0u8; 18];
        bytes[2] = 8;
        assert!(parse(&bytes).is_err());
    }
}
