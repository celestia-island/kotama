//! DDS surface header parser.
//!
//! Only the 128-byte header is handled; compressed payload blocks stay opaque.

use crate::ResourceError;

/// DDS pixel-format flags.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DdsPixelFormat {
    /// Pixel-format flags.
    pub flags: u32,
    /// FourCC when DDPF_FOURCC is set.
    pub fourcc: Option<String>,
    /// RGB bit count.
    pub rgb_bit_count: u32,
    /// Red mask.
    pub red_mask: u32,
    /// Green mask.
    pub green_mask: u32,
    /// Blue mask.
    pub blue_mask: u32,
    /// Alpha mask.
    pub alpha_mask: u32,
}

/// Parsed DDS header facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DdsInfo {
    /// Surface width.
    pub width: u32,
    /// Surface height.
    pub height: u32,
    /// Surface flags.
    pub flags: u32,
    /// Mipmap count (1 when DDSD_MIPMAPCOUNT is clear).
    pub mipmaps: u32,
    /// Pixel format.
    pub pixel_format: DdsPixelFormat,
    /// Caps.
    pub caps: u32,
    /// Caps2.
    pub caps2: u32,
    /// Caps3.
    pub caps3: u32,
    /// Caps4.
    pub caps4: u32,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// True when the bytes start with the DDS magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"DDS ".as_slice())
}

/// Parse and validate a DDS header.
///
/// # Errors
/// Returns ResourceError::Invalid for a wrong magic or a header shorter than
/// 128 bytes.
pub fn parse(bytes: &[u8]) -> Result<DdsInfo, ResourceError> {
    if !has_magic(bytes) {
        return Err(ResourceError::UnknownFormat);
    }
    if bytes.len() < 128 {
        return Err(ResourceError::Invalid(
            "DDS header is shorter than 128 bytes".to_string(),
        ));
    }
    let size = u32_at(bytes, 4)
        .ok_or_else(|| ResourceError::Invalid("DDS size is unreadable".to_string()))?;
    if size < 124 {
        return Err(ResourceError::Invalid(format!(
            "DDS header size {size} is below 124"
        )));
    }
    let pf_flags = u32_at(bytes, 80).ok_or_else(|| {
        ResourceError::Invalid("DDS pixel-format flags are unreadable".to_string())
    })?;
    let fourcc = if pf_flags & 0x4 != 0 {
        let raw = bytes
            .get(84..88)
            .ok_or_else(|| ResourceError::Invalid("DDS FourCC is unreadable".to_string()))?;
        let text = String::from_utf8_lossy(raw);
        let trimmed = text.trim_end_matches(['\0', ' ']);
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    } else {
        None
    };
    Ok(DdsInfo {
        width: u32_at(bytes, 16)
            .ok_or_else(|| ResourceError::Invalid("DDS width is unreadable".to_string()))?,
        height: u32_at(bytes, 12)
            .ok_or_else(|| ResourceError::Invalid("DDS height is unreadable".to_string()))?,
        flags: u32_at(bytes, 8)
            .ok_or_else(|| ResourceError::Invalid("DDS flags are unreadable".to_string()))?,
        mipmaps: u32_at(bytes, 28)
            .ok_or_else(|| ResourceError::Invalid("DDS mipmap count is unreadable".to_string()))?,
        pixel_format: DdsPixelFormat {
            flags: pf_flags,
            fourcc,
            rgb_bit_count: u32_at(bytes, 88).ok_or_else(|| {
                ResourceError::Invalid("DDS RGB bit count is unreadable".to_string())
            })?,
            red_mask: u32_at(bytes, 92)
                .ok_or_else(|| ResourceError::Invalid("DDS red mask is unreadable".to_string()))?,
            green_mask: u32_at(bytes, 96).ok_or_else(|| {
                ResourceError::Invalid("DDS green mask is unreadable".to_string())
            })?,
            blue_mask: u32_at(bytes, 100)
                .ok_or_else(|| ResourceError::Invalid("DDS blue mask is unreadable".to_string()))?,
            alpha_mask: u32_at(bytes, 104).ok_or_else(|| {
                ResourceError::Invalid("DDS alpha mask is unreadable".to_string())
            })?,
        },
        caps: u32_at(bytes, 108)
            .ok_or_else(|| ResourceError::Invalid("DDS caps are unreadable".to_string()))?,
        caps2: u32_at(bytes, 112)
            .ok_or_else(|| ResourceError::Invalid("DDS caps2 is unreadable".to_string()))?,
        caps3: u32_at(bytes, 116)
            .ok_or_else(|| ResourceError::Invalid("DDS caps3 is unreadable".to_string()))?,
        caps4: u32_at(bytes, 120)
            .ok_or_else(|| ResourceError::Invalid("DDS caps4 is unreadable".to_string()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_fourcc() {
        let mut bytes = vec![0u8; 128];
        bytes[0..4].copy_from_slice(b"DDS ");
        bytes[4..8].copy_from_slice(&124u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x1007u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&32u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&64u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&4u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&0x4u32.to_le_bytes());
        bytes[84..88].copy_from_slice(b"DXT1");
        let info = parse(&bytes).unwrap();
        assert_eq!(info.width, 64);
        assert_eq!(info.height, 32);
        assert_eq!(info.mipmaps, 4);
        assert_eq!(info.pixel_format.fourcc.as_deref(), Some("DXT1"));
    }

    #[test]
    fn rejects_bad_magic_and_short_header() {
        assert!(parse(b"not dds").is_err());
        assert!(parse(b"DDS ").is_err());
    }
}
