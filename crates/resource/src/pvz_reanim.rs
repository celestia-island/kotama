//! PvZ Reanim compiled container parser.
//!
//! Container: u32 `0xDEADFED4`, u32 uncompressed size, zlib stream.
//! Body: magic `0xB393B4C0`, track count, fps, `0x0C` marker, frame counts,
//! then length-prefixed track names and 44-byte transforms + 3-string elements.

use crate::ResourceError;

/// Optional float sentinel used by Reanim transforms.
pub const OPTIONAL_SENTINEL: u32 = 0xC61C_4000;

/// One Reanim transform.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PvzReanimTransform {
    /// x, y, kx, ky, sx, sy, f, a.
    pub values: [Option<f32>; 8],
}

/// One Reanim frame's elements.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PvzReanimElements {
    /// Image name.
    pub image: Option<String>,
    /// Font name.
    pub font: Option<String>,
    /// Text.
    pub text: Option<String>,
}

/// One Reanim frame.
#[derive(Clone, PartialEq, Debug)]
pub struct PvzReanimFrame {
    /// Transform.
    pub transform: PvzReanimTransform,
    /// Elements.
    pub elements: PvzReanimElements,
}

/// One Reanim track.
#[derive(Clone, PartialEq, Debug)]
pub struct PvzReanimTrack {
    /// Track name.
    pub name: String,
    /// Frame count.
    pub frame_count: u32,
    /// First frame, when present.
    pub first_frame: Option<PvzReanimFrame>,
}

/// Parsed PvZ Reanim container/header facts.
#[derive(Clone, PartialEq, Debug)]
pub struct PvzReanimInfo {
    /// Declared uncompressed size.
    pub uncompressed_size: u32,
    /// Body magic.
    pub body_magic: u32,
    /// Unknown u32 at body + 4.
    pub unknown_4: u32,
    /// Track count at body + 8.
    pub track_count: u32,
    /// Frames per second.
    pub fps: f32,
    /// Unknown u32 at body + 16.
    pub unknown_16: u32,
    /// Marker at body + 20 (expected 0x0C).
    pub track_count_2: u32,
    /// Printable strings found after the body header.
    pub strings: Vec<String>,
    /// Frame counts in track order.
    pub frame_counts: Vec<u32>,
    /// Parsed tracks.
    pub tracks: Vec<PvzReanimTrack>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// True when the bytes start with the Reanim container magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    u32_at(bytes, 0) == Some(0xDEAD_FED4)
}

#[cfg(feature = "pvz-reanim")]
fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<Option<String>, ResourceError> {
    let length = u32_at(bytes, *cursor)
        .ok_or_else(|| ResourceError::Invalid("Reanim string length is unreadable".to_string()))?
        as usize;
    *cursor += 4;
    let text = bytes
        .get(
            *cursor..cursor.checked_add(length).ok_or_else(|| {
                ResourceError::Invalid("Reanim string length overflows".to_string())
            })?,
        )
        .ok_or_else(|| ResourceError::Invalid("Reanim string is outside the body".to_string()))?;
    let text = String::from_utf8_lossy(text).to_string();
    *cursor += length;
    Ok((!text.is_empty()).then_some(text))
}

#[cfg(feature = "pvz-reanim")]
fn parse_frame_at(
    bytes: &[u8],
    transform_offset: usize,
    elements_offset: usize,
) -> Result<PvzReanimFrame, ResourceError> {
    let mut cursor = transform_offset;
    let mut values = [None; 8];
    for (index, slot) in values.iter_mut().enumerate() {
        let raw = u32_at(bytes, cursor + index * 4).ok_or_else(|| {
            ResourceError::Invalid("Reanim transform value is unreadable".to_string())
        })?;
        *slot = (raw != OPTIONAL_SENTINEL).then(|| f32::from_bits(raw));
    }
    cursor = elements_offset;
    let image = read_string(bytes, &mut cursor)?;
    let font = read_string(bytes, &mut cursor)?;
    let text = read_string(bytes, &mut cursor)?;
    Ok(PvzReanimFrame {
        transform: PvzReanimTransform { values },
        elements: PvzReanimElements { image, font, text },
    })
}

#[cfg(feature = "pvz-reanim")]
fn scan_tracks(bytes: &[u8], frame_counts: &[u32]) -> Vec<PvzReanimTrack> {
    let mut tracks = Vec::new();
    let mut count_index = 0;
    for offset in 24..bytes.len().saturating_sub(5) {
        let Some(length) = u32_at(bytes, offset) else {
            continue;
        };
        let length = length as usize;
        if !(3..=64).contains(&length) {
            continue;
        }
        let Some(text) = bytes.get(offset + 4..offset + 4 + length) else {
            continue;
        };
        if bytes.get(offset + 4 + length) != Some(&0x2C) {
            continue;
        }
        if !text
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            continue;
        }
        let Ok(name) = std::str::from_utf8(text) else {
            continue;
        };
        let Some(frame_count) = frame_counts.get(count_index).copied() else {
            break;
        };
        count_index += 1;
        let transform_offset = offset + 4 + length + 1 + 3;
        let elements_offset = transform_offset + frame_count as usize * 44;
        let first_frame = (frame_count > 0)
            .then(|| parse_frame_at(bytes, transform_offset, elements_offset))
            .transpose()
            .ok()
            .flatten();
        tracks.push(PvzReanimTrack {
            name: name.to_string(),
            frame_count,
            first_frame,
        });
        if count_index == frame_counts.len() {
            break;
        }
    }
    tracks
}

/// Parse and validate a Reanim compiled container.
///
/// # Errors
/// Returns ResourceError::Invalid for a short container, a size mismatch, a
/// zlib error or malformed track data.
#[cfg(feature = "pvz-reanim")]
pub fn parse(bytes: &[u8]) -> Result<PvzReanimInfo, ResourceError> {
    use std::io::Read;

    if bytes.len() < 8 {
        return Err(ResourceError::Invalid(
            "Reanim container is shorter than 8 bytes".to_string(),
        ));
    }
    if !has_magic(bytes) {
        return Err(ResourceError::UnknownFormat);
    }
    let uncompressed_size = u32_at(bytes, 4)
        .ok_or_else(|| ResourceError::Invalid("Reanim size is unreadable".to_string()))?;
    let mut body = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[8..])
        .read_to_end(&mut body)
        .map_err(|error| ResourceError::Invalid(format!("Reanim zlib error: {error}")))?;
    if body.len() != uncompressed_size as usize {
        return Err(ResourceError::Invalid(format!(
            "Reanim uncompressed size {} does not match {}",
            body.len(),
            uncompressed_size
        )));
    }
    if body.len() < 24 {
        return Err(ResourceError::Invalid(
            "Reanim body header is shorter than 24 bytes".to_string(),
        ));
    }
    let body_magic = u32_at(&body, 0)
        .ok_or_else(|| ResourceError::Invalid("Reanim body magic is unreadable".to_string()))?;
    if body_magic != 0xB393_B4C0 {
        return Err(ResourceError::Invalid(format!(
            "Reanim body magic {body_magic:#x} is invalid"
        )));
    }
    let track_count = u32_at(&body, 8)
        .ok_or_else(|| ResourceError::Invalid("Reanim track count is unreadable".to_string()))?;
    let fps = f32::from_le_bytes(
        body[12..16]
            .try_into()
            .map_err(|_| ResourceError::Invalid("Reanim fps is unreadable".to_string()))?,
    );
    let marker = u32_at(&body, 20)
        .ok_or_else(|| ResourceError::Invalid("Reanim marker is unreadable".to_string()))?;
    if marker != 0x0C {
        return Err(ResourceError::Invalid(format!(
            "Reanim marker {marker:#x} is invalid"
        )));
    }
    let frame_counts = (0..track_count as usize)
        .filter_map(|index| u32_at(&body, 24 + index * 12 + 8))
        .collect::<Vec<_>>();
    let tracks = scan_tracks(&body, &frame_counts);
    let mut strings = Vec::new();
    let mut start: Option<usize> = None;
    for (offset, byte) in body.iter().enumerate().skip(24) {
        if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(offset);
            }
        } else if let Some(begin) = start {
            if offset - begin >= 3 {
                if let Ok(text) = std::str::from_utf8(&body[begin..offset]) {
                    strings.push(text.to_string());
                }
            }
            start = None;
        }
    }
    if let Some(begin) = start {
        if body.len() - begin >= 3 {
            if let Ok(text) = std::str::from_utf8(&body[begin..]) {
                strings.push(text.to_string());
            }
        }
    }
    Ok(PvzReanimInfo {
        uncompressed_size,
        body_magic,
        unknown_4: u32_at(&body, 4)
            .ok_or_else(|| ResourceError::Invalid("Reanim field 4 is unreadable".to_string()))?,
        track_count,
        fps,
        unknown_16: u32_at(&body, 16)
            .ok_or_else(|| ResourceError::Invalid("Reanim field 16 is unreadable".to_string()))?,
        track_count_2: marker,
        strings,
        frame_counts,
        tracks,
    })
}

#[cfg(not(feature = "pvz-reanim"))]
/// Parse a Reanim container (disabled build).
///
/// # Errors
/// Always returns ResourceError::FeatureDisabled.
pub fn parse(_bytes: &[u8]) -> Result<PvzReanimInfo, ResourceError> {
    Err(ResourceError::FeatureDisabled {
        kind: crate::ResourceKind::PvzReanim,
        feature: "pvz-reanim",
    })
}

#[cfg(all(test, feature = "pvz-reanim"))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_container_and_first_frame() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xB393_B4C0u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&12.0f32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0x0Cu32.to_le_bytes());
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        body.extend_from_slice(b"anim_idle");
        body.push(0x2C);
        body.extend_from_slice(&[0; 3]);
        for _ in 0..8 {
            body.extend_from_slice(&OPTIONAL_SENTINEL.to_le_bytes());
        }
        body.extend_from_slice(&[0; 12]);
        for _ in 0..3 {
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(&body).unwrap();
        let compressed = zlib.finish().unwrap();
        let mut bytes = 0xDEAD_FED4u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&compressed);
        let info = parse(&bytes).unwrap();
        assert_eq!(info.track_count, 1);
        assert_eq!(info.fps, 12.0);
        assert_eq!(info.tracks.len(), 1);
        assert_eq!(info.tracks[0].name, "anim_idle");
        let frame = info.tracks[0].first_frame.as_ref().unwrap();
        assert_eq!(frame.transform.values, [None; 8]);
        assert_eq!(frame.elements.image, None);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(parse(&[0u8; 8]).is_err());
    }
}
