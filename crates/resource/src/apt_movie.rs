//! Minimal APT movie and character-type parser.
//!
//! RA3 AptData files carry a 16-byte prefix before the movie character. The
//! entry offset is supplied by the caller (normally from the paired const
//! file). Frame contents and nested character payloads stay opaque.

use crate::ResourceError;

/// One APT character reference.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AptCharacter {
    /// Character offset relative to the 16-byte prefix.
    pub offset: u32,
    /// Character type id.
    pub type_id: u32,
    /// Character type name.
    pub type_name: &'static str,
}

/// Parsed APT movie facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptMovieInfo {
    /// Movie entry offset.
    pub entry_offset: usize,
    /// Frame count.
    pub frame_count: u32,
    /// Declared character count.
    pub character_count: u32,
    /// Screen width.
    pub screen_width: u32,
    /// Screen height.
    pub screen_height: u32,
    /// Milliseconds per frame.
    pub milliseconds_per_frame: u32,
    /// Import count.
    pub import_count: u32,
    /// Export count.
    pub export_count: u32,
    /// Resolved characters.
    pub characters: Vec<AptCharacter>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

const CHARACTER_SIGNATURE: u32 = 0x0987_6543;
const PREFIX: usize = 16;

fn character_type_name(type_id: u32) -> &'static str {
    match type_id {
        1 => "shape",
        2 => "text",
        3 => "font",
        4 => "button",
        5 => "sprite",
        6 => "sound",
        7 => "image",
        8 => "morph",
        9 => "movie",
        10 => "static-text",
        11 => "none",
        12 => "video",
        _ => "unknown",
    }
}

/// Parse a movie character at the given entry offset.
///
/// # Errors
/// Returns ResourceError::Invalid for a short file, wrong movie signature or a
/// character pointer outside the file.
pub fn parse(bytes: &[u8], entry_offset: usize) -> Result<AptMovieInfo, ResourceError> {
    let _header_end = entry_offset
        .checked_add(56)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| {
            ResourceError::Invalid("APT movie header is outside the file".to_string())
        })?;
    if u32_at(bytes, entry_offset) != Some(9) {
        return Err(ResourceError::Invalid(
            "APT entry is not a movie character".to_string(),
        ));
    }
    if u32_at(bytes, entry_offset + 4) != Some(CHARACTER_SIGNATURE) {
        return Err(ResourceError::Invalid(
            "APT movie signature is invalid".to_string(),
        ));
    }
    let frame_count = u32_at(bytes, entry_offset + 8)
        .ok_or_else(|| ResourceError::Invalid("APT frame count is unreadable".to_string()))?;
    let character_count = u32_at(bytes, entry_offset + 20)
        .ok_or_else(|| ResourceError::Invalid("APT character count is unreadable".to_string()))?;
    let character_list = u32_at(bytes, entry_offset + 24)
        .ok_or_else(|| ResourceError::Invalid("APT character list is unreadable".to_string()))?
        as usize;
    let screen_width = u32_at(bytes, entry_offset + 28)
        .ok_or_else(|| ResourceError::Invalid("APT screen width is unreadable".to_string()))?;
    let screen_height = u32_at(bytes, entry_offset + 32)
        .ok_or_else(|| ResourceError::Invalid("APT screen height is unreadable".to_string()))?;
    let milliseconds_per_frame = u32_at(bytes, entry_offset + 36)
        .ok_or_else(|| ResourceError::Invalid("APT frame time is unreadable".to_string()))?;
    let import_count = u32_at(bytes, entry_offset + 40)
        .ok_or_else(|| ResourceError::Invalid("APT import count is unreadable".to_string()))?;
    let export_count = u32_at(bytes, entry_offset + 48)
        .ok_or_else(|| ResourceError::Invalid("APT export count is unreadable".to_string()))?;
    let mut characters = Vec::new();
    for index in 0..character_count as usize {
        let pointer_offset = PREFIX
            .checked_add(character_list)
            .and_then(|offset| offset.checked_add(index * 4))
            .ok_or_else(|| ResourceError::Invalid("APT character list is too large".to_string()))?;
        let pointer = u32_at(bytes, pointer_offset).ok_or_else(|| {
            ResourceError::Invalid("APT character pointer is unreadable".to_string())
        })?;
        if pointer == 0 {
            continue;
        }
        let character_offset = PREFIX
            .checked_add(pointer as usize)
            .filter(|offset| *offset < bytes.len())
            .ok_or_else(|| {
                ResourceError::Invalid("APT character pointer is outside the file".to_string())
            })?;
        let type_id = u32_at(bytes, character_offset).ok_or_else(|| {
            ResourceError::Invalid("APT character type is unreadable".to_string())
        })?;
        if u32_at(bytes, character_offset + 4) != Some(CHARACTER_SIGNATURE) {
            return Err(ResourceError::Invalid(
                "APT character signature is invalid".to_string(),
            ));
        }
        characters.push(AptCharacter {
            offset: pointer,
            type_id,
            type_name: character_type_name(type_id),
        });
    }
    Ok(AptMovieInfo {
        entry_offset,
        frame_count,
        character_count,
        screen_width,
        screen_height,
        milliseconds_per_frame,
        import_count,
        export_count,
        characters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_movie_and_characters() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // frames
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // unknown
        bytes.extend_from_slice(&1u32.to_le_bytes()); // characters
        bytes.extend_from_slice(&56u32.to_le_bytes()); // list at prefix+56 = 72
        bytes.extend_from_slice(&800u32.to_le_bytes()); // width
        bytes.extend_from_slice(&600u32.to_le_bytes()); // height
        bytes.extend_from_slice(&33u32.to_le_bytes()); // ms
        bytes.extend_from_slice(&0u32.to_le_bytes()); // imports
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // exports
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(72, 0);
        bytes.extend_from_slice(&64u32.to_le_bytes()); // character at prefix+64 = 80
        bytes.resize(80, 0);
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.frame_count, 0);
        assert_eq!(info.character_count, 1);
        assert_eq!(info.screen_width, 800);
        assert_eq!(info.screen_height, 600);
        assert_eq!(info.characters.len(), 1);
        assert_eq!(info.characters[0].type_name, "sprite");
    }

    #[test]
    fn rejects_non_movie() {
        assert!(parse(&[0u8; 64], 16).is_err());
    }
}
