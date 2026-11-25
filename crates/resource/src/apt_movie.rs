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

/// One APT import.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptImport {
    /// Imported movie path.
    pub movie: String,
    /// Imported symbol name.
    pub name: String,
    /// Character index.
    pub character: u32,
    /// Pointer field.
    pub pointer: u32,
}

/// One APT export.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptExport {
    /// Exported symbol name.
    pub name: String,
    /// Character index.
    pub character: u32,
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
    /// Imports.
    pub imports: Vec<AptImport>,
    /// Exports.
    pub exports: Vec<AptExport>,
    /// Image texture ids.
    pub texture_ids: Vec<u32>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

const CHARACTER_SIGNATURE: u32 = 0x0987_6543;
const PREFIX: usize = 16;

fn read_cstr(bytes: &[u8], offset: usize) -> Option<String> {
    let end = bytes[offset..].iter().position(|byte| *byte == 0)? + offset;
    Some(String::from_utf8_lossy(&bytes[offset..end]).to_string())
}

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
    let import_list = u32_at(bytes, entry_offset + 44)
        .ok_or_else(|| ResourceError::Invalid("APT import list is unreadable".to_string()))?
        as usize;
    let export_count = u32_at(bytes, entry_offset + 48)
        .ok_or_else(|| ResourceError::Invalid("APT export count is unreadable".to_string()))?;
    let export_list = u32_at(bytes, entry_offset + 52)
        .ok_or_else(|| ResourceError::Invalid("APT export list is unreadable".to_string()))?
        as usize;
    let mut characters = Vec::new();
    let mut texture_ids = Vec::new();
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
        if type_id == 7 {
            let texture_id = u32_at(bytes, character_offset + 8).ok_or_else(|| {
                ResourceError::Invalid("APT image texture id is unreadable".to_string())
            })?;
            texture_ids.push(texture_id);
        }
    }
    let mut imports = Vec::new();
    for index in 0..import_count as usize {
        let offset = PREFIX
            .checked_add(import_list)
            .and_then(|offset| offset.checked_add(index * 16))
            .ok_or_else(|| ResourceError::Invalid("APT import list is too large".to_string()))?;
        let movie_offset = u32_at(bytes, offset)
            .ok_or_else(|| ResourceError::Invalid("APT import movie is unreadable".to_string()))?;
        let name_offset = u32_at(bytes, offset + 4)
            .ok_or_else(|| ResourceError::Invalid("APT import name is unreadable".to_string()))?;
        imports.push(AptImport {
            movie: read_cstr(bytes, PREFIX + movie_offset as usize).ok_or_else(|| {
                ResourceError::Invalid("APT import movie string is unreadable".to_string())
            })?,
            name: read_cstr(bytes, PREFIX + name_offset as usize).ok_or_else(|| {
                ResourceError::Invalid("APT import name string is unreadable".to_string())
            })?,
            character: u32_at(bytes, offset + 8).ok_or_else(|| {
                ResourceError::Invalid("APT import character is unreadable".to_string())
            })?,
            pointer: u32_at(bytes, offset + 12).ok_or_else(|| {
                ResourceError::Invalid("APT import pointer is unreadable".to_string())
            })?,
        });
    }
    let mut exports = Vec::new();
    for index in 0..export_count as usize {
        let offset = PREFIX
            .checked_add(export_list)
            .and_then(|offset| offset.checked_add(index * 8))
            .ok_or_else(|| ResourceError::Invalid("APT export list is too large".to_string()))?;
        let name_offset = u32_at(bytes, offset)
            .ok_or_else(|| ResourceError::Invalid("APT export name is unreadable".to_string()))?;
        exports.push(AptExport {
            name: read_cstr(bytes, PREFIX + name_offset as usize).ok_or_else(|| {
                ResourceError::Invalid("APT export name string is unreadable".to_string())
            })?,
            character: u32_at(bytes, offset + 4).ok_or_else(|| {
                ResourceError::Invalid("APT export character is unreadable".to_string())
            })?,
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
        imports,
        exports,
        texture_ids,
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
        bytes.extend_from_slice(&1u32.to_le_bytes()); // imports
        bytes.extend_from_slice(&80u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // exports
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(72, 0);
        bytes.extend_from_slice(&64u32.to_le_bytes()); // character at prefix+64 = 80
        bytes.resize(80, 0);
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.resize(96, 0);
        for value in [112u32, 128, 5, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.resize(128, 0);
        bytes.extend_from_slice(b"movie\0");
        bytes.resize(144, 0);
        bytes.extend_from_slice(b"name\0");
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.frame_count, 0);
        assert_eq!(info.character_count, 1);
        assert_eq!(info.screen_width, 800);
        assert_eq!(info.screen_height, 600);
        assert_eq!(info.characters.len(), 1);
        assert_eq!(info.characters[0].type_name, "sprite");
        assert_eq!(info.imports.len(), 1);
        assert_eq!(info.imports[0].movie, "movie");
        assert_eq!(info.imports[0].name, "name");
        assert_eq!(info.imports[0].character, 5);
    }

    #[test]
    fn parses_image_texture_ids() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&56u32.to_le_bytes());
        bytes.extend_from_slice(&800u32.to_le_bytes());
        bytes.extend_from_slice(&600u32.to_le_bytes());
        bytes.extend_from_slice(&33u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes.resize(72, 0);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.resize(80, 0);
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&42u32.to_le_bytes());
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.characters[0].type_name, "image");
        assert_eq!(info.texture_ids, vec![42]);
    }

    #[test]
    fn rejects_non_movie() {
        assert!(parse(&[0u8; 64], 16).is_err());
    }
}
