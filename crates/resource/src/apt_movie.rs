//! Minimal APT movie and character-type parser.
//!
//! Two layouts are accepted: a bare `.apt` whose `Apt Data:` tag starts at 0, and
//! an extracted `.bin` whose tag begins after a 16-byte prefix. All internal
//! pointers are relative to the tag, so the caller-visible entry offset already
//! encodes the layout; the parser detects the tag instead of assuming a prefix.
//! Frame contents and nested character payloads stay opaque.

use crate::ResourceError;

/// One APT character reference.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AptCharacter {
    /// Character offset relative to the Apt Data tag.
    pub offset: u32,
    /// Character type id.
    pub type_id: u32,
    /// Character type name.
    pub type_name: &'static str,
    /// Shape bounds (left, top, right, bottom).
    pub bounds: Option<[f32; 4]>,
    /// Shape geometry id.
    pub geometry: Option<u32>,
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

/// One APT animation table entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AptAnimationEntry {
    /// Entry offset.
    pub offset: u32,
    /// Entry count.
    pub count: u32,
}

/// One decoded `PlaceObject2` control payload.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AptPlacement {
    /// Placement flags (has-clip-actions / move / character / matrix ...).
    pub flags: u32,
    /// Display-list depth.
    pub depth: u32,
    /// Character id (0 when the control only moves an existing depth).
    pub character: u32,
    /// 2D affine matrix: `[a, b, c, d, tx, ty]`.
    pub matrix: [f32; 6],
    /// Colour multiplier: `[red, green, blue, alpha]`, 0-255 (255 = unchanged).
    pub colour: [u8; 4],
    /// Colour addend: `[red, green, blue, alpha]`, signed.
    pub colour_add: [i8; 4],
}

/// One decoded `FrameLabel` control payload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptFrameLabel {
    /// Label text.
    pub name: String,
    /// Frame index this label attaches to.
    pub frame: u32,
}

/// One control inside an APT frame.
#[derive(Clone, PartialEq, Debug)]
pub struct AptFrameControl {
    /// Control type (1 DoAction, 2 FrameLabel, 3 PlaceObject2, ...).
    pub control_type: u32,
    /// Control payload offset relative to the Apt Data tag.
    pub offset: u32,
    /// Control end offset relative to the Apt Data tag.
    pub end: u32,
    /// Decoded placement, when the control is a `PlaceObject2` with a full payload.
    pub placement: Option<AptPlacement>,
    /// Decoded label, when the control is a `FrameLabel`.
    pub frame_label: Option<AptFrameLabel>,
}

/// One top-level APT frame.
#[derive(Clone, PartialEq, Debug)]
pub struct AptFrame {
    /// Frame index.
    pub index: u32,
    /// Controls in this frame.
    pub controls: Vec<AptFrameControl>,
}

/// Parsed APT movie facts.
#[derive(Clone, PartialEq, Debug)]
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
    /// Animation file offset.
    pub animation_file: Option<u32>,
    /// Animation file version.
    pub animation_version: Option<u32>,
    /// Animation file size.
    pub animation_size: Option<u32>,
    /// Animation table entries.
    pub animation_entries: Vec<AptAnimationEntry>,
    /// Top-level frames with their controls.
    pub frames: Vec<AptFrame>,
    /// Characters whose slot pointer is null; they carry no local payload and
    /// take their symbol name from the matching `imports[]` entry.
    pub imported_character_count: u32,
    /// Characters with a local payload but no import/export symbol.
    pub anonymous_character_count: u32,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

const CHARACTER_SIGNATURE: u32 = 0x0987_6543;
const TAG: &[u8] = b"Apt Data:";

/// Offset of the Apt Data tag: 0 for a bare `.apt`, else the prefix length.
///
/// Legacy synthetic fixtures omit the tag entirely; they keep the historical
/// 16-byte prefix so old callers are unaffected.
fn data_base(bytes: &[u8]) -> usize {
    bytes
        .windows(TAG.len())
        .position(|window| window == TAG)
        .unwrap_or(16)
}

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
    let base = data_base(bytes);
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
    // Two layouts share this header. A bare/extracted `.apt` stores
    // `{nFrames, aFrames}` at `+8`/`+12`. A fix-up `.bin` stores the raw
    // `AptCharacter` `{dataBits, m_pAnimFile}` instead, so `+12` points at an
    // `AptAnimFile` (magic 0x09876543) rather than a frame array. The magic
    // decides which reading applies; `+0x14..` is the same movie data in both.
    let raw_count = u32_at(bytes, entry_offset + 8)
        .ok_or_else(|| ResourceError::Invalid("APT frame count is unreadable".to_string()))?;
    let raw_list = u32_at(bytes, entry_offset + 12).unwrap_or(0) as usize;
    let fixed_up = u32_at(bytes, raw_list) == Some(CHARACTER_SIGNATURE);
    let frame_count = if fixed_up { 0 } else { raw_count };
    let frame_list = if fixed_up { 0 } else { raw_list };
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
    // A null slot pointer means "this character comes from an import"; a local
    // payload without any symbol is simply anonymous. Keeping the two counts
    // apart stops "no local name" from being read as "unknown name".
    let mut imported_character_count = 0u32;
    for index in 0..character_count as usize {
        let pointer_offset = base
            .checked_add(character_list)
            .and_then(|offset| offset.checked_add(index * 4))
            .ok_or_else(|| ResourceError::Invalid("APT character list is too large".to_string()))?;
        let pointer = u32_at(bytes, pointer_offset).ok_or_else(|| {
            ResourceError::Invalid("APT character pointer is unreadable".to_string())
        })?;
        if pointer == 0 {
            imported_character_count += 1;
            continue;
        }
        let character_offset = base
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
        let bounds = if type_id == 1 {
            let mut values = [0f32; 4];
            for (slot, index) in values.iter_mut().zip(0..4) {
                let raw = u32_at(bytes, character_offset + 8 + index * 4).ok_or_else(|| {
                    ResourceError::Invalid("APT shape bounds are unreadable".to_string())
                })?;
                *slot = f32::from_bits(raw);
            }
            Some(values)
        } else {
            None
        };
        let geometry = if type_id == 1 {
            Some(u32_at(bytes, character_offset + 24).ok_or_else(|| {
                ResourceError::Invalid("APT shape geometry is unreadable".to_string())
            })?)
        } else {
            None
        };
        characters.push(AptCharacter {
            offset: pointer,
            type_id,
            type_name: character_type_name(type_id),
            bounds,
            geometry,
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
        let offset = base
            .checked_add(import_list)
            .and_then(|offset| offset.checked_add(index * 16))
            .ok_or_else(|| ResourceError::Invalid("APT import list is too large".to_string()))?;
        let movie_offset = u32_at(bytes, offset)
            .ok_or_else(|| ResourceError::Invalid("APT import movie is unreadable".to_string()))?;
        let name_offset = u32_at(bytes, offset + 4)
            .ok_or_else(|| ResourceError::Invalid("APT import name is unreadable".to_string()))?;
        imports.push(AptImport {
            movie: read_cstr(bytes, base + movie_offset as usize).ok_or_else(|| {
                ResourceError::Invalid("APT import movie string is unreadable".to_string())
            })?,
            name: read_cstr(bytes, base + name_offset as usize).ok_or_else(|| {
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
        let offset = base
            .checked_add(export_list)
            .and_then(|offset| offset.checked_add(index * 8))
            .ok_or_else(|| ResourceError::Invalid("APT export list is too large".to_string()))?;
        let name_offset = u32_at(bytes, offset)
            .ok_or_else(|| ResourceError::Invalid("APT export name is unreadable".to_string()))?;
        exports.push(AptExport {
            name: read_cstr(bytes, base + name_offset as usize).ok_or_else(|| {
                ResourceError::Invalid("APT export name string is unreadable".to_string())
            })?,
            character: u32_at(bytes, offset + 4).ok_or_else(|| {
                ResourceError::Invalid("APT export character is unreadable".to_string())
            })?,
        });
    }
    // Every non-null character that no export names is anonymous by construction.
    let anonymous_character_count = characters
        .len()
        .saturating_sub(exports.len())
        .try_into()
        .unwrap_or(u32::MAX);
    // `aFrames` is an array of `AptFrame` records, 8 bytes each:
    // `{ nControls, apControls }` where `apControls` points at an array of
    // control offsets. Layout confirmed against the SDK `apt2xml` oracle.
    let mut frames = Vec::new();
    for index in 0..frame_count.min(4096) {
        let frame_record = base
            .checked_add(frame_list)
            .and_then(|offset| offset.checked_add(index as usize * 8))
            .ok_or_else(|| ResourceError::Invalid("APT frame list is too large".to_string()))?;
        let Some(control_count) = u32_at(bytes, frame_record) else {
            break;
        };
        let Some(control_array) = u32_at(bytes, frame_record + 4) else {
            break;
        };
        let control_array = control_array as usize;
        if control_array >= bytes.len() {
            frames.push(AptFrame {
                index,
                controls: Vec::new(),
            });
            continue;
        }
        let mut controls = Vec::new();
        for control_index in 0..control_count.min(4096) as usize {
            let slot = control_array
                .checked_add(control_index * 4)
                .ok_or_else(|| {
                    ResourceError::Invalid("APT frame controls are too large".to_string())
                })?;
            let Some(control_offset) = u32_at(bytes, slot) else {
                break;
            };
            let control_offset_usize = control_offset as usize;
            if control_offset_usize >= bytes.len() {
                continue;
            }
            let Some(control_type) = u32_at(bytes, control_offset_usize) else {
                continue;
            };
            // Control payloads have no stored length; the next entry in the offset
            // array (or the end of the file) bounds this one.
            let control_end = if control_index + 1 < control_count as usize {
                u32_at(bytes, slot + 4).unwrap_or(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
            } else {
                u32::try_from(bytes.len()).unwrap_or(u32::MAX)
            };
            // PlaceObject2 is the only fixed-size payload decoded so far:
            // type, flags, depth, character, then the six matrix floats.
            let placement = (control_type == 3 && control_end - control_offset >= 44).then(|| {
                let flags = u32_at(bytes, control_offset_usize + 4).unwrap_or(0);
                let depth = u32_at(bytes, control_offset_usize + 8).unwrap_or(0);
                let character = u32_at(bytes, control_offset_usize + 12).unwrap_or(0);
                let mut matrix = [0f32; 6];
                for (slot, index) in matrix.iter_mut().zip(0..6) {
                    *slot = u32_at(bytes, control_offset_usize + 16 + index * 4)
                        .map(f32::from_bits)
                        .unwrap_or(0.0);
                }
                let mut colour = [255u8; 4];
                if control_end - control_offset >= 44 {
                    for (slot, index) in colour.iter_mut().zip(0..4) {
                        *slot = bytes
                            .get(control_offset_usize + 40 + index)
                            .copied()
                            .unwrap_or(255);
                    }
                }
                let mut colour_add = [0i8; 4];
                if control_end - control_offset >= 48 {
                    for (slot, index) in colour_add.iter_mut().zip(0..4) {
                        *slot = bytes
                            .get(control_offset_usize + 44 + index)
                            .copied()
                            .unwrap_or(0) as i8;
                    }
                }
                AptPlacement {
                    flags,
                    depth,
                    character,
                    matrix,
                    colour,
                    colour_add,
                }
            });
            // FrameLabel carries a name pointer plus a fixed two-word prefix:
            // `{ u32 name_ptr, u16 unused, u16 vft(Integer), u32 frame }`.
            let frame_label =
                (control_type == 2 && control_end - control_offset >= 12).then(|| {
                    let name_pointer =
                        u32_at(bytes, control_offset_usize + 4).unwrap_or(0) as usize;
                    AptFrameLabel {
                        name: read_cstr(bytes, base + name_pointer).unwrap_or_default(),
                        frame: u32_at(bytes, control_offset_usize + 8).unwrap_or(0),
                    }
                });
            controls.push(AptFrameControl {
                control_type,
                offset: control_offset,
                end: control_end,
                placement,
                frame_label,
            });
        }
        frames.push(AptFrame { index, controls });
    }
    let animation_file = u32_at(bytes, entry_offset + 12).filter(|value| *value != 0);
    let mut animation_version = None;
    let mut animation_size = None;
    let mut animation_entries = Vec::new();
    if let Some(file_offset) = animation_file {
        let base = file_offset as usize;
        if u32_at(bytes, base) == Some(0x0987_6543) {
            animation_version = u32_at(bytes, base + 4);
            animation_size = u32_at(bytes, base + 8);
            if let Some(count) = u32_at(bytes, base + 16).filter(|count| *count <= 1024) {
                for index in 0..count as usize {
                    let offset = base
                        .checked_add(20)
                        .and_then(|offset| offset.checked_add(index * 8))
                        .ok_or_else(|| {
                            ResourceError::Invalid("APT animation table is too large".to_string())
                        })?;
                    animation_entries.push(AptAnimationEntry {
                        offset: u32_at(bytes, offset).ok_or_else(|| {
                            ResourceError::Invalid("APT animation offset is unreadable".to_string())
                        })?,
                        count: u32_at(bytes, offset + 4).ok_or_else(|| {
                            ResourceError::Invalid("APT animation count is unreadable".to_string())
                        })?,
                    });
                }
            }
        }
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
        animation_file,
        animation_version,
        animation_size,
        animation_entries,
        frames,
        imported_character_count,
        anonymous_character_count,
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
    fn parses_frame_control_array() {
        // Layout: AptFrame is {nControls, apControls}; apControls points at an
        // array of control offsets. Regression guard for the earlier mistake of
        // treating the frame as {count, (offset, end)*}.
        // tag occupies [0,16), the movie header [16,72), so the frame record
        // must sit at 72 and every pointer below is relative to the tag.
        let mut bytes = b"Apt Data:74\x1a\x00\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&9u32.to_le_bytes()); // type: sprite
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nFrames
        bytes.extend_from_slice(&72u32.to_le_bytes()); // aFrames at tag+72
        bytes.resize(72, 0);
        // AptFrame { nControls = 2, apControls = 80 }
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&80u32.to_le_bytes());
        bytes.resize(80, 0);
        // control offset array: 88, 96
        bytes.extend_from_slice(&88u32.to_le_bytes());
        bytes.extend_from_slice(&96u32.to_le_bytes());
        bytes.resize(88, 0);
        // control 0: type 1 (DoAction)
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(96, 0);
        // control 1: type 3 (PlaceObject2), flags/depth/character/matrix/colour
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&38u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&23u32.to_le_bytes());
        for value in [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0] {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        bytes.extend_from_slice(&[255, 255, 255, 255, 0, 0, 0, 0]);
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.frames.len(), 1);
        assert_eq!(info.frames[0].controls.len(), 2);
        assert_eq!(info.frames[0].controls[0].control_type, 1);
        assert!(info.frames[0].controls[0].placement.is_none());
        let placement = info.frames[0].controls[1].placement.unwrap();
        assert_eq!(placement.flags, 38);
        assert_eq!(placement.depth, 1);
        assert_eq!(placement.character, 23);
        assert_eq!(placement.matrix, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
        assert_eq!(placement.colour, [255, 255, 255, 255]);
    }

    #[test]
    fn parses_frame_label_control() {
        // A FrameLabel payload is `{ u32 name_ptr, u16 unused, u16 vft, u32 frame }`
        // where name_ptr is relative to the Apt Data tag.
        let mut bytes = b"Apt Data:74\x1a\x00\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&9u32.to_le_bytes()); // type: sprite
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nFrames
        bytes.extend_from_slice(&72u32.to_le_bytes()); // aFrames at tag+72
        bytes.resize(72, 0);
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nControls
        bytes.extend_from_slice(&80u32.to_le_bytes()); // apControls
        bytes.resize(80, 0);
        bytes.extend_from_slice(&88u32.to_le_bytes()); // control 0 at tag+88
        bytes.resize(88, 0);
        bytes.extend_from_slice(&2u32.to_le_bytes()); // type 2: FrameLabel
        bytes.extend_from_slice(&104u32.to_le_bytes()); // name at tag+104
        bytes.extend_from_slice(&7u32.to_le_bytes()); // frame index
        bytes.resize(104, 0);
        bytes.extend_from_slice(b"intro");
        bytes.push(0);
        let info = parse(&bytes, 16).unwrap();
        let label = info.frames[0].controls[0]
            .frame_label
            .clone()
            .expect("frame label should decode");
        assert_eq!(label.name, "intro");
        assert_eq!(label.frame, 7);
        assert!(info.frames[0].controls[0].placement.is_none());
    }

    #[test]
    fn detects_fixed_up_bin_layout() {
        // A fix-up `.bin` stores `AptCharacter` at +8/+12: data bits and
        // m_pAnimFile. Here +12 points at an AptAnimFile magic, so the parser
        // must not treat it as a frame array.
        let mut bytes = b"Apt Data:74\x1a\x00\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&9u32.to_le_bytes()); // type: sprite
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&0x27fu32.to_le_bytes()); // data bits
        bytes.extend_from_slice(&72u32.to_le_bytes()); // m_pAnimFile at tag+72
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 character
        bytes.extend_from_slice(&40u32.to_le_bytes()); // character list at tag+40
        bytes.extend_from_slice(&800u32.to_le_bytes());
        bytes.extend_from_slice(&600u32.to_le_bytes());
        bytes.extend_from_slice(&33u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no imports
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no exports
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(40, 0);
        bytes.extend_from_slice(&32u32.to_le_bytes()); // ptr: character at tag+32
        bytes.resize(72, 0);
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.frame_count, 0, "fixed-up layout has no frame table");
        assert!(info.frames.is_empty());
        assert_eq!(info.character_count, 1);
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
    fn parses_shape_geometry() {
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
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&CHARACTER_SIGNATURE.to_le_bytes());
        for value in [-1.0f32, -2.0, 3.0, 4.0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&7u32.to_le_bytes());
        let info = parse(&bytes, 16).unwrap();
        assert_eq!(info.characters[0].type_name, "shape");
        assert_eq!(info.characters[0].bounds, Some([-1.0, -2.0, 3.0, 4.0]));
        assert_eq!(info.characters[0].geometry, Some(7));
    }

    #[test]
    fn rejects_non_movie() {
        assert!(parse(&[0u8; 64], 16).is_err());
    }
}
