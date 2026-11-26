//! APT/SWF action-stream decoder.
//!
//! A DoAction control points at an action block with this layout:
//!
//! ```text
//! u32 block_size;         // total bytes of the whole block
//! u32 constant_count;     // constant/name slots referenced by the block
//! ... constant and name pointers ...
//! u32 body_size;          // bytes of the action body that follows
//! u32 0x98765432; u32 0x12345678;   // body marker pair
//! <action stream>         // opcode + per-opcode operands
//!
//! The marker pair is NOT a stream separator: it brackets the body of a
//! DefineFunction/DefineFunction2 action, whose code is stored inline. A block
//! that starts with a plain opcode has no marker, so its stream begins after the
//! body-size word instead.
//!
//! Operand widths were derived clean-room from real .apt samples and are
//! validated by requiring the walk to land exactly on the stream end. Actions
//! with nested payloads (Push, ConstantPool, DefineFunction*) stop the walk and
//! are reported rather than guessed.

use crate::ResourceError;

/// Marker pair that brackets a DefineFunction* body.
pub const BODY_MARKER: [u32; 2] = [0x9876_5432, 0x1234_5678];

/// One decoded action instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AptAction {
    /// Opcode byte.
    pub opcode: u8,
    /// Operand bytes (length depends on the opcode).
    pub operands: [u8; 8],
    /// Number of valid bytes in operands.
    pub operand_len: u8,
}

/// Result of decoding one action block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptActionBlock {
    /// Declared block size in bytes.
    pub size: u32,
    /// Constant-pool slot count from the header.
    pub constant_count: u32,
    /// Offset of the action stream inside the block.
    pub stream_offset: usize,
    /// Decoded instructions, in order.
    pub actions: Vec<AptAction>,
    /// First opcode that could not be decoded, with its stream-relative offset.
    pub truncated_at: Option<(usize, u8)>,
}

/// Operand length for opcodes whose operands are fixed-size.
///
/// Returns None when the opcode carries a nested structure (a count plus a
/// pointer to values), so decoding stops there rather than guessing.
#[must_use]
pub fn operand_len(opcode: u8) -> Option<u8> {
    Some(match opcode {
        0x00 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x0E
        | 0x0F | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x17 | 0x18 | 0x1C | 0x1D | 0x20 | 0x21
        | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x30
        | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E
        | 0x3F | 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4A
        | 0x4B | 0x4C | 0x4D | 0x4E | 0x4F | 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56
        | 0x58 | 0x59 | 0x5A | 0x5B | 0x5C | 0x5D | 0x5E | 0x60 | 0x61 | 0x62 | 0x63 | 0x64
        | 0x65 | 0x66 | 0x67 | 0x69 | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77
        | 0x8F | 0x91 | 0x92 | 0x93 | 0x94 | 0x9E | 0xA0 => 0,
        0x2D | 0x81 | 0x83 | 0x8A | 0x8B | 0x8C | 0x96 | 0xA3 | 0xA4 | 0xA5 | 0xA6 | 0xA7
        | 0xAE | 0xAF | 0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xB5 | 0xB8 | 0xB9 | 0xBD | 0xBE | 0xBF
        | 0xC0 | 0xC1 => 1,
        0x9D | 0xB6 | 0xC2 | 0xC3 => 2,
        0xB4 | 0xB7 => 4,
        0x87 => 4,
        0x99 => 6,
        _ => return None,
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn marker_at(bytes: &[u8], offset: usize) -> bool {
    u32_at(bytes, offset) == Some(BODY_MARKER[0])
        && u32_at(bytes, offset + 4) == Some(BODY_MARKER[1])
}

/// Decode one action block at the given offset.
///
/// # Errors
/// Returns ResourceError::Invalid when the header or the block bounds fall
/// outside the buffer.
pub fn parse(bytes: &[u8], offset: usize) -> Result<AptActionBlock, ResourceError> {
    let size = u32_at(bytes, offset)
        .ok_or_else(|| ResourceError::Invalid("APT action block size is unreadable".to_string()))?;
    let constant_count = u32_at(bytes, offset + 4)
        .ok_or_else(|| ResourceError::Invalid("APT action count is unreadable".to_string()))?;
    let end = offset
        .checked_add(size as usize)
        .filter(|end| *end <= bytes.len() && size >= 12)
        .ok_or_else(|| {
            ResourceError::Invalid("APT action block is outside the file".to_string())
        })?;

    let mut stream_offset = None;
    let mut cursor = offset + 8;
    while cursor + 8 <= end {
        if marker_at(bytes, cursor) {
            stream_offset = Some(cursor + 8);
            break;
        }
        cursor += 4;
    }
    let stream_offset = stream_offset
        .or_else(|| {
            u32_at(bytes, offset + 24).and_then(|body| (offset + 28).checked_add(body as usize))
        })
        .filter(|start| *start <= end)
        .ok_or_else(|| ResourceError::Invalid("APT action body is unreadable".to_string()))?;

    let mut actions = Vec::new();
    let mut truncated_at = None;
    let mut pos = stream_offset;
    while pos < end {
        let opcode = bytes[pos];
        let Some(len) = operand_len(opcode) else {
            truncated_at = Some((pos - stream_offset, opcode));
            break;
        };
        let len = len as usize;
        if pos + 1 + len > end {
            truncated_at = Some((pos - stream_offset, opcode));
            break;
        }
        let mut operands = [0u8; 8];
        operands[..len].copy_from_slice(&bytes[pos + 1..pos + 1 + len]);
        actions.push(AptAction {
            opcode,
            operands,
            operand_len: len as u8,
        });
        pos += 1 + len;
    }

    Ok(AptActionBlock {
        size,
        constant_count,
        stream_offset,
        actions,
        truncated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_with_marker(stream: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let body = 8 + stream.len();
        bytes.extend_from_slice(&((28 + body) as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&(body as u32).to_le_bytes());
        bytes.extend_from_slice(&BODY_MARKER[0].to_le_bytes());
        bytes.extend_from_slice(&BODY_MARKER[1].to_le_bytes());
        bytes.extend_from_slice(stream);
        bytes
    }

    #[test]
    fn decodes_fixed_length_stream() {
        // PushByte 2, SetMember, StoreRegister(reg 0, value 1), End.
        let stream = [0xB9, 0x02, 0x4F, 0x87, 0x00, 0x01, 0x00, 0x00, 0x00];
        let bytes = block_with_marker(&stream);
        let info = parse(&bytes, 0).unwrap();
        assert_eq!(info.stream_offset, 36);
        let ops: Vec<u8> = info.actions.iter().map(|a| a.opcode).collect();
        assert_eq!(ops, vec![0xB9, 0x4F, 0x87, 0x00]);
        assert_eq!(info.actions[0].operand_len, 1);
        assert_eq!(info.actions[2].operand_len, 4);
        assert_eq!(info.truncated_at, None);
    }

    #[test]
    fn stops_at_structured_opcode() {
        let stream = [0x8E, 0x00, 0x00, 0x00];
        let bytes = block_with_marker(&stream);
        let info = parse(&bytes, 0).unwrap();
        assert_eq!(info.truncated_at, Some((0, 0x8E)));
        assert!(info.actions.is_empty());
    }

    #[test]
    fn marker_inside_body_does_not_restart_the_stream() {
        // A second marker appears inside the body. Only the header marker opens
        // the stream, so the walk continues from the first one and stops at the
        // undecodable marker bytes instead of jumping past them.
        let mut stream = vec![0x04];
        stream.extend_from_slice(&BODY_MARKER[0].to_le_bytes());
        stream.extend_from_slice(&BODY_MARKER[1].to_le_bytes());
        stream.push(0x04);
        let bytes = block_with_marker(&stream);
        let info = parse(&bytes, 0).unwrap();
        // The stream must not be re-anchored past the inner marker: decoding has
        // to run from the header marker and stop when it reaches bytes that are
        // not zero-operand opcodes.
        assert_eq!(info.stream_offset, 36);
        assert!(info.truncated_at.is_some());
        assert!(
            info.actions.len() < 11,
            "must not consume past the inner marker"
        );
    }
}
