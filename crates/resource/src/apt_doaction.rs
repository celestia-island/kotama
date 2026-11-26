//! APT/SWF action-stream decoder.
//!
//! A `DoAction` control points at an action block:
//!
//! ```text
//! u32 block_size;      // total bytes of header + streams
//! u32 constant_count;  // constant-pool entries referenced by the header
//! ... constant/name pointers ...
//! u32 0x98765432; u32 0x12345678;   // sentinel pair
//! <action stream(s)>                 // opcode + fixed-size operands
//! ```
//!
//! Streams are split by repeated sentinel pairs. Each stream is a sequence of
//! `opcode` + operands whose length depends on the opcode; the table below was
//! derived clean-room from four real `.apt` samples and validated by requiring
//! the walk to land exactly on the stream end. Opcodes with variable-length
//! operands (notably `DefineFunction`/`DefineFunction2`) stop the walk and are
//! reported, so callers never receive guessed bytes.

use crate::ResourceError;

/// Sentinel marking the end of an action-block header.
pub const SENTINEL: [u32; 2] = [0x9876_5432, 0x1234_5678];

/// One decoded action instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AptAction {
    /// Opcode byte.
    pub opcode: u8,
    /// Operand bytes (length depends on the opcode).
    pub operands: [u8; 6],
    /// Number of valid bytes in `operands`.
    pub operand_len: u8,
}

/// Result of decoding one action block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptActionBlock {
    /// Declared block size in bytes.
    pub size: u32,
    /// Constant-pool entry count from the header.
    pub constant_count: u32,
    /// Action streams (one per sentinel section).
    pub streams: Vec<Vec<AptAction>>,
    /// Opcode that stopped decoding, with the byte offset inside its stream.
    pub truncated_at: Option<(usize, usize, u8)>,
}

/// Operand length for opcodes whose operands are fixed-size.
///
/// `None` means the opcode is unknown or has variable-length operands; decoding
/// stops there rather than guessing.
#[must_use]
pub fn operand_len(opcode: u8) -> Option<u8> {
    Some(match opcode {
        // No operands.
        0x00 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x0E
        | 0x0F | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x17 | 0x18 | 0x1C | 0x1D | 0x20 | 0x21
        | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x30
        | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E
        | 0x3F | 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4A
        | 0x4B | 0x4C | 0x4D | 0x4E | 0x4F | 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56
        | 0x58 | 0x59 | 0x5A | 0x5B | 0x5C | 0x5D | 0x5E | 0x60 | 0x61 | 0x62 | 0x63 | 0x64
        | 0x65 | 0x66 | 0x67 | 0x69 | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77
        | 0x8F | 0x91 | 0x92 | 0x93 | 0x94 | 0x9A | 0x9E | 0x9F | 0xA0 => 0,
        // One operand byte.
        0x2D | 0x81 | 0x83 | 0x8A | 0x8B | 0x8C | 0x96 | 0xA2 | 0xA3 | 0xA4 | 0xA5 | 0xA6
        | 0xA7 | 0xAE | 0xAF | 0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xB5 | 0xB8 | 0xB9 | 0xBD | 0xBE
        | 0xBF | 0xC0 | 0xC1 => 1,
        // Two operand bytes.
        0x9D | 0xB6 | 0xC2 | 0xC3 => 2,
        // Four operand bytes.
        0xB4 | 0xB7 => 4,
        // StoreRegister: register byte + 4-byte value.
        0x87 => 5,
        // BranchAlways: 6-byte operand in the observed samples.
        0x99 => 6,
        // Everything else (incl. DefineFunction/DefineFunction2) is variable.
        _ => return None,
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Decode one action block at `offset`.
///
/// # Errors
/// Returns `ResourceError::Invalid` when the header or sentinel belongs outside
/// the buffer.
pub fn parse(bytes: &[u8], offset: usize) -> Result<AptActionBlock, ResourceError> {
    let size = u32_at(bytes, offset)
        .ok_or_else(|| ResourceError::Invalid("APT action block size is unreadable".to_string()))?;
    let constant_count = u32_at(bytes, offset + 4)
        .ok_or_else(|| ResourceError::Invalid("APT action count is unreadable".to_string()))?;
    let end = offset
        .checked_add(size as usize)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| {
            ResourceError::Invalid("APT action block is outside the file".to_string())
        })?;

    // Locate sentinel pairs; each marks the start of a stream.
    let mut marks = Vec::new();
    let needle = {
        let mut raw = [0u8; 8];
        for (slot, value) in SENTINEL.iter().enumerate() {
            raw[slot * 4..slot * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw
    };
    let mut cursor = offset;
    while cursor + needle.len() <= end {
        if bytes[cursor..cursor + needle.len()] == needle {
            marks.push(cursor + needle.len());
            cursor += needle.len();
        } else {
            cursor += 1;
        }
    }

    let mut streams = Vec::new();
    let mut truncated_at = None;
    for (index, start) in marks.iter().enumerate() {
        let stop = marks.get(index + 1).copied().unwrap_or(end);
        let mut stream = Vec::new();
        let mut pos = *start;
        while pos < stop {
            let opcode = bytes[pos];
            let Some(len) = operand_len(opcode) else {
                truncated_at = Some((index, pos - start, opcode));
                break;
            };
            let len = len as usize;
            if pos + 1 + len > stop {
                truncated_at = Some((index, pos - start, opcode));
                break;
            }
            let mut operands = [0u8; 6];
            operands[..len].copy_from_slice(&bytes[pos + 1..pos + 1 + len]);
            stream.push(AptAction {
                opcode,
                operands,
                operand_len: len as u8,
            });
            pos += 1 + len;
        }
        streams.push(stream);
    }

    Ok(AptActionBlock {
        size,
        constant_count,
        streams,
        truncated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(stream: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Header: u32 size, u32 count, 16 bytes of pointers, then the 8-byte sentinel.
        bytes.extend_from_slice(&((32 + stream.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&SENTINEL[0].to_le_bytes());
        bytes.extend_from_slice(&SENTINEL[1].to_le_bytes());
        bytes.extend_from_slice(stream);
        bytes
    }

    #[test]
    fn decodes_fixed_length_stream() {
        // PushByte 2, SetMember, StoreRegister reg0 value1, End
        let stream = [0xB9, 0x02, 0x4F, 0x87, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let bytes = block(&stream);
        let info = parse(&bytes, 0).unwrap();
        assert_eq!(info.streams.len(), 1);
        let ops: Vec<u8> = info.streams[0].iter().map(|a| a.opcode).collect();
        assert_eq!(ops, vec![0xB9, 0x4F, 0x87, 0x00]);
        assert_eq!(info.streams[0][0].operand_len, 1);
        assert_eq!(info.streams[0][2].operand_len, 5);
        assert_eq!(info.truncated_at, None);
    }

    #[test]
    fn stops_at_variable_length_opcode() {
        let stream = [0x8E, 0x00, 0x00, 0x00];
        let bytes = block(&stream);
        let info = parse(&bytes, 0).unwrap();
        assert_eq!(info.truncated_at, Some((0, 0, 0x8E)));
        assert!(info.streams[0].is_empty());
    }
}
