//! EA FESL message framing and key/value body decoding.
//!
//! EA's federated login service (FESL) frames every message as:
//!
//! ```text
//! byte[4]  component id      e.g. "fsys", "pnow", "acct"
//! u32be    flags             high bit 0x8000_0000 = reply, low byte = sequence
//! u32be    length            total bytes including this 12-byte header
//! byte[]   body              "key=value" lines, NUL-terminated
//! ```
//!
//! Keys encode structure by punctuation:
//!
//! - `a.b` — nested field `b` under `a`;
//! - `a.[]` — element count for the list at `a`, whose members are `a.0`, `a.1`, ...
//! - `a.{k}` — mapping entry `k` under `a`.
//!
//! Values are URL-quoted only for `=` (and historically `:`), so decoding must
//! unquote without treating `+` as a space.

use crate::ResourceError;

/// One decoded FESL message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeslMessage {
    /// Component id, e.g. `fsys`.
    pub component: String,
    /// Raw flags word.
    pub flags: u32,
    /// Declared total length including the header.
    pub length: u32,
    /// Decoded key/value pairs, unflattened into `.`-joined keys with lists
    /// restored as `key.0`, `key.1`, ... entries.
    pub fields: Vec<(String, String)>,
}

impl FeslMessage {
    /// True when the high flag bit marks this as a reply.
    #[must_use]
    pub const fn is_reply(&self) -> bool {
        self.flags & 0x8000_0000 != 0
    }

    /// Sequence number carried in the low flag byte.
    #[must_use]
    pub const fn sequence(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }

    /// Look up a field by its flattened key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// Parse every FESL message contained in `bytes`.
///
/// # Errors
/// Returns `ResourceError::Invalid` on a truncated header, a length field that
/// cannot be satisfied, or a body without a NUL terminator.
pub fn parse_messages(bytes: &[u8]) -> Result<Vec<FeslMessage>, ResourceError> {
    let mut messages = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let header_end = cursor
            .checked_add(12)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| ResourceError::Invalid("FESL header is truncated".to_string()))?;
        let component = String::from_utf8_lossy(&bytes[cursor..cursor + 4]).into_owned();
        let flags = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]);
        let length = u32::from_be_bytes([
            bytes[cursor + 8],
            bytes[cursor + 9],
            bytes[cursor + 10],
            bytes[cursor + 11],
        ]);
        let total = usize::try_from(length)
            .map_err(|_| ResourceError::Invalid("FESL length overflows".to_string()))?;
        let end = cursor
            .checked_add(total)
            .filter(|end| *end <= bytes.len() && total >= 12)
            .ok_or_else(|| ResourceError::Invalid("FESL length exceeds the buffer".to_string()))?;
        let body = &bytes[header_end..end];
        let body = body
            .strip_suffix(&[0])
            .ok_or_else(|| ResourceError::Invalid("FESL body lacks a terminator".to_string()))?;
        messages.push(FeslMessage {
            component,
            flags,
            length,
            fields: parse_body(body)?,
        });
        cursor = end;
    }
    Ok(messages)
}

fn parse_body(body: &[u8]) -> Result<Vec<(String, String)>, ResourceError> {
    let text = String::from_utf8_lossy(body);
    let mut fields = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ResourceError::Invalid("FESL field lacks '='".to_string()))?;
        fields.push((key.to_string(), unquote(value)));
    }
    // Restore list membership: "a.[]=3" plus "a.0".."a.2" already share a prefix,
    // so nothing to rewrite; only the count entry carries the marker.
    Ok(fields)
}

/// Undo the selective URL quoting used inside FESL values.
///
/// Only `%3d`/`%3D` (and historically `%3a`) appear; `+` stays a plus sign.
#[must_use]
pub fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hi = hex_digit(bytes[index + 1]);
            let lo = hex_digit(bytes[index + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi * 16 + lo);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(component: &[u8; 4], flags: u32, body: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(component);
        bytes.extend_from_slice(&flags.to_be_bytes());
        let total = (12 + body.len() + 1) as u32;
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(body.as_bytes());
        bytes.push(0);
        bytes
    }

    #[test]
    fn parses_hello_request() {
        let bytes = frame(b"fsys", 0, "TXN=Hello\nclientType=PC\n");
        let messages = parse_messages(&bytes).unwrap();
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.component, "fsys");
        assert!(!message.is_reply());
        assert_eq!(message.sequence(), 0);
        assert_eq!(message.get("TXN"), Some("Hello"));
        assert_eq!(message.get("clientType"), Some("PC"));
    }

    #[test]
    fn parses_reply_with_lists_and_sequence() {
        let body = "TXN=NuLogin\npersonas.[]=2\npersonas.0=alpha\npersonas.1=beta\n";
        let bytes = frame(b"acct", 0x8000_0003, body);
        let messages = parse_messages(&bytes).unwrap();
        let message = &messages[0];
        assert!(message.is_reply());
        assert_eq!(message.sequence(), 3);
        assert_eq!(message.get("personas.[]"), Some("2"));
        assert_eq!(message.get("personas.1"), Some("beta"));
    }

    #[test]
    fn unquotes_only_percent_escapes() {
        assert_eq!(unquote("a%3db"), "a=b");
        assert_eq!(unquote("a%3Ab"), "a:b");
        assert_eq!(unquote("a+b"), "a+b");
        assert_eq!(unquote("100%"), "100%");
    }
}
