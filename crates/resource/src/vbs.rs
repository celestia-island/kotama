//! Strict VBScript text decoding. No parsing, hosting, or execution.

use std::borrow::Cow;

use crate::Extracted;
use crate::ResourceError;

/// Detected source encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VbsEncoding {
    /// Plain UTF-8 without a BOM.
    Utf8,
    /// UTF-8 with a BOM.
    Utf8Bom,
    /// UTF-16 little endian with a BOM.
    Utf16Le,
    /// UTF-16 big endian with a BOM.
    Utf16Be,
}

impl VbsEncoding {
    /// Stable identifier for JSON output.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf8Bom => "utf-8-bom",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
        }
    }
}

/// Decoded VBScript source.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VbsResource {
    /// Source encoding.
    pub encoding: VbsEncoding,
    /// Decoded text without a BOM.
    pub text: String,
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String, ResourceError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ResourceError::Invalid(
            "UTF-16 source has an odd byte length".to_string(),
        ));
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16(&units)
        .map_err(|error| ResourceError::Invalid(format!("UTF-16 source: {error}")))
}

fn reject_nul(text: String) -> Result<String, ResourceError> {
    if text.contains('\0') {
        return Err(ResourceError::Invalid(
            "VBS source contains a NUL character".to_string(),
        ));
    }
    Ok(text)
}

/// Decode VBScript source with strict encoding rules.
///
/// # Errors
/// Returns ResourceError::Invalid for malformed encodings or NUL bytes.
pub fn parse(bytes: &[u8]) -> Result<VbsResource, ResourceError> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        let text = std::str::from_utf8(rest)
            .map_err(|error| ResourceError::Invalid(format!("UTF-8 source: {error}")))?;
        return Ok(VbsResource {
            encoding: VbsEncoding::Utf8Bom,
            text: reject_nul(text.to_string())?,
        });
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Ok(VbsResource {
            encoding: VbsEncoding::Utf16Le,
            text: reject_nul(decode_utf16(rest, true)?)?,
        });
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Ok(VbsResource {
            encoding: VbsEncoding::Utf16Be,
            text: reject_nul(decode_utf16(rest, false)?)?,
        });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ResourceError::Invalid(format!("UTF-8 source: {error}")))?;
    Ok(VbsResource {
        encoding: VbsEncoding::Utf8,
        text: reject_nul(text.to_string())?,
    })
}

impl VbsResource {
    /// Extract decoded UTF-8 text without a BOM.
    ///
    /// # Errors
    /// This decoder always succeeds after a successful parse.
    pub fn extract(&self) -> Result<Extracted<'_>, ResourceError> {
        Ok(Extracted::Text(Cow::Borrowed(self.text.as_str())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_utf8_and_bom_variants() {
        let plain = parse(b"WScript.Echo \"synthetic\"\r\n").unwrap();
        assert_eq!(plain.encoding, VbsEncoding::Utf8);
        assert_eq!(plain.text, "WScript.Echo \"synthetic\"\r\n");
        let bom = parse(b"\xEF\xBB\xBFWScript.Echo \"x\"").unwrap();
        assert_eq!(bom.encoding, VbsEncoding::Utf8Bom);
        assert_eq!(bom.text, "WScript.Echo \"x\"");
    }

    #[test]
    fn decodes_utf16_and_preserves_newlines() {
        let text = "WScript.Echo \"hi\"\r\n";
        let mut little = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            little.extend_from_slice(&unit.to_le_bytes());
        }
        let resource = parse(&little).unwrap();
        assert_eq!(resource.encoding, VbsEncoding::Utf16Le);
        assert_eq!(resource.text, text);

        let mut big = vec![0xFE, 0xFF];
        for unit in text.encode_utf16() {
            big.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(parse(&big).unwrap().text, text);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(parse(b"\xFF\xFEa").is_err());
        assert!(parse(b"\xEF\xBB\xBF\xFF").is_err());
        assert!(parse(b"a\0b").is_err());
    }
}
