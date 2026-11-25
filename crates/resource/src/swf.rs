//! SWF header recognition and bounded decompression.
//!
//! Only the container is handled here: no tags, ABC, or ActionScript execution.

use std::borrow::Cow;

use crate::Extracted;
use crate::ResourceError;

/// Compression scheme from the SWF signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Compression {
    /// FWS: verbatim bytes.
    None,
    /// CWS: zlib after the 8-byte header.
    Zlib,
    /// ZWS: LZMA after the 8-byte header (recognized, not extracted).
    Lzma,
}

/// Parsed SWF header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SwfResource<'a> {
    /// Original file bytes.
    pub data: &'a [u8],
    /// SWF version byte.
    pub version: u8,
    /// Compression scheme.
    pub compression: Compression,
    /// Declared uncompressed length, including the 8-byte header.
    pub declared_length: u32,
}

/// True when the bytes start with a known SWF signature.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    matches!(bytes.get(..3), Some(b"FWS" | b"CWS" | b"ZWS"))
}

/// Parse and validate an SWF header.
///
/// # Errors
/// Returns ResourceError::Invalid for short, truncated or inconsistent headers.
pub fn parse(bytes: &[u8]) -> Result<SwfResource<'_>, ResourceError> {
    if bytes.len() < 8 {
        return Err(ResourceError::Invalid(
            "SWF header is shorter than 8 bytes".to_string(),
        ));
    }
    let compression = match &bytes[..3] {
        b"FWS" => Compression::None,
        b"CWS" => Compression::Zlib,
        b"ZWS" => Compression::Lzma,
        _ => return Err(ResourceError::UnknownFormat),
    };
    let version = bytes[3];
    let declared_length = u32::from_le_bytes(bytes[4..8].try_into().expect("four bytes"));
    if declared_length < 8 {
        return Err(ResourceError::Invalid(
            "declared SWF length is below the 8-byte header".to_string(),
        ));
    }
    if compression == Compression::None && bytes.len() as u64 != u64::from(declared_length) {
        return Err(ResourceError::Invalid(format!(
            "FWS length {} does not match declared {}",
            bytes.len(),
            declared_length
        )));
    }
    if compression != Compression::None && bytes.len() < 8 {
        return Err(ResourceError::Invalid(
            "compressed SWF is missing its stored body".to_string(),
        ));
    }
    Ok(SwfResource {
        data: bytes,
        version,
        compression,
        declared_length,
    })
}

impl SwfResource<'_> {
    /// Extract the SWF as an uncompressed FWS byte stream.
    ///
    /// # Errors
    /// Returns ResourceError for LZMA compression, cap violations or corrupt zlib.
    pub fn extract(&self, max_output_len: usize) -> Result<Extracted<'_>, ResourceError> {
        match self.compression {
            Compression::None => Ok(Extracted::Bytes(Cow::Borrowed(self.data))),
            Compression::Zlib => inflate(self, max_output_len).map(Extracted::Bytes),
            Compression::Lzma => Err(ResourceError::Unsupported(
                "LZMA-compressed SWF (ZWS) extraction is not implemented".to_string(),
            )),
        }
    }
}

#[cfg(feature = "swf")]
fn inflate(
    resource: &SwfResource<'_>,
    max_output_len: usize,
) -> Result<Cow<'static, [u8]>, ResourceError> {
    use std::io::Read;

    let expected = usize::try_from(resource.declared_length - 8)
        .map_err(|_| ResourceError::Invalid("declared SWF body does not fit memory".to_string()))?;
    if expected > max_output_len {
        return Err(ResourceError::OutputTooLarge {
            declared: expected as u64,
            limit: max_output_len,
        });
    }
    let mut decoder = flate2::read::ZlibDecoder::new(&resource.data[8..]);
    let mut body = Vec::with_capacity(expected.min(1 << 20));
    let mut limited = decoder.by_ref().take(expected as u64 + 1);
    limited
        .read_to_end(&mut body)
        .map_err(|error| ResourceError::Invalid(format!("zlib: {error}")))?;
    if body.len() != expected {
        return Err(ResourceError::Invalid(format!(
            "decompressed body is {} bytes, declared {}",
            body.len(),
            expected
        )));
    }
    let mut output = Vec::with_capacity(8 + body.len());
    output.extend_from_slice(b"FWS");
    output.push(resource.version);
    output.extend_from_slice(&resource.declared_length.to_le_bytes());
    output.extend_from_slice(&body);
    Ok(Cow::Owned(output))
}

#[cfg(not(feature = "swf"))]
fn inflate(
    _resource: &SwfResource<'_>,
    _max_output_len: usize,
) -> Result<Cow<'static, [u8]>, ResourceError> {
    Err(ResourceError::FeatureDisabled {
        kind: crate::ResourceKind::Swf,
        feature: "swf",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fws(body: &[u8]) -> Vec<u8> {
        let declared = 8 + body.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FWS");
        bytes.push(9);
        bytes.extend_from_slice(&(declared as u32).to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn verbatim_fws_extraction_is_deterministic() {
        let bytes = fws(b"abcd");
        let resource = parse(&bytes).unwrap();
        let first = resource.extract(1024).unwrap();
        let second = resource.extract(1024).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, Extracted::Bytes(Cow::Borrowed(bytes.as_slice())));
    }

    #[test]
    fn bad_lengths_are_rejected() {
        assert!(parse(b"FWS\x09\x07\0\0\0").is_err());
        assert!(parse(b"FWS\x09\x09\0\0\0").is_err());
        assert!(parse(b"FWS").is_err());
    }

    #[test]
    fn zws_is_recognized_but_not_extracted() {
        let mut bytes = b"ZWS\x0d\x08\0\0\0".to_vec();
        bytes.extend_from_slice(b"x");
        let resource = parse(&bytes).unwrap();
        assert_eq!(resource.compression, Compression::Lzma);
        assert!(matches!(
            resource.extract(1024),
            Err(ResourceError::Unsupported(_))
        ));
    }

    #[cfg(feature = "swf")]
    #[test]
    fn zlib_cws_is_decoded_with_a_cap() {
        use std::io::Write;

        let body = b"hello swf body";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();
        let declared = 8 + body.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"CWS");
        bytes.push(9);
        bytes.extend_from_slice(&(declared as u32).to_le_bytes());
        bytes.extend_from_slice(&compressed);
        let resource = parse(&bytes).unwrap();
        let extracted = resource.extract(1024).unwrap();
        let Extracted::Bytes(output) = extracted else {
            panic!("expected bytes");
        };
        assert_eq!(&output[..3], b"FWS");
        assert_eq!(&output[8..], body);
        assert!(matches!(
            resource.extract(4),
            Err(ResourceError::OutputTooLarge { .. })
        ));
    }

    #[cfg(feature = "swf")]
    #[test]
    fn corrupt_zlib_is_rejected() {
        let mut bytes = b"CWS\x09\x0c\0\0\0".to_vec();
        bytes.extend_from_slice(b"not zlib");
        let resource = parse(&bytes).unwrap();
        assert!(matches!(
            resource.extract(1024),
            Err(ResourceError::Invalid(_))
        ));
    }
}
