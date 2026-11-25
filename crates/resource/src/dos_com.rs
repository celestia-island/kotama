//! DOS COM recognition and verbatim extraction. No execution or disassembly.

use std::borrow::Cow;

use crate::Extracted;
use crate::ResourceError;

/// Parsed DOS COM image.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DosComResource<'a> {
    /// Original image bytes.
    pub data: &'a [u8],
}

/// Standard COM load address.
pub const LOAD_ADDRESS: u32 = 0x100;
/// Standard COM entry address.
pub const ENTRY_ADDRESS: u32 = 0x100;

/// Validate a DOS COM image.
///
/// # Errors
/// Returns ResourceError::Invalid for an empty image.
pub fn parse(bytes: &[u8]) -> Result<DosComResource<'_>, ResourceError> {
    if bytes.is_empty() {
        return Err(ResourceError::Invalid("DOS COM image is empty".to_string()));
    }
    Ok(DosComResource { data: bytes })
}

impl DosComResource<'_> {
    /// Original image size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Extract the original bytes verbatim, without synthesizing a PSP.
    ///
    /// # Errors
    /// This parser always succeeds after a successful parse.
    pub fn extract(&self) -> Result<Extracted<'_>, ResourceError> {
        Ok(Extracted::Bytes(Cow::Borrowed(self.data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_verbatim_and_rejects_empty() {
        let bytes = [0xB8, 0x00, 0x4C, 0xCD, 0x21];
        let resource = parse(&bytes).unwrap();
        assert_eq!(resource.size(), 5);
        assert_eq!(LOAD_ADDRESS, 0x100);
        assert_eq!(ENTRY_ADDRESS, 0x100);
        assert_eq!(
            resource.extract().unwrap(),
            Extracted::Bytes(Cow::Borrowed(bytes.as_slice()))
        );
        assert!(parse(&[]).is_err());
    }
}
