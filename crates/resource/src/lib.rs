//! Deterministic, I/O-free identification/parsing/extraction for non-image resources.
//!
//! Only the standard library is used in the core. Format parsers are feature-gated so
//! downstream consumers can opt out of any parser and its dependencies.

use std::borrow::Cow;
use std::fmt;

pub mod apt;
pub mod big;
pub mod csf;
pub mod dos_com;
pub mod swf;
pub mod vbs;
pub mod w3d;

/// A recognized resource format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceKind {
    /// Shockwave Flash (FWS/CWS/ZWS header).
    Swf,
    /// VBScript text source.
    Vbs,
    /// DOS COM image.
    DosCom,
    /// EA BIG archive container (BIGF/BIG4).
    Big,
    /// W3D chunk container.
    W3d,
    /// APT constant file.
    AptConst,
    /// CSF string table.
    Csf,
}

impl ResourceKind {
    /// Stable lowercase identifier used by the CLI and manifests.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Swf => "swf",
            Self::Vbs => "vbs",
            Self::DosCom => "dos-com",
            Self::Big => "big",
            Self::W3d => "w3d",
            Self::AptConst => "apt-const",
            Self::Csf => "csf",
        }
    }

    /// Parse a CLI kind name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "swf" => Some(Self::Swf),
            "vbs" => Some(Self::Vbs),
            "dos-com" | "com" => Some(Self::DosCom),
            "big" | "bigf" | "big4" => Some(Self::Big),
            "w3d" => Some(Self::W3d),
            "apt-const" => Some(Self::AptConst),
            "csf" => Some(Self::Csf),
            _ => None,
        }
    }

    /// Cargo feature that enables this parser.
    #[must_use]
    pub const fn feature(self) -> &'static str {
        match self {
            Self::Swf => "swf",
            Self::Vbs => "vbs",
            Self::DosCom => "dos-com",
            Self::Big => "big",
            Self::W3d => "w3d",
            Self::AptConst => "apt-const",
            Self::Csf => "csf",
        }
    }

    /// True when the parser was compiled in.
    #[must_use]
    pub const fn enabled(self) -> bool {
        match self {
            Self::Swf => cfg!(feature = "swf"),
            Self::Vbs => cfg!(feature = "vbs"),
            Self::DosCom => cfg!(feature = "dos-com"),
            Self::Big => cfg!(feature = "big"),
            Self::W3d => cfg!(feature = "w3d"),
            Self::AptConst => cfg!(feature = "apt-const"),
            Self::Csf => cfg!(feature = "csf"),
        }
    }
}

/// How a resource was recognized.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetectionBasis {
    /// Recognized from file contents (SWF magic).
    Magic,
    /// Recognized from a filename extension hint.
    Extension,
}

/// Identification result, including whether the matching parser is compiled in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identification {
    /// Recognized format.
    pub kind: ResourceKind,
    /// Why it was recognized.
    pub basis: DetectionBasis,
    /// Whether parsing can succeed in this build.
    pub enabled: bool,
}

/// A parsed resource.
#[derive(Debug)]
pub enum Resource<'a> {
    /// SWF header and body.
    Swf(swf::SwfResource<'a>),
    /// VBScript text source.
    Vbs(vbs::VbsResource),
    /// DOS COM image.
    DosCom(dos_com::DosComResource<'a>),
    /// EA BIG archive container.
    Big(big::BigArchive<'a>),
    /// W3D chunk container.
    W3d(w3d::W3dFile<'a>),
    /// APT constant file.
    AptConst(apt::AptConstFile),
    /// CSF string table.
    Csf(csf::CsfFile),
}

impl Resource<'_> {
    /// Format of this resource.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Swf(_) => ResourceKind::Swf,
            Self::Vbs(_) => ResourceKind::Vbs,
            Self::DosCom(_) => ResourceKind::DosCom,
            Self::Big(_) => ResourceKind::Big,
            Self::W3d(_) => ResourceKind::W3d,
            Self::AptConst(_) => ResourceKind::AptConst,
            Self::Csf(_) => ResourceKind::Csf,
        }
    }
}

/// Extracted payload.
#[derive(Debug, PartialEq, Eq)]
pub enum Extracted<'a> {
    /// Binary payload, possibly decompressed into owned storage.
    Bytes(Cow<'a, [u8]>),
    /// Decoded text without a BOM.
    Text(Cow<'a, str>),
}

impl Resource<'_> {
    /// Extract the resource, bounded by the max_output_len byte cap.
    ///
    /// # Errors
    /// Returns a parse/unsupported/limit error rather than a partial payload.
    pub fn extract(&self, max_output_len: usize) -> Result<Extracted<'_>, ResourceError> {
        match self {
            Self::Swf(resource) => resource.extract(max_output_len),
            Self::Vbs(resource) => resource.extract(),
            Self::DosCom(resource) => resource.extract(),
            Self::Big(_) => Err(ResourceError::Unsupported(
                "BIG archive is a container; select an entry".to_string(),
            )),
            Self::W3d(_) => Err(ResourceError::Unsupported(
                "W3D is a chunk container; select a chunk".to_string(),
            )),
            Self::AptConst(_) => Err(ResourceError::Unsupported(
                "APT constants are a table; inspect entries".to_string(),
            )),
            Self::Csf(_) => Err(ResourceError::Unsupported(
                "CSF is a string table; inspect labels".to_string(),
            )),
        }
    }
}

/// Parsing and extraction errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Bytes/extensions did not identify a supported format.
    UnknownFormat,
    /// The format was recognized but its parser feature is not compiled in.
    FeatureDisabled {
        /// The recognized format.
        kind: ResourceKind,
        /// Required Cargo feature.
        feature: &'static str,
    },
    /// The resource is malformed.
    Invalid(String),
    /// The recognized format is not extractable.
    Unsupported(String),
    /// Declared output exceeds the caller's cap.
    OutputTooLarge {
        /// Declared output size.
        declared: u64,
        /// Caller-provided cap.
        limit: usize,
    },
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat => f.write_str("unknown resource format"),
            Self::FeatureDisabled { kind, feature } => write!(
                f,
                "{} parser is disabled; rebuild with feature {}",
                kind.short(),
                feature
            ),
            Self::Invalid(message) => write!(f, "invalid resource: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported resource: {message}"),
            Self::OutputTooLarge { declared, limit } => write!(
                f,
                "declared output {declared} exceeds the {limit}-byte limit"
            ),
        }
    }
}

impl std::error::Error for ResourceError {}

fn extension_matches(extension: Option<&str>, wanted: &str) -> bool {
    extension.is_some_and(|extension| {
        extension
            .trim_start_matches('.')
            .eq_ignore_ascii_case(wanted)
    })
}

/// Identify a resource from contents and an optional extension hint.
#[must_use]
pub fn identify(bytes: &[u8], extension: Option<&str>) -> Option<Identification> {
    if csf::has_magic(bytes) {
        return Some(Identification {
            kind: ResourceKind::Csf,
            basis: DetectionBasis::Magic,
            enabled: ResourceKind::Csf.enabled(),
        });
    }
    if bytes.get(..17) == Some(b"Apt constant file".as_slice())
        || bytes.get(16..33) == Some(b"Apt constant file".as_slice())
    {
        return Some(Identification {
            kind: ResourceKind::AptConst,
            basis: DetectionBasis::Magic,
            enabled: ResourceKind::AptConst.enabled(),
        });
    }
    if big::has_magic(bytes) {
        return Some(Identification {
            kind: ResourceKind::Big,
            basis: DetectionBasis::Magic,
            enabled: ResourceKind::Big.enabled(),
        });
    }
    if swf::has_magic(bytes) {
        return Some(Identification {
            kind: ResourceKind::Swf,
            basis: DetectionBasis::Magic,
            enabled: ResourceKind::Swf.enabled(),
        });
    }
    if extension_matches(extension, "vbs") {
        return Some(Identification {
            kind: ResourceKind::Vbs,
            basis: DetectionBasis::Extension,
            enabled: ResourceKind::Vbs.enabled(),
        });
    }
    if extension_matches(extension, "w3d") {
        return Some(Identification {
            kind: ResourceKind::W3d,
            basis: DetectionBasis::Extension,
            enabled: ResourceKind::W3d.enabled(),
        });
    }
    if extension_matches(extension, "com") {
        return Some(Identification {
            kind: ResourceKind::DosCom,
            basis: DetectionBasis::Extension,
            enabled: ResourceKind::DosCom.enabled(),
        });
    }
    None
}

/// Parse a resource, auto-detecting from magic/extension.
///
/// # Errors
/// Returns ResourceError for unknown formats, disabled features or malformed input.
pub fn parse<'a>(bytes: &'a [u8], extension: Option<&str>) -> Result<Resource<'a>, ResourceError> {
    let identification = identify(bytes, extension).ok_or(ResourceError::UnknownFormat)?;
    parse_as(bytes, identification.kind)
}

/// Parse a resource with an explicit kind, still validating the bytes.
///
/// # Errors
/// Returns ResourceError for disabled features or malformed input.
pub fn parse_as<'a>(bytes: &'a [u8], kind: ResourceKind) -> Result<Resource<'a>, ResourceError> {
    if !kind.enabled() {
        return Err(ResourceError::FeatureDisabled {
            kind,
            feature: kind.feature(),
        });
    }
    match kind {
        ResourceKind::Swf => swf::parse(bytes).map(Resource::Swf),
        ResourceKind::Vbs => vbs::parse(bytes).map(Resource::Vbs),
        ResourceKind::DosCom => dos_com::parse(bytes).map(Resource::DosCom),
        ResourceKind::Big => big::parse(bytes).map(Resource::Big),
        ResourceKind::W3d => w3d::parse(bytes).map(Resource::W3d),
        ResourceKind::AptConst => apt::parse(bytes).map(Resource::AptConst),
        ResourceKind::Csf => csf::parse(bytes).map(Resource::Csf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swf_magic_wins_over_a_misleading_extension() {
        let identification = identify(b"FWS\x0a\x08\0\0\0", Some("vbs")).unwrap();
        assert_eq!(identification.kind, ResourceKind::Swf);
        assert_eq!(identification.basis, DetectionBasis::Magic);
        assert_eq!(identification.enabled, cfg!(feature = "swf"));
    }

    #[test]
    fn extension_detection_is_case_insensitive_and_dot_tolerant() {
        assert_eq!(
            identify(b"x", Some(".VBS")).unwrap().kind,
            ResourceKind::Vbs
        );
        assert_eq!(
            identify(b"x", Some("COM")).unwrap().kind,
            ResourceKind::DosCom
        );
        assert!(identify(b"x", Some("vbe")).is_none());
    }

    #[test]
    fn disabled_features_are_reported_explicitly() {
        if ResourceKind::Swf.enabled() {
            return;
        }
        let error = parse(b"FWS\x0a\x08\0\0\0", None).unwrap_err();
        assert!(matches!(
            error,
            ResourceError::FeatureDisabled {
                kind: ResourceKind::Swf,
                ..
            }
        ));
    }
}
