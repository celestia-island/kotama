//! Deterministic, I/O-free identification/parsing/extraction for widely used,
//! vendor-neutral container and image formats.
//!
//! Only the standard library is used in the core. Format parsers are feature-gated so
//! downstream consumers can opt out of any parser and its dependencies. Parsers tied to a
//! specific engine or studio deliberately do not live here; see the examples directory.

use std::borrow::Cow;
use std::fmt;

pub mod dds;
pub mod dos_com;
pub mod swf;
pub mod tga;
pub mod vbs;

/// A recognized resource format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceKind {
    /// Shockwave Flash (FWS/CWS/ZWS header).
    Swf,
    /// VBScript text source.
    Vbs,
    /// DOS COM image.
    DosCom,
    /// DDS surface.
    Dds,
    /// TGA image header.
    Tga,
}

impl ResourceKind {
    /// Stable lowercase identifier used by the CLI and manifests.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Swf => "swf",
            Self::Vbs => "vbs",
            Self::DosCom => "dos-com",
            Self::Dds => "dds",
            Self::Tga => "tga",
        }
    }

    /// Parse a CLI kind name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "swf" => Some(Self::Swf),
            "vbs" => Some(Self::Vbs),
            "dos-com" | "com" => Some(Self::DosCom),
            "dds" => Some(Self::Dds),
            "tga" => Some(Self::Tga),
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
            Self::Dds => "dds",
            Self::Tga => "tga",
        }
    }

    /// True when the parser was compiled in.
    #[must_use]
    pub const fn enabled(self) -> bool {
        match self {
            Self::Swf => cfg!(feature = "swf"),
            Self::Vbs => cfg!(feature = "vbs"),
            Self::DosCom => cfg!(feature = "dos-com"),
            Self::Dds => cfg!(feature = "dds"),
            Self::Tga => cfg!(feature = "tga"),
        }
    }
}

/// How a resource was recognized.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetectionBasis {
    /// Recognized from file contents (format magic).
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
    /// DDS surface header.
    Dds(dds::DdsInfo),
    /// TGA image header.
    Tga(tga::TgaInfo),
}

impl Resource<'_> {
    /// Format of this resource.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Swf(_) => ResourceKind::Swf,
            Self::Vbs(_) => ResourceKind::Vbs,
            Self::DosCom(_) => ResourceKind::DosCom,
            Self::Dds(_) => ResourceKind::Dds,
            Self::Tga(_) => ResourceKind::Tga,
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
            Self::Dds(_) => Err(ResourceError::Unsupported(
                "DDS is a surface container; inspect header".to_string(),
            )),
            Self::Tga(_) => Err(ResourceError::Unsupported(
                "TGA is an image container; inspect header".to_string(),
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
    if dds::has_magic(bytes) {
        return Some(Identification {
            kind: ResourceKind::Dds,
            basis: DetectionBasis::Magic,
            enabled: ResourceKind::Dds.enabled(),
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
    if extension_matches(extension, "tga") {
        return Some(Identification {
            kind: ResourceKind::Tga,
            basis: DetectionBasis::Extension,
            enabled: ResourceKind::Tga.enabled(),
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
        ResourceKind::Dds => dds::parse(bytes).map(Resource::Dds),
        ResourceKind::Tga => tga::parse(bytes).map(Resource::Tga),
    }
}
