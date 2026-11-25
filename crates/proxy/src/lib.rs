//! Deterministic, auditable DLL forwarding-mirror generation.
//!
//! This crate only plans and renders artifacts. It never changes the input DLL,
//! guesses function ABIs, or claims to install hooks.

use serde::Serialize;
use sha2::{Digest, Sha256};

use kotama_image::pe_export::{PeExportTable, PeExportTarget, PeForwardTarget};

/// Errors produced while planning or rendering a mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyError(pub String);

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyError {}

/// Mirror module names. The backing DLL is a user-managed renamed original.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MirrorOptions {
    /// Output mirror DLL basename, normally mirror.dll.
    pub library: String,
    /// Backing original DLL basename used by forwarders.
    pub backing: String,
}

/// One auditable export decision.
#[derive(Serialize)]
pub struct MirrorExport {
    /// Public ordinal.
    pub ordinal: u16,
    /// Public names in deterministic order; empty means ordinal-only.
    pub names: Vec<String>,
    /// The .def target: address exports go through the backing DLL, while
    /// original forwarders retain their original target.
    pub forwarded_to: String,
}

/// The deterministic manifest written beside proxy.def.
#[derive(Serialize)]
pub struct MirrorManifest {
    /// Input basename, never a machine-specific absolute path.
    pub input: String,
    /// Input size in bytes.
    pub input_size: u64,
    /// Input SHA-256.
    pub input_sha256: String,
    /// Output mirror basename.
    pub library: String,
    /// Backing original basename.
    pub backing: String,
    /// Complete export decisions; no entry is dropped.
    pub exports: Vec<MirrorExport>,
    /// Present only after a successful direct build.
    pub built_dll_sha256: Option<String>,
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn atom(bytes: &[u8]) -> Result<String, ProxyError> {
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|byte| *byte < 0x20 || *byte > 0x7e || *byte == b'"' || *byte == b'\\')
    {
        return Err(ProxyError(format!(
            "name cannot be represented safely in a .def file: {}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )));
    }
    let text = std::str::from_utf8(bytes).map_err(|error| ProxyError(error.to_string()))?;
    if text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "_@?$#.-".contains(ch))
    {
        Ok(text.to_string())
    } else {
        Ok(format!("\"{text}\""))
    }
}

fn module(name: &str) -> Result<String, ProxyError> {
    if name.is_empty() || name.contains(['/', '\\', '"', '\r', '\n']) || name == "." || name == ".."
    {
        return Err(ProxyError(format!("unsafe module name: {name:?}")));
    }
    Ok(name.to_string())
}

fn target_text(target: &PeExportTarget, ordinal: u16, backing: &str) -> Result<String, ProxyError> {
    match target {
        PeExportTarget::Address(_) => Ok(format!("{backing}.#{ordinal}")),
        PeExportTarget::Forward { library, target } => {
            let library = atom(library)?;
            match target {
                PeForwardTarget::Name(name) => Ok(format!("{library}.{}", atom(name)?)),
                PeForwardTarget::Ordinal(target) => Ok(format!("{library}.#{target}")),
            }
        }
    }
}

/// Render a buildable module-definition file that forwards every export.
///
/// Address exports use ordinal forwarding, preserving public aliases and NONAME
/// entries without relying on RVAs. Original forwarders are reproduced verbatim.
///
/// # Errors
/// Returns an error for unsafe module names or unrepresentable export names.
pub fn mirror_def(table: &PeExportTable, options: &MirrorOptions) -> Result<String, ProxyError> {
    let library = module(&options.library)?;
    let backing = module(&options.backing)?;
    let mut out = format!("LIBRARY \"{library}\"\nEXPORTS\n");
    for entry in &table.entries {
        let target = target_text(&entry.target, entry.ordinal, &backing)?;
        if entry.names.is_empty() {
            out.push_str(&format!(
                "    KOTAMA_ORDINAL_{}={target} @{} NONAME\n",
                entry.ordinal, entry.ordinal
            ));
        } else {
            for name in &entry.names {
                out.push_str(&format!(
                    "    {}={target} @{}\n",
                    atom(name)?,
                    entry.ordinal
                ));
            }
        }
    }
    Ok(out)
}

/// Build the deterministic audit manifest for one input image.
#[must_use]
pub fn manifest(
    input_name: &str,
    input: &[u8],
    table: &PeExportTable,
    options: &MirrorOptions,
    built_dll: Option<&[u8]>,
) -> MirrorManifest {
    let exports = table
        .entries
        .iter()
        .map(|entry| MirrorExport {
            ordinal: entry.ordinal,
            names: entry
                .names
                .iter()
                .map(|name| match std::str::from_utf8(name) {
                    Ok(text) => text.to_string(),
                    Err(_) => format!(
                        "hex:{}",
                        name.iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    ),
                })
                .collect(),
            forwarded_to: target_text(&entry.target, entry.ordinal, &options.backing)
                .unwrap_or_else(|error| format!("invalid: {error}")),
        })
        .collect();
    MirrorManifest {
        input: input_name.to_string(),
        input_size: input.len() as u64,
        input_sha256: hex_digest(input),
        library: options.library.clone(),
        backing: options.backing.clone(),
        exports,
        built_dll_sha256: built_dll.map(hex_digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotama_image::pe_export::PeExport;

    fn table() -> PeExportTable {
        PeExportTable {
            ordinal_base: 5,
            entries: vec![
                PeExport {
                    ordinal: 5,
                    names: vec![b"Alpha".to_vec(), b"Alias".to_vec()],
                    target: PeExportTarget::Address(0x5000),
                },
                PeExport {
                    ordinal: 6,
                    names: vec![],
                    target: PeExportTarget::Address(0x6000),
                },
                PeExport {
                    ordinal: 7,
                    names: vec![b"Forwarded".to_vec()],
                    target: PeExportTarget::Forward {
                        library: b"OTHER".to_vec(),
                        target: PeForwardTarget::Name(b"Run".to_vec()),
                    },
                },
            ],
        }
    }

    #[test]
    fn definition_is_complete_and_deterministic() {
        let options = MirrorOptions {
            library: "mirror.dll".to_string(),
            backing: "original_real.dll".to_string(),
        };
        let first = mirror_def(&table(), &options).unwrap();
        let second = mirror_def(&table(), &options).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("Alpha=original_real.dll.#5 @5"));
        assert!(first.contains("Alias=original_real.dll.#5 @5"));
        assert!(first.contains("KOTAMA_ORDINAL_6=original_real.dll.#6 @6 NONAME"));
        assert!(first.contains("Forwarded=OTHER.Run @7"));
    }

    #[test]
    fn rejects_module_path_injection() {
        let options = MirrorOptions {
            library: "mirror.dll".to_string(),
            backing: "../original.dll".to_string(),
        };
        assert!(mirror_def(&table(), &options).is_err());
    }
}
