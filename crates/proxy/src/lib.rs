//! Deterministic, auditable DLL forwarding-mirror generation.
//!
//! This crate only plans and renders artifacts. It never changes the input DLL,
//! guesses function ABIs, or claims to install hooks.

use std::collections::BTreeMap;

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

/// Explicit override selection. Exact names and ordinals only; regex logging is
/// a separate stage so a typo cannot silently broaden a write surface.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct OverrideSelection {
    /// Exact public names to override.
    pub names: Vec<String>,
    /// Exact public ordinals to override.
    pub ordinals: Vec<u16>,
    /// Names excluded from the selection; deny wins over include.
    pub exclude_names: Vec<String>,
    /// Ordinals excluded from the selection; deny wins over include.
    pub exclude_ordinals: Vec<u16>,
}

impl OverrideSelection {
    /// True when no include selector was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.ordinals.is_empty()
    }
}

/// One resolved override decision.
#[derive(Clone, Serialize)]
pub struct OverrideRecord {
    /// Public ordinal of the overridden export group.
    pub ordinal: u16,
    /// Every public name mapped to the override symbol.
    pub names: Vec<String>,
    /// Generated C symbol the user-supplied hooks file must define.
    pub symbol: String,
}

/// Resolved override plan. Every export not in this map keeps forwarding.
#[derive(Clone, Default)]
pub struct OverridePlan {
    symbols: BTreeMap<u16, String>,
    records: Vec<OverrideRecord>,
}

impl OverridePlan {
    /// Overridden ordinals mapped to their generated C symbol.
    #[must_use]
    pub fn symbols(&self) -> &BTreeMap<u16, String> {
        &self.symbols
    }

    /// Audit records in ordinal order.
    #[must_use]
    pub fn records(&self) -> &[OverrideRecord] {
        &self.records
    }

    /// Number of overridden export groups.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// True when nothing is overridden.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

fn name_text(bytes: &[u8]) -> Result<String, ProxyError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| ProxyError("override selection requires a UTF-8 export name".to_string()))
}

/// Resolve exact-name/ordinal overrides against a strict export table.
///
/// Unknown exact selectors are errors. Alias names on one ordinal are overridden
/// together; each group gets one generated symbol so a user C file can implement
/// it without guessing decorated-name rules.
///
/// # Errors
/// Returns an error for unknown selectors or non-UTF-8 export names.
pub fn plan_overrides(
    table: &PeExportTable,
    selection: &OverrideSelection,
) -> Result<OverridePlan, ProxyError> {
    let mut wanted = BTreeMap::<u16, ()>::new();
    for name in &selection.names {
        let mut found = false;
        for entry in &table.entries {
            if entry
                .names
                .iter()
                .any(|candidate| std::str::from_utf8(candidate).is_ok_and(|text| text == name))
            {
                wanted.insert(entry.ordinal, ());
                found = true;
            }
        }
        if !found {
            return Err(ProxyError(format!("override name not found: {name}")));
        }
    }
    for ordinal in &selection.ordinals {
        if !table.entries.iter().any(|entry| entry.ordinal == *ordinal) {
            return Err(ProxyError(format!("override ordinal not found: {ordinal}")));
        }
        wanted.insert(*ordinal, ());
    }
    for name in &selection.exclude_names {
        for entry in &table.entries {
            if entry
                .names
                .iter()
                .any(|candidate| std::str::from_utf8(candidate).is_ok_and(|text| text == name))
            {
                wanted.remove(&entry.ordinal);
            }
        }
    }
    for ordinal in &selection.exclude_ordinals {
        wanted.remove(ordinal);
    }
    let mut symbols = BTreeMap::new();
    let mut records = Vec::new();
    for ordinal in wanted.keys() {
        let entry = table
            .entries
            .iter()
            .find(|entry| entry.ordinal == *ordinal)
            .ok_or_else(|| ProxyError(format!("missing export ordinal {ordinal}")))?;
        let symbol = format!("KOTAMA_OVERRIDE_{ordinal}");
        let mut names = Vec::new();
        for name in &entry.names {
            names.push(name_text(name)?);
        }
        symbols.insert(*ordinal, symbol.clone());
        records.push(OverrideRecord {
            ordinal: *ordinal,
            names,
            symbol,
        });
    }
    Ok(OverridePlan { symbols, records })
}

/// One auditable export decision.
#[derive(Serialize)]
pub struct MirrorExport {
    /// Public ordinal.
    pub ordinal: u16,
    /// Public names in deterministic order; empty means ordinal-only.
    pub names: Vec<String>,
    /// Either forward or override.
    pub action: &'static str,
    /// The .def target for forwarded exports; empty for overrides.
    pub forwarded_to: String,
    /// Generated symbol the hooks file must define, for overrides.
    pub symbol: Option<String>,
}

/// User hook source recorded in the manifest.
#[derive(Serialize)]
pub struct HookSource {
    /// Source basename, never a machine-specific absolute path.
    pub source: String,
    /// Source SHA-256.
    pub source_sha256: String,
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
    /// User hook source when overrides were selected.
    pub hooks: Option<HookSource>,
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
    mirror_def_with(table, options, None)
}

/// Render a mirror with an optional set of overridden export groups.
///
/// Overridden groups must be implemented by the user-supplied hooks source under
/// the generated KOTAMA_OVERRIDE_<ordinal> symbols; every other export forwards.
///
/// # Errors
/// Returns an error for unsafe module names or unrepresentable export names.
pub fn mirror_def_with(
    table: &PeExportTable,
    options: &MirrorOptions,
    overrides: Option<&OverridePlan>,
) -> Result<String, ProxyError> {
    let library = module(&options.library)?;
    let backing = module(&options.backing)?;
    let mut out = format!("LIBRARY \"{library}\"\nEXPORTS\n");
    for entry in &table.entries {
        if let Some(plan) = overrides {
            if let Some(symbol) = plan.symbols().get(&entry.ordinal) {
                if entry.names.is_empty() {
                    out.push_str(&format!("    {symbol} @{} NONAME\n", entry.ordinal));
                } else {
                    for name in &entry.names {
                        out.push_str(&format!(
                            "    {}={symbol} @{}\n",
                            atom(name)?,
                            entry.ordinal
                        ));
                    }
                }
                continue;
            }
        }
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
    manifest_with(input_name, input, table, options, built_dll, None, None)
}

/// Build a manifest that also records override decisions and the hooks source.
#[must_use]
pub fn manifest_with(
    input_name: &str,
    input: &[u8],
    table: &PeExportTable,
    options: &MirrorOptions,
    built_dll: Option<&[u8]>,
    overrides: Option<&OverridePlan>,
    hooks: Option<(&str, &[u8])>,
) -> MirrorManifest {
    let exports = table
        .entries
        .iter()
        .map(|entry| {
            let symbol = overrides.and_then(|plan| plan.symbols().get(&entry.ordinal).cloned());
            let action = if symbol.is_some() {
                "override"
            } else {
                "forward"
            };
            let forwarded_to = if symbol.is_some() {
                String::new()
            } else {
                target_text(&entry.target, entry.ordinal, &options.backing)
                    .unwrap_or_else(|error| format!("invalid: {error}"))
            };
            MirrorExport {
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
                action,
                forwarded_to,
                symbol,
            }
        })
        .collect();
    MirrorManifest {
        input: input_name.to_string(),
        input_size: input.len() as u64,
        input_sha256: hex_digest(input),
        library: options.library.clone(),
        backing: options.backing.clone(),
        exports,
        hooks: hooks.map(|(source, bytes)| HookSource {
            source: source.to_string(),
            source_sha256: hex_digest(bytes),
        }),
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
    fn override_plan_maps_alias_groups_and_keeps_other_exports_forwarding() {
        let options = MirrorOptions {
            library: "mirror.dll".to_string(),
            backing: "original_real.dll".to_string(),
        };
        let selection = OverrideSelection {
            names: vec!["Alpha".to_string()],
            ordinals: vec![6],
            ..OverrideSelection::default()
        };
        let plan = plan_overrides(&table(), &selection).unwrap();
        assert_eq!(
            plan.records()
                .iter()
                .map(|record| record.ordinal)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
        let definition = mirror_def_with(&table(), &options, Some(&plan)).unwrap();
        assert!(definition.contains("Alpha=KOTAMA_OVERRIDE_5 @5"));
        assert!(definition.contains("Alias=KOTAMA_OVERRIDE_5 @5"));
        assert!(definition.contains("KOTAMA_OVERRIDE_6 @6 NONAME"));
        assert!(definition.contains("Forwarded=OTHER.Run @7"));
        let facts = manifest_with(
            "original.dll",
            b"input",
            &table(),
            &options,
            None,
            Some(&plan),
            Some(("hooks.c", b"int KOTAMA_OVERRIDE_5(void){return 0;}")),
        );
        assert_eq!(facts.exports[0].action, "override");
        assert_eq!(
            facts.exports[0].symbol.as_deref(),
            Some("KOTAMA_OVERRIDE_5")
        );
        assert_eq!(facts.hooks.as_ref().unwrap().source, "hooks.c");
        assert!(facts.exports[2].forwarded_to.contains("OTHER.Run"));
    }

    #[test]
    fn unknown_override_names_are_errors() {
        let selection = OverrideSelection {
            names: vec!["Missing".to_string()],
            ..OverrideSelection::default()
        };
        assert!(plan_overrides(&table(), &selection).is_err());
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
