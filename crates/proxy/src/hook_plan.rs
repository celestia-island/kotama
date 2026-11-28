//! Container-agnostic hook planning.
//!
//! A shared library exposes callable symbols under names. Every container has
//! its own way of naming and binding them (PE ordinals + names, ELF dynamic
//! symbols with binding and visibility), but the decision of *which* symbols to
//! intercept is the same question either way. This module answers that question
//! once and hands each container renderer a plain data plan.
//!
//! Nothing here knows how to emit a `.def` file or a version script; it only
//! decides, for every exported name, whether it is intercepted and what the
//! user-supplied hook must be called.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Serialize;

/// Error produced while planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookPlanError(pub String);

impl std::fmt::Display for HookPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HookPlanError {}

/// One exported symbol a plan may intercept.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HookableSymbol {
    /// Symbol name exactly as the container stores it.
    pub name: Vec<u8>,
    /// Container-specific grouping key: PE ordinal, ELF version index, ...
    /// Symbols sharing a key are intercepted as one group (PE aliases).
    pub group: u32,
}

/// Which exported symbols to intercept.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct HookSelection {
    /// Intercept every exported symbol.
    pub all: bool,
    /// Exact names to intercept.
    pub names: Vec<String>,
    /// Regular expressions matched against names.
    pub patterns: Vec<String>,
    /// Exact names never intercepted.
    pub exclude_names: Vec<String>,
    /// Regular expressions never intercepted.
    pub exclude_patterns: Vec<String>,
    /// Exact names that are not expected on this target, so their absence is not
    /// an error.
    ///
    /// A preset is a family that spans platforms; `dlopen` is in the loader
    /// family and is simply not a Windows symbol. Listing it here lets the same
    /// selection be used on either platform without weakening the rule that an
    /// exact name must exist: a name neither present nor excused is still an
    /// error, so a typo still cannot narrow the surface silently.
    pub not_on_platform: Vec<String>,
}

impl HookSelection {
    /// True when nothing selects symbols (an empty deny list is not a selection).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.all && self.names.is_empty() && self.patterns.is_empty()
    }
}

/// One resolved interception.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HookRecord {
    /// Group key the symbol belongs to.
    pub group: u32,
    /// Every name in the group that resolves to the hook.
    pub names: Vec<String>,
    /// Generated identifier the user hook must define.
    pub hook_symbol: String,
}

/// A resolved, container-agnostic hook plan.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct HookPlan {
    hooks: BTreeMap<u32, HookRecord>,
    warnings: Vec<String>,
}

impl HookPlan {
    /// Intercepted groups keyed by their container key.
    #[must_use]
    pub fn hooks(&self) -> &BTreeMap<u32, HookRecord> {
        &self.hooks
    }

    /// Selector warnings (for example a regex that matched nothing).
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Number of intercepted groups.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// True when nothing is intercepted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}

fn compile(patterns: &[String], what: &str) -> Result<Vec<Regex>, HookPlanError> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|error| {
                HookPlanError(format!("invalid {what} regex {pattern:?}: {error}"))
            })
        })
        .collect()
}

fn name_text(name: &[u8]) -> Result<String, HookPlanError> {
    std::str::from_utf8(name)
        .map(str::to_string)
        .map_err(|_| HookPlanError("hook selection requires UTF-8 symbol names".to_string()))
}

/// Resolve a selection against the symbols a container exposes.
///
/// Unknown exact names are an error, so a typo cannot silently narrow the
/// interception surface. Exclusions always win over inclusions.
///
/// # Errors
/// Returns an error for invalid regexes, non-UTF-8 names, or unknown exact names.
pub fn plan_hooks(
    symbols: &[HookableSymbol],
    selection: &HookSelection,
) -> Result<HookPlan, HookPlanError> {
    let patterns = compile(&selection.patterns, "hook")?;
    let excludes = compile(&selection.exclude_patterns, "hook exclude")?;
    for name in &selection.names {
        if selection
            .not_on_platform
            .iter()
            .any(|excused| excused == name)
        {
            continue;
        }
        if !symbols
            .iter()
            .any(|symbol| std::str::from_utf8(&symbol.name).is_ok_and(|text| text == name))
        {
            return Err(HookPlanError(format!("hook name not found: {name}")));
        }
    }
    let mut warnings = Vec::new();
    for pattern in &selection.patterns {
        if !patterns.iter().zip(&selection.patterns).any(|(regex, p)| {
            p == pattern
                && symbols.iter().any(|symbol| {
                    std::str::from_utf8(&symbol.name).is_ok_and(|n| regex.is_match(n))
                })
        }) {
            warnings.push(format!("hook regex matched no symbols: {pattern}"));
        }
    }
    // Phase 1: which groups are hit. A group is one interceptable address, so
    // every name it exposes (PE aliases, versioned ELF symbols) shares its fate.
    let mut hit_groups: Vec<u32> = Vec::new();
    let mut excluded_groups: Vec<u32> = Vec::new();
    for symbol in symbols {
        let text = std::str::from_utf8(&symbol.name).unwrap_or("");
        let included = selection.all
            || selection.names.iter().any(|name| name == text)
            || patterns.iter().any(|regex| regex.is_match(text));
        if included {
            hit_groups.push(symbol.group);
        }
        if selection.exclude_names.iter().any(|name| name == text)
            || excludes.iter().any(|regex| regex.is_match(text))
        {
            excluded_groups.push(symbol.group);
        }
    }
    // Phase 2: collect EVERY name of each surviving group. Excluding one alias
    // excludes the whole address, because the hook sits on the address, not the name.
    let mut groups: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for symbol in symbols {
        if !hit_groups.contains(&symbol.group) || excluded_groups.contains(&symbol.group) {
            continue;
        }
        groups
            .entry(symbol.group)
            .or_default()
            .push(name_text(&symbol.name)?);
    }
    let mut hooks = BTreeMap::new();
    for (group, mut names) in groups {
        names.sort();
        names.dedup();
        hooks.insert(
            group,
            HookRecord {
                group,
                hook_symbol: format!("KOTAMA_HOOK_{group}"),
                names,
            },
        );
    }
    Ok(HookPlan { hooks, warnings })
}
/// Hookable symbols for a PE image, one group per ordinal.
///
/// Only exports whose address lands in an executable section are offered. The
/// export directory names vtables and static data as readily as functions — the
/// local C runtime exports 1,330 names and 46 of them are RTTI vtables — and a
/// planner that accepted those would intercept a data address. Forwarders are
/// excluded too: they are a string in `.rdata`, not code in this image. The
/// rule is the address's section, because that is what the process jumps to.
///
/// A PE with no sections keeps every export: the filter cannot tell, and
/// refusing everything would make a sectionless image unplannable for a reason
/// that is not the image's.
///
/// # Errors
/// Returns [HookPlanError] when the image is not a PE or its export table is
/// malformed; the message says which.
pub fn pe_hookable_symbols(data: &[u8]) -> Result<Vec<HookableSymbol>, HookPlanError> {
    let table = kotama_image::pe_export::parse_pe_exports(data)
        .map_err(|error| HookPlanError(format!("export table: {error}")))?
        .ok_or_else(|| HookPlanError("not a PE image".to_string()))?;
    let module = kotama_image::LoadedModule::parse(data)
        .map_err(|error| HookPlanError(error.to_string()))?;
    let executable = |rva: u32| {
        module.sections.iter().any(|section| {
            section.executable
                && u64::from(rva) >= section.rva
                && u64::from(rva) < section.rva.saturating_add(section.size)
        })
    };
    let has_sections = !module.sections.is_empty();
    Ok(table
        .entries
        .iter()
        .filter(|entry| match entry.target {
            kotama_image::pe_export::PeExportTarget::Address(rva) => {
                !has_sections || executable(rva)
            }
            kotama_image::pe_export::PeExportTarget::Forward { .. } => false,
        })
        .flat_map(|entry| {
            entry.names.iter().map(move |name| HookableSymbol {
                name: name.clone(),
                group: u32::from(entry.ordinal),
            })
        })
        .collect())
}

/// Hookable symbols for a shared ELF object, one group per exported name.
///
/// ELF has no ordinals; the group is the name's index among the exports in
/// table order, so two names never share a group the way PE aliases do.
/// Names are deduplicated: a name exported under two bindings is one hook. No
/// fixture here carries such a duplicate, so that is the contract, not a test.
///
/// # Errors
/// Returns [HookPlanError] when the image is not an ELF shared object.
pub fn elf_hookable_symbols(data: &[u8]) -> Result<Vec<HookableSymbol>, HookPlanError> {
    let module = kotama_image::LoadedModule::parse(data)
        .map_err(|error| HookPlanError(error.to_string()))?;
    if !matches!(
        module.container,
        kotama_image::Container::Elf32 | kotama_image::Container::Elf64
    ) {
        return Err(HookPlanError("not an ELF image".to_string()));
    }
    let has_sections = !module.sections.is_empty();
    let executable = |rva: u64| {
        module.sections.iter().any(|section| {
            section.executable
                && rva >= section.rva
                && rva < section.rva.saturating_add(section.size)
        })
    };
    let mut symbols: Vec<HookableSymbol> = module
        .dynamic_symbols
        .iter()
        .filter(|symbol| !symbol.name.is_empty())
        .filter(|symbol| !has_sections || executable(symbol.rva))
        .enumerate()
        .map(|(index, symbol)| HookableSymbol {
            name: symbol.name.clone().into_bytes(),
            group: u32::try_from(index).unwrap_or(u32::MAX) + 1,
        })
        .collect();
    symbols.sort_by(|a, b| a.name.cmp(&b.name));
    symbols.dedup_by(|a, b| a.name == b.name);
    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syms(pairs: &[(u32, &str)]) -> Vec<HookableSymbol> {
        pairs
            .iter()
            .map(|(group, name)| HookableSymbol {
                name: name.as_bytes().to_vec(),
                group: *group,
            })
            .collect()
    }

    #[test]
    fn exact_names_are_grouped_by_container_key() {
        // Two names on one PE ordinal are aliases and must share one hook.
        let symbols = syms(&[(1, "add"), (2, "mul"), (3, "Foo"), (3, "FooW")]);
        let plan = plan_hooks(
            &symbols,
            &HookSelection {
                names: vec!["add".into(), "FooW".into()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert_eq!(plan.len(), 2);
        let add = &plan.hooks()[&1];
        assert_eq!(add.names, vec!["add".to_string()]);
        assert_eq!(add.hook_symbol, "KOTAMA_HOOK_1");
        // Selecting one alias pulls in the whole group, sorted and deduped.
        let foo = &plan.hooks()[&3];
        assert_eq!(foo.names, vec!["Foo".to_string(), "FooW".to_string()]);
        assert!(plan.warnings().is_empty());
    }

    #[test]
    fn unknown_exact_name_is_an_error_not_a_silent_narrowing() {
        let symbols = syms(&[(1, "add")]);
        let err = plan_hooks(
            &symbols,
            &HookSelection {
                names: vec!["addd".into()],
                ..HookSelection::default()
            },
        )
        .unwrap_err();
        assert!(err.0.contains("hook name not found: addd"), "{err}");
    }

    #[test]
    fn exclusions_always_win_over_includes() {
        let symbols = syms(&[(1, "send"), (2, "sendto"), (3, "recv"), (4, "malloc")]);
        let plan = plan_hooks(
            &symbols,
            &HookSelection {
                patterns: vec!["^send".into(), "^recv".into()],
                exclude_names: vec!["sendto".into()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        let hooked: Vec<_> = plan
            .hooks()
            .values()
            .flat_map(|h| h.names.clone())
            .collect();
        // hooks are keyed by group, so send (1) precedes recv (3).
        assert_eq!(hooked, vec!["send".to_string(), "recv".to_string()]);
    }

    #[test]
    fn unmatched_regex_warns_but_does_not_fail() {
        let symbols = syms(&[(1, "add")]);
        let plan = plan_hooks(
            &symbols,
            &HookSelection {
                patterns: vec!["^nothing".into()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.warnings().len(), 1);
        assert!(plan.warnings()[0].contains("matched no symbols"));
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let symbols = syms(&[(1, "add")]);
        let err = plan_hooks(
            &symbols,
            &HookSelection {
                patterns: vec!["[unclosed".into()],
                ..HookSelection::default()
            },
        )
        .unwrap_err();
        assert!(err.0.contains("invalid hook regex"), "{err}");
    }

    #[test]
    fn excluding_one_alias_excludes_the_whole_address() {
        // The hook sits on an address, not a name: excluding one alias must
        // remove every alias that resolves to the same place.
        let symbols = syms(&[(1, "send"), (1, "WSASend"), (2, "recv")]);
        let plan = plan_hooks(
            &symbols,
            &HookSelection {
                all: true,
                exclude_names: vec!["WSASend".into()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.hooks()[&2].names, vec!["recv".to_string()]);
        assert!(plan.hooks().get(&1).is_none());
    }

    #[test]
    fn select_all_is_a_valid_selection() {
        assert!(HookSelection::default().is_empty());
        let all = HookSelection {
            all: true,
            ..HookSelection::default()
        };
        assert!(!all.is_empty());
        let symbols = syms(&[(1, "a"), (2, "b")]);
        let plan = plan_hooks(&symbols, &all).unwrap();
        assert_eq!(plan.len(), 2);
    }

    /// The loader preset on Windows: dlopen and friends are excused, every Windows
    /// name is still strictly checked against the target's export table.
    #[test]
    fn a_cross_platform_preset_plans_on_windows_without_erroring_on_posix_names() {
        let windows_names = [
            "CreateThread",
            "ExitThread",
            "FreeLibrary",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetModuleFileNameW",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryExW",
            "LoadLibraryW",
        ];
        let symbols: Vec<HookableSymbol> = windows_names
            .iter()
            .enumerate()
            .map(|(index, name)| HookableSymbol {
                name: name.as_bytes().to_vec(),
                group: u32::try_from(index).unwrap() + 1,
            })
            .collect();
        let selection = crate::sdk_presets::by_id("loader")
            .unwrap()
            .selection_for(crate::sdk_presets::Platform::Native);
        assert!(selection.not_on_platform.contains(&"dlopen".to_string()));
        assert_eq!(
            selection.not_on_platform.len(),
            8,
            "dlopen, dlclose, dlsym, dlerror, and the four pthread calls"
        );
        let plan = plan_hooks(&symbols, &selection).unwrap();
        assert_eq!(plan.hooks.len(), windows_names.len());
    }

    /// The same selection against a target that lacks one of the *Windows* names:
    /// still an error. The excuse never reaches a Native name.
    #[test]
    fn a_missing_native_name_in_a_cross_platform_preset_is_still_an_error() {
        let symbols = [HookableSymbol {
            name: b"LoadLibraryW".to_vec(),
            group: 1,
        }];
        let selection = crate::sdk_presets::by_id("loader")
            .unwrap()
            .selection_for(crate::sdk_presets::Platform::Native);
        let err = plan_hooks(&symbols, &selection).unwrap_err();
        assert!(err.0.contains("hook name not found"), "{err}");
        assert!(
            !err.0.contains("dlopen"),
            "a Posix name must not be the error: {err}"
        );
    }

    /// The same preset on a POSIX target: nothing is excused, so a Windows-only
    /// name in the selection is an error exactly as before.
    #[test]
    fn on_posix_nothing_is_excused() {
        let symbols = [HookableSymbol {
            name: b"dlopen".to_vec(),
            group: 1,
        }];
        let selection = crate::sdk_presets::by_id("loader")
            .unwrap()
            .selection_for(crate::sdk_presets::Platform::Posix);
        assert!(selection.not_on_platform.is_empty());
        assert!(plan_hooks(&symbols, &selection).is_err());
    }

    /// An excuse covers only absence. A name that is excused *and* present is
    /// still hooked — the excuse is not an exclusion.
    #[test]
    fn an_excused_name_that_is_present_is_still_hooked() {
        let symbols = [HookableSymbol {
            name: b"snprintf".to_vec(),
            group: 1,
        }];
        let selection = HookSelection {
            names: vec!["snprintf".to_string()],
            not_on_platform: vec!["snprintf".to_string()],
            ..Default::default()
        };
        let plan = plan_hooks(&symbols, &selection).unwrap();
        assert_eq!(plan.hooks.len(), 1);
    }

    /// The excuse is exact, like the name check: a prefix does not excuse.
    #[test]
    fn the_excuse_is_an_exact_match() {
        let symbols = [HookableSymbol {
            name: b"malloc".to_vec(),
            group: 1,
        }];
        let selection = HookSelection {
            names: vec!["mallocx".to_string()],
            not_on_platform: vec!["malloc".to_string()],
            ..Default::default()
        };
        assert!(plan_hooks(&symbols, &selection).is_err());
    }

    /// A typo in a Native name is still an error when the same selection also
    /// carries excuses — the excuse list must not become a blanket.
    #[test]
    fn a_typo_among_excused_names_is_still_an_error() {
        let symbols = [HookableSymbol {
            name: b"LoadLibraryW".to_vec(),
            group: 1,
        }];
        let mut selection = crate::sdk_presets::by_id("loader")
            .unwrap()
            .selection_for(crate::sdk_presets::Platform::Native);
        selection.names.push("LoadLibraryX".to_string());
        assert!(plan_hooks(&symbols, &selection).is_err());
    }

    /// The PE bridge groups aliases by ordinal, and offers only what is code.
    /// The shared-library fixture has six exports: three of its own, two CRT
    /// glue functions in `.text`, and one — the toolchain's "is this a DLL"
    /// flag — which is a **variable** in `.data`. Six names, five hookable.
    ///
    /// mutate: data-not-filtered (dropping the executable-section filter
    /// brings the count back to six; the assertion that the DLL flag is absent
    /// fails on it).
    #[test]
    fn the_pe_bridge_groups_aliases_by_ordinal() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/libexports.dll");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: fixture not built");
            return;
        };
        let symbols = pe_hookable_symbols(&data).unwrap();
        assert_eq!(
            symbols.len(),
            5,
            "three exports plus two CRT-glue functions; the DLL flag is data: {symbols:?}"
        );
        assert!(
            !symbols
                .iter()
                .any(|symbol| symbol.name == b"__mingw_module_is_dll"),
            "a variable in .data is not a hook site"
        );
        let groups: std::collections::BTreeSet<u32> =
            symbols.iter().map(|symbol| symbol.group).collect();
        assert_eq!(groups.len(), 5, "five names on five ordinals here");
    }

    /// The ELF bridge dedupes by name: a name exported twice (once as a default
    /// and once as a hidden alias, say) is one hookable symbol, not two groups.
    #[test]
    fn the_elf_bridge_dedupes_by_name() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/lua/liblua-5.4.7.so");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: Lua fixture not built");
            return;
        };
        let symbols = elf_hookable_symbols(&data).unwrap();
        let names: std::collections::BTreeSet<&[u8]> = symbols
            .iter()
            .map(|symbol| symbol.name.as_slice())
            .collect();
        assert_eq!(names.len(), symbols.len(), "no name appears twice");
        let groups: std::collections::BTreeSet<u32> =
            symbols.iter().map(|symbol| symbol.group).collect();
        assert_eq!(groups.len(), symbols.len(), "one group per name");
        for pair in symbols.windows(2) {
            assert!(pair[0].name < pair[1].name, "sorted by name");
        }
    }

    /// A non-PE input is an error from the PE bridge, not a panic and not a empty
    /// table that would plan nothing and look like success.
    #[test]
    fn the_pe_bridge_refuses_non_pe_input() {
        assert!(pe_hookable_symbols(b"not a binary").is_err());
    }

    #[test]
    fn the_elf_bridge_refuses_non_elf_input() {
        assert!(elf_hookable_symbols(b"not a binary").is_err());
    }

    /// The ELF bridge offers code only. The shared-library fixture exports a
    /// const variable alongside its three functions, and the variable is not a
    /// hook site — it is the ELF shape of what the toolchain's DLL flag is on the
    /// PE side.
    ///
    /// mutate: elf-data-offered (dropping the executable-section filter brings
    /// the count to four; the assertion that the variable is absent fails).
    #[test]
    fn the_elf_bridge_offers_code_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-linux-gnu/-O2/libexports.so");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: fixture not built");
            return;
        };
        let symbols = elf_hookable_symbols(&data).unwrap();
        assert_eq!(
            symbols.len(),
            3,
            "three functions; the variable is data: {symbols:?}"
        );
        assert!(
            !symbols
                .iter()
                .any(|symbol| symbol.name == b"exported_rodata"),
            "a const in .rodata is not a hook site"
        );
        for name in [
            b"exported_add".as_slice(),
            b"exported_mul".as_slice(),
            b"exported_void".as_slice(),
        ] {
            assert!(
                symbols.iter().any(|symbol| symbol.name == name),
                "{name:?} missing"
            );
        }
    }

    /// A PE forwarder is a string in `.rdata`, not code in this image, and is
    /// not offered. The proxy smoke fixture forwards to kernel32.Sleep; it is
    /// built by the CLI test, so this builds the same shape here rather than
    /// depend on a test-order.
    ///
    /// mutate: forwarder-offered (accepting Forward targets makes the count 4
    /// on a three-name-plus-one-forwarder image; the forwarder-absent assertion
    /// fails).
    #[test]
    fn a_pe_forwarder_is_not_a_hook_site() {
        let Some(zig) = std::env::var_os("KOTAMA_ZIG") else {
            eprintln!("skip: KOTAMA_ZIG not set");
            return;
        };
        let root = std::env::temp_dir().join(format!("kotama-forwarder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("o.c"), "int __cdecl A(void) { return 1; }\n").unwrap();
        std::fs::write(
            root.join("o.def"),
            "LIBRARY o\nEXPORTS\n    A @1\n    B=kernel32.Sleep @2\n",
        )
        .unwrap();
        let status = std::process::Command::new(zig)
            .args(["cc", "-target", "x86_64-windows-gnu", "-shared", "-o"])
            .arg(root.join("o.dll"))
            .arg(root.join("o.c"))
            .arg(root.join("o.def"))
            .status()
            .unwrap();
        assert!(status.success());
        let data = std::fs::read(root.join("o.dll")).unwrap();
        let symbols = pe_hookable_symbols(&data).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            symbols.len(),
            1,
            "one function; the forwarder is a string: {symbols:?}"
        );
        assert_eq!(symbols[0].name, b"A");
    }
}
