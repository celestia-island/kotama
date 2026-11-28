//! Resolve a runtime hook plan to concrete addresses.
//!
//! `runtime-mount` decides *which* slots and functions to intercept. This module
//! answers the next question: given what is actually in memory, *where* is each one?
//! It is pure. It takes a snapshot that someone else read and returns addresses, so
//! the resolution rules can be tested without a process, and a live reader can be a
//! thin wrapper around them.
//!
//! Two shapes of input cover the three runtimes:
//!
//! - a **table snapshot**: the `JNINativeInterface_` struct as bytes, where a slot is
//!   an index into an array of function pointers of the target width;
//! - a **named export list**: `(name, address)` pairs, which is what a Lua or QuickJS
//!   shared library exposes and what a container export table already provides.
//!
//! A null pointer is reported as unresolved rather than skipped silently: a slot the
//! runtime left empty is a fact a caller wants to see.

use kotama_proxy::hook_plan::{HookPlan, HookRecord};
use kotama_runtime_mount::Runtime;

/// Width of a function pointer in the target, which selects how a table is read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PointerWidth {
    /// 32-bit targets: four bytes per slot.
    W32,
    /// 64-bit targets: eight bytes per slot.
    W64,
}

impl PointerWidth {
    /// Bytes per slot.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }
}

/// One planned hook with the address it resolves to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedHook {
    /// Runtime the hook belongs to.
    pub runtime: Runtime,
    /// Group key as `runtime-mount` assigned it.
    pub group: u32,
    /// Name the plan uses.
    pub name: String,
    /// Address in the target address space.
    pub address: u64,
}

/// Why a planned hook could not be resolved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Unresolved {
    /// The table is too short to contain the slot.
    TableTooShort {
        /// Slot index that was wanted.
        slot: u32,
        /// Slots the table actually held.
        have: u32,
    },
    /// The slot exists but holds a null pointer.
    NullPointer {
        /// Slot index that was null.
        slot: u32,
    },
    /// No export of that name was present.
    NoExport {
        /// Name that was looked up.
        name: String,
    },
}

/// Read a function pointer of `width` at `offset` in `bytes`.
fn pointer_at(bytes: &[u8], offset: usize, width: PointerWidth) -> Option<u64> {
    match width {
        PointerWidth::W32 => bytes
            .get(offset..offset + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
        PointerWidth::W64 => bytes
            .get(offset..offset + 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
    }
}

/// Resolve every JNI slot in a `JNINativeInterface_` snapshot.
///
/// Slots 0..=3 are reserved and absent from the table description, so they are never
/// reported. A slot past the end of the snapshot is unresolved with `TableTooShort`,
/// a present but null slot with `NullPointer`.
#[must_use]
pub fn resolve_jni_table(
    bytes: &[u8],
    width: PointerWidth,
) -> (Vec<ResolvedHook>, Vec<(u32, Unresolved)>) {
    let slots = u32::try_from(bytes.len() / width.size()).unwrap_or(u32::MAX);
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for entry in kotama_runtime_jni::JNI_ENTRIES {
        let slot = entry.slot;
        if slot >= slots {
            unresolved.push((slot, Unresolved::TableTooShort { slot, have: slots }));
            continue;
        }
        let offset = slot as usize * width.size();
        match pointer_at(bytes, offset, width) {
            Some(0) => unresolved.push((slot, Unresolved::NullPointer { slot })),
            Some(address) => resolved.push(ResolvedHook {
                runtime: Runtime::Jni,
                group: slot,
                name: entry.name.to_string(),
                address,
            }),
            None => unresolved.push((slot, Unresolved::TableTooShort { slot, have: slots })),
        }
    }
    (resolved, unresolved)
}

/// Resolve a named-export list against a runtime whose table is name-keyed.
///
/// Every name in the runtime table is looked up in `exports`; a name with no export is
/// unresolved. This is the shape for Lua and QuickJS, whose entry points are ordinary
/// shared-library exports.
#[must_use]
pub fn resolve_named_exports(
    runtime: Runtime,
    group_base: u32,
    names: &[&str],
    exports: &[(String, u64)],
) -> (Vec<ResolvedHook>, Vec<(String, Unresolved)>) {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let group = group_base + u32::try_from(index).unwrap_or(u32::MAX);
        match exports.iter().find(|(export, _)| export == name) {
            Some((_, address)) => resolved.push(ResolvedHook {
                runtime,
                group,
                name: (*name).to_string(),
                address: *address,
            }),
            None => unresolved.push((
                (*name).to_string(),
                Unresolved::NoExport {
                    name: (*name).to_string(),
                },
            )),
        }
    }
    (resolved, unresolved)
}

/// Resolve the Lua C API against a Lua shared library export list.
#[must_use]
pub fn resolve_lua_exports(
    exports: &[(String, u64)],
) -> (Vec<ResolvedHook>, Vec<(String, Unresolved)>) {
    let names: Vec<&str> = kotama_runtime_lua::LUA_API
        .iter()
        .map(|api| api.name)
        .collect();
    resolve_named_exports(
        Runtime::Lua,
        kotama_runtime_mount::LUA_GROUP_BASE,
        &names,
        exports,
    )
}

/// Resolve the JNI Invocation API against a VM library's export list.
///
/// Unlike [`resolve_jni_table`], which needs a `JNIEnv*` snapshot that only exists once
/// a VM is in the process, this resolves the three exported symbols a VM library ships
/// — so it can be run against the library's export table before anything is attached.
#[must_use]
pub fn resolve_jni_invocation(
    exports: &[(String, u64)],
) -> (Vec<ResolvedHook>, Vec<(String, Unresolved)>) {
    let names: Vec<&str> = kotama_runtime_jni::INVOCATION_EXPORTS
        .iter()
        .map(|export| export.name)
        .collect();
    resolve_named_exports(
        Runtime::Jni,
        kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE,
        &names,
        exports,
    )
}

/// Resolve the QuickJS C ABI against an export list.
#[must_use]
pub fn resolve_quickjs_exports(
    exports: &[(String, u64)],
) -> (Vec<ResolvedHook>, Vec<(String, Unresolved)>) {
    let names: Vec<&str> = kotama_runtime_quickjs::QUICKJS_ENTRIES
        .iter()
        .map(|entry| entry.name)
        .collect();
    resolve_named_exports(
        Runtime::QuickJs,
        kotama_runtime_mount::QUICKJS_GROUP_BASE,
        &names,
        exports,
    )
}

/// Outcome of checking a plan against what was resolved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanVerification {
    /// Planned hooks with an address, keyed by group.
    pub addressed: Vec<u32>,
    /// Planned hooks with no address, keyed by group.
    pub missing: Vec<u32>,
}

impl PlanVerification {
    /// True when every planned hook resolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Check that every hook in `plan` has been resolved in `resolved`.
///
/// Both sides are keyed by the group `runtime-mount` assigned, so a plan and a
/// snapshot made at different times still line up.
#[must_use]
pub fn verify_plan(plan: &HookPlan, resolved: &[ResolvedHook]) -> PlanVerification {
    let mut addressed = Vec::new();
    let mut missing = Vec::new();
    for (group, record) in plan.hooks() {
        if resolved.iter().any(|hook| hook.group == *group) {
            addressed.push(*group);
        } else {
            missing.push(*group);
        }
        let _: &HookRecord = record;
    }
    addressed.sort_unstable();
    missing.sort_unstable();
    PlanVerification { addressed, missing }
}

/// Build the `(name, absolute address)` list the runtime resolvers take from a
/// module's dynamic symbols.
///
/// A Lua or QuickJS shared library exposes its C ABI as ordinary exports, which the
/// image crate already parses into `dynamic_symbols`. This turns them into what
/// [`resolve_lua_exports`] / [`resolve_quickjs_exports`] consume, applying the load base
/// so the addresses are absolute — the form a live process needs, and the form a static
/// file gets by passing its own image base.
///
/// Aliases are kept: two names for one address yield two entries, because a hook plan
/// keyed by either name must find it. Names are not deduplicated against each other.
#[must_use]
pub fn exports_from_symbols(base: u64, symbols: &[kotama_image::SymbolInfo]) -> Vec<(String, u64)> {
    symbols
        .iter()
        .filter(|symbol| !symbol.name.is_empty())
        .map(|symbol| (symbol.name.clone(), base.wrapping_add(symbol.rva)))
        .collect()
}

/// The same list read straight off a loaded module, filtered to what a hook
/// can be planted on: an export whose address lands in an executable section.
///
/// A PE export directory names vtables, RTTI and static data as readily as
/// functions — the local VM library exports 4,507 names and 4,291 of them are
/// data — and a resolver given those would plan a hook on a data address.
/// `exports_from_symbols` cannot do this filter: it sees symbols, not sections.
/// The rule is the address's section, not the symbol's kind, because that is
/// what the process will actually jump to.
#[must_use]
pub fn exports_from_module(module: &kotama_image::LoadedModule) -> Vec<(String, u64)> {
    exports_from_symbols(module.image_base, &module.dynamic_symbols)
        .into_iter()
        .filter(|(_, address)| {
            let rva = address.wrapping_sub(module.image_base);
            module.sections.iter().any(|section| {
                section.executable
                    && rva >= section.rva
                    && rva < section.rva.saturating_add(section.size)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotama_proxy::hook_plan::HookSelection;

    fn table64(pointers: &[u64]) -> Vec<u8> {
        pointers.iter().flat_map(|p| p.to_le_bytes()).collect()
    }

    #[test]
    fn jni_slots_resolve_by_index_at_64_bit() {
        // A 300-slot table where slot 6 (FindClass) holds 0x1234 and slot 4 holds 0xAA.
        let mut pointers = vec![0u64; 300];
        pointers[4] = 0xAA;
        pointers[6] = 0x1234;
        let (resolved, _) = resolve_jni_table(&table64(&pointers), PointerWidth::W64);
        let by_name = |n: &str| resolved.iter().find(|h| h.name == n).unwrap();
        assert_eq!(by_name("GetVersion").address, 0xAA);
        assert_eq!(by_name("FindClass").address, 0x1234);
    }

    #[test]
    fn jni_null_slots_are_reported_not_skipped() {
        let pointers = vec![0u64; 300];
        let (resolved, unresolved) = resolve_jni_table(&table64(&pointers), PointerWidth::W64);
        assert!(resolved.is_empty());
        assert_eq!(unresolved.len(), kotama_runtime_jni::JNI_ENTRIES.len());
        assert!(unresolved
            .iter()
            .all(|(_, u)| matches!(u, Unresolved::NullPointer { .. })));
    }

    #[test]
    fn a_short_table_reports_the_slot_it_could_not_reach() {
        let pointers = vec![0u64; 10];
        let (_, unresolved) = resolve_jni_table(&table64(&pointers), PointerWidth::W64);
        // Slots 4..=9 exist and are null; everything from 10 upward is out of reach.
        let nulls = unresolved
            .iter()
            .filter(|(_, u)| matches!(u, Unresolved::NullPointer { .. }))
            .count();
        let short = unresolved
            .iter()
            .filter(|(_, u)| matches!(u, Unresolved::TableTooShort { have: 10, .. }))
            .count();
        assert_eq!(nulls, 6);
        assert_eq!(nulls + short, kotama_runtime_jni::JNI_ENTRIES.len());
        assert!(unresolved.iter().all(|(slot, _)| *slot >= 4));
    }

    #[test]
    fn jni_32_bit_tables_read_four_byte_pointers() {
        let mut pointers = vec![0u32; 300];
        pointers[6] = 0xdead_beef;
        let bytes: Vec<u8> = pointers.iter().flat_map(|p| p.to_le_bytes()).collect();
        let (resolved, _) = resolve_jni_table(&bytes, PointerWidth::W32);
        assert_eq!(
            resolved
                .iter()
                .find(|h| h.name == "FindClass")
                .unwrap()
                .address,
            0xdead_beef
        );
    }

    #[test]
    fn lua_exports_resolve_by_exact_name() {
        let exports = vec![
            ("lua_callk".to_string(), 0x1000u64),
            ("lua_close".to_string(), 0x2000),
        ];
        let (resolved, unresolved) = resolve_lua_exports(&exports);
        assert_eq!(resolved.len(), 2);
        assert_eq!(unresolved.len(), kotama_runtime_lua::LUA_API.len() - 2);
        assert!(resolved.iter().all(|h| h.runtime == Runtime::Lua));
    }

    #[test]
    fn quickjs_exports_use_their_own_group_base() {
        let exports = vec![("JS_Eval".to_string(), 0x3000u64)];
        let (resolved, _) = resolve_quickjs_exports(&exports);
        assert_eq!(resolved[0].runtime, Runtime::QuickJs);
        assert!(resolved[0].group >= kotama_runtime_mount::QUICKJS_GROUP_BASE);
    }

    #[test]
    fn a_plan_is_verified_against_resolved_addresses_by_group() {
        let points = kotama_runtime_mount::lua_points();
        let plan = kotama_runtime_mount::plan_runtime(
            &points,
            &HookSelection {
                names: vec!["lua_callk".to_string(), "lua_close".to_string()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        // Only lua_callk is present in memory.
        let exports = vec![("lua_callk".to_string(), 0x1000u64)];
        let (resolved, _) = resolve_lua_exports(&exports);
        let v = verify_plan(&plan, &resolved);
        assert_eq!(v.addressed.len(), 1);
        assert_eq!(v.missing.len(), 1);
        assert!(!v.is_complete());
    }

    #[test]
    fn a_fully_resolved_plan_is_complete() {
        let points = kotama_runtime_mount::lua_points();
        let names: Vec<String> = vec!["lua_callk".to_string()];
        let plan = kotama_runtime_mount::plan_runtime(
            &points,
            &HookSelection {
                names: names.clone(),
                ..HookSelection::default()
            },
        )
        .unwrap();
        let exports: Vec<(String, u64)> = names.into_iter().map(|n| (n, 0x1000)).collect();
        let (resolved, _) = resolve_lua_exports(&exports);
        assert!(verify_plan(&plan, &resolved).is_complete());
    }

    #[test]
    fn jni_resolved_hooks_carry_their_slot_as_group_and_the_jni_runtime() {
        let mut pointers = vec![0u64; 300];
        pointers[6] = 0x1234;
        pointers[15] = 0x5678;
        let (resolved, _) = resolve_jni_table(&table64(&pointers), PointerWidth::W64);
        assert!(resolved.iter().all(|h| h.runtime == Runtime::Jni));
        let find = resolved.iter().find(|h| h.name == "FindClass").unwrap();
        assert_eq!(find.group, 6);
        let ex = resolved
            .iter()
            .find(|h| h.name == "ExceptionOccurred")
            .unwrap();
        assert_eq!(ex.group, 15);
        assert_eq!(ex.address, 0x5678);
    }

    #[test]
    fn verification_lists_are_sorted_by_group() {
        let points = kotama_runtime_mount::lua_points();
        // Three planned hooks with descending group order; resolved set is a subset.
        let names = vec![
            "lua_callk".to_string(),
            "lua_close".to_string(),
            "lua_error".to_string(),
        ];
        let plan = kotama_runtime_mount::plan_runtime(
            &points,
            &HookSelection {
                names: names.clone(),
                ..HookSelection::default()
            },
        )
        .unwrap();
        let exports = vec![("lua_close".to_string(), 0x2000u64)];
        let (resolved, _) = resolve_lua_exports(&exports);
        let v = verify_plan(&plan, &resolved);
        assert_eq!(v.addressed.len(), 1);
        assert_eq!(v.missing.len(), 2);
        let m = &v.missing;
        assert!(
            m.windows(2).all(|w| w[0] < w[1]),
            "missing not sorted: {m:?}"
        );
        let a = &v.addressed;
        assert!(
            a.windows(2).all(|w| w[0] < w[1]),
            "addressed not sorted: {a:?}"
        );
    }

    #[test]
    fn named_export_groups_are_offset_from_the_runtime_base() {
        let exports = vec![("JS_Eval".to_string(), 0x3000u64)];
        let (resolved, _) = resolve_quickjs_exports(&exports);
        assert!(resolved[0].group >= kotama_runtime_mount::QUICKJS_GROUP_BASE);
        let (lua, _) = resolve_lua_exports(&[("lua_close".to_string(), 0x1000u64)]);
        assert!(lua[0].group >= kotama_runtime_mount::LUA_GROUP_BASE);
        assert!(lua[0].group < kotama_runtime_mount::QUICKJS_GROUP_BASE);
    }

    fn fixture(rel: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated")
            .join(rel);
        if path.exists() {
            Some(path)
        } else if std::env::var("KOTAMA_REQUIRE_FIXTURES").as_deref() == Ok("1") {
            panic!(
                "required fixture missing: {}; run tools/build_fixtures.py",
                path.display()
            )
        } else {
            None
        }
    }

    #[test]
    fn symbols_become_absolute_named_exports() {
        use kotama_image::SymbolInfo;
        let symbols = vec![
            SymbolInfo {
                rva: 0x1000,
                size: 16,
                name: "lua_callk".into(),
            },
            SymbolInfo {
                rva: 0x1000,
                size: 16,
                name: "lua_callk_alias".into(),
            },
            SymbolInfo {
                rva: 0x2000,
                size: 0,
                name: String::new(),
            },
        ];
        let exports = exports_from_symbols(0x400000, &symbols);
        assert_eq!(
            exports,
            vec![
                ("lua_callk".to_string(), 0x401000),
                ("lua_callk_alias".to_string(), 0x401000),
            ]
        );
    }

    #[test]
    fn a_pe_fixture_yields_its_exported_names_at_absolute_addresses() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/exports.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let exports = exports_from_module(&module);
        assert!(
            !exports.is_empty(),
            "the fixture exports symbols by construction"
        );
        for (name, address) in &exports {
            assert!(
                *address >= module.image_base,
                "{name} resolved below the image base"
            );
        }
        let names: std::collections::BTreeSet<&str> =
            exports.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names.len(), exports.len(), "names must be unique per entry");
    }

    #[test]
    fn an_elf_shared_library_yields_its_exports_at_absolute_addresses() {
        // A Lua or QuickJS runtime on Linux is a .so: its C ABI is the dynamic symbol
        // table. This fixture exports three functions by construction.
        let Some(path) = fixture("x86_64-linux-gnu/-O2/libexports.so") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let exports = exports_from_module(&module);
        let names: std::collections::BTreeSet<&str> =
            exports.iter().map(|(n, _)| n.as_str()).collect();
        for wanted in ["exported_add", "exported_mul", "exported_void"] {
            assert!(names.contains(wanted), "{wanted} missing: {names:?}");
        }
        assert!(
            !names.contains("hidden_helper"),
            "static must not be exported"
        );
        for (_, address) in &exports {
            assert!(*address >= module.image_base);
        }
    }

    #[test]
    fn an_elf_executable_exports_nothing_to_the_dynamic_table() {
        // An ET_EXEC binary does not export symbols for other modules to bind; its
        // .dynsym holds only imports. Pinning this keeps the shared-library test honest:
        // an empty result there would be a real failure, not the executable's nature.
        let Some(path) = fixture("x86_64-linux-gnu/-O2/exports") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(exports_from_module(&module).is_empty());
    }

    #[test]
    fn a_pe_shared_library_yields_its_exports_too() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/libexports.dll") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let exports = exports_from_module(&module);
        let names: std::collections::BTreeSet<&str> =
            exports.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains("exported_add"), "{names:?}");
    }

    #[test]
    fn exports_feed_the_lua_resolver_end_to_end() {
        use kotama_image::SymbolInfo;
        let symbols = vec![SymbolInfo {
            rva: 0x10,
            size: 8,
            name: "lua_close".into(),
        }];
        let exports = exports_from_symbols(0x7f0000, &symbols);
        let (resolved, _) = resolve_lua_exports(&exports);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].address, 0x7f0010);
    }

    /// The Invocation API resolves from an export list alone — no environment snapshot.
    #[test]
    fn the_invocation_api_resolves_from_a_bare_export_list() {
        let exports = vec![
            ("JNI_GetCreatedJavaVMs".to_string(), 0x7f0100u64),
            ("JNI_CreateJavaVM".to_string(), 0x7f0200),
            ("JNI_GetDefaultJavaVMInitArgs".to_string(), 0x7f0300),
        ];
        let (resolved, unresolved) = resolve_jni_invocation(&exports);
        assert!(unresolved.is_empty());
        assert_eq!(resolved.len(), 3);
        let by_name: std::collections::BTreeMap<&str, u64> = resolved
            .iter()
            .map(|hook| (hook.name.as_str(), hook.address))
            .collect();
        assert_eq!(by_name["JNI_CreateJavaVM"], 0x7f0200);
        assert_eq!(by_name["JNI_GetCreatedJavaVMs"], 0x7f0100);
        for hook in &resolved {
            assert_eq!(hook.runtime, Runtime::Jni);
            assert!(
                hook.group >= kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE,
                "invocation groups must sit above the slot range"
            );
        }
    }

    /// A library that is not a VM exports none of the three; all are reported, by name.
    #[test]
    fn a_library_without_the_invocation_api_reports_all_three_unresolved() {
        let exports = vec![("malloc".to_string(), 0x1000u64)];
        let (resolved, unresolved) = resolve_jni_invocation(&exports);
        assert!(resolved.is_empty());
        assert_eq!(unresolved.len(), 3);
        for (name, reason) in &unresolved {
            assert!(matches!(reason, Unresolved::NoExport { .. }), "{name}");
        }
    }

    /// The invocation groups must not collide with the slot groups: slot 0..=255 and
    /// The invocation groups must not collide with the slot groups: slot 0..=255 and
    /// the invocation base are different key spaces, and a plan over both must keep
    /// them apart. The bound is absolute — above every slot the table knows — so a
    /// base moved down into the slot range fails here rather than in some plan.
    #[test]
    fn invocation_groups_never_collide_with_slot_groups() {
        let exports: Vec<(String, u64)> = kotama_runtime_jni::INVOCATION_EXPORTS
            .iter()
            .map(|export| (export.name.to_string(), 0x4000))
            .collect();
        let (resolved, _) = resolve_jni_invocation(&exports);
        let highest_slot = kotama_runtime_jni::JNI_ENTRIES
            .iter()
            .map(|entry| entry.slot)
            .max()
            .unwrap();
        assert!(
            kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE > highest_slot,
            "base {:#x} sits inside the slot range (highest slot {highest_slot})",
            kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE
        );
        for hook in &resolved {
            assert!(
                hook.group >= kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE
                    && hook.group < kotama_runtime_mount::JNI_INVOCATION_GROUP_BASE + 3,
                "{} group {}",
                hook.name,
                hook.group
            );
        }
    }
    #[test]
    fn invocation_mount_points_and_resolver_agree() {
        let points = kotama_runtime_mount::jni_invocation_points();
        let exports: Vec<(String, u64)> = kotama_runtime_jni::INVOCATION_EXPORTS
            .iter()
            .map(|export| (export.name.to_string(), 0x5000))
            .collect();
        let (resolved, _) = resolve_jni_invocation(&exports);
        assert_eq!(points.len(), resolved.len());
        for (point, hook) in points.iter().zip(&resolved) {
            assert_eq!(point.name, hook.name);
            assert_eq!(point.group, hook.group);
        }
    }

    /// A Lua fixture: `fixtures/generated/lua/liblua-<version>.so`, built by the
    /// fixture lane from the official release tarball.
    fn lua_lib(version: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/lua")
            .join(format!("liblua-{version}.so"));
        if path.exists() {
            Some(path)
        } else if std::env::var("KOTAMA_REQUIRE_FIXTURES").as_deref() == Ok("1") {
            panic!(
                "required Lua fixture missing: {}; run tools/build_fixtures.py",
                path.display()
            )
        } else {
            None
        }
    }

    /// Core-API names a Lua library exports (aux library and luaopen_* excluded).
    fn lua_core_exports(version: &str) -> Option<Vec<String>> {
        let path = lua_lib(version)?;
        let module = kotama_image::LoadedModule::parse(&std::fs::read(path).unwrap())
            .expect("Lua fixture must parse");
        let mut core: Vec<String> = exports_from_module(&module)
            .iter()
            .map(|(name, _)| name.clone())
            .filter(|name| name.starts_with("lua_") && !name.starts_with("luaL_"))
            .collect();
        core.sort();
        Some(core)
    }

    fn lua_resolved(version: &str) -> (usize, Vec<String>) {
        let module =
            kotama_image::LoadedModule::parse(&std::fs::read(lua_lib(version).unwrap()).unwrap())
                .unwrap();
        let (resolved, unresolved) = resolve_lua_exports(&exports_from_module(&module));
        let mut missing: Vec<String> = unresolved.iter().map(|(n, _)| n.clone()).collect();
        missing.sort();
        (resolved.len(), missing)
    }

    fn claimed_absent(version: u32) -> Vec<String> {
        let mut names: Vec<String> = kotama_runtime_lua::KNOWN_ABSENT
            .iter()
            .find(|(v, _)| *v == version)
            .unwrap()
            .1
            .iter()
            .map(|n| (*n).to_string())
            .collect();
        names.sort();
        names
    }

    /// The table was derived from the 5.4 header. Against a real 5.4 library it must
    /// resolve completely, and the core names it exports must be exactly the table.
    #[test]
    fn the_table_is_exactly_the_core_api_of_a_real_5_4_library() {
        let Some(core) = lua_core_exports("5.4.7") else {
            eprintln!("skip: Lua fixtures not built");
            return;
        };
        let mut table: Vec<&str> = kotama_runtime_lua::LUA_API.iter().map(|a| a.name).collect();
        table.sort();
        assert_eq!(core, table, "real 5.4 core exports vs table");
        let (resolved, missing) = lua_resolved("5.4.7");
        assert_eq!(resolved, 98);
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// KNOWN_ABSENT for 5.3 names ten functions. Against a real 5.3 library the
    /// unresolved set must be exactly those ten; the binary is what makes it so.
    #[test]
    fn the_5_3_absence_list_is_exactly_what_a_real_5_3_library_lacks() {
        if lua_lib("5.3.6").is_none() {
            eprintln!("skip: Lua fixtures not built");
            return;
        }
        let (resolved, missing) = lua_resolved("5.3.6");
        assert_eq!(resolved, 88);
        let claimed = claimed_absent(503);
        assert_eq!(missing, claimed, "5.3 claimed vs real absence");
    }

    /// Same for 5.1.
    #[test]
    fn the_5_1_absence_list_is_exactly_what_a_real_5_1_library_lacks() {
        if lua_lib("5.1.5").is_none() {
            eprintln!("skip: Lua fixtures not built");
            return;
        }
        let (resolved, missing) = lua_resolved("5.1.5");
        assert_eq!(resolved, 64);
        let claimed = claimed_absent(501);
        assert_eq!(missing, claimed, "5.1 claimed vs real absence");
    }

    /// The older libraries export names the 5.4 table has never heard of. A mount
    /// against an old runtime needs to know these exist, or it will report functions
    /// missing that the library in fact has under older names.
    #[test]
    fn older_libraries_export_names_the_5_4_table_renamed_or_dropped() {
        let Some(core) = lua_core_exports("5.3.6") else {
            eprintln!("skip: Lua fixtures not built");
            return;
        };
        for old in ["lua_getuservalue", "lua_setuservalue", "lua_newuserdata"] {
            assert!(core.iter().any(|n| n == old), "5.3 must export {old}");
            assert!(kotama_runtime_lua::by_name(old).is_none());
        }
        let Some(core) = lua_core_exports("5.1.5") else {
            return;
        };
        for old in [
            "lua_call",
            "lua_pcall",
            "lua_yield",
            "lua_remove",
            "lua_insert",
            "lua_replace",
        ] {
            assert!(core.iter().any(|n| n == old), "5.1 must export {old}");
        }
    }

    /// 98, 88, 64: monotone, because each absence list is a superset of the previous.
    #[test]
    fn resolution_shrinks_monotonically_across_releases() {
        let mut counts = Vec::new();
        for version in ["5.4.7", "5.3.6", "5.1.5"] {
            if lua_lib(version).is_none() {
                continue;
            }
            counts.push(lua_resolved(version).0);
        }
        if counts.len() == 3 {
            assert_eq!(counts, [98, 88, 64]);
            assert!(counts.windows(2).all(|w| w[0] > w[1]));
        }
    }

    /// The VM library exports 4,507 names and most are data: vtables, RTTI, static
    /// objects. Only the executable ones are hookable, and the three Invocation
    /// API exports are among them.
    ///
    /// mutate: section-filter-dropped (removing the executable-section filter
    /// makes the count jump to the raw export total; the assertion on "every
    /// export is executable" fails on the first vtable).
    #[test]
    fn exports_from_module_keeps_only_what_lands_in_executable_sections() {
        let dll = std::path::Path::new(
            "D:/源代码/工程项目/celestia/_scratch/kotama-tools/jdk25/jdk-25.0.5.1+2/bin/server/jvm.dll",
        );
        let Ok(data) = std::fs::read(dll) else {
            eprintln!("skip: VM library not on this machine");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&data).unwrap();
        let raw = module.dynamic_symbols.len();
        let filtered = exports_from_module(&module);
        assert!(raw > 4000, "the VM library exports thousands: {raw}");
        assert!(
            filtered.len() < raw / 2,
            "most of those are data; {} of {raw} survived",
            filtered.len()
        );
        for (name, address) in &filtered {
            let rva = address - module.image_base;
            let section = module
                .sections
                .iter()
                .find(|s| rva >= s.rva && rva < s.rva + s.size)
                .unwrap_or_else(|| panic!("{name} lands in no section"));
            assert!(
                section.executable,
                "{name} @ {rva:#x} is in {}",
                section.name
            );
        }
        // The three the Invocation API resolver needs are still there.
        for needed in [
            "JNI_CreateJavaVM",
            "JNI_GetCreatedJavaVMs",
            "JNI_GetDefaultJavaVMInitArgs",
        ] {
            assert!(
                filtered.iter().any(|(n, _)| n == needed),
                "{needed} was filtered out"
            );
        }
        // And a vtable is not.
        assert!(
            !filtered.iter().any(|(n, _)| n.starts_with("??_7")),
            "vtables must not survive"
        );
    }

    /// A module with no sections keeps everything: the filter cannot tell, and
    /// refusing everything would make a sectionless image unhookable for a reason
    /// that is not the image's.
    #[test]
    fn a_sectionless_module_keeps_every_export() {
        let symbols = vec![kotama_image::SymbolInfo {
            rva: 0x1000,
            size: 8,
            name: "f".into(),
        }];
        let exports = exports_from_symbols(0x400000, &symbols);
        assert_eq!(exports, vec![("f".to_string(), 0x401000)]);
    }
}
