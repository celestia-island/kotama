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
}
