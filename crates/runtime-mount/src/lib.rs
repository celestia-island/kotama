//! Runtime function-table mounting.
//!
//! A shared library exposes hooks through its export table, and `kotama-proxy`
//! plans those by name. A language runtime does not: the Java native interface
//! hands out a struct of function pointers obtained at run time through
//! `GetEnv`, and Lua's C API is a loose set of exports reached through a
//! `lua_State`. Neither is a DLL export the loader binds, so neither can be
//! planned by scanning a container.
//!
//! What they do have in common with an export table is the shape: a set of named
//! call sites, some sharing one address. This module gives both runtimes that
//! shape, so the same selector and the same planner decide what to intercept:
//!
//! - JNI slots are grouped by the slot number the specification froze, which is
//!   the address-equivalent key an export table would provide;
//! - Lua functions are grouped by name, because Lua has no slot table to alias.
//!
//! Nothing here reads a process or installs a hook. It produces a plan, which is
//! the container-agnostic part every mounting strategy shares.

use kotama_proxy::hook_plan::{plan_hooks, HookPlan, HookPlanError, HookSelection, HookableSymbol};
use kotama_runtime_jni::JniCategory;
use kotama_runtime_lua::LuaCategory;

/// Which runtime a mount point belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Runtime {
    /// The Java native interface (`JNINativeInterface_`).
    Jni,
    /// The Lua C API.
    Lua,
}

/// Semantic grouping shared by both runtimes, for selecting by role rather than name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Environment / state lifecycle and queries.
    State,
    /// Lookup of classes, methods, globals.
    Lookup,
    /// Calling into hosted code.
    Call,
    /// Throwing and handling errors.
    Error,
    /// Memory, references, allocation.
    Memory,
    /// String and data access.
    Data,
    /// Everything else.
    Other,
}

/// One call site a runtime exposes for mounting.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MountPoint {
    /// Runtime this point belongs to.
    pub runtime: Runtime,
    /// Group key: JNI slot number, or the Lua entry index.
    pub group: u32,
    /// Name exactly as the runtime spells it.
    pub name: String,
    /// Role, for selecting by kind of operation.
    pub role: Role,
}

impl MountPoint {
    /// The planner's container-neutral view of this point.
    #[must_use]
    fn hookable(&self) -> HookableSymbol {
        HookableSymbol {
            name: self.name.clone().into_bytes(),
            group: self.group,
        }
    }
}

/// Map a JNI category onto the shared roles.
const fn jni_role(category: JniCategory) -> Role {
    match category {
        JniCategory::Environment | JniCategory::Invocation => Role::State,
        JniCategory::Class => Role::Lookup,
        JniCategory::Call => Role::Call,
        JniCategory::Exception => Role::Error,
        JniCategory::Reference => Role::Memory,
        JniCategory::String | JniCategory::Array => Role::Data,
        JniCategory::Object | JniCategory::Field | JniCategory::Native | JniCategory::Thread => {
            Role::Other
        }
    }
}

/// Map a Lua category onto the shared roles.
const fn lua_role(category: LuaCategory) -> Role {
    match category {
        LuaCategory::State => Role::State,
        LuaCategory::Access | LuaCategory::Global => Role::Lookup,
        LuaCategory::Call => Role::Call,
        LuaCategory::Stack => Role::Memory,
        LuaCategory::Push | LuaCategory::Convert => Role::Data,
    }
}

/// First group key used for Lua mount points.
///
/// JNI slots are numbered from 4 and stay well under 256; Lua has no slots, so its
/// groups are an index. Left at zero those indices overlap the JNI slot range, and a
/// plan over both runtimes would merge a Lua function with whichever JNI slot shares
/// the number. The base keeps the two key spaces disjoint.
pub const LUA_GROUP_BASE: u32 = 0x1_0000;

/// Every JNI slot as a mount point, grouped by slot.
#[must_use]
pub fn jni_points() -> Vec<MountPoint> {
    kotama_runtime_jni::JNI_ENTRIES
        .iter()
        .map(|entry| MountPoint {
            runtime: Runtime::Jni,
            group: entry.slot,
            name: entry.name.to_string(),
            role: jni_role(entry.category),
        })
        .collect()
}

/// Every Lua C API function as a mount point, one group per name.
#[must_use]
pub fn lua_points() -> Vec<MountPoint> {
    kotama_runtime_lua::LUA_API
        .iter()
        .enumerate()
        .map(|(index, api)| MountPoint {
            runtime: Runtime::Lua,
            group: LUA_GROUP_BASE + u32::try_from(index).unwrap_or(u32::MAX),
            name: api.name.to_string(),
            role: lua_role(api.category),
        })
        .collect()
}

/// Every mount point of both runtimes, in one table.
#[must_use]
pub fn all_points() -> Vec<MountPoint> {
    let mut out = jni_points();
    out.extend(lua_points());
    out
}

/// Plan hooks over runtime mount points using the shared selector.
///
/// # Errors
/// Propagates the planner's errors: invalid regexes or names not in the table.
pub fn plan_runtime(
    points: &[MountPoint],
    selection: &HookSelection,
) -> Result<HookPlan, HookPlanError> {
    let symbols: Vec<HookableSymbol> = points.iter().map(MountPoint::hookable).collect();
    plan_hooks(&symbols, selection)
}

/// Narrow a selection to one role, returning the names that match.
///
/// Roles are not part of `HookSelection`, which only knows names; this resolves a
/// role to the names that carry it so it can be fed into the same planner.
#[must_use]
pub fn names_with_role(points: &[MountPoint], role: Role) -> Vec<String> {
    points
        .iter()
        .filter(|point| point.role == role)
        .map(|point| point.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_points_cover_every_slot_in_the_table() {
        let points = jni_points();
        assert_eq!(points.len(), kotama_runtime_jni::JNI_ENTRIES.len());
        assert!(points.iter().all(|p| p.runtime == Runtime::Jni));
        assert!(points.iter().all(|p| p.group >= 4));
    }

    #[test]
    fn lua_points_give_each_function_its_own_group() {
        let points = lua_points();
        assert_eq!(points.len(), kotama_runtime_lua::LUA_API.len());
        let groups: std::collections::BTreeSet<u32> = points.iter().map(|p| p.group).collect();
        assert_eq!(groups.len(), points.len());
    }

    #[test]
    fn the_shared_selector_plans_jni_slots_by_name() {
        let plan = plan_runtime(
            &jni_points(),
            &HookSelection {
                names: vec!["FindClass".to_string(), "GetStringUTFChars".to_string()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert_eq!(plan.hooks().len(), 2);
        assert!(plan
            .hooks()
            .values()
            .any(|r| r.names.contains(&"FindClass".to_string())));
    }

    #[test]
    fn the_shared_selector_plans_lua_functions_by_pattern() {
        let plan = plan_runtime(
            &lua_points(),
            &HookSelection {
                patterns: vec!["^lua_get.*".to_string()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert!(plan.hooks().len() > 5, "got {}", plan.hooks().len());
    }

    #[test]
    fn an_unknown_name_is_rejected_rather_than_silently_ignored() {
        let err = plan_runtime(
            &jni_points(),
            &HookSelection {
                names: vec!["NoSuchSlot".to_string()],
                ..HookSelection::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("NoSuchSlot"));
    }

    #[test]
    fn roles_resolve_to_names_the_planner_accepts() {
        let points = jni_points();
        let error_names = names_with_role(&points, Role::Error);
        assert!(!error_names.is_empty());
        let plan = plan_runtime(
            &points,
            &HookSelection {
                names: error_names,
                ..HookSelection::default()
            },
        )
        .unwrap();
        assert!(plan.hooks().len() >= 3);
    }

    #[test]
    fn the_two_runtables_do_not_share_group_keys() {
        // JNI slots start at 4; Lua groups are offset past the slot range so a plan
        // over both runtimes never merges a Lua function with a JNI slot.
        let all = all_points();
        let jni_groups: std::collections::BTreeSet<u32> = all
            .iter()
            .filter(|p| p.runtime == Runtime::Jni)
            .map(|p| p.group)
            .collect();
        let lua_groups: std::collections::BTreeSet<u32> = all
            .iter()
            .filter(|p| p.runtime == Runtime::Lua)
            .map(|p| p.group)
            .collect();
        assert!(
            jni_groups.intersection(&lua_groups).next().is_none(),
            "groups collide across runtimes"
        );
    }

    #[test]
    fn a_plan_over_both_runtimes_keeps_them_apart() {
        // The same selector over the combined table must hit a JNI slot and a Lua
        // function independently; before the Lua group base, index 6 of Lua and JNI
        // slot 6 (DefineClass) collapsed into one group.
        let all = all_points();
        let plan = plan_runtime(
            &all,
            &HookSelection {
                names: vec!["DefineClass".to_string(), "lua_callk".to_string()],
                ..HookSelection::default()
            },
        )
        .unwrap();
        let records: Vec<&Vec<String>> = plan.hooks().values().map(|r| &r.names).collect();
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(records
            .iter()
            .any(|n| n.contains(&"DefineClass".to_string())));
        assert!(records.iter().any(|n| n.contains(&"lua_callk".to_string())));
    }

    #[test]
    fn a_role_resolves_to_a_distinct_name_set_per_runtime() {
        let jni_state = names_with_role(&jni_points(), Role::State);
        let lua_state = names_with_role(&lua_points(), Role::State);
        assert!(!jni_state.is_empty() && !lua_state.is_empty());
        // The role must select, not merely exclude the other runtime: GetVersion is
        // State and FindClass is Lookup, so a filter that returned everything would
        // leak FindClass into this list.
        assert!(
            jni_state.contains(&"GetVersion".to_string()),
            "{jni_state:?}"
        );
        assert!(
            !jni_state.contains(&"FindClass".to_string()),
            "{jni_state:?}"
        );
        assert!(jni_state.iter().all(|n| !n.starts_with("lua_")));
        assert!(lua_state.iter().all(|n| n.starts_with("lua_")));
    }

    #[test]
    fn call_role_picks_the_calling_entries_of_each_runtime() {
        // Lua has exactly one Call category; JNI has a Call category of its own. Both
        // must resolve through the shared role without bleeding into the other table.
        let lua_call = names_with_role(&lua_points(), Role::Call);
        assert!(lua_call.contains(&"lua_callk".to_string()), "{lua_call:?}");
        assert!(lua_call.iter().all(|n| n.starts_with("lua_")));
        let jni_call = names_with_role(&jni_points(), Role::Call);
        assert!(!jni_call.is_empty());
        assert!(jni_call.iter().all(|n| !n.starts_with("lua_")));
    }

    #[test]
    fn every_role_is_reached_from_at_least_one_named_entry() {
        // Pins each mapping row by a concrete name, so a single mis-routed category
        // cannot hide behind a test that only checks the other runtime's prefix.
        let jni = jni_points();
        let lua = lua_points();
        let has = |points: &[MountPoint], role: Role, name: &str| {
            names_with_role(points, role).contains(&name.to_string())
        };
        assert!(has(&jni, Role::State, "GetVersion"));
        assert!(has(&jni, Role::Lookup, "FindClass"));
        assert!(has(&jni, Role::Error, "Throw"));
        assert!(has(&jni, Role::Memory, "NewGlobalRef"));
        assert!(has(&jni, Role::Data, "NewStringUTF"));
        assert!(has(&lua, Role::State, "lua_close"));
        assert!(has(&lua, Role::Lookup, "lua_getfield"));
        assert!(has(&lua, Role::Call, "lua_callk"));
        // and the negative side: a Lookup entry is not a Call
        assert!(!has(&lua, Role::Call, "lua_getfield"));
    }

    #[test]
    fn each_table_carries_its_own_runtime_tag() {
        assert!(lua_points().iter().all(|p| p.runtime == Runtime::Lua));
        assert!(jni_points().iter().all(|p| p.runtime == Runtime::Jni));
    }
}
