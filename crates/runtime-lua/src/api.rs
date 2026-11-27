//! Lua C API export description.
//!
//! Unlike the JNI native interface, the Lua C API is a set of directly exported
//! functions (`lua_*`) rather than a function-pointer table, so the
//! interposition point is the exported symbol itself. This module lists every public
//! core-API function with a semantic category, so a caller can decide what to
//! intercept by category and feed it straight into the container-agnostic hook
//! planner. It knows nothing about any particular Lua distribution's internals.
//!
//! The entries were extracted mechanically from the public `lua.h` header
//! (Lua 5.4), not typed by hand. The auxiliary library (`luaL_*`) lives in a
//! separate header and is not part of this table.

/// Semantic category of a Lua C API function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LuaCategory {
    /// State lifecycle, allocator, GC, panic.
    State,
    /// Stack discipline: top, index, move, rotate.
    Stack,
    /// Pushing values onto the stack.
    Push,
    /// Type queries, conversions and length.
    Convert,
    /// Table, userdata, metatable, upvalue and field access.
    Access,
    /// Global variable access.
    Global,
    /// Calling Lua, coroutine resume/yield, loading and dumping.
    Call,
}

impl LuaCategory {
    /// Stable lowercase name for reports.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Stack => "stack",
            Self::Push => "push",
            Self::Convert => "convert",
            Self::Access => "access",
            Self::Global => "global",
            Self::Call => "call",
        }
    }
}

/// One public Lua C API function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LuaApi {
    /// Exported function name.
    pub name: &'static str,
    /// Semantic category.
    pub category: LuaCategory,
}

impl LuaApi {
    const fn new(name: &'static str, category: LuaCategory) -> Self {
        Self { name, category }
    }
}

/// The public core-API functions, sorted by name.
pub const LUA_API: &[LuaApi] = &[
    LuaApi::new("lua_absindex", LuaCategory::Stack),
    LuaApi::new("lua_arith", LuaCategory::Push),
    LuaApi::new("lua_atpanic", LuaCategory::State),
    LuaApi::new("lua_callk", LuaCategory::Call),
    LuaApi::new("lua_checkstack", LuaCategory::State),
    LuaApi::new("lua_close", LuaCategory::State),
    LuaApi::new("lua_closeslot", LuaCategory::Stack),
    LuaApi::new("lua_closethread", LuaCategory::State),
    LuaApi::new("lua_compare", LuaCategory::Convert),
    LuaApi::new("lua_concat", LuaCategory::Push),
    LuaApi::new("lua_copy", LuaCategory::Stack),
    LuaApi::new("lua_createtable", LuaCategory::Access),
    LuaApi::new("lua_dump", LuaCategory::Call),
    LuaApi::new("lua_error", LuaCategory::Call),
    LuaApi::new("lua_gc", LuaCategory::State),
    LuaApi::new("lua_getallocf", LuaCategory::State),
    LuaApi::new("lua_getfield", LuaCategory::Access),
    LuaApi::new("lua_getglobal", LuaCategory::Global),
    LuaApi::new("lua_gethook", LuaCategory::Call),
    LuaApi::new("lua_gethookcount", LuaCategory::Call),
    LuaApi::new("lua_gethookmask", LuaCategory::Call),
    LuaApi::new("lua_geti", LuaCategory::Access),
    LuaApi::new("lua_getinfo", LuaCategory::Access),
    LuaApi::new("lua_getiuservalue", LuaCategory::Access),
    LuaApi::new("lua_getlocal", LuaCategory::Access),
    LuaApi::new("lua_getmetatable", LuaCategory::Access),
    LuaApi::new("lua_getstack", LuaCategory::Call),
    LuaApi::new("lua_gettable", LuaCategory::Access),
    LuaApi::new("lua_gettop", LuaCategory::Stack),
    LuaApi::new("lua_getupvalue", LuaCategory::Access),
    LuaApi::new("lua_iscfunction", LuaCategory::Convert),
    LuaApi::new("lua_isinteger", LuaCategory::Convert),
    LuaApi::new("lua_isnumber", LuaCategory::Convert),
    LuaApi::new("lua_isstring", LuaCategory::Convert),
    LuaApi::new("lua_isuserdata", LuaCategory::Convert),
    LuaApi::new("lua_isyieldable", LuaCategory::Convert),
    LuaApi::new("lua_len", LuaCategory::Push),
    LuaApi::new("lua_load", LuaCategory::Call),
    LuaApi::new("lua_newstate", LuaCategory::State),
    LuaApi::new("lua_newthread", LuaCategory::State),
    LuaApi::new("lua_newuserdatauv", LuaCategory::Access),
    LuaApi::new("lua_next", LuaCategory::Access),
    LuaApi::new("lua_pcallk", LuaCategory::Call),
    LuaApi::new("lua_pushboolean", LuaCategory::Push),
    LuaApi::new("lua_pushcclosure", LuaCategory::Push),
    LuaApi::new("lua_pushfstring", LuaCategory::Push),
    LuaApi::new("lua_pushinteger", LuaCategory::Push),
    LuaApi::new("lua_pushlightuserdata", LuaCategory::Push),
    LuaApi::new("lua_pushlstring", LuaCategory::Push),
    LuaApi::new("lua_pushnil", LuaCategory::Push),
    LuaApi::new("lua_pushnumber", LuaCategory::Push),
    LuaApi::new("lua_pushstring", LuaCategory::Push),
    LuaApi::new("lua_pushthread", LuaCategory::Push),
    LuaApi::new("lua_pushvalue", LuaCategory::Stack),
    LuaApi::new("lua_pushvfstring", LuaCategory::Push),
    LuaApi::new("lua_rawequal", LuaCategory::Convert),
    LuaApi::new("lua_rawget", LuaCategory::Access),
    LuaApi::new("lua_rawgeti", LuaCategory::Access),
    LuaApi::new("lua_rawgetp", LuaCategory::Access),
    LuaApi::new("lua_rawlen", LuaCategory::Convert),
    LuaApi::new("lua_rawset", LuaCategory::Access),
    LuaApi::new("lua_rawseti", LuaCategory::Access),
    LuaApi::new("lua_rawsetp", LuaCategory::Access),
    LuaApi::new("lua_resetthread", LuaCategory::State),
    LuaApi::new("lua_resume", LuaCategory::Call),
    LuaApi::new("lua_rotate", LuaCategory::State),
    LuaApi::new("lua_setallocf", LuaCategory::State),
    LuaApi::new("lua_setcstacklimit", LuaCategory::Access),
    LuaApi::new("lua_setfield", LuaCategory::Access),
    LuaApi::new("lua_setglobal", LuaCategory::Global),
    LuaApi::new("lua_sethook", LuaCategory::Call),
    LuaApi::new("lua_seti", LuaCategory::Access),
    LuaApi::new("lua_setiuservalue", LuaCategory::Access),
    LuaApi::new("lua_setlocal", LuaCategory::Access),
    LuaApi::new("lua_setmetatable", LuaCategory::Access),
    LuaApi::new("lua_settable", LuaCategory::Access),
    LuaApi::new("lua_settop", LuaCategory::Stack),
    LuaApi::new("lua_setupvalue", LuaCategory::Access),
    LuaApi::new("lua_setwarnf", LuaCategory::Access),
    LuaApi::new("lua_status", LuaCategory::Call),
    LuaApi::new("lua_stringtonumber", LuaCategory::Push),
    LuaApi::new("lua_toboolean", LuaCategory::Convert),
    LuaApi::new("lua_tocfunction", LuaCategory::Convert),
    LuaApi::new("lua_toclose", LuaCategory::Convert),
    LuaApi::new("lua_tointegerx", LuaCategory::Convert),
    LuaApi::new("lua_tolstring", LuaCategory::Convert),
    LuaApi::new("lua_tonumberx", LuaCategory::Convert),
    LuaApi::new("lua_topointer", LuaCategory::Convert),
    LuaApi::new("lua_tothread", LuaCategory::Convert),
    LuaApi::new("lua_touserdata", LuaCategory::Convert),
    LuaApi::new("lua_type", LuaCategory::Convert),
    LuaApi::new("lua_typename", LuaCategory::Convert),
    LuaApi::new("lua_upvalueid", LuaCategory::Access),
    LuaApi::new("lua_upvaluejoin", LuaCategory::Access),
    LuaApi::new("lua_version", LuaCategory::State),
    LuaApi::new("lua_warning", LuaCategory::State),
    LuaApi::new("lua_xmove", LuaCategory::Stack),
    LuaApi::new("lua_yieldk", LuaCategory::Call),
];

/// Core-API functions that a given Lua minor version is known NOT to export.
///
/// Observed on real binaries: a 5.4 build exports the whole table; a 5.3 build
/// lacks the 5.4 additions and still exports the pre-uv userdata names; a 5.1
/// build predates the 5.2 stack/index API and the `k`-suffixed call variants.
/// A mount plan must check the target's version before selecting these.
pub const KNOWN_ABSENT: &[(u32, &[&str])] = &[
    (
        503,
        &[
            "lua_closeslot",
            "lua_closethread",
            "lua_getiuservalue",
            "lua_newuserdatauv",
            "lua_resetthread",
            "lua_setcstacklimit",
            "lua_setiuservalue",
            "lua_setwarnf",
            "lua_toclose",
            "lua_warning",
        ],
    ),
    (
        501,
        &[
            "lua_absindex",
            "lua_arith",
            "lua_callk",
            "lua_closeslot",
            "lua_closethread",
            "lua_compare",
            "lua_copy",
            "lua_getglobal",
            "lua_geti",
            "lua_getiuservalue",
            "lua_isinteger",
            "lua_isyieldable",
            "lua_len",
            "lua_newuserdatauv",
            "lua_pcallk",
            "lua_rawgetp",
            "lua_rawlen",
            "lua_rawsetp",
            "lua_resetthread",
            "lua_rotate",
            "lua_setcstacklimit",
            "lua_setglobal",
            "lua_seti",
            "lua_setiuservalue",
            "lua_setwarnf",
            "lua_stringtonumber",
            "lua_toclose",
            "lua_tointegerx",
            "lua_tonumberx",
            "lua_upvalueid",
            "lua_upvaluejoin",
            "lua_version",
            "lua_warning",
            "lua_yieldk",
        ],
    ),
];

/// Lua version this table was derived from (LUA_VERSION_NUM).
pub const LUA_VERSION_NUM: u32 = 504;

/// Look up an API function by exact name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static LuaApi> {
    LUA_API
        .binary_search_by(|entry| entry.name.cmp(name))
        .ok()
        .map(|index| &LUA_API[index])
}

/// Every API function in a category, in name order.
pub fn in_category(category: LuaCategory) -> impl Iterator<Item = &'static LuaApi> {
    LUA_API
        .iter()
        .filter(move |entry| entry.category == category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_sorted_and_unique() {
        for pair in LUA_API.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} !< {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn the_public_core_api_is_complete() {
        assert_eq!(LUA_API.len(), 98);
        for name in [
            "lua_newstate",
            "lua_close",
            "lua_pushinteger",
            "lua_tolstring",
            "lua_setglobal",
            "lua_pcallk",
            "lua_resume",
            "lua_yieldk",
            "lua_getfield",
            "lua_setmetatable",
            "lua_gc",
            "lua_error",
        ] {
            assert!(by_name(name).is_some(), "{name} missing");
        }
    }

    #[test]
    fn lookup_is_exact() {
        assert_eq!(by_name("lua_pushnil").unwrap().category, LuaCategory::Push);
        assert!(by_name("lua_pushnilx").is_none());
        assert!(
            by_name("luaL_checkinteger").is_none(),
            "aux library is not in this table"
        );
    }

    #[test]
    fn known_absent_lists_only_reference_real_table_entries() {
        for (version, names) in KNOWN_ABSENT {
            for name in *names {
                assert!(
                    by_name(name).is_some(),
                    "{version} cites {name} which is not in the table"
                );
            }
        }
        // A 5.1 absence is a superset constraint: every 5.3 absence is also absent in 5.1.
        let v503 = KNOWN_ABSENT.iter().find(|(v, _)| *v == 503).unwrap().1;
        let v501 = KNOWN_ABSENT.iter().find(|(v, _)| *v == 501).unwrap().1;
        for n in v503 {
            assert!(v501.contains(n), "5.1 must also lack {n}");
        }
    }

    #[test]
    fn every_category_is_populated() {
        for category in [
            LuaCategory::State,
            LuaCategory::Stack,
            LuaCategory::Push,
            LuaCategory::Convert,
            LuaCategory::Access,
            LuaCategory::Global,
            LuaCategory::Call,
        ] {
            assert!(
                in_category(category).next().is_some(),
                "{category:?} has no members"
            );
        }
    }
}
