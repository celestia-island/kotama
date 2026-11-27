//! Runtime mounting facts for the Lua C API.
//!
//! Read-only half of a runtime hook shell: the exported core API with a semantic
//! category per function. It never installs anything.

pub mod api;

pub use api::{by_name, in_category, LuaApi, LuaCategory, KNOWN_ABSENT, LUA_API, LUA_VERSION_NUM};
