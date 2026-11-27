//! Runtime mounting facts for the JNI native interface.
//!
//! This crate is the read-only half of a runtime hook shell: it knows the frozen
//! slot order of the JNI function table and the semantic category of every slot,
//! so a caller can decide what to intercept by category rather than by vendor
//! internals. It never installs anything.

pub mod table;

pub use table::{
    by_name, by_slot, in_category, invocation_by_name, InvocationExport, InvocationRole,
    JniCategory, JniEntry, FIRST_PUBLIC_SLOT, INVOCATION_EXPORTS, JNI_ENTRIES, KNOWN_ALIAS_GROUPS,
};
