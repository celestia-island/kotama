//! QuickJS-ng C ABI export facts for runtime mounting.
//!
//! This is the function table the QuickJS-ng engine exposes through extern C, as
//! re-implemented in pure Rust by the quickrs-capi crate. It matters here for one
//! specific reason: a Rust engine that speaks the QuickJS C ABI is mountable by the
//! same means as the C engine, because the hooks are extern symbols rather than Rust
//! trait methods, so the existing runtime-mount planner applies to it unchanged.
//!
//! The list was extracted from the published crate source (0.16.2), not typed by
//! hand, and the extraction is asserted by the test against the count.

/// Semantic category of a QuickJS entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuickJsCategory {
    /// Runtime operations.
    Runtime,
    /// Call operations.
    Call,
    /// Error operations.
    Error,
    /// Memory operations.
    Memory,
    /// Data operations.
    Data,
    /// Module operations.
    Module,
    /// Class operations.
    Class,
    /// Property operations.
    Property,
    /// Value operations.
    Value,
    /// Other operations.
    Other,
}

/// One QuickJS C ABI entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QuickJsEntry {
    /// Exported function name exactly as the C ABI spells it.
    pub name: &'static str,
    /// Semantic category.
    pub category: QuickJsCategory,
}

impl QuickJsEntry {
    const fn new(name: &'static str, category: QuickJsCategory) -> Self {
        Self { name, category }
    }
}

/// Crate version the table was extracted from.
pub const EXTRACTED_FROM: &str = "quickrs-capi 0.16.2";

/// The C ABI entry points, sorted by name.
pub const QUICKJS_ENTRIES: &[QuickJsEntry] = &[
    QuickJsEntry::new("JS_AddIntrinsicBaseObjects", QuickJsCategory::Other),
    QuickJsEntry::new("JS_AddIntrinsicRegExpCompiler", QuickJsCategory::Other),
    QuickJsEntry::new("JS_AddModuleExport", QuickJsCategory::Module),
    QuickJsEntry::new("JS_AddModuleExportList", QuickJsCategory::Module),
    QuickJsEntry::new("JS_AddRuntimeFinalizer", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_AtomToCStringLen", QuickJsCategory::Data),
    QuickJsEntry::new("JS_AtomToString", QuickJsCategory::Data),
    QuickJsEntry::new("JS_AtomToValue", QuickJsCategory::Data),
    QuickJsEntry::new("JS_Call", QuickJsCategory::Call),
    QuickJsEntry::new("JS_CallConstructor", QuickJsCategory::Call),
    QuickJsEntry::new("JS_CallConstructor2", QuickJsCategory::Call),
    QuickJsEntry::new("JS_ClearUncatchableError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ComputeMemoryUsage", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_DefineProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DefinePropertyGetSet", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DefinePropertyValue", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DefinePropertyValueStr", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DefinePropertyValueUint32", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DeleteProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_DetachArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_DetectModule", QuickJsCategory::Call),
    QuickJsEntry::new("JS_DumpMemoryUsage", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_DupAtom", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_DupAtomRT", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_DupContext", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_DupValue", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_DupValueRT", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_EnqueueJob", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_Eval", QuickJsCategory::Call),
    QuickJsEntry::new("JS_Eval2", QuickJsCategory::Call),
    QuickJsEntry::new("JS_EvalFunction", QuickJsCategory::Call),
    QuickJsEntry::new("JS_EvalThis", QuickJsCategory::Call),
    QuickJsEntry::new("JS_EvalThis2", QuickJsCategory::Call),
    QuickJsEntry::new("JS_ExecutePendingJob", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_FormatException", QuickJsCategory::Error),
    QuickJsEntry::new("JS_FreeAtom", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_FreeAtomRT", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_FreeCString", QuickJsCategory::Data),
    QuickJsEntry::new("JS_FreeCStringRT", QuickJsCategory::Data),
    QuickJsEntry::new("JS_FreeCStringRT_UTF16", QuickJsCategory::Data),
    QuickJsEntry::new("JS_FreeCStringUTF16", QuickJsCategory::Data),
    QuickJsEntry::new("JS_FreeContext", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_FreePropertyEnum", QuickJsCategory::Value),
    QuickJsEntry::new("JS_FreeRuntime", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_FreeValue", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_FreeValueRT", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_FreezeObject", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetAnyOpaque", QuickJsCategory::Value),
    QuickJsEntry::new("JS_GetArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_GetClassID", QuickJsCategory::Class),
    QuickJsEntry::new("JS_GetClassName", QuickJsCategory::Class),
    QuickJsEntry::new("JS_GetClassProto", QuickJsCategory::Class),
    QuickJsEntry::new("JS_GetContextOpaque", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetDumpFlags", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetException", QuickJsCategory::Error),
    QuickJsEntry::new("JS_GetFunctionProto", QuickJsCategory::Call),
    QuickJsEntry::new("JS_GetGCThreshold", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetGlobalObject", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetImportMeta", QuickJsCategory::Module),
    QuickJsEntry::new("JS_GetLength", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetModuleName", QuickJsCategory::Module),
    QuickJsEntry::new("JS_GetModuleNamespace", QuickJsCategory::Module),
    QuickJsEntry::new("JS_GetModulePrivateValue", QuickJsCategory::Module),
    QuickJsEntry::new("JS_GetOpaque", QuickJsCategory::Value),
    QuickJsEntry::new("JS_GetOpaque2", QuickJsCategory::Value),
    QuickJsEntry::new("JS_GetOwnProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetOwnPropertyNames", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPendingJobContext", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPropertyInt64", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPropertyStr", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPropertyUint32", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPropertyValue", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetPrototype", QuickJsCategory::Property),
    QuickJsEntry::new("JS_GetProxyHandler", QuickJsCategory::Value),
    QuickJsEntry::new("JS_GetProxyTarget", QuickJsCategory::Value),
    QuickJsEntry::new("JS_GetRuntime", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetRuntimeOpaque", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_GetScriptOrModuleName", QuickJsCategory::Module),
    QuickJsEntry::new("JS_GetTypedArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_GetTypedArrayType", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_GetUint8Array", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_GetVersion", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_HasException", QuickJsCategory::Error),
    QuickJsEntry::new("JS_HasProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_Invoke", QuickJsCategory::Call),
    QuickJsEntry::new("JS_IsArray", QuickJsCategory::Property),
    QuickJsEntry::new("JS_IsArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_IsAsyncFunction", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsConstructor", QuickJsCategory::Call),
    QuickJsEntry::new("JS_IsEqual", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_IsExtensible", QuickJsCategory::Property),
    QuickJsEntry::new("JS_IsFunction", QuickJsCategory::Call),
    QuickJsEntry::new("JS_IsImmutableArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_IsInstanceOf", QuickJsCategory::Property),
    QuickJsEntry::new("JS_IsJobPending", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_IsLiveObject", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsRegisteredClass", QuickJsCategory::Class),
    QuickJsEntry::new("JS_IsSameValue", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsSameValueZero", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsStrictEqual", QuickJsCategory::Value),
    QuickJsEntry::new("JS_IsUncatchableError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_JSONStringify", QuickJsCategory::Value),
    QuickJsEntry::new("JS_LoadModule", QuickJsCategory::Module),
    QuickJsEntry::new("JS_MarkValue", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_NewArray", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_NewArrayBufferCopy", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_NewArrayFrom", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewAtom", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewAtomLen", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewAtomString", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewAtomUInt32", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewBigInt64", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewBigUint64", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewCClosure", QuickJsCategory::Call),
    QuickJsEntry::new("JS_NewCFunction2", QuickJsCategory::Call),
    QuickJsEntry::new("JS_NewCFunction3", QuickJsCategory::Call),
    QuickJsEntry::new("JS_NewCFunctionData", QuickJsCategory::Call),
    QuickJsEntry::new("JS_NewCFunctionData2", QuickJsCategory::Call),
    QuickJsEntry::new("JS_NewCModule", QuickJsCategory::Module),
    QuickJsEntry::new("JS_NewClass", QuickJsCategory::Class),
    QuickJsEntry::new("JS_NewClassID", QuickJsCategory::Class),
    QuickJsEntry::new("JS_NewContext", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_NewContextRaw", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_NewDate", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_NewNumber", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewObject", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewObjectClass", QuickJsCategory::Class),
    QuickJsEntry::new("JS_NewObjectFrom", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewObjectFromStr", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewObjectProto", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewObjectProtoClass", QuickJsCategory::Class),
    QuickJsEntry::new("JS_NewObjectProtoClassExt", QuickJsCategory::Class),
    QuickJsEntry::new("JS_NewPrivateSymbol", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewPromiseCapability", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewProxy", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewRuntime", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_NewRuntime2", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_NewSettledPromise", QuickJsCategory::Value),
    QuickJsEntry::new("JS_NewStringLen", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewStringUTF16", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewSymbol", QuickJsCategory::Data),
    QuickJsEntry::new("JS_NewTypedArray", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_NewUint8Array", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_NewUint8ArrayCopy", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_ParseJSON", QuickJsCategory::Value),
    QuickJsEntry::new("JS_PreventExtensions", QuickJsCategory::Property),
    QuickJsEntry::new("JS_PromiseMarkAsHandled", QuickJsCategory::Value),
    QuickJsEntry::new("JS_PromiseResult", QuickJsCategory::Value),
    QuickJsEntry::new("JS_PromiseState", QuickJsCategory::Value),
    QuickJsEntry::new("JS_PromiseThen", QuickJsCategory::Value),
    QuickJsEntry::new("JS_ReadObject", QuickJsCategory::Value),
    QuickJsEntry::new("JS_ReadObject2", QuickJsCategory::Value),
    QuickJsEntry::new("JS_RegisterCModule", QuickJsCategory::Module),
    QuickJsEntry::new("JS_ResetUncatchableError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ResolveModule", QuickJsCategory::Module),
    QuickJsEntry::new("JS_RunGC", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SealObject", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetCanBlock", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetClassProto", QuickJsCategory::Class),
    QuickJsEntry::new("JS_SetConstructor", QuickJsCategory::Call),
    QuickJsEntry::new("JS_SetConstructorBit", QuickJsCategory::Call),
    QuickJsEntry::new("JS_SetContextOpaque", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetDumpFlags", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetGCThreshold", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetHostPromiseRejectionTracker", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetImmutableArrayBuffer", QuickJsCategory::Memory),
    QuickJsEntry::new("JS_SetInterruptHandler", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetIsHTMLDDA", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetLength", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetMaxStackSize", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetMemoryLimit", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetModuleExport", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetModuleExportList", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetModuleLoaderFunc", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetModuleLoaderFunc2", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetModuleNormalizeFunc2", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetModulePrivateValue", QuickJsCategory::Module),
    QuickJsEntry::new("JS_SetOpaque", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetPromiseHook", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetProperty", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPropertyFunctionList", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPropertyInt64", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPropertyStr", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPropertyUint32", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPropertyValue", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetPrototype", QuickJsCategory::Property),
    QuickJsEntry::new("JS_SetRuntimeInfo", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetRuntimeOpaque", QuickJsCategory::Runtime),
    QuickJsEntry::new("JS_SetSharedArrayBufferFunctions", QuickJsCategory::Value),
    QuickJsEntry::new("JS_SetUncatchableError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_Throw", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ThrowDOMException", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ThrowOutOfMemory", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ThrowTypeError", QuickJsCategory::Error),
    QuickJsEntry::new("JS_ToBigInt64", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToBigUint64", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToBool", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToCStringLen2", QuickJsCategory::Data),
    QuickJsEntry::new("JS_ToCStringLenUTF16", QuickJsCategory::Data),
    QuickJsEntry::new("JS_ToIndex", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToInt64", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToInt64Ext", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToNumber", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToObject", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToObjectString", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToPropertyKey", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ToString", QuickJsCategory::Other),
    QuickJsEntry::new("JS_UpdateStackTop", QuickJsCategory::Other),
    QuickJsEntry::new("JS_ValueToAtom", QuickJsCategory::Other),
    QuickJsEntry::new("JS_WriteObject", QuickJsCategory::Value),
    QuickJsEntry::new("JS_WriteObject2", QuickJsCategory::Value),
];

/// Look an entry up by its exact C name.
///
/// Binary search, which is only correct because the table is sorted; that makes the
/// ordering a functional invariant rather than one a test merely asserts.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static QuickJsEntry> {
    QUICKJS_ENTRIES
        .binary_search_by(|entry| entry.name.cmp(name))
        .ok()
        .map(|index| &QUICKJS_ENTRIES[index])
}

/// Every entry in a category, sorted by name.
///
/// The categories partition the table, so their sizes sum to its length; the test
/// checks that sum, which gives the count a second use beyond being asserted once.
#[must_use]
pub fn in_category(category: QuickJsCategory) -> Vec<&'static QuickJsEntry> {
    QUICKJS_ENTRIES
        .iter()
        .filter(|entry| entry.category == category)
        .collect()
}

/// Sum of `in_category` over every category, which must equal the table length.
#[must_use]
pub fn categorised_total() -> usize {
    use QuickJsCategory::*;
    [
        Runtime, Call, Error, Memory, Data, Module, Class, Property, Value, Other,
    ]
    .into_iter()
    .map(in_category)
    .map(|entries| entries.len())
    .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_extracted_count() {
        assert_eq!(QUICKJS_ENTRIES.len(), 215);
    }

    #[test]
    fn the_table_is_sorted_and_unique() {
        let names: Vec<&str> = QUICKJS_ENTRIES.iter().map(|e| e.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted);
    }

    #[test]
    fn the_core_lifecycle_entry_points_are_present() {
        for name in [
            "JS_NewRuntime",
            "JS_NewContext",
            "JS_Eval",
            "JS_Call",
            "JS_FreeRuntime",
        ] {
            assert!(by_name(name).is_some(), "{name} missing");
        }
    }

    #[test]
    fn lifecycle_entries_are_categorised() {
        assert_eq!(by_name("JS_Eval").unwrap().category, QuickJsCategory::Call);
        assert_eq!(
            by_name("JS_NewRuntime").unwrap().category,
            QuickJsCategory::Runtime
        );
        assert_eq!(
            by_name("JS_GetException").unwrap().category,
            QuickJsCategory::Error
        );
    }

    #[test]
    fn the_categories_partition_the_table() {
        assert_eq!(categorised_total(), QUICKJS_ENTRIES.len());
    }

    #[test]
    fn by_name_finds_entries_at_both_ends_and_the_middle() {
        // Binary search depends on ordering; probe the ends and a middle key so an
        // unsorted table fails here rather than silently returning nothing.
        assert!(by_name("JS_AddIntrinsicBaseObjects").is_some());
        assert!(by_name("JS_WriteObject").is_some());
        assert!(by_name("JS_NewRuntime").is_some());
        assert!(by_name("JS_NotARealEntry").is_none());
    }

    #[test]
    fn the_extracted_from_version_is_pinned() {
        // The table is only as trustworthy as its provenance; a silent re-extraction
        // against a different engine version must be a visible change.
        assert_eq!(EXTRACTED_FROM, "quickrs-capi 0.16.2");
    }
}
