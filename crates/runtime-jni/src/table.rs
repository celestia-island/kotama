//! JNI native-interface table description.
//!
//! A JVM embeds a `JNINativeInterface_`: a table of function pointers whose
//! slot order is frozen by the JNI specification. Every `JNIEnv*` handed to
//! native code points at this table, so a slot is the single interposition
//! point for a whole category of runtime activity. This module describes the
//! table as data: slot index, name, and the semantic category of the call.
//! It knows nothing about any particular JVM vendor's internals.
//!
//! The four reserved slots (0..=3) are deliberately absent: they are not part
//! of the public contract and must never be planned against. The slot order
//! was extracted mechanically from the public `jni.h` specification header,
//! not typed by hand.

/// Semantic category of a JNI entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JniCategory {
    /// Version and environment queries.
    Environment,
    /// Class lookup, method/field ids, reflection bridges.
    Class,
    /// Exceptions: throw, describe, clear.
    Exception,
    /// Global / local / weak references and direct buffers.
    Reference,
    /// `jstring` construction and UTF / char access.
    String,
    /// Array allocation, element and region access.
    Array,
    /// Object construction.
    Object,
    /// Instance and static field access by signature.
    Field,
    /// Method invocation by signature, virtual and non-virtual.
    Call,
    /// Native binding registration and monitors.
    Native,
    /// Virtual-thread query.
    Thread,
    /// Creating, attaching to and destroying a VM.
    Invocation,
}

impl JniCategory {
    /// Stable lowercase name for reports.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Class => "class",
            Self::Exception => "exception",
            Self::Reference => "reference",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
            Self::Field => "field",
            Self::Call => "call",
            Self::Native => "native",
            Self::Thread => "thread",
            Self::Invocation => "invocation",
        }
    }
}

/// One public JNI entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JniEntry {
    /// Slot index in `JNINativeInterface_`, as frozen by the specification.
    pub slot: u32,
    /// Entry point name.
    pub name: &'static str,
    /// Semantic category.
    pub category: JniCategory,
}

impl JniEntry {
    const fn new(slot: u32, name: &'static str, category: JniCategory) -> Self {
        Self {
            slot,
            name,
            category,
        }
    }
}

/// The public JNI native-interface entries in slot order.
///
/// Covers slots 4..=235, every entry present in the JNI 1.2 table plus the
/// direct-buffer, weak-reference, module, virtual-thread and long-UTF-length
/// additions. It stops at the last published slot so it never assumes a vendor
/// extension.
pub const JNI_ENTRIES: &[JniEntry] = &[
    JniEntry::new(4, "GetVersion", JniCategory::Environment),
    JniEntry::new(5, "DefineClass", JniCategory::Class),
    JniEntry::new(6, "FindClass", JniCategory::Class),
    JniEntry::new(7, "FromReflectedMethod", JniCategory::Class),
    JniEntry::new(8, "FromReflectedField", JniCategory::Class),
    JniEntry::new(9, "ToReflectedMethod", JniCategory::Class),
    JniEntry::new(10, "GetSuperclass", JniCategory::Class),
    JniEntry::new(11, "IsAssignableFrom", JniCategory::Class),
    JniEntry::new(12, "ToReflectedField", JniCategory::Class),
    JniEntry::new(13, "Throw", JniCategory::Exception),
    JniEntry::new(14, "ThrowNew", JniCategory::Exception),
    JniEntry::new(15, "ExceptionOccurred", JniCategory::Exception),
    JniEntry::new(16, "ExceptionDescribe", JniCategory::Exception),
    JniEntry::new(17, "ExceptionClear", JniCategory::Exception),
    JniEntry::new(18, "FatalError", JniCategory::Exception),
    JniEntry::new(19, "PushLocalFrame", JniCategory::Reference),
    JniEntry::new(20, "PopLocalFrame", JniCategory::Reference),
    JniEntry::new(21, "NewGlobalRef", JniCategory::Reference),
    JniEntry::new(22, "DeleteGlobalRef", JniCategory::Reference),
    JniEntry::new(23, "DeleteLocalRef", JniCategory::Reference),
    JniEntry::new(24, "IsSameObject", JniCategory::Reference),
    JniEntry::new(25, "NewLocalRef", JniCategory::Reference),
    JniEntry::new(26, "EnsureLocalCapacity", JniCategory::Reference),
    JniEntry::new(27, "AllocObject", JniCategory::Object),
    JniEntry::new(28, "NewObject", JniCategory::Object),
    JniEntry::new(29, "NewObjectV", JniCategory::Object),
    JniEntry::new(30, "NewObjectA", JniCategory::Object),
    JniEntry::new(31, "GetObjectClass", JniCategory::Class),
    JniEntry::new(32, "IsInstanceOf", JniCategory::Class),
    JniEntry::new(33, "GetMethodID", JniCategory::Class),
    JniEntry::new(34, "CallObjectMethod", JniCategory::Call),
    JniEntry::new(35, "CallObjectMethodV", JniCategory::Call),
    JniEntry::new(36, "CallObjectMethodA", JniCategory::Call),
    JniEntry::new(37, "CallBooleanMethod", JniCategory::Call),
    JniEntry::new(38, "CallBooleanMethodV", JniCategory::Call),
    JniEntry::new(39, "CallBooleanMethodA", JniCategory::Call),
    JniEntry::new(40, "CallByteMethod", JniCategory::Call),
    JniEntry::new(41, "CallByteMethodV", JniCategory::Call),
    JniEntry::new(42, "CallByteMethodA", JniCategory::Call),
    JniEntry::new(43, "CallCharMethod", JniCategory::Call),
    JniEntry::new(44, "CallCharMethodV", JniCategory::Call),
    JniEntry::new(45, "CallCharMethodA", JniCategory::Call),
    JniEntry::new(46, "CallShortMethod", JniCategory::Call),
    JniEntry::new(47, "CallShortMethodV", JniCategory::Call),
    JniEntry::new(48, "CallShortMethodA", JniCategory::Call),
    JniEntry::new(49, "CallIntMethod", JniCategory::Call),
    JniEntry::new(50, "CallIntMethodV", JniCategory::Call),
    JniEntry::new(51, "CallIntMethodA", JniCategory::Call),
    JniEntry::new(52, "CallLongMethod", JniCategory::Call),
    JniEntry::new(53, "CallLongMethodV", JniCategory::Call),
    JniEntry::new(54, "CallLongMethodA", JniCategory::Call),
    JniEntry::new(55, "CallFloatMethod", JniCategory::Call),
    JniEntry::new(56, "CallFloatMethodV", JniCategory::Call),
    JniEntry::new(57, "CallFloatMethodA", JniCategory::Call),
    JniEntry::new(58, "CallDoubleMethod", JniCategory::Call),
    JniEntry::new(59, "CallDoubleMethodV", JniCategory::Call),
    JniEntry::new(60, "CallDoubleMethodA", JniCategory::Call),
    JniEntry::new(61, "CallVoidMethod", JniCategory::Call),
    JniEntry::new(62, "CallVoidMethodV", JniCategory::Call),
    JniEntry::new(63, "CallVoidMethodA", JniCategory::Call),
    JniEntry::new(64, "CallNonvirtualObjectMethod", JniCategory::Call),
    JniEntry::new(65, "CallNonvirtualObjectMethodV", JniCategory::Call),
    JniEntry::new(66, "CallNonvirtualObjectMethodA", JniCategory::Call),
    JniEntry::new(67, "CallNonvirtualBooleanMethod", JniCategory::Call),
    JniEntry::new(68, "CallNonvirtualBooleanMethodV", JniCategory::Call),
    JniEntry::new(69, "CallNonvirtualBooleanMethodA", JniCategory::Call),
    JniEntry::new(70, "CallNonvirtualByteMethod", JniCategory::Call),
    JniEntry::new(71, "CallNonvirtualByteMethodV", JniCategory::Call),
    JniEntry::new(72, "CallNonvirtualByteMethodA", JniCategory::Call),
    JniEntry::new(73, "CallNonvirtualCharMethod", JniCategory::Call),
    JniEntry::new(74, "CallNonvirtualCharMethodV", JniCategory::Call),
    JniEntry::new(75, "CallNonvirtualCharMethodA", JniCategory::Call),
    JniEntry::new(76, "CallNonvirtualShortMethod", JniCategory::Call),
    JniEntry::new(77, "CallNonvirtualShortMethodV", JniCategory::Call),
    JniEntry::new(78, "CallNonvirtualShortMethodA", JniCategory::Call),
    JniEntry::new(79, "CallNonvirtualIntMethod", JniCategory::Call),
    JniEntry::new(80, "CallNonvirtualIntMethodV", JniCategory::Call),
    JniEntry::new(81, "CallNonvirtualIntMethodA", JniCategory::Call),
    JniEntry::new(82, "CallNonvirtualLongMethod", JniCategory::Call),
    JniEntry::new(83, "CallNonvirtualLongMethodV", JniCategory::Call),
    JniEntry::new(84, "CallNonvirtualLongMethodA", JniCategory::Call),
    JniEntry::new(85, "CallNonvirtualFloatMethod", JniCategory::Call),
    JniEntry::new(86, "CallNonvirtualFloatMethodV", JniCategory::Call),
    JniEntry::new(87, "CallNonvirtualFloatMethodA", JniCategory::Call),
    JniEntry::new(88, "CallNonvirtualDoubleMethod", JniCategory::Call),
    JniEntry::new(89, "CallNonvirtualDoubleMethodV", JniCategory::Call),
    JniEntry::new(90, "CallNonvirtualDoubleMethodA", JniCategory::Call),
    JniEntry::new(91, "CallNonvirtualVoidMethod", JniCategory::Call),
    JniEntry::new(92, "CallNonvirtualVoidMethodV", JniCategory::Call),
    JniEntry::new(93, "CallNonvirtualVoidMethodA", JniCategory::Call),
    JniEntry::new(94, "GetFieldID", JniCategory::Class),
    JniEntry::new(95, "GetObjectField", JniCategory::Field),
    JniEntry::new(96, "GetBooleanField", JniCategory::Field),
    JniEntry::new(97, "GetByteField", JniCategory::Field),
    JniEntry::new(98, "GetCharField", JniCategory::Field),
    JniEntry::new(99, "GetShortField", JniCategory::Field),
    JniEntry::new(100, "GetIntField", JniCategory::Field),
    JniEntry::new(101, "GetLongField", JniCategory::Field),
    JniEntry::new(102, "GetFloatField", JniCategory::Field),
    JniEntry::new(103, "GetDoubleField", JniCategory::Field),
    JniEntry::new(104, "SetObjectField", JniCategory::Field),
    JniEntry::new(105, "SetBooleanField", JniCategory::Field),
    JniEntry::new(106, "SetByteField", JniCategory::Field),
    JniEntry::new(107, "SetCharField", JniCategory::Field),
    JniEntry::new(108, "SetShortField", JniCategory::Field),
    JniEntry::new(109, "SetIntField", JniCategory::Field),
    JniEntry::new(110, "SetLongField", JniCategory::Field),
    JniEntry::new(111, "SetFloatField", JniCategory::Field),
    JniEntry::new(112, "SetDoubleField", JniCategory::Field),
    JniEntry::new(113, "GetStaticMethodID", JniCategory::Class),
    JniEntry::new(114, "CallStaticObjectMethod", JniCategory::Call),
    JniEntry::new(115, "CallStaticObjectMethodV", JniCategory::Call),
    JniEntry::new(116, "CallStaticObjectMethodA", JniCategory::Call),
    JniEntry::new(117, "CallStaticBooleanMethod", JniCategory::Call),
    JniEntry::new(118, "CallStaticBooleanMethodV", JniCategory::Call),
    JniEntry::new(119, "CallStaticBooleanMethodA", JniCategory::Call),
    JniEntry::new(120, "CallStaticByteMethod", JniCategory::Call),
    JniEntry::new(121, "CallStaticByteMethodV", JniCategory::Call),
    JniEntry::new(122, "CallStaticByteMethodA", JniCategory::Call),
    JniEntry::new(123, "CallStaticCharMethod", JniCategory::Call),
    JniEntry::new(124, "CallStaticCharMethodV", JniCategory::Call),
    JniEntry::new(125, "CallStaticCharMethodA", JniCategory::Call),
    JniEntry::new(126, "CallStaticShortMethod", JniCategory::Call),
    JniEntry::new(127, "CallStaticShortMethodV", JniCategory::Call),
    JniEntry::new(128, "CallStaticShortMethodA", JniCategory::Call),
    JniEntry::new(129, "CallStaticIntMethod", JniCategory::Call),
    JniEntry::new(130, "CallStaticIntMethodV", JniCategory::Call),
    JniEntry::new(131, "CallStaticIntMethodA", JniCategory::Call),
    JniEntry::new(132, "CallStaticLongMethod", JniCategory::Call),
    JniEntry::new(133, "CallStaticLongMethodV", JniCategory::Call),
    JniEntry::new(134, "CallStaticLongMethodA", JniCategory::Call),
    JniEntry::new(135, "CallStaticFloatMethod", JniCategory::Call),
    JniEntry::new(136, "CallStaticFloatMethodV", JniCategory::Call),
    JniEntry::new(137, "CallStaticFloatMethodA", JniCategory::Call),
    JniEntry::new(138, "CallStaticDoubleMethod", JniCategory::Call),
    JniEntry::new(139, "CallStaticDoubleMethodV", JniCategory::Call),
    JniEntry::new(140, "CallStaticDoubleMethodA", JniCategory::Call),
    JniEntry::new(141, "CallStaticVoidMethod", JniCategory::Call),
    JniEntry::new(142, "CallStaticVoidMethodV", JniCategory::Call),
    JniEntry::new(143, "CallStaticVoidMethodA", JniCategory::Call),
    JniEntry::new(144, "GetStaticFieldID", JniCategory::Class),
    JniEntry::new(145, "GetStaticObjectField", JniCategory::Field),
    JniEntry::new(146, "GetStaticBooleanField", JniCategory::Field),
    JniEntry::new(147, "GetStaticByteField", JniCategory::Field),
    JniEntry::new(148, "GetStaticCharField", JniCategory::Field),
    JniEntry::new(149, "GetStaticShortField", JniCategory::Field),
    JniEntry::new(150, "GetStaticIntField", JniCategory::Field),
    JniEntry::new(151, "GetStaticLongField", JniCategory::Field),
    JniEntry::new(152, "GetStaticFloatField", JniCategory::Field),
    JniEntry::new(153, "GetStaticDoubleField", JniCategory::Field),
    JniEntry::new(154, "SetStaticObjectField", JniCategory::Field),
    JniEntry::new(155, "SetStaticBooleanField", JniCategory::Field),
    JniEntry::new(156, "SetStaticByteField", JniCategory::Field),
    JniEntry::new(157, "SetStaticCharField", JniCategory::Field),
    JniEntry::new(158, "SetStaticShortField", JniCategory::Field),
    JniEntry::new(159, "SetStaticIntField", JniCategory::Field),
    JniEntry::new(160, "SetStaticLongField", JniCategory::Field),
    JniEntry::new(161, "SetStaticFloatField", JniCategory::Field),
    JniEntry::new(162, "SetStaticDoubleField", JniCategory::Field),
    JniEntry::new(163, "NewString", JniCategory::String),
    JniEntry::new(164, "GetStringLength", JniCategory::String),
    JniEntry::new(165, "GetStringChars", JniCategory::String),
    JniEntry::new(166, "ReleaseStringChars", JniCategory::String),
    JniEntry::new(167, "NewStringUTF", JniCategory::String),
    JniEntry::new(168, "GetStringUTFLength", JniCategory::String),
    JniEntry::new(169, "GetStringUTFChars", JniCategory::String),
    JniEntry::new(170, "ReleaseStringUTFChars", JniCategory::String),
    JniEntry::new(171, "GetArrayLength", JniCategory::Array),
    JniEntry::new(172, "NewObjectArray", JniCategory::Array),
    JniEntry::new(173, "GetObjectArrayElement", JniCategory::Array),
    JniEntry::new(174, "SetObjectArrayElement", JniCategory::Array),
    JniEntry::new(175, "NewBooleanArray", JniCategory::Array),
    JniEntry::new(176, "NewByteArray", JniCategory::Array),
    JniEntry::new(177, "NewCharArray", JniCategory::Array),
    JniEntry::new(178, "NewShortArray", JniCategory::Array),
    JniEntry::new(179, "NewIntArray", JniCategory::Array),
    JniEntry::new(180, "NewLongArray", JniCategory::Array),
    JniEntry::new(181, "NewFloatArray", JniCategory::Array),
    JniEntry::new(182, "NewDoubleArray", JniCategory::Array),
    JniEntry::new(183, "GetBooleanArrayElements", JniCategory::Array),
    JniEntry::new(184, "GetByteArrayElements", JniCategory::Array),
    JniEntry::new(185, "GetCharArrayElements", JniCategory::Array),
    JniEntry::new(186, "GetShortArrayElements", JniCategory::Array),
    JniEntry::new(187, "GetIntArrayElements", JniCategory::Array),
    JniEntry::new(188, "GetLongArrayElements", JniCategory::Array),
    JniEntry::new(189, "GetFloatArrayElements", JniCategory::Array),
    JniEntry::new(190, "GetDoubleArrayElements", JniCategory::Array),
    JniEntry::new(191, "ReleaseBooleanArrayElements", JniCategory::Array),
    JniEntry::new(192, "ReleaseByteArrayElements", JniCategory::Array),
    JniEntry::new(193, "ReleaseCharArrayElements", JniCategory::Array),
    JniEntry::new(194, "ReleaseShortArrayElements", JniCategory::Array),
    JniEntry::new(195, "ReleaseIntArrayElements", JniCategory::Array),
    JniEntry::new(196, "ReleaseLongArrayElements", JniCategory::Array),
    JniEntry::new(197, "ReleaseFloatArrayElements", JniCategory::Array),
    JniEntry::new(198, "ReleaseDoubleArrayElements", JniCategory::Array),
    JniEntry::new(199, "GetBooleanArrayRegion", JniCategory::Array),
    JniEntry::new(200, "GetByteArrayRegion", JniCategory::Array),
    JniEntry::new(201, "GetCharArrayRegion", JniCategory::Array),
    JniEntry::new(202, "GetShortArrayRegion", JniCategory::Array),
    JniEntry::new(203, "GetIntArrayRegion", JniCategory::Array),
    JniEntry::new(204, "GetLongArrayRegion", JniCategory::Array),
    JniEntry::new(205, "GetFloatArrayRegion", JniCategory::Array),
    JniEntry::new(206, "GetDoubleArrayRegion", JniCategory::Array),
    JniEntry::new(207, "SetBooleanArrayRegion", JniCategory::Array),
    JniEntry::new(208, "SetByteArrayRegion", JniCategory::Array),
    JniEntry::new(209, "SetCharArrayRegion", JniCategory::Array),
    JniEntry::new(210, "SetShortArrayRegion", JniCategory::Array),
    JniEntry::new(211, "SetIntArrayRegion", JniCategory::Array),
    JniEntry::new(212, "SetLongArrayRegion", JniCategory::Array),
    JniEntry::new(213, "SetFloatArrayRegion", JniCategory::Array),
    JniEntry::new(214, "SetDoubleArrayRegion", JniCategory::Array),
    JniEntry::new(215, "RegisterNatives", JniCategory::Native),
    JniEntry::new(216, "UnregisterNatives", JniCategory::Native),
    JniEntry::new(217, "MonitorEnter", JniCategory::Native),
    JniEntry::new(218, "MonitorExit", JniCategory::Native),
    JniEntry::new(219, "GetJavaVM", JniCategory::Invocation),
    JniEntry::new(220, "GetStringRegion", JniCategory::String),
    JniEntry::new(221, "GetStringUTFRegion", JniCategory::String),
    JniEntry::new(222, "GetPrimitiveArrayCritical", JniCategory::Array),
    JniEntry::new(223, "ReleasePrimitiveArrayCritical", JniCategory::Array),
    JniEntry::new(224, "GetStringCritical", JniCategory::String),
    JniEntry::new(225, "ReleaseStringCritical", JniCategory::String),
    JniEntry::new(226, "NewWeakGlobalRef", JniCategory::Reference),
    JniEntry::new(227, "DeleteWeakGlobalRef", JniCategory::Reference),
    JniEntry::new(228, "ExceptionCheck", JniCategory::Exception),
    JniEntry::new(229, "NewDirectByteBuffer", JniCategory::Reference),
    JniEntry::new(230, "GetDirectBufferAddress", JniCategory::Reference),
    JniEntry::new(231, "GetDirectBufferCapacity", JniCategory::Reference),
    JniEntry::new(232, "GetObjectRefType", JniCategory::Reference),
    JniEntry::new(233, "GetModule", JniCategory::Class),
    JniEntry::new(234, "IsVirtualThread", JniCategory::Thread),
    JniEntry::new(235, "GetStringUTFLengthAsLong", JniCategory::String),
];

/// Slot pairs that a conforming implementation is known to alias onto one
/// function (observed on a real JVM: the byte-sized and the boolean-sized
/// accessors share a body). Planning must treat each pair as one address.
pub const KNOWN_ALIAS_GROUPS: &[&[u32]] = &[
    &[146, 147], // GetStaticBooleanField / GetStaticByteField
    &[148, 149], // GetStaticCharField / GetStaticShortField
    &[183, 184], // GetBooleanArrayElements / GetByteArrayElements
    &[185, 186], // GetCharArrayElements / GetShortArrayElements
    &[187, 189], // GetIntArrayElements / GetFloatArrayElements
];

/// First public slot; slots below it are reserved by the specification.
pub const FIRST_PUBLIC_SLOT: u32 = 4;

/// Look up an entry by slot.
#[must_use]
pub fn by_slot(slot: u32) -> Option<&'static JniEntry> {
    JNI_ENTRIES
        .binary_search_by(|entry| entry.slot.cmp(&slot))
        .ok()
        .map(|index| &JNI_ENTRIES[index])
}

/// Look up an entry by exact name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static JniEntry> {
    JNI_ENTRIES.iter().find(|entry| entry.name == name)
}

/// Every entry in a category, in slot order.
pub fn in_category(category: JniCategory) -> impl Iterator<Item = &'static JniEntry> {
    JNI_ENTRIES
        .iter()
        .filter(move |entry| entry.category == category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_contiguous_from_the_first_public_slot() {
        assert_eq!(JNI_ENTRIES[0].slot, FIRST_PUBLIC_SLOT);
        for pair in JNI_ENTRIES.windows(2) {
            assert_eq!(pair[1].slot, pair[0].slot + 1, "gap after {}", pair[0].name);
        }
    }

    #[test]
    fn the_frozen_anchors_are_where_the_specification_puts_them() {
        // Slot numbers every JNI implementation publishes.
        assert_eq!(by_slot(4).unwrap().name, "GetVersion");
        assert_eq!(by_slot(6).unwrap().name, "FindClass");
        assert_eq!(by_slot(13).unwrap().name, "Throw");
        assert_eq!(by_slot(17).unwrap().name, "ExceptionClear");
        assert_eq!(by_slot(21).unwrap().name, "NewGlobalRef");
        assert_eq!(by_slot(215).unwrap().name, "RegisterNatives");
        assert_eq!(by_slot(217).unwrap().name, "MonitorEnter");
        assert_eq!(by_slot(219).unwrap().name, "GetJavaVM");
        assert_eq!(by_slot(228).unwrap().name, "ExceptionCheck");
    }

    #[test]
    fn reserved_slots_are_absent() {
        for slot in 0..FIRST_PUBLIC_SLOT {
            assert!(by_slot(slot).is_none());
        }
    }

    #[test]
    fn lookup_by_name_is_exact() {
        assert_eq!(by_name("GetStringUTFChars").unwrap().slot, 169);
        assert!(by_name("GetStringUTFCharsX").is_none());
        assert!(by_name("").is_none());
    }

    #[test]
    fn known_alias_groups_reference_real_slots() {
        for group in KNOWN_ALIAS_GROUPS {
            assert!(group.len() >= 2);
            for slot in *group {
                assert!(
                    by_slot(*slot).is_some(),
                    "alias group cites absent slot {slot}"
                );
            }
        }
    }

    #[test]
    fn every_entry_has_a_category_and_a_name() {
        assert!(!JNI_ENTRIES.is_empty());
        assert!(JNI_ENTRIES.iter().all(|entry| !entry.name.is_empty()));
        for category in [
            JniCategory::Environment,
            JniCategory::Class,
            JniCategory::Exception,
            JniCategory::Reference,
            JniCategory::String,
            JniCategory::Array,
            JniCategory::Object,
            JniCategory::Field,
            JniCategory::Call,
            JniCategory::Native,
            JniCategory::Thread,
            JniCategory::Invocation,
        ] {
            assert!(
                in_category(category).next().is_some(),
                "{category:?} has no members"
            );
        }
    }
}

/// The Invocation API: the `JNI_*` symbols a JVM library **exports directly**.
///
/// Everything in [`JNI_ENTRIES`] is reached through a `JNIEnv*`, which only exists
/// once a VM is in the process. These three are how it gets there, and they are
/// ordinary exported symbols rather than table slots — so they are what a module's
/// export table is searched for, and what a hook planner can describe before any
/// environment exists.
///
/// The names and the count were read off the export directory of a real JVM
/// library (`jvm.dll`, 4507 exports, exactly three `JNI_*`): the Invocation API
/// is specified as these three and nothing else, and the binary agrees.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvocationExport {
    /// Exported symbol name.
    pub name: &'static str,
    /// What the call does for a mount.
    pub role: InvocationRole,
}

/// What an Invocation API call means to someone mounting a runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvocationRole {
    /// Creates a VM and hands back its `JavaVM*` and a `JNIEnv*` for the current thread.
    CreateVm,
    /// Finds VMs already running in the process — the attach path for an injected agent.
    FindVms,
    /// Fills an init-args struct with defaults for the version; a prerequisite of `CreateVm`.
    DefaultInitArgs,
}

/// The Invocation API exports, sorted by name.
pub const INVOCATION_EXPORTS: &[InvocationExport] = &[
    InvocationExport {
        name: "JNI_CreateJavaVM",
        role: InvocationRole::CreateVm,
    },
    InvocationExport {
        name: "JNI_GetCreatedJavaVMs",
        role: InvocationRole::FindVms,
    },
    InvocationExport {
        name: "JNI_GetDefaultJavaVMInitArgs",
        role: InvocationRole::DefaultInitArgs,
    },
];

/// Look up an Invocation API export by its exact name.
#[must_use]
pub fn invocation_by_name(name: &str) -> Option<&'static InvocationExport> {
    INVOCATION_EXPORTS.iter().find(|export| export.name == name)
}

#[cfg(test)]
mod invocation_tests {
    use super::*;

    /// Exactly three, because that is what the specification defines and what the
    /// real library exports. A fourth would be a vendor extension, which this table
    /// deliberately does not assume.
    #[test]
    fn the_invocation_api_is_three_exports() {
        assert_eq!(INVOCATION_EXPORTS.len(), 3);
    }

    /// Sorted by name, as the planner's merge assumes.
    #[test]
    fn invocation_exports_are_sorted_by_name() {
        for pair in INVOCATION_EXPORTS.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} !< {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    /// The three names the binary exports, spelled exactly as it spells them.
    #[test]
    fn the_names_match_the_jvm_library_export_directory() {
        assert_eq!(
            INVOCATION_EXPORTS
                .iter()
                .map(|e| e.name)
                .collect::<Vec<_>>(),
            [
                "JNI_CreateJavaVM",
                "JNI_GetCreatedJavaVMs",
                "JNI_GetDefaultJavaVMInitArgs"
            ]
        );
    }

    /// Each role appears exactly once, so a mount plan can ask for "the create path"
    /// without naming the symbol.
    #[test]
    fn each_role_is_present_exactly_once() {
        for role in [
            InvocationRole::CreateVm,
            InvocationRole::FindVms,
            InvocationRole::DefaultInitArgs,
        ] {
            assert_eq!(
                INVOCATION_EXPORTS.iter().filter(|e| e.role == role).count(),
                1,
                "{role:?}"
            );
        }
    }

    /// The Invocation API and the table slots are disjoint namespaces: nothing here
    /// is a slot, nothing in the table is an export. The two halves of a mount must
    /// not be confused for one another.
    #[test]
    fn invocation_exports_are_not_table_slots_and_vice_versa() {
        for export in INVOCATION_EXPORTS {
            assert!(
                by_name(export.name).is_none(),
                "{} is an export, not a slot",
                export.name
            );
        }
        assert!(invocation_by_name("GetVersion").is_none());
    }

    /// An injected agent finds a running VM; it does not create one. The role the
    /// agent needs is the find path, and it must be addressable without the symbol.
    #[test]
    fn the_attach_path_is_addressable_by_role() {
        let find = INVOCATION_EXPORTS
            .iter()
            .find(|e| e.role == InvocationRole::FindVms)
            .expect("find path");
        assert_eq!(find.name, "JNI_GetCreatedJavaVMs");
    }

    #[test]
    fn lookup_by_name_is_exact() {
        assert!(invocation_by_name("JNI_CreateJavaVM").is_some());
        assert!(invocation_by_name("jni_createjavavm").is_none());
        assert!(invocation_by_name("CreateJavaVM").is_none());
    }
}
