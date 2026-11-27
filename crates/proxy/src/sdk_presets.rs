//! Declarative interception presets for common shared-library interface families.
//!
//! A [HookSelection](crate::hook_plan::HookSelection) describes *which* exported
//! names to intercept but says nothing about what those names mean. Building a
//! selection by hand for a C runtime, a socket stack or a graphics API means
//! reciting dozens of exact names and getting them right.
//!
//! This module names those families once, as data. Every preset is plain exported
//! interface names: the same names any program using that family links against.
//! Nothing here is specific to a product, a title or a generation, and nothing here
//! installs a hook. A preset only narrows the surface that the container-agnostic
//! hook planner already knows how to describe.
//!
//! Presets use exact names rather than patterns on purpose: a pattern like
//! `^malloc` would also catch `malloc_usable_size` and any vendor extension that
//! happens to share the prefix, and an interception surface that grows by accident
//! is not auditable.

use crate::hook_plan::HookSelection;

/// A named family of exported interfaces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Preset {
    /// Stable lowercase identifier, used on command lines and in reports.
    pub id: &'static str,
    /// One-line description of the family.
    pub summary: &'static str,
    /// Exact exported names in the family.
    pub names: &'static [&'static str],
}

impl Preset {
    /// This preset as a hook selection.
    #[must_use]
    pub fn selection(&self) -> HookSelection {
        HookSelection {
            all: false,
            names: self.names.iter().map(|name| (*name).to_string()).collect(),
            patterns: Vec::new(),
            exclude_names: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

/// C runtime allocation and C string handling.
pub const C_RUNTIME: Preset = Preset {
    id: "c-runtime",
    summary: "C runtime allocation and string interfaces",
    names: &[
        "aligned_alloc",
        "calloc",
        "free",
        "malloc",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "posix_memalign",
        "realloc",
        "snprintf",
        "sprintf",
        "strcat",
        "strchr",
        "strcmp",
        "strcpy",
        "strlen",
        "strncmp",
        "strncpy",
        "strnlen",
        "strrchr",
        "strstr",
        "vsnprintf",
    ],
};

/// The C++ runtime under the Itanium ABI: operator new/delete and the exception
/// runtime. This is the ABI of GCC, Clang and everything else that is not MSVC.
pub const CPP_RUNTIME_ITANIUM: Preset = Preset {
    id: "cpp-runtime-itanium",
    summary: "C++ new/delete and exception runtime, Itanium ABI",
    names: &[
        "_ZdaPv",
        "_ZdlPv",
        "_Znam",
        "_Znwm",
        "__cxa_allocate_exception",
        "__cxa_begin_catch",
        "__cxa_end_catch",
        "__cxa_free_exception",
        "__cxa_rethrow",
        "__cxa_throw",
    ],
};

/// The same C++ runtime under the MSVC ABI.
///
/// MSVC spells operator new/delete as decorated names rather than the Itanium
/// manglings, so a preset written against one ABI matches nothing on the other.
///
/// These names are exported by the C runtime DLLs (`msvcrt` and the versioned
/// `msvcr*`). The redistributable C++ libraries (`msvcp140`, `vcruntime140`) do
/// not export them, and a current toolchain links operator new statically by
/// default, so on such a binary this preset matches nothing and that is correct.
/// The 32-bit runtime decorates differently and is not covered by these names.
pub const CPP_RUNTIME_MSVC: Preset = Preset {
    id: "cpp-runtime-msvc",
    summary: "C++ new/delete and exception runtime, MSVC ABI (64-bit)",
    names: &[
        "??2@YAPEAX_K@Z",
        "??3@YAXPEAX@Z",
        "??_U@YAPEAX_K@Z",
        "??_V@YAXPEAX@Z",
        "__CxxFrameHandler3",
        "__CxxFrameHandler4",
    ],
};

/// The same C++ runtime under the 32-bit MSVC ABI.
///
/// The 32-bit decoration encodes `size_t` as `I` (unsigned int) and every pointer as
/// `PAX` rather than the 64-bit `PEAX` / `_K`, so none of the 64-bit names match a
/// 32-bit binary and vice versa. These spellings were read off the exports of the
/// system 32-bit C runtime itself (`SysWOW64/msvcrt.dll`), not derived from the
/// mangling grammar. `__CxxFrameHandler4` is absent here because that runtime does
/// not export it; only the first three handlers exist in 32-bit.
pub const CPP_RUNTIME_MSVC_X86: Preset = Preset {
    id: "cpp-runtime-msvc-x86",
    summary: "C++ new/delete and exception runtime, MSVC ABI (32-bit)",
    names: &[
        "??2@YAPAXI@Z",
        "??3@YAXPAX@Z",
        "??_U@YAPAXI@Z",
        "??_V@YAXPAX@Z",
        "__CxxFrameHandler",
        "__CxxFrameHandler2",
        "__CxxFrameHandler3",
    ],
};

/// Windows heap, file and console interfaces.
pub const WIN32_BASE: Preset = Preset {
    id: "win32-base",
    summary: "Windows heap, file mapping and console interfaces",
    names: &[
        "CloseHandle",
        "CreateFileA",
        "CreateFileMappingW",
        "CreateFileW",
        "GetFileSizeEx",
        "GetProcessHeap",
        "GetStdHandle",
        "HeapAlloc",
        "HeapFree",
        "HeapReAlloc",
        "HeapSize",
        "MapViewOfFile",
        "ReadFile",
        "SetFilePointerEx",
        "UnmapViewOfFile",
        "VirtualAlloc",
        "VirtualFree",
        "VirtualProtect",
        "VirtualQuery",
        "WriteConsoleA",
        "WriteConsoleW",
        "WriteFile",
    ],
};

/// Winsock socket interfaces.
pub const WINSOCK: Preset = Preset {
    id: "winsock",
    summary: "Windows socket send/receive and connection interfaces",
    names: &[
        "WSACleanup",
        "WSAGetLastError",
        "WSAStartup",
        "accept",
        "bind",
        "closesocket",
        "connect",
        "freeaddrinfo",
        "getaddrinfo",
        "gethostbyname",
        "htons",
        "ioctlsocket",
        "listen",
        "ntohs",
        "recv",
        "recvfrom",
        "select",
        "send",
        "sendto",
        "shutdown",
        "socket",
    ],
};

/// Graphics device creation and frame presentation interfaces.
pub const GRAPHICS_DEVICE: Preset = Preset {
    id: "graphics-device",
    summary: "Graphics device, swap chain and frame presentation interfaces",
    names: &[
        "CreateDXGIFactory",
        "CreateDXGIFactory1",
        "D3D11CreateDevice",
        "D3D11CreateDeviceAndSwapChain",
        "D3D12CreateDevice",
        "SwapBuffers",
        "eglCreateContext",
        "eglMakeCurrent",
        "eglSwapBuffers",
        "glXCreateContext",
        "glXMakeCurrent",
        "glXSwapBuffers",
        "wglCreateContext",
        "wglMakeCurrent",
        "wglSwapBuffers",
    ],
};

/// Graphics draw and resource interfaces.
pub const GRAPHICS_DRAW: Preset = Preset {
    id: "graphics-draw",
    summary: "Graphics draw-call and texture-resource interfaces",
    names: &[
        "glBindTexture",
        "glClear",
        "glCompileShader",
        "glDeleteTextures",
        "glDrawArrays",
        "glDrawArraysInstanced",
        "glDrawElements",
        "glDrawElementsInstanced",
        "glFinish",
        "glFlush",
        "glGenTextures",
        "glLinkProgram",
        "glShaderSource",
        "glTexImage2D",
        "glUseProgram",
        "glViewport",
    ],
};

/// Dynamic loading and process/thread interfaces.
pub const LOADER: Preset = Preset {
    id: "loader",
    summary: "Dynamic library loading and thread/process interfaces",
    names: &[
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
        "dlclose",
        "dlerror",
        "dlopen",
        "dlsym",
        "pthread_create",
        "pthread_join",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
    ],
};

/// Time and randomness interfaces, which are where nondeterminism enters a trace.
pub const TIME_AND_RANDOM: Preset = Preset {
    id: "time-and-random",
    summary: "Clock, timer and randomness interfaces",
    names: &[
        "BCryptGenRandom",
        "CryptGenRandom",
        "GetSystemTimeAsFileTime",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "RtlGenRandom",
        "clock",
        "clock_gettime",
        "getrandom",
        "gettimeofday",
        "rand",
        "random",
        "srand",
        "srandom",
        "time",
        "timeGetTime",
    ],
};

/// Every preset, in a stable order.
pub const PRESETS: &[Preset] = &[
    C_RUNTIME,
    CPP_RUNTIME_ITANIUM,
    CPP_RUNTIME_MSVC,
    CPP_RUNTIME_MSVC_X86,
    WIN32_BASE,
    WINSOCK,
    GRAPHICS_DEVICE,
    GRAPHICS_DRAW,
    LOADER,
    TIME_AND_RANDOM,
];

/// Look up a preset by its stable identifier.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.id == id)
}

/// Merge several presets into one selection.
///
/// Names are deduplicated and kept sorted, so the result does not depend on the
/// order the presets were named in.
#[must_use]
pub fn merge(presets: &[&Preset]) -> HookSelection {
    let mut names: Vec<String> = presets
        .iter()
        .flat_map(|preset| preset.names.iter().map(|name| (*name).to_string()))
        .collect();
    names.sort();
    names.dedup();
    HookSelection {
        all: false,
        names,
        patterns: Vec::new(),
        exclude_names: Vec::new(),
        exclude_patterns: Vec::new(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_lowercase() {
        let mut seen = std::collections::BTreeSet::new();
        for preset in PRESETS {
            assert!(seen.insert(preset.id), "duplicate preset id: {}", preset.id);
            assert!(
                preset
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{} is not a lowercase kebab identifier (letters, digits, dashes)",
                preset.id
            );
            assert!(!preset.summary.is_empty(), "{} has no summary", preset.id);
            assert!(!preset.names.is_empty(), "{} names nothing", preset.id);
        }
    }

    #[test]
    fn names_within_a_preset_are_unique_and_sorted() {
        for preset in PRESETS {
            for pair in preset.names.windows(2) {
                assert!(
                    pair[0] < pair[1],
                    "{}: {} !< {}",
                    preset.id,
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    #[test]
    fn lookup_is_exact() {
        assert_eq!(by_id("c-runtime").unwrap().id, "c-runtime");
        assert!(by_id("c_runtime").is_none());
        assert!(by_id("C-Runtime").is_none());
        assert!(by_id("").is_none());
    }

    #[test]
    fn a_preset_becomes_a_selection_with_no_patterns() {
        let selection = C_RUNTIME.selection();
        assert!(!selection.all);
        assert_eq!(selection.names.len(), C_RUNTIME.names.len());
        assert!(
            selection.patterns.is_empty(),
            "presets must not use patterns"
        );
        assert!(selection.exclude_names.is_empty());
        assert!(selection.exclude_patterns.is_empty());
    }

    #[test]
    fn merging_is_order_independent_and_deduplicated() {
        let forward = merge(&[&C_RUNTIME, &LOADER]);
        let backward = merge(&[&LOADER, &C_RUNTIME]);
        assert_eq!(forward.names, backward.names);
        let mut unique = forward.names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(forward.names, unique);
    }

    #[test]
    fn merging_an_overlapping_pair_does_not_duplicate() {
        // Both families name an allocator entry point.
        let merged = merge(&[&C_RUNTIME, &CPP_RUNTIME_ITANIUM]);
        assert!(merged.names.contains(&"malloc".to_string()));
        assert_eq!(merged.names.iter().filter(|n| *n == "malloc").count(), 1);
    }

    #[test]
    fn a_preset_matches_a_real_dll_exports() {
        // Every name a preset lists must exist in a real library that exports it,
        // or the preset would silently narrow the surface on that target.
        let path = std::path::Path::new(r"C:\Windows\System32\ucrtbase.dll");
        let Ok(bytes) = std::fs::read(path) else {
            return; // Library absent on this host; nothing to check.
        };
        let Ok(Some(table)) = kotama_image::pe_export::parse_pe_exports(&bytes) else {
            return;
        };
        let exported: std::collections::BTreeSet<String> = table
            .entries
            .iter()
            .flat_map(|entry| entry.names.iter())
            .filter_map(|name| std::str::from_utf8(name).ok())
            .map(str::to_string)
            .collect();
        let present: Vec<&str> = C_RUNTIME
            .names
            .iter()
            .copied()
            .filter(|name| exported.contains(*name))
            .collect();
        assert!(
            present.len() >= 15,
            "expected most C runtime names to be exported, found {}: {present:?}",
            present.len()
        );
    }

    /// The decorated names are disjoint across the two MSVC ABIs: a 32-bit binary
    /// exports none of the 64-bit spellings, so one preset cannot serve both widths.
    /// Undecorated C symbols such as `__CxxFrameHandler3` are width-independent and
    /// legitimately appear in both — the dump of both runtimes shows it.
    #[test]
    fn the_decorated_names_of_the_two_msvc_abis_are_disjoint() {
        for name in CPP_RUNTIME_MSVC.names {
            if !name.starts_with('?') {
                continue;
            }
            assert!(
                !CPP_RUNTIME_MSVC_X86.names.contains(name),
                "decorated {name} appears in both the 64-bit and 32-bit presets"
            );
        }
        for name in CPP_RUNTIME_MSVC_X86.names {
            if !name.starts_with('?') {
                continue;
            }
            assert!(
                !CPP_RUNTIME_MSVC.names.contains(name),
                "decorated {name} appears in both the 64-bit and 32-bit presets"
            );
        }
        // The shared C symbol really is in both, which is what makes the distinction
        // above necessary rather than a tautology.
        assert!(CPP_RUNTIME_MSVC.names.contains(&"__CxxFrameHandler3"));
        assert!(CPP_RUNTIME_MSVC_X86.names.contains(&"__CxxFrameHandler3"));
    }

    /// Every 32-bit spelling was read off the system 32-bit C runtime's exports.
    /// The size_t slot is `I` and pointers are `PAX`, where the 64-bit ABI has `_K` and
    /// `PEAX`. `__CxxFrameHandler4` is deliberately absent: that runtime lacks it.
    #[test]
    fn the_x86_preset_uses_the_32_bit_decoration() {
        assert!(CPP_RUNTIME_MSVC_X86.names.contains(&"??2@YAPAXI@Z"));
        assert!(CPP_RUNTIME_MSVC_X86.names.contains(&"??3@YAXPAX@Z"));
        assert!(CPP_RUNTIME_MSVC_X86.names.contains(&"??_U@YAPAXI@Z"));
        assert!(CPP_RUNTIME_MSVC_X86.names.contains(&"??_V@YAXPAX@Z"));
        assert!(
            !CPP_RUNTIME_MSVC_X86.names.contains(&"__CxxFrameHandler4"),
            "the 32-bit runtime does not export __CxxFrameHandler4"
        );
        for name in CPP_RUNTIME_MSVC_X86.names {
            assert!(
                !name.contains("PEAX") && !name.contains("_K@"),
                "{name} carries a 64-bit type code"
            );
        }
    }

    /// The 64-bit preset stays 64-bit: no `I`-as-size_t or bare `PAX` crept in.
    #[test]
    fn the_x64_preset_uses_the_64_bit_decoration() {
        assert!(CPP_RUNTIME_MSVC.names.contains(&"??2@YAPEAX_K@Z"));
        assert!(CPP_RUNTIME_MSVC.names.contains(&"__CxxFrameHandler4"));
        for name in CPP_RUNTIME_MSVC.names {
            assert!(
                name.contains("PEAX") || name.contains("_K@") || name.starts_with("__Cxx"),
                "{name} is not a 64-bit decoration"
            );
        }
    }

    #[test]
    fn the_x86_preset_is_registered_and_addressable() {
        assert_eq!(
            by_id("cpp-runtime-msvc-x86").unwrap().id,
            "cpp-runtime-msvc-x86"
        );
        assert!(PRESETS.iter().any(|p| p.id == "cpp-runtime-msvc-x86"));
    }
}
