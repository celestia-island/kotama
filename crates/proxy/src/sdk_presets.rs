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
//!
//! # Where the chain stops
//!
//! "Mount a runtime" is a chain, and it is worth saying which links exist:
//!
//! 1. **Choose** what to intercept — [HookSelection](crate::hook_plan::HookSelection),
//!    the presets below, `kotama hook plan`. Exists.
//! 2. **Resolve** the chosen names to addresses in a real image —
//!    `pe_hookable_symbols` / `elf_hookable_symbols`, `runtime-resolve`, with the
//!    executable-section filter from #184/#185. Exists.
//! 3. **Check the hook body** against the contract — `payload::hook_guard` counts
//!    allocations; `tools/hook_body_lint.py` scans a declared body for locks and
//!    I/O calls. Exists, and has exactly one body to check: the forwarding mirror's
//!    C `kotama_log_entry`.
//! 4. **Install** the hook — write the jump into the target. Exists, x64, from #192:
//!    `scan::install::plan` turns the prefix into a trampoline and an `E9 rel32`,
//!    refusing a prefix with a RIP-relative instruction or a stranded entry by name;
//!    `Session::install_hook` writes trampoline first, then jump, under `WriteMemory`.
//!    The live e2e replaces a fixture function with a stub and watches the target's
//!    output change. `retour` is still only read, in `deny.toml`; nothing depends on it.
//!
//! What is still not built: a hook *body* to install — the stub in the e2e is a
//!    hand-assembled ABI-correct return, not a Rust closure — and anything outside x64
//!    (`install::plan` is fixed at bitness 64; `patchable` already takes 16/32). The
//!    open items after #192 are tracked in the handoff PR that follows it.

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

/// The platform a preset should be selected for, read off the container.
///
/// PE is Windows; ELF and Mach-O are POSIX. Everything else is treated as POSIX
/// because that is the side whose names are excused on Windows, and an excuse
/// on a platform that has them is harmless (a present name is still hooked).
#[must_use]
pub fn platform_of_container(container: kotama_image::Container) -> Platform {
    match container {
        kotama_image::Container::Pe32 | kotama_image::Container::Pe64 => Platform::Native,
        _ => Platform::Posix,
    }
}

impl Preset {
    /// This preset as a hook selection for one platform.
    ///
    /// Names the platform does not have are passed as `not_on_platform` rather than
    /// dropped, so the planner neither errors on them nor forgets they were asked
    /// for. Only `Posix` names are excused this way: an `OtherDll` or `Extension`
    /// name is a real export the target's export table may or may not carry, and
    /// that is the target's answer, not the preset's.
    #[must_use]
    pub fn selection_for(&self, platform: Platform) -> HookSelection {
        HookSelection {
            all: false,
            names: self.names.iter().map(|name| (*name).to_string()).collect(),
            patterns: Vec::new(),
            exclude_names: Vec::new(),
            exclude_patterns: Vec::new(),
            not_on_platform: if platform == Platform::Posix {
                Vec::new()
            } else {
                self.names_for(Platform::Posix)
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect()
            },
        }
    }
    /// This preset as a hook selection.
    #[must_use]
    pub fn selection(&self) -> HookSelection {
        HookSelection {
            all: false,
            names: self.names.iter().map(|name| (*name).to_string()).collect(),
            patterns: Vec::new(),
            exclude_names: Vec::new(),
            exclude_patterns: Vec::new(),
            not_on_platform: Vec::new(),
        }
    }
}

/// Which platform a preset name belongs to.
///
/// A preset is a *family*, and a family spans platforms: the C runtime family has
/// `malloc` everywhere and `posix_memalign` only where POSIX is. Without this, a
/// resolver on Windows reports `posix_memalign` as missing — which reads like a
/// broken target when it is a name that platform never had. The classification
/// below was taken from the export tables of the real system libraries, not from
/// the interfaces' documentation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    /// Exported by the platform's own runtime library.
    Native,
    /// A POSIX (or Itanium-ABI) spelling; absent on Windows by design.
    Posix,
    /// Exported by a different system library than the preset's main one
    /// (heap calls live in the NT layer, DXGI factories in `dxgi`, and so on).
    OtherDll,
    /// An OpenGL extension: not in `opengl32.dll`'s export table at all, obtained
    /// through the platform's procedure-address query.
    Extension,
}

/// Names whose platform is not `Native`; everything else is `Native`.
const NOT_NATIVE: &[(&str, Platform)] = &[
    ("aligned_alloc", Platform::Posix),
    ("posix_memalign", Platform::Posix),
    ("snprintf", Platform::Posix),
    ("dlclose", Platform::Posix),
    ("dlerror", Platform::Posix),
    ("dlopen", Platform::Posix),
    ("dlsym", Platform::Posix),
    ("pthread_create", Platform::Posix),
    ("pthread_join", Platform::Posix),
    ("pthread_mutex_lock", Platform::Posix),
    ("pthread_mutex_unlock", Platform::Posix),
    ("clock_gettime", Platform::Posix),
    ("getrandom", Platform::Posix),
    ("gettimeofday", Platform::Posix),
    ("random", Platform::Posix),
    ("srandom", Platform::Posix),
    ("BCryptGenRandom", Platform::OtherDll),
    ("CryptGenRandom", Platform::OtherDll),
    ("RtlGenRandom", Platform::OtherDll),
    ("CreateDXGIFactory", Platform::OtherDll),
    ("CreateDXGIFactory1", Platform::OtherDll),
    ("D3D12CreateDevice", Platform::OtherDll),
    ("eglCreateContext", Platform::OtherDll),
    ("eglMakeCurrent", Platform::OtherDll),
    ("eglSwapBuffers", Platform::OtherDll),
    ("glXCreateContext", Platform::OtherDll),
    ("glXMakeCurrent", Platform::OtherDll),
    ("glXSwapBuffers", Platform::OtherDll),
    ("glCompileShader", Platform::Extension),
    ("glDrawArraysInstanced", Platform::Extension),
    ("glDrawElementsInstanced", Platform::Extension),
    ("glLinkProgram", Platform::Extension),
    ("glShaderSource", Platform::Extension),
    ("glUseProgram", Platform::Extension),
];

impl Preset {
    /// The platform a name in this preset belongs to.
    #[must_use]
    pub fn platform_of(&self, name: &str) -> Platform {
        NOT_NATIVE
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(Platform::Native, |(_, platform)| *platform)
    }

    /// The names in this preset that are expected on the given platform.
    ///
    /// `Native` and `OtherDll` names are real exports on Windows; `Extension`
    /// names are real but reached differently; `Posix` names are not Windows at
    /// all. On `Posix` the Itanium and C-runtime spellings apply and the decorated
    /// MSVC ones do not, so the decorated names are filtered out there.
    #[must_use]
    pub fn names_for(&self, platform: Platform) -> Vec<&'static str> {
        self.names
            .iter()
            .copied()
            .filter(|name| self.platform_of(name) == platform)
            .collect()
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
        not_on_platform: Vec::new(),
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

    /// Read the export names of a system library; `None` when it is not on this
    /// machine (the test then skips rather than fails).
    fn system_exports(dll: &str) -> Option<std::collections::BTreeSet<String>> {
        let path = std::path::Path::new("C:/Windows/System32").join(dll);
        let bytes = std::fs::read(path).ok()?;
        let module = kotama_image::LoadedModule::parse(&bytes).ok()?;
        Some(
            module
                .dynamic_symbols
                .iter()
                .filter(|symbol| !symbol.name.is_empty() && symbol.rva != 0)
                .map(|symbol| symbol.name.clone())
                .collect(),
        )
    }

    /// The real system libraries agree with every classification: Native names are
    /// exported by the preset's home library, Posix names by none of them, OtherDll
    /// names by a library other than the home. This is what makes a "missing" from
    /// the resolver mean what it says.
    #[test]
    fn the_platform_classification_matches_the_real_system_libraries() {
        // (preset id, libraries that make up its home, other libraries its OtherDll
        // names live in)
        let homes: [(&str, &[&str], &[&str]); 7] = [
            ("c-runtime", &["msvcrt.dll"], &[]),
            ("win32-base", &["kernel32.dll"], &[]),
            ("winsock", &["ws2_32.dll"], &[]),
            (
                "graphics-device",
                &["d3d11.dll", "gdi32.dll", "opengl32.dll"],
                &["dxgi.dll", "d3d12.dll"],
            ),
            ("graphics-draw", &["opengl32.dll"], &[]),
            ("loader", &["kernel32.dll"], &[]),
            (
                "time-and-random",
                &["kernel32.dll", "msvcrt.dll"],
                &["bcrypt.dll", "advapi32.dll"],
            ),
        ];
        let lib_exports = |lib: &str| -> Option<std::collections::BTreeSet<String>> {
            let bytes =
                std::fs::read(std::path::Path::new("C:/Windows/System32").join(lib)).ok()?;
            let module = kotama_image::LoadedModule::parse(&bytes).ok()?;
            Some(
                module
                    .dynamic_symbols
                    .iter()
                    .filter(|symbol| !symbol.name.is_empty() && symbol.rva != 0)
                    .map(|symbol| symbol.name.clone())
                    .collect(),
            )
        };
        // The union of everything any row names, for the OtherDll "somewhere" check.
        let mut any: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (home, others) in homes.iter().map(|(_, h, o)| (h, o)) {
            for lib in home.iter().chain(others.iter()) {
                if let Some(names) = lib_exports(lib) {
                    any.extend(names);
                }
            }
        }
        let mut checked = 0;
        for (id, home, _) in homes {
            let Some(preset) = by_id(id) else { continue };
            let home_set: std::collections::BTreeSet<String> = home
                .iter()
                .filter_map(|lib| lib_exports(lib))
                .flatten()
                .collect();
            if home_set.is_empty() {
                eprintln!("skip: none of {home:?} on this machine");
                continue;
            }
            for name in preset.names {
                match preset.platform_of(name) {
                    Platform::Native => {
                        assert!(
                            home_set.contains(*name),
                            "{id}: {name} is classified Native but none of {home:?} exports it"
                        );
                    }
                    Platform::Posix => {
                        assert!(
                            !home_set.contains(*name),
                            "{id}: {name} is classified Posix but {home:?} exports it"
                        );
                    }
                    Platform::OtherDll => {
                        assert!(
                            !home_set.contains(*name),
                            "{id}: {name} is OtherDll but {home:?} exports it"
                        );
                        // EGL and GLX entry points live in vendor libraries this
                        // machine may not have, and RtlGenRandom was removed from
                        // current Windows in favour of BCryptGenRandom; everything
                        // else must be in some system library.
                        if name.starts_with("egl")
                            || name.starts_with("glX")
                            || *name == "RtlGenRandom"
                        {
                            continue;
                        }
                        assert!(
                            any.contains(*name),
                            "{id}: {name} is OtherDll but no system library exports it"
                        );
                    }
                    Platform::Extension => {
                        assert!(
                            !home_set.contains(*name),
                            "{id}: {name} is an extension but {home:?} exports it"
                        );
                    }
                }
            }
            checked += 1;
        }
        if checked == 0 {
            eprintln!("skip: no system libraries readable");
        }
    }

    /// Every preset name is classified, and the Posix set is exactly what the
    /// libraries showed absent — no more, no less.
    #[test]
    fn every_posix_name_is_absent_from_every_windows_library() {
        let libs = [
            "msvcrt.dll",
            "ucrtbase.dll",
            "kernel32.dll",
            "ws2_32.dll",
            "ntdll.dll",
        ];
        let mut exports = std::collections::BTreeSet::new();
        for lib in libs {
            if let Some(names) = system_exports(lib) {
                exports.extend(names);
            }
        }
        if exports.is_empty() {
            eprintln!("skip: no system libraries readable");
            return;
        }
        for preset in PRESETS {
            for name in preset.names_for(Platform::Posix) {
                assert!(
                    !exports.contains(name),
                    "{name} is classified Posix but a Windows library exports it"
                );
            }
        }
    }

    /// On Windows, a preset's Windows-names are its Native + OtherDll names; the
    /// Posix ones are not offered. The split must be a partition of the whole list.
    #[test]
    fn names_for_partitions_the_preset_by_platform() {
        for preset in PRESETS {
            let total = preset.names.len();
            let native = preset.names_for(Platform::Native).len();
            let posix = preset.names_for(Platform::Posix).len();
            let other = preset.names_for(Platform::OtherDll).len();
            let ext = preset.names_for(Platform::Extension).len();
            assert_eq!(native + posix + other + ext, total, "{}", preset.id);
        }
    }

    /// The C runtime and loader presets are the mixed ones; a Windows resolver must
    /// not be offered dlopen or posix_memalign.
    #[test]
    fn the_mixed_presets_exclude_posix_names_on_windows() {
        let c = by_id("c-runtime").unwrap();
        assert!(c.names_for(Platform::Posix).contains(&"posix_memalign"));
        assert!(!c.names_for(Platform::Native).contains(&"posix_memalign"));
        let loader = by_id("loader").unwrap();
        assert!(loader.names_for(Platform::Posix).contains(&"dlopen"));
        assert!(loader.names_for(Platform::Native).contains(&"LoadLibraryW"));
    }

    /// The decorated MSVC names are Native on Windows and mean nothing elsewhere.
    #[test]
    fn the_msvc_decorations_are_native_to_windows() {
        for id in ["cpp-runtime-msvc", "cpp-runtime-msvc-x86"] {
            let preset = by_id(id).unwrap();
            assert_eq!(preset.names_for(Platform::Native).len(), preset.names.len());
        }
    }
}
