//! kotama proxy: strict PE export inspection and forwarding-mirror generation.
//!
//! # What the generated runtime may and may not do
//!
//! The mirror's C runtime has three kinds of code in it, and the hook-body
//! contract — no allocation, no locking, no I/O on the target's thread — applies
//! to exactly one of them:
//!
//! - **`kotama_log_entry`** is the hook body. It runs on the caller's thread,
//!   inside the caller's lock hierarchy. It does an atomic increment, writes a
//!   slot in a pre-allocated ring, and reads two thread/time APIs. No heap, no
//!   lock, no file, and it does not start the runtime.
//! - **`kotama_original`** resolves the backing export. It calls
//!   `InitOnceExecuteOnce` to start the runtime the first time any stub
//!   forwards, then reads the cached module. The once-only fast path is a
//!   status read; the first call runs `kotama_start` under the once lock.
//! - **`kotama_start`** is the only place with side effects: it opens the log,
//!   loads the backing module, and starts the worker. It runs once, from
//!   whichever thread first forwards — never from `DllMain`, so the loader lock
//!   is not held while a file is opened or a thread is created.
//! - **`worker_main`** is the consumer: its own thread, drains the ring,
//!   formats and writes. The contract does not apply to it.
//!
//! `DllMain` is registration only: it sets the stop flag on detach and does
//! nothing else. The mirror still needs no cooperation from the host to begin
//! logging — the first forwarded call starts it — but no longer does file I/O or
//! thread creation under the loader lock, which #181 had recorded as the two
//! things it did against Microsoft's guidance.
//!
//! # What checks this
//!
//! Nothing here is checked by `kotama_payload::hook_guard`: that counter guards
//! the payload's own hook bodies, and this runtime is a separate binary with its
//! own C. The tests slice the four functions out of the generated source and
//! hold each to its contents, and every side effect is asserted to have exactly
//! one home. The smoke test in `proxy_cli.rs` builds the mirror with zig, loads
//! it, and calls through it on both x64 and x86 — that is the proof the once
//! start actually runs, which the source-shape tests cannot give.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use kotama_image::pe_export::{parse_pe_exports, PeExportTable};
use kotama_proxy::{
    manifest, manifest_with, mirror_def_with, plan_logs, plan_overrides, LogPlan, LogSelection,
    MirrorExport, MirrorOptions, OverrideSelection,
};
use serde::Serialize;

#[derive(Serialize)]
struct InspectJson {
    input: String,
    ordinal_base: u16,
    export_count: usize,
    exports: Vec<MirrorExport>,
}

#[derive(Serialize)]
struct GenerateJson {
    output: String,
    library: String,
    backing: String,
    export_count: usize,
    override_count: usize,
    log_count: usize,
    hooks: Option<String>,
    built: bool,
}

fn usage() -> ExitCode {
    eprintln!("usage:\n  kotama proxy inspect <dll>\n  kotama proxy generate <dll> --output <dir> [--backing <name>] [--build]\n      [--override <name>]... [--override-ordinal <n>]... [--exclude <name>]... [--exclude-ordinal <n>]... [--hooks <file.c>]\n      [--log-all] [--log <name>]... [--log-ordinal <n>]... [--log-regex <re>]...\n      [--log-exclude <name>]... [--log-exclude-ordinal <n>]... [--log-exclude-regex <re>]...");
    ExitCode::from(2)
}

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("kotama: proxy: {message}");
    ExitCode::FAILURE
}

fn load(path: &Path) -> Result<(Vec<u8>, PeExportTable), String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let table = parse_pe_exports(&data)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("{} is not a PE image", path.display()))?;
    Ok((data, table))
}

fn pe_machine(data: &[u8]) -> Result<u16, String> {
    let offset = data
        .get(0x3c..0x40)
        .ok_or_else(|| "missing PE header offset".to_string())?;
    let offset = u32::from_le_bytes(offset.try_into().expect("four bytes")) as usize;
    let machine = data
        .get(offset + 4..offset + 6)
        .ok_or_else(|| "missing PE COFF header".to_string())?;
    Ok(u16::from_le_bytes(machine.try_into().expect("two bytes")))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    use std::io::Write;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

const RUNTIME_TEMPLATE: &str = r#"#include <windows.h>
#include <stdio.h>

#define KOTAMA_LOG_CAP 1024
#define KOTAMA_BACKING_NAME L"@BACKING@"

typedef struct {
    volatile LONG seq;
    volatile LONG ordinal;
    volatile LONG tid;
    volatile DWORD tick;
} KOTAMA_LOG_ENTRY;

static KOTAMA_LOG_ENTRY ring[KOTAMA_LOG_CAP];
static volatile LONG write_index;
static volatile LONG stopping;
static HANDLE log_handle = INVALID_HANDLE_VALUE;
static HANDLE worker_thread;
static HMODULE backing_module;
static INIT_ONCE start_once = INIT_ONCE_STATIC_INIT;
static DWORD WINAPI worker_main(LPVOID unused);

/* Runs once, under InitOnceExecuteOnce, the first time a forwarding stub needs
 * the backing module. DllMain does not call it: file I/O and thread creation
 * under the loader lock are what this defers, and a mirror that starts itself
 * lazily needs no cooperation from the host to begin logging. */
static BOOL CALLBACK kotama_start(PINIT_ONCE once, LPVOID param, LPVOID *context) {
    (void)once;
    (void)param;
    (void)context;
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("KOTAMA_PROXY_LOG", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        lstrcpyA(path, "kotama-proxy.log");
    }
    log_handle = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HMODULE loaded = LoadLibraryW(KOTAMA_BACKING_NAME);
    if (loaded) {
        backing_module = loaded;
    }
    if (log_handle != INVALID_HANDLE_VALUE) {
        worker_thread = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
    }
    return TRUE;
}

__declspec(noreturn) static void kotama_missing_original(void) {
    RaiseException(0xE0000001u, 0, 0, NULL);
    for (;;) {
    }
}

void *kotama_original(unsigned ordinal) {
    InitOnceExecuteOnce(&start_once, kotama_start, NULL, NULL);
    if (!backing_module) {
        return (void *)kotama_missing_original;
    }
    FARPROC address = GetProcAddress(backing_module, MAKEINTRESOURCEA(ordinal));
    return address ? (void *)address : (void *)kotama_missing_original;
}

/* The hook body. Runs on the caller's thread inside its lock hierarchy: an
 * atomic increment, a slot in the pre-allocated ring, two thread/time reads.
 * No heap, no lock, no file, and it does not start the runtime — kotama_original
 * does, so by the time any entry is logged the ring has a consumer. */
void kotama_log_entry(unsigned ordinal) {
    LONG slot = InterlockedIncrement(&write_index) - 1;
    KOTAMA_LOG_ENTRY *entry = &ring[(unsigned)slot % KOTAMA_LOG_CAP];
    entry->ordinal = (LONG)ordinal;
    entry->tid = (LONG)GetCurrentThreadId();
    entry->tick = GetTickCount();
    InterlockedIncrement(&entry->seq);
}

static DWORD WINAPI worker_main(LPVOID unused) {
    (void)unused;
    LONG last[KOTAMA_LOG_CAP];
    char line[96];
    unsigned i;
    for (i = 0; i < KOTAMA_LOG_CAP; ++i) {
        last[i] = 0;
    }
    while (!stopping) {
        for (i = 0; i < KOTAMA_LOG_CAP; ++i) {
            LONG seq = ring[i].seq;
            if (seq == last[i]) {
                continue;
            }
            last[i] = seq;
            int length = snprintf(line, sizeof(line), "ord=%lu tid=%lu tick=%lu\n",
                                  (unsigned long)ring[i].ordinal,
                                  (unsigned long)ring[i].tid,
                                  (unsigned long)ring[i].tick);
            if (length > 0 && log_handle != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(log_handle, line, (DWORD)length, &written, NULL);
            }
        }
        Sleep(20);
    }
    return 0;
}

/* Registration only. The runtime starts the first time a stub forwards; the
 * loader lock is never held while a file is opened or a thread is created. */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_DETACH) {
        InterlockedExchange(&stopping, 1);
    }
    return TRUE;
}
"#;

fn runtime_source(backing: &str) -> String {
    RUNTIME_TEMPLATE.replace("@BACKING@", backing)
}

fn stubs_source(plan: &LogPlan, machine: u16) -> String {
    let mut out = String::from(".text\n");
    for ordinal in plan.symbols().keys() {
        if machine == 0x8664 {
            out.push_str(&format!(
                r#"
.p2align 4
.globl KOTAMA_LOG_STUB_{ordinal}
KOTAMA_LOG_STUB_{ordinal}:
    pushfq
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %r8
    pushq %r9
    subq $96, %rsp
    movdqu %xmm0, 0(%rsp)
    movdqu %xmm1, 16(%rsp)
    movdqu %xmm2, 32(%rsp)
    movdqu %xmm3, 48(%rsp)
    movdqu %xmm4, 64(%rsp)
    movdqu %xmm5, 80(%rsp)
    subq $40, %rsp
    movl ${ordinal}, %ecx
    call kotama_log_entry
    addq $40, %rsp
    subq $8, %rsp
    movl ${ordinal}, %ecx
    call kotama_original
    addq $8, %rsp
    movq %rax, %r10
    movdqu 0(%rsp), %xmm0
    movdqu 16(%rsp), %xmm1
    movdqu 32(%rsp), %xmm2
    movdqu 48(%rsp), %xmm3
    movdqu 64(%rsp), %xmm4
    movdqu 80(%rsp), %xmm5
    addq $96, %rsp
    popq %r9
    popq %r8
    popq %rdx
    popq %rcx
    popq %rax
    popfq
    jmp *%r10
"#
            ));
        } else {
            out.push_str(&format!(
                r#"
.p2align 4
.globl _KOTAMA_LOG_STUB_{ordinal}
_KOTAMA_LOG_STUB_{ordinal}:
    pushfd
    pushl ${ordinal}
    call _kotama_log_entry
    addl $4, %esp
    pushl ${ordinal}
    call _kotama_original
    addl $4, %esp
    popfd
    jmp *%eax
"#
            ));
        }
    }
    out
}

pub fn run(args: &[String]) -> ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "inspect" => {
            let Some(path) = args.get(1).map(PathBuf::from) else {
                return usage();
            };
            if args.len() != 2 {
                return usage();
            }
            match inspect(&path) {
                Ok(json) => match serde_json::to_string_pretty(&json) {
                    Ok(text) => {
                        println!("{text}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(error),
                },
                Err(error) => fail(error),
            }
        }
        "generate" => generate(&args[1..]),
        _ => usage(),
    }
}

fn inspect(path: &Path) -> Result<InspectJson, String> {
    let (data, table) = load(path)?;
    let input = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let options = MirrorOptions {
        library: "mirror.dll".to_string(),
        backing: "original.dll".to_string(),
    };
    let facts = manifest(&input, &data, &table, &options, None);
    Ok(InspectJson {
        input,
        ordinal_base: table.ordinal_base,
        export_count: table.entries.len(),
        exports: facts.exports,
    })
}

fn generate(args: &[String]) -> ExitCode {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut backing: Option<String> = None;
    let mut build = false;
    let mut selection = OverrideSelection::default();
    let mut logs = LogSelection::default();
    let mut hooks: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                index += 1;
                output = args.get(index).map(PathBuf::from);
            }
            "--backing" => {
                index += 1;
                backing = args.get(index).cloned();
            }
            "--build" => build = true,
            "--override" => {
                index += 1;
                let Some(name) = args.get(index) else {
                    return usage();
                };
                selection.names.push(name.clone());
            }
            "--override-ordinal" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    return usage();
                };
                let Ok(ordinal) = raw.parse::<u16>() else {
                    return usage();
                };
                selection.ordinals.push(ordinal);
            }
            "--exclude" => {
                index += 1;
                let Some(name) = args.get(index) else {
                    return usage();
                };
                selection.exclude_names.push(name.clone());
            }
            "--exclude-ordinal" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    return usage();
                };
                let Ok(ordinal) = raw.parse::<u16>() else {
                    return usage();
                };
                selection.exclude_ordinals.push(ordinal);
            }
            "--hooks" => {
                index += 1;
                hooks = args.get(index).map(PathBuf::from);
            }
            "--log-all" => logs.all = true,
            "--log" => {
                index += 1;
                let Some(name) = args.get(index) else {
                    return usage();
                };
                logs.names.push(name.clone());
            }
            "--log-ordinal" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    return usage();
                };
                let Ok(ordinal) = raw.parse::<u16>() else {
                    return usage();
                };
                logs.ordinals.push(ordinal);
            }
            "--log-regex" => {
                index += 1;
                let Some(pattern) = args.get(index) else {
                    return usage();
                };
                logs.patterns.push(pattern.clone());
            }
            "--log-exclude" => {
                index += 1;
                let Some(name) = args.get(index) else {
                    return usage();
                };
                logs.exclude_names.push(name.clone());
            }
            "--log-exclude-ordinal" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    return usage();
                };
                let Ok(ordinal) = raw.parse::<u16>() else {
                    return usage();
                };
                logs.exclude_ordinals.push(ordinal);
            }
            "--log-exclude-regex" => {
                index += 1;
                let Some(pattern) = args.get(index) else {
                    return usage();
                };
                logs.exclude_patterns.push(pattern.clone());
            }
            other if input.is_none() && !other.starts_with('-') => {
                input = Some(PathBuf::from(other));
            }
            _ => return usage(),
        }
        index += 1;
    }
    let (Some(input), Some(output)) = (input, output) else {
        return usage();
    };
    let backing = backing.unwrap_or_else(|| {
        let stem = input
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "original".to_string());
        let extension = input
            .extension()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "dll".to_string());
        format!("{stem}_original.{extension}")
    });
    let options = MirrorOptions {
        library: "mirror.dll".to_string(),
        backing,
    };
    if selection.is_empty() && hooks.is_some() {
        return fail("--hooks requires at least one --override or --override-ordinal");
    }
    if !selection.is_empty() && hooks.is_none() {
        return fail("overrides require --hooks <file.c> defining the generated symbols");
    }
    let hooks_bytes = match hooks.as_ref() {
        Some(path) => match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) => return fail(format!("read {}: {error}", path.display())),
        },
        None => None,
    };
    let result = (|| -> Result<GenerateJson, String> {
        let (data, table) = load(&input)?;
        let plan = if selection.is_empty() {
            None
        } else {
            Some(plan_overrides(&table, &selection).map_err(|error| error.to_string())?)
        };
        let log_plan = if logs.is_empty() {
            None
        } else {
            Some(plan_logs(&table, &logs).map_err(|error| error.to_string())?)
        };
        if let (Some(overrides), Some(entry_logs)) = (plan.as_ref(), log_plan.as_ref()) {
            if let Some(ordinal) = overrides
                .symbols()
                .keys()
                .find(|ordinal| entry_logs.symbols().contains_key(ordinal))
            {
                return Err(format!(
                    "ordinal {ordinal} cannot be both overridden and logged"
                ));
            }
        }
        if let Some(plan) = log_plan.as_ref() {
            for warning in plan.warnings() {
                eprintln!("kotama: proxy: warning: {warning}");
            }
        }
        let definition = mirror_def_with(&table, &options, plan.as_ref(), log_plan.as_ref())
            .map_err(|error| error.to_string())?;
        fs::create_dir_all(&output)
            .map_err(|error| format!("create output directory {}: {error}", output.display()))?;
        let def_path = output.join("proxy.def");
        let c_path = output.join("proxy.c");
        let manifest_path = output.join("manifest.json");
        let dll_path = output.join(&options.library);
        let runtime_path = output.join("proxy_runtime.c");
        let stubs_path = output.join("proxy_stubs.S");
        for path in [&def_path, &c_path, &manifest_path, &dll_path] {
            if path.exists() {
                return Err(format!("refusing to overwrite {}", path.display()));
            }
        }
        if log_plan.is_some() && (runtime_path.exists() || stubs_path.exists()) {
            return Err(format!("refusing to overwrite {}", runtime_path.display()));
        }
        write_new(&def_path, definition.as_bytes())?;
        write_new(
            &c_path,
            b"/* Synthetic translation unit; exports come from proxy.def. */\nvoid kotama_proxy_anchor(void) {}\n",
        )?;
        if let Some(plan) = log_plan.as_ref() {
            let machine = pe_machine(&data)?;
            write_new(&runtime_path, runtime_source(&options.backing).as_bytes())?;
            write_new(&stubs_path, stubs_source(plan, machine).as_bytes())?;
        }
        if build {
            let target = match pe_machine(&data)? {
                0x014c => "x86-windows-gnu",
                0x8664 => "x86_64-windows-gnu",
                other => {
                    return Err(format!(
                        "cannot choose a Zig target for COFF machine {other:#06x}"
                    ))
                }
            };
            let zig = std::env::var_os("KOTAMA_ZIG").unwrap_or_else(|| "zig".into());
            let mut command = Command::new(&zig);
            command
                .arg("cc")
                .arg("-target")
                .arg(target)
                .arg("-shared")
                .arg("-o")
                .arg(&dll_path)
                .arg(&c_path);
            if let Some(hooks) = hooks.as_ref() {
                command.arg(hooks);
            }
            if log_plan.is_some() {
                command.arg(&runtime_path).arg(&stubs_path);
            }
            let status = command
                .arg(&def_path)
                .status()
                .map_err(|error| format!("run zig cc: {error}"))?;
            if !status.success() {
                return Err(format!("zig cc failed with {status}"));
            }
        }
        let built = if build {
            Some(fs::read(&dll_path).map_err(|error| format!("read built DLL: {error}"))?)
        } else {
            None
        };
        let input_name = input
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| input.display().to_string());
        let hooks_source = hooks.as_ref().map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string())
        });
        let hooks_pair = match (hooks_source.as_deref(), hooks_bytes.as_deref()) {
            (Some(name), Some(bytes)) => Some((name, bytes)),
            _ => None,
        };
        let facts = manifest_with(
            &input_name,
            &data,
            &table,
            &options,
            built.as_deref(),
            kotama_proxy::ExportActions {
                overrides: plan.as_ref(),
                logs: log_plan.as_ref(),
            },
            hooks_pair,
        );
        let text = serde_json::to_vec_pretty(&facts).map_err(|error| error.to_string())?;
        write_new(&manifest_path, &text)?;
        Ok(GenerateJson {
            output: output.display().to_string(),
            library: options.library,
            backing: options.backing,
            export_count: table.entries.len(),
            override_count: plan.as_ref().map_or(0, |plan| plan.len()),
            log_count: log_plan.as_ref().map_or(0, |plan| plan.len()),
            hooks: hooks_source,
            built: build,
        })
    })();
    match result {
        Ok(json) => match serde_json::to_string_pretty(&json) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        },
        Err(error) => fail(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated runtime's contract after lazy start: DllMain registers
    /// only, the one-time starter is the only place a file is opened, a thread
    /// created or a library loaded, the hook body touches the ring and nothing
    /// else, and the resolver triggers the start before it reads the module.
    ///
    /// mutate: start-moved-to-dllmain (a CreateFileA in DllMain fails the
    /// "registration only" slice); io-in-hook-body (a WriteFile in the hook
    /// body fails its slice).
    #[test]
    fn the_generated_runtime_starts_lazily_and_keeps_the_hook_body_clean() {
        let source = runtime_source("original_real.dll");
        let body = |name: &str, until: &str| -> &str {
            let start = source.find(name).expect(name);
            let end = source[start..].find(until).expect(until) + start;
            &source[start..end]
        };
        let starter = body("static BOOL CALLBACK kotama_start(", "\n}\n");
        let resolver = body("void *kotama_original(", "\n}\n");
        let hook = body("void kotama_log_entry(", "\n}\n");
        let dllmain = body("BOOL WINAPI DllMain(", "\n}\n");

        // The one-time starter holds every side effect.
        for needed in ["CreateFileA", "CreateThread", "LoadLibraryW"] {
            assert!(
                starter.contains(needed),
                "starter must do {needed}:\n{starter}"
            );
        }
        // The resolver starts the runtime, then reads the cached module.
        assert!(
            resolver.contains("InitOnceExecuteOnce(&start_once"),
            "{resolver}"
        );
        assert!(resolver.contains("GetProcAddress"), "{resolver}");
        for forbidden in [
            "LoadLibraryW",
            "CreateFile",
            "WriteFile",
            "malloc",
            "HeapAlloc",
            "EnterCriticalSection",
        ] {
            assert!(
                !resolver.contains(forbidden),
                "resolver must not call {forbidden}:\n{resolver}"
            );
        }
        // The hook body: ring writes and interlocked ops only. It does not
        // start the runtime — that is the resolver's job, so a hook that fires
        // before any forward simply writes a slot the worker will read later.
        assert!(hook.contains("InterlockedIncrement"), "{hook}");
        assert!(hook.contains("ring["), "{hook}");
        for forbidden in [
            "WriteFile",
            "CreateFile",
            "LoadLibrary",
            "InitOnceExecuteOnce",
            "malloc",
            "HeapAlloc",
            "EnterCriticalSection",
            "WaitFor",
        ] {
            assert!(
                !hook.contains(forbidden),
                "hook body must not call {forbidden}:\n{hook}"
            );
        }
        // DllMain: registration only. Nothing else.
        assert!(dllmain.contains("DLL_PROCESS_DETACH"), "{dllmain}");
        assert!(
            dllmain.contains("InterlockedExchange(&stopping"),
            "{dllmain}"
        );
        for forbidden in [
            "CreateFile",
            "CreateThread",
            "LoadLibrary",
            "ring[",
            "kotama_start",
            "kotama_log_entry",
            "InitOnceExecuteOnce",
        ] {
            assert!(
                !dllmain.contains(forbidden),
                "DllMain must not contain {forbidden}:\n{dllmain}"
            );
        }
    }

    /// Every side effect in the runtime lives in exactly one function, so a
    /// reader looking for "where does the file get opened" has one answer.
    #[test]
    fn each_side_effect_has_exactly_one_home() {
        let source = runtime_source("original_real.dll");
        for (call, home) in [
            ("CreateFileA", "kotama_start"),
            ("CreateThread", "kotama_start"),
            ("LoadLibraryW", "kotama_start"),
            ("WriteFile", "worker_main"),
        ] {
            let count = source.matches(call).count();
            assert_eq!(
                count, 1,
                "{call} appears {count} times, expected exactly one"
            );
            let at = source.find(call).unwrap();
            let fn_start = source[..at]
                .rfind(
                    "
}
",
                )
                .map_or(0, |i| i + 3);
            let fn_head = &source[fn_start..at];
            assert!(fn_head.contains(home), "{call} is not inside {home}");
        }
    }
}
