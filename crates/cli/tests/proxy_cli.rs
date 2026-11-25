//! Native end-to-end proof for generated forwarding mirrors (synthetic DLLs only).
#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn zig() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("KOTAMA_ZIG") {
        return Some(PathBuf::from(path));
    }
    Command::new("zig")
        .arg("version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|_| PathBuf::from("zig"))
}

fn run(command: &mut Command) {
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).expect("write fixture");
}

fn cc(zig: &Path, target: &str) -> Command {
    let mut command = Command::new(zig);
    command.arg("cc").arg("-target").arg(target);
    command
}

#[test]
fn mirror_forwards_exports_on_x64() {
    exercise("x86_64-windows-gnu");
}

#[test]
fn mirror_forwards_exports_on_x86() {
    exercise("x86-windows-gnu");
}

fn exercise(target: &str) {
    let Some(zig) = zig() else {
        eprintln!("skip: Zig is unavailable");
        return;
    };
    let root =
        std::env::temp_dir().join(format!("kotama-proxy-test-{}-{target}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let original = root.join("original.dll");
    write(
        &root.join("original.c"),
        "int __cdecl Alpha(void) { return 42; }\nint __cdecl Plain(void) { return 7; }\n",
    );
    write(
        &root.join("original.def"),
        "LIBRARY original\nEXPORTS\n    Alpha @5\n    Alias=Alpha @6\n    Plain @7 NONAME\n    Forwarded=kernel32.Sleep @8\n",
    );
    run(cc(&zig, target)
        .arg("-shared")
        .arg("-o")
        .arg(&original)
        .arg(root.join("original.c"))
        .arg(root.join("original.def")));

    let out = root.join("mirror");
    let output = Command::new(env!("CARGO_BIN_EXE_kotama"))
        .args(["proxy", "generate"])
        .arg(&original)
        .arg("--output")
        .arg(&out)
        .arg("--backing")
        .arg("original_real.dll")
        .arg("--build")
        .env("KOTAMA_ZIG", &zig)
        .output()
        .expect("generate mirror");
    assert!(
        output.status.success(),
        "generation failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.join("proxy.def").is_file());
    assert!(out.join("manifest.json").is_file());
    assert!(out.join("mirror.dll").is_file());
    fs::copy(&original, out.join("original_real.dll")).unwrap();

    write(
        &out.join("client.c"),
        r#"#include <windows.h>
typedef int (__cdecl *IntFn)(void);
typedef void (WINAPI *SleepFn)(DWORD);
int main(void) {
    HMODULE module = LoadLibraryW(L"mirror.dll");
    if (!module) return 10;
    IntFn alpha = (IntFn)GetProcAddress(module, "Alpha");
    IntFn alias = (IntFn)GetProcAddress(module, "Alias");
    IntFn plain = (IntFn)GetProcAddress(module, (LPCSTR)7);
    SleepFn forwarded = (SleepFn)GetProcAddress(module, "Forwarded");
    if (!alpha || !alias || !plain || !forwarded) return 11;
    if (alpha() != 42 || alias() != 42 || plain() != 7) return 12;
    forwarded(0);
    return 0;
}
"#,
    );
    run(cc(&zig, target)
        .arg("-o")
        .arg(out.join("client.exe"))
        .arg(out.join("client.c")));
    run(Command::new(out.join("client.exe")).current_dir(&out));

    let inspection = Command::new(env!("CARGO_BIN_EXE_kotama"))
        .args(["proxy", "inspect"])
        .arg(out.join("mirror.dll"))
        .output()
        .expect("inspect mirror");
    assert!(inspection.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&inspection.stdout).unwrap();
    assert_eq!(facts["export_count"].as_u64(), Some(4));
    let text = String::from_utf8_lossy(&inspection.stdout);
    assert!(text.contains("Alpha"));
    assert!(text.contains("Alias"));

    let second = Command::new(env!("CARGO_BIN_EXE_kotama"))
        .args(["proxy", "generate"])
        .arg(&original)
        .arg("--output")
        .arg(&out)
        .arg("--build")
        .env("KOTAMA_ZIG", &zig)
        .output()
        .expect("overwrite refusal");
    assert!(
        !second.status.success(),
        "existing outputs must not be overwritten"
    );

    let hooks = root.join("hooks.c");
    write(
        &hooks,
        "int __cdecl KOTAMA_OVERRIDE_5(void) { return 99; }\nint __cdecl KOTAMA_OVERRIDE_7(void) { return 77; }\n",
    );
    let out_override = root.join("override");
    let override_output = Command::new(env!("CARGO_BIN_EXE_kotama"))
        .args(["proxy", "generate"])
        .arg(&original)
        .arg("--output")
        .arg(&out_override)
        .arg("--backing")
        .arg("original_real.dll")
        .arg("--override")
        .arg("Alpha")
        .arg("--override-ordinal")
        .arg("7")
        .arg("--hooks")
        .arg(&hooks)
        .arg("--build")
        .env("KOTAMA_ZIG", &zig)
        .output()
        .expect("generate override mirror");
    assert!(
        override_output.status.success(),
        "override generation failed:\n{}\n{}",
        String::from_utf8_lossy(&override_output.stdout),
        String::from_utf8_lossy(&override_output.stderr)
    );
    fs::copy(&original, out_override.join("original_real.dll")).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(out_override.join("manifest.json")).unwrap()).unwrap();
    let overridden = manifest["exports"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|export| export["action"] == "override")
        .count();
    assert_eq!(overridden, 2);
    assert_eq!(manifest["hooks"]["source"], "hooks.c");

    write(
        &out_override.join("client_override.c"),
        r#"#include <windows.h>
typedef int (__cdecl *IntFn)(void);
typedef void (WINAPI *SleepFn)(DWORD);
int main(void) {
    HMODULE module = LoadLibraryW(L"mirror.dll");
    if (!module) return 20;
    IntFn alpha = (IntFn)GetProcAddress(module, "Alpha");
    IntFn alias = (IntFn)GetProcAddress(module, "Alias");
    IntFn plain = (IntFn)GetProcAddress(module, (LPCSTR)7);
    SleepFn forwarded = (SleepFn)GetProcAddress(module, "Forwarded");
    if (!alpha || !alias || !plain || !forwarded) return 21;
    if (alpha() != 99 || alias() != 42 || plain() != 77) return 22;
    forwarded(0);
    return 0;
}
"#,
    );
    run(cc(&zig, target)
        .arg("-o")
        .arg(out_override.join("client.exe"))
        .arg(out_override.join("client_override.c")));
    run(Command::new(out_override.join("client.exe")).current_dir(&out_override));

    let out_log = root.join("log");
    let log_output = Command::new(env!("CARGO_BIN_EXE_kotama"))
        .args(["proxy", "generate"])
        .arg(&original)
        .arg("--output")
        .arg(&out_log)
        .arg("--backing")
        .arg("original_real.dll")
        .args(["--log", "Alpha", "--log-ordinal", "7", "--build"])
        .env("KOTAMA_ZIG", &zig)
        .output()
        .expect("generate log mirror");
    assert!(
        log_output.status.success(),
        "log generation failed:\n{}\n{}",
        String::from_utf8_lossy(&log_output.stdout),
        String::from_utf8_lossy(&log_output.stderr)
    );
    fs::copy(&original, out_log.join("original_real.dll")).unwrap();
    write(
        &out_log.join("client_log.c"),
        r#"#include <windows.h>
typedef int (__cdecl *IntFn)(void);
int main(void) {
    HMODULE module = LoadLibraryW(L"mirror.dll");
    if (!module) return 30;
    IntFn alpha = (IntFn)GetProcAddress(module, "Alpha");
    IntFn alias = (IntFn)GetProcAddress(module, "Alias");
    IntFn plain = (IntFn)GetProcAddress(module, (LPCSTR)7);
    if (!alpha || !alias || !plain) return 31;
    if (alpha() != 42 || alias() != 42 || plain() != 7) return 32;
    Sleep(300);
    return 0;
}
"#,
    );
    run(cc(&zig, target)
        .arg("-o")
        .arg(out_log.join("client.exe"))
        .arg(out_log.join("client_log.c")));
    let log_path = out_log.join("calls.txt");
    run(Command::new(out_log.join("client.exe"))
        .current_dir(&out_log)
        .env("KOTAMA_PROXY_LOG", &log_path));
    let mut text = String::new();
    for _ in 0..40 {
        text = fs::read_to_string(&log_path).unwrap_or_default();
        if text.contains("ord=5") && text.contains("ord=7") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(text.contains("ord=5"), "log missing ordinal 5: {text:?}");
    assert!(text.contains("ord=7"), "log missing ordinal 7: {text:?}");
    assert!(
        !text.contains("ord=6"),
        "unselected alias was logged: {text:?}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(out_log.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["log_count"], 2);
    assert_eq!(
        manifest["exports"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|export| export["action"] == "log")
            .count(),
        2
    );
    fs::remove_dir_all(&root).unwrap();
}
