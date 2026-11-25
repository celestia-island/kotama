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
    fs::remove_dir_all(&root).unwrap();
}
