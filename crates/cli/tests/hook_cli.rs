//! End-to-end proof for `kotama hook plan`: a preset against a real binary.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

fn kotama() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kotama"));
    command.arg("hook");
    command
}

fn fixture(relative: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/generated")
        .join(relative);
    path.exists().then_some(path)
}

/// `--list` names every preset and its native/posix split; the loader preset is
/// the mixed one the whole feature exists for.
#[test]
fn list_shows_every_preset_with_its_platform_split() {
    let output = kotama().arg("--list").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("loader"), "{text}");
    let loader = text
        .lines()
        .find(|line| line.starts_with("loader"))
        .unwrap();
    assert!(loader.contains("12 native"), "{loader}");
    assert!(loader.contains("8 posix"), "{loader}");
}

/// A preset whose Windows names the fixture does not carry fails on a Windows
/// name. The fixture has no socket exports, so the first missing name is one of
/// winsock's own.
/// mutate: pe-read-as-posix (platform_of_container returning Posix for a PE makes
/// the Windows names excused and the plan succeed with zero hooks instead).
#[test]
fn a_windows_preset_plans_against_a_windows_library() {
    let Some(dll) = fixture("x86_64-windows-gnu/-O2/libexports.dll") else {
        eprintln!("skip: fixture not built");
        return;
    };
    let output = kotama()
        .args(["plan", dll.to_str().unwrap(), "--preset", "winsock"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("hook name not found"), "{stderr}");
}

/// The loader preset against the fixture: it carries none of the Windows names,
/// so the plan fails — and the failure names a Windows name, not one of the
/// eight Posix names the selection excuses.
#[test]
fn a_plan_lists_excused_posix_names_without_erroring_on_them() {
    let Some(dll) = fixture("x86_64-windows-gnu/-O2/libexports.dll") else {
        eprintln!("skip: fixture not built");
        return;
    };
    let output = kotama()
        .args(["plan", dll.to_str().unwrap(), "--preset", "loader"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for posix in ["dlopen", "pthread_create", "dlerror"] {
        assert!(
            !stderr.contains(posix),
            "a Posix name must not be the error: {stderr}"
        );
    }
    assert!(stderr.contains("hook name not found"), "{stderr}");
}

/// A POSIX binary selects the POSIX names and excuses nothing, so a Windows
/// name in the same preset is the error — and the error is not `dlopen`.
#[test]
fn a_posix_binary_selects_posix_names_and_excuses_nothing() {
    let Some(so) = fixture("lua/liblua-5.4.7.so") else {
        eprintln!("skip: Lua fixture not built");
        return;
    };
    let output = kotama()
        .args(["plan", so.to_str().unwrap(), "--preset", "loader"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("hook name not found"), "{stderr}");
    // Lua exports none of the loader names, so the first missing one is sorted
    // as the preset lists it; it must not be a Posix name being excused.
    assert!(!stderr.contains("dlopen"), "{stderr}");
}

/// An unknown preset is rejected with the known ids listed, exit code 1.
#[test]
fn an_unknown_preset_is_rejected_by_name() {
    let Some(so) = fixture("lua/liblua-5.4.7.so") else {
        eprintln!("skip: Lua fixture not built");
        return;
    };
    let output = kotama()
        .args(["plan", so.to_str().unwrap(), "--preset", "nope"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown preset"), "{stderr}");
    assert!(stderr.contains("loader"), "{stderr}");
}

/// No preset, no path: usage on stderr, exit 2.
#[test]
fn missing_arguments_print_usage() {
    let output = kotama().arg("plan").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--preset"));
}

/// A real system library and the preset written for it: every preset name
/// resolves, the plan carries all 21 hooks, nothing is excused. Skips where the
/// library is absent.
#[test]
fn winsock_plans_completely_against_the_real_system_library() {
    let dll = std::path::Path::new("C:/Windows/System32/ws2_32.dll");
    if !dll.exists() {
        eprintln!("skip: ws2_32.dll not on this machine");
        return;
    }
    let output = kotama()
        .args(["plan", dll.to_str().unwrap(), "--preset", "winsock"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["platform"], "windows");
    assert_eq!(json["hooks"].as_array().unwrap().len(), 21);
    assert_eq!(json["excused"].as_array().unwrap().len(), 0);
}

/// The mixed preset against the real C runtime: 20 hooks land, and exactly the
/// three Posix names are excused — the figure the export-table read predicted.
#[test]
fn c_runtime_plans_against_the_real_system_library_with_posix_names_excused() {
    let dll = std::path::Path::new("C:/Windows/System32/msvcrt.dll");
    if !dll.exists() {
        eprintln!("skip: msvcrt.dll not on this machine");
        return;
    }
    let output = kotama()
        .args(["plan", dll.to_str().unwrap(), "--preset", "c-runtime"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["hooks"].as_array().unwrap().len(), 20);
    let excused: Vec<&str> = json["excused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(excused, ["aligned_alloc", "posix_memalign", "snprintf"]);
}
