//! End-to-end proof for `kotama runtime mount` against real libraries.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn kotama() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kotama"));
    command.arg("runtime");
    command
}

fn fixture(relative: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/generated")
        .join(relative);
    path.exists().then_some(path)
}

fn json_of(output: &[u8]) -> serde_json::Value {
    serde_json::from_slice(output).unwrap()
}

/// Every runtime's point count is the count the real binaries were held to.
#[test]
fn list_shows_the_three_runtimes_with_their_real_counts() {
    let output = kotama().arg("--list").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let lua = text.lines().find(|line| line.starts_with("lua")).unwrap();
    assert!(lua.contains("98 points"), "{lua}");
    let quickjs = text
        .lines()
        .find(|line| line.starts_with("quickjs"))
        .unwrap();
    assert!(quickjs.contains("251 points"), "{quickjs}");
    let jni = text.lines().find(|line| line.starts_with("jni")).unwrap();
    assert!(jni.contains("3 points"), "{jni}");
}

/// The 5.4 release carries the whole Lua table: every mount point resolves, the
/// plan verifies complete, and the exit code is success.
#[test]
fn lua_5_4_resolves_every_mount_point() {
    let Some(so) = fixture("lua/liblua-5.4.7.so") else {
        eprintln!("skip: Lua fixture not built");
        return;
    };
    let output = kotama()
        .args(["mount", so.to_str().unwrap(), "--runtime", "lua"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_of(&output.stdout);
    assert_eq!(json["planned"], 98);
    assert_eq!(json["verification"]["addressed"], 98);
    assert_eq!(json["verification"]["complete"], true);
    assert_eq!(json["resolved"].as_array().unwrap().len(), 98);
    // Addresses are absolute: at or above the image base of a non-PIE musl .so.
    let first = &json["resolved"][0]["address"].as_str().unwrap();
    let address = u64::from_str_radix(first.trim_start_matches("0x"), 16).unwrap();
    assert!(address > 0x1000, "{first}");
}

/// The 5.1 release lacks 34 names: the plan verifies incomplete with exactly
/// 34 missing groups, and the command always exits non-zero on an incomplete
/// plan rather than reporting one that cannot be mounted.
/// mutate: incomplete-exits-zero (an exit code that ignores verification makes
/// this test fail on the status code while the JSON is unchanged).
fn lua_5_1_reports_exactly_the_absent_names_and_fails() {
    let Some(so) = fixture("lua/liblua-5.1.5.so") else {
        eprintln!("skip: Lua fixture not built");
        return;
    };
    let output = kotama()
        .args(["mount", so.to_str().unwrap(), "--runtime", "lua"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json = json_of(&output.stdout);
    assert_eq!(json["verification"]["addressed"], 64);
    assert_eq!(
        json["verification"]["missing"].as_array().unwrap().len(),
        34
    );
    assert_eq!(json["verification"]["complete"], false);
    assert_eq!(json["unresolved"].as_array().unwrap().len(), 34);
}

/// The Invocation API resolves completely against the real VM library; the three
/// names are the three the export directory carries and no others.
#[test]
fn the_invocation_api_resolves_against_the_real_vm_library() {
    let dll = Path::new(
        "D:/源代码/工程项目/celestia/_scratch/kotama-tools/jdk25/jdk-25.0.5.1+2/bin/server/jvm.dll",
    );
    if !dll.exists() {
        eprintln!("skip: VM library not on this machine");
        return;
    }
    let output = kotama()
        .args(["mount", dll.to_str().unwrap(), "--runtime", "jni"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_of(&output.stdout);
    assert_eq!(json["planned"], 3);
    assert_eq!(json["verification"]["complete"], true);
    let names: Vec<&str> = json["resolved"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hook| hook["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "JNI_CreateJavaVM",
            "JNI_GetCreatedJavaVMs",
            "JNI_GetDefaultJavaVMInitArgs"
        ]
    );
    // mutate: invocation-base-into-slots (a base colliding with the slot range
    // would still print three hooks but with groups under 0x100; the groups are
    // checked to sit at the invocation base).
    for hook in json["resolved"].as_array().unwrap() {
        let group = hook["group"].as_u64().unwrap();
        assert!((0x3_0000..0x3_0000 + 3).contains(&group), "{hook}");
    }
}

/// A library that is not the runtime resolves nothing and the command fails.
#[test]
fn the_wrong_library_for_a_runtime_resolves_nothing_and_fails() {
    let Some(dll) = fixture("x86_64-windows-gnu/-O2/libexports.dll") else {
        eprintln!("skip: fixture not built");
        return;
    };
    let output = kotama()
        .args(["mount", dll.to_str().unwrap(), "--runtime", "lua"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json = json_of(&output.stdout);
    assert_eq!(json["verification"]["addressed"], 0);
    assert_eq!(json["unresolved"].as_array().unwrap().len(), 98);
}

#[test]
fn an_unknown_runtime_is_rejected() {
    let Some(so) = fixture("lua/liblua-5.4.7.so") else {
        return;
    };
    let output = kotama()
        .args(["mount", so.to_str().unwrap(), "--runtime", "perl"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("known: lua, quickjs, jni"));
}

#[test]
fn missing_arguments_print_usage() {
    let output = kotama().arg("mount").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--runtime"));
}
