//! CLI integration tests for kotama resource (synthetic inputs only).
#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("kotama-resource-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn kotama() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kotama"))
}

#[cfg(feature = "resource-vbs")]
#[test]
fn vbs_source_is_identified_inspected_and_extracted() {
    let root = temp_dir("vbs");
    let source = root.join("synthetic.vbs");
    let text = "WScript.Echo \"synthetic\"\r\n";
    fs::write(&source, text).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "vbs");
    assert_eq!(facts["enabled"], true);

    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["encoding"], "utf-8");

    let output = root.join("out.txt");
    let extract = kotama()
        .args(["resource", "extract"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(fs::read_to_string(&output).unwrap(), text);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-dos-com")]
#[test]
fn dos_com_is_extracted_verbatim() {
    let root = temp_dir("com");
    let source = root.join("program.com");
    let payload = [0xB8u8, 0x00, 0x4C, 0xCD, 0x21];
    fs::write(&source, payload).unwrap();
    let output = root.join("out.com");
    let extract = kotama()
        .args(["resource", "extract"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(fs::read(&output).unwrap(), payload);
    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["kind"], "dos-com");
    assert_eq!(facts["load_address"], 0x100);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-swf")]
#[test]
fn swf_header_is_inspected_and_fws_is_extracted() {
    let root = temp_dir("swf");
    let source = root.join("movie.swf");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"FWS");
    bytes.push(9);
    bytes.extend_from_slice(&12u32.to_le_bytes());
    bytes.extend_from_slice(b"abcd");
    fs::write(&source, &bytes).unwrap();
    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["kind"], "swf");
    assert_eq!(facts["compression"], "none");
    let output = root.join("out.swf");
    let extract = kotama()
        .args(["resource", "extract"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-big")]
#[test]
fn big_archive_is_identified_and_inspected() {
    let root = temp_dir("big");
    let source = root.join("sample.big");
    let name = "data\\sample.xml";
    let payload = b"<asset/>";
    let table_len = 8 + name.len() + 1;
    let data_start = 16 + table_len;
    let total = data_start + payload.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BIG4");
    bytes.extend_from_slice(&(total as u32).to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&(data_start as u32).to_be_bytes());
    bytes.extend_from_slice(&(data_start as u32).to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(payload);
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "big");
    assert_eq!(facts["basis"], "magic");

    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["archive_version"], "big4");
    assert_eq!(facts["entries"], 1);
    assert_eq!(facts["declared_length"], total);

    let entries = kotama()
        .args(["resource", "entries"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(entries.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&entries.stdout).unwrap();
    assert_eq!(facts["count"], 1);
    assert_eq!(facts["entries"][0]["name"], name);

    let output = root.join("entry.xml");
    let extract = kotama()
        .args(["resource", "extract"])
        .arg(&source)
        .args(["--entry", name, "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(fs::read(&output).unwrap(), payload);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(not(feature = "resource-vbs"))]
#[test]
fn disabled_vbs_feature_is_reported_with_exit_code_three() {
    let root = temp_dir("disabled");
    let source = root.join("synthetic.vbs");
    fs::write(&source, "WScript.Echo \"synthetic\"").unwrap();
    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(info.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&info.stderr).contains("feature vbs"));
    fs::remove_dir_all(&root).unwrap();
}
