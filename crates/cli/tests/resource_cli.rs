//! CLI integration tests for kotama resource (synthetic inputs only).
#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

// Every test is feature-gated, so without --all-features these helpers look unused.
#[allow(dead_code)]
fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("kotama-resource-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[allow(dead_code)]
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

#[cfg(feature = "resource-dds")]
#[test]
fn dds_header_is_inspected() {
    let root = temp_dir("dds");
    let source = root.join("surface.dds");
    let mut bytes = vec![0u8; 128];
    bytes[0..4].copy_from_slice(b"DDS ");
    bytes[4..8].copy_from_slice(&124u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x1007u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&32u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&64u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&4u32.to_le_bytes());
    bytes[80..84].copy_from_slice(&0x4u32.to_le_bytes());
    bytes[84..88].copy_from_slice(b"DXT1");
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "dds");
    assert_eq!(facts["basis"], "magic");

    let dds = kotama()
        .args(["resource", "dds"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(dds.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&dds.stdout).unwrap();
    assert_eq!(facts["width"], 64);
    assert_eq!(facts["height"], 32);
    assert_eq!(facts["mipmaps"], 4);
    assert_eq!(facts["fourcc"], "DXT1");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-tga")]
#[test]
fn tga_header_is_inspected() {
    let root = temp_dir("tga");
    let source = root.join("image.tga");
    let mut bytes = vec![0u8; 18];
    bytes[2] = 2;
    bytes[12..14].copy_from_slice(&64u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&32u16.to_le_bytes());
    bytes[16] = 24;
    bytes[17] = 0x20;
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "tga");
    assert_eq!(facts["basis"], "extension");

    let tga = kotama()
        .args(["resource", "tga"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(tga.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&tga.stdout).unwrap();
    assert_eq!(facts["width"], 64);
    assert_eq!(facts["height"], 32);
    assert_eq!(facts["pixel_depth"], 24);
    fs::remove_dir_all(&root).unwrap();
}
