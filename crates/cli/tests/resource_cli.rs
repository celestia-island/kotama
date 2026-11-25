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

#[cfg(feature = "resource-w3d")]
#[test]
fn w3d_chunks_are_inspected() {
    let root = temp_dir("w3d");
    let source = root.join("model.w3d");
    let mut child = 31u32.to_le_bytes().to_vec();
    child.extend_from_slice(&4u32.to_le_bytes());
    child.extend_from_slice(b"abcd");
    let mut bytes = 0u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(0x8000_0000u32 | child.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&child);
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "w3d");
    assert_eq!(facts["basis"], "extension");

    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["chunks"], 2);

    let chunks = kotama()
        .args(["resource", "chunks"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(chunks.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&chunks.stdout).unwrap();
    assert_eq!(facts["count"], 2);
    assert_eq!(facts["chunks"][1]["type_id"], 31);
    assert_eq!(facts["chunks"][1]["name"], "mesh_header3");
    assert_eq!(facts["chunks"][1]["depth"], 1);
    assert_eq!(facts["chunks"][1]["offset"], 8);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-w3d")]
#[test]
fn w3d_mesh_records_are_inspected() {
    let root = temp_dir("w3d-mesh");
    let source = root.join("mesh.w3d");

    fn chunk(type_id: u32, payload: &[u8], container: bool) -> Vec<u8> {
        let mut bytes = type_id.to_le_bytes().to_vec();
        let size = if container {
            0x8000_0000 | payload.len() as u32
        } else {
            payload.len() as u32
        };
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    let mut header = vec![0u8; 116];
    header[0..4].copy_from_slice(&1u32.to_le_bytes());
    header[8..11].copy_from_slice(b"box");
    header[24..29].copy_from_slice(b"scene");
    header[44..48].copy_from_slice(&2u32.to_le_bytes());
    let vertices = vec![0u8; 24];
    let payload = [chunk(0x1f, &header, false), chunk(0x02, &vertices, false)].concat();
    let bytes = chunk(0, &payload, true);
    fs::write(&source, &bytes).unwrap();

    let mesh = kotama()
        .args(["resource", "mesh"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        mesh.status.success(),
        "{}",
        String::from_utf8_lossy(&mesh.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&mesh.stdout).unwrap();
    assert_eq!(facts["mesh_name"], "box");
    assert_eq!(facts["container_name"], "scene");
    assert_eq!(facts["num_vertices"], 2);
    assert_eq!(facts["vertex_count"], 2);
    assert_eq!(facts["triangle_count"], 0);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-apt-const")]
#[test]
fn apt_constants_are_inspected() {
    let root = temp_dir("apt");
    let source = root.join("sample.const");
    let mut bytes = b"Apt constant file".to_vec();
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&0x50cu32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&32u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&48u32.to_le_bytes());
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&42i32.to_le_bytes());
    bytes.extend_from_slice(b"hello\0");
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "apt-const");
    assert_eq!(facts["basis"], "magic");

    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["apt_entry_offset"], 0x50c);
    assert_eq!(facts["constants"], 2);

    let apt = kotama()
        .args(["resource", "apt"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(apt.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&apt.stdout).unwrap();
    assert_eq!(facts["count"], 2);
    assert_eq!(facts["entries"][0]["value"], "hello");
    assert_eq!(facts["entries"][1]["value"], 42);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-csf")]
#[test]
fn csf_labels_are_inspected() {
    let root = temp_dir("csf");
    let source = root.join("strings.csf");
    let mut bytes = b" FSC".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(b" LBL");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(b"NAME\0");
    bytes.extend_from_slice(b"STR ");
    let value = "HELLO".encode_utf16().map(|unit| !unit).collect::<Vec<_>>();
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    for unit in value {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "csf");
    assert_eq!(facts["basis"], "magic");

    let info = kotama()
        .args(["resource", "info"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(info.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(facts["entries"], 1);

    let csf = kotama()
        .args(["resource", "csf"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(csf.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&csf.stdout).unwrap();
    assert_eq!(facts["labels"][0]["name"], "NAME");
    assert_eq!(facts["labels"][0]["values"][0], "HELLO");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-apt-geometry")]
#[test]
fn apt_geometry_is_inspected() {
    let root = temp_dir("apt-geometry");
    let source = root.join("shape.ru");
    fs::write(
        &source,
        "c\ns s:255:255:255:255\nt -1:-1:-2:-2:2:-2\nt 1:1:2:2:2:2\nl 0:0:1:1\n",
    )
    .unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "apt-geometry");
    assert_eq!(facts["basis"], "extension");

    let geometry = kotama()
        .args(["resource", "geometry"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        geometry.status.success(),
        "{}",
        String::from_utf8_lossy(&geometry.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&geometry.stdout).unwrap();
    assert_eq!(facts["styles"][0]["kind"], "s");
    assert_eq!(facts["triangle_count"], 2);
    assert_eq!(facts["line_count"], 1);
    assert_eq!(facts["bounds"], serde_json::json!([-2.0, -2.0, 2.0, 2.0]));
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

#[cfg(feature = "resource-vp6")]
#[test]
fn vp6_header_is_inspected() {
    let root = temp_dir("vp6");
    let source = root.join("movie.vp6");
    let mut bytes = b"MVhd".to_vec();
    bytes.extend_from_slice(&32u32.to_le_bytes());
    bytes.extend_from_slice(b"vp60");
    bytes.extend_from_slice(&1280u16.to_le_bytes());
    bytes.extend_from_slice(&720u16.to_le_bytes());
    bytes.extend_from_slice(&514u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 14]);
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "vp6");
    assert_eq!(facts["basis"], "magic");

    let vp6 = kotama()
        .args(["resource", "vp6"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(vp6.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&vp6.stdout).unwrap();
    assert_eq!(facts["width"], 1280);
    assert_eq!(facts["height"], 720);
    assert_eq!(facts["frame_count"], 514);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-asset-manifest")]
#[test]
fn asset_manifest_header_is_inspected() {
    let root = temp_dir("asset-manifest");
    let source = root.join("sample.manifest");
    let mut bytes = vec![0u8; 48];
    bytes[1] = 1;
    bytes[2..4].copy_from_slice(&6u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&16u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&8u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&15u32.to_le_bytes());
    bytes[44..48].copy_from_slice(&11u32.to_le_bytes());
    let mut entry = Vec::new();
    for value in [1u32, 2, 3, 4, 0, 1, 0, 0, 16, 8, 4, 0] {
        entry.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(b"AptAptData:Foo\0");
    bytes.extend_from_slice(b"source.xml\0");
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "asset-manifest");
    assert_eq!(facts["basis"], "extension");

    let manifest = kotama()
        .args(["resource", "manifest"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(manifest.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(facts["version"], 6);
    assert_eq!(facts["asset_count"], 1);
    assert_eq!(facts["total_instance_data_size"], 16);
    assert_eq!(facts["source_file_name_buffer_size"], 11);
    assert_eq!(facts["names"][0], "AptAptData:Foo");
    assert_eq!(facts["names"][1], "source.xml");
    assert_eq!(facts["entries"][0]["name"], "AptAptData:Foo");
    assert_eq!(facts["entries"][0]["source_name"], "source.xml");
    assert_eq!(facts["entries"][0]["references"][0]["type_id"], 7);
    assert_eq!(facts["entries"][0]["references"][0]["instance_id"], 8);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-asset")]
#[test]
fn asset_header_is_inspected() {
    let root = temp_dir("asset");
    let source = root.join("sample.asset");
    let mut bytes = vec![0u8; 36];
    bytes[0..16].copy_from_slice(&[1u8; 16]);
    bytes[20..24].copy_from_slice(&856u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&5u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&37u32.to_le_bytes());
    bytes.extend_from_slice(b"ArmorTemplate:JapanHiveGeneratorArmorA");
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(b"DATA:civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml");
    for value in [
        0xffe88740u32,
        0x645864f3,
        60,
        0x6c827073,
        0x5d448fd8,
        64,
        0x11111111,
        0x22222222,
        68,
        0x33333333,
        0x44444444,
        72,
        0x55555555,
        0x66666666,
        76,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&1.0f32.to_le_bytes());
    bytes.extend_from_slice(&24u32.to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0]);
    bytes.extend_from_slice(&7u32.to_le_bytes());
    for value in [
        0x6c827073u32,
        0x5d448fd8,
        0,
        0xb151a0eb,
        0,
        254,
        0x6c827073,
        0x5d448fd8,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&258u32.to_le_bytes());
    bytes.extend_from_slice(b"REGION\0");
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "asset");
    assert_eq!(facts["basis"], "extension");

    let asset = kotama()
        .args(["resource", "asset"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(asset.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&asset.stdout).unwrap();
    assert_eq!(facts["data_size"], 856);
    assert_eq!(facts["property_count"], 5);
    assert_eq!(facts["type_name"], "ArmorTemplate:JapanHiveGeneratorArmorA");
    assert_eq!(
        facts["data_path"],
        "civilian/tokyo_harbor_th/buildings/th_japanhivegenerator.xml"
    );
    assert_eq!(facts["properties"][0]["name_hash"], 0xffe88740u64);
    assert_eq!(facts["properties"][0]["type_hash"], 0x645864f3u64);
    assert_eq!(facts["properties"][0]["value_or_offset"], 60u64);

    let map = root.join("hash-map.tsv");
    fs::write(
        &map,
        b"4293429056\tDefault\n1683514611\tfloat_t\n1820487795\tCount\n1564774360\tsize_t\n286331153\tIsTrainable\n572662306\tbool\n858993459\tFlags\n1145324612\tuint32_t\n1431655765\tBrowser\n1717986918\tStringList\n",
    )
    .unwrap();
    let resolved = kotama()
        .args(["resource", "asset"])
        .arg(&source)
        .arg("--hash-map")
        .arg(&map)
        .output()
        .unwrap();
    assert!(resolved.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(facts["properties"][0]["name"], "Default");
    assert_eq!(facts["properties"][0]["property_type"], "float_t");
    assert_eq!(facts["properties"][0]["value"], 1.0);
    assert_eq!(facts["properties"][1]["name"], "Count");
    assert_eq!(facts["properties"][1]["property_type"], "size_t");
    assert_eq!(facts["properties"][1]["value"], 24);
    assert_eq!(facts["properties"][2]["name"], "IsTrainable");
    assert_eq!(facts["properties"][2]["property_type"], "bool");
    assert_eq!(facts["properties"][2]["value"], true);
    assert_eq!(facts["properties"][3]["name"], "Flags");
    assert_eq!(facts["properties"][3]["property_type"], "uint32_t");
    assert_eq!(facts["properties"][3]["value"], 7);
    assert_eq!(facts["properties"][4]["name"], "Browser");
    assert_eq!(facts["properties"][4]["property_type"], "StringList");
    assert_eq!(
        facts["properties"][4]["value"],
        serde_json::json!(["REGION"]),
        "property = {} stderr = {}",
        facts["properties"][4],
        String::from_utf8_lossy(&resolved.stderr)
    );
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-asset-relocation")]
#[test]
fn relocation_table_is_inspected() {
    let root = temp_dir("relocation");
    let source = root.join("sample.relo");
    let mut bytes = 0x6d1ddbe1u32.to_le_bytes().to_vec();
    for value in [4u32, 0xffff_ffff, 4, 0x1234_5678] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(&source, &bytes).unwrap();

    let identify = kotama()
        .args(["resource", "identify"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(identify.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&identify.stdout).unwrap();
    assert_eq!(facts["kind"], "asset-relocation");
    assert_eq!(facts["basis"], "extension");

    let relocation = kotama()
        .args(["resource", "relocation"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(relocation.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&relocation.stdout).unwrap();
    assert_eq!(facts["checksum"], 1830673377u64);
    assert_eq!(facts["entries"].as_array().unwrap().len(), 2);
    assert_eq!(facts["entries"][0]["kind"], 4);
    assert_eq!(facts["entries"][0]["offset"], 4294967295u64);
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-apt-movie")]
#[test]
fn apt_movie_is_inspected() {
    let root = temp_dir("apt-movie");
    let source = root.join("sample.apt");
    let mut bytes = vec![0u8; 16];
    bytes.extend_from_slice(&9u32.to_le_bytes());
    bytes.extend_from_slice(&0x0987_6543u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&56u32.to_le_bytes());
    bytes.extend_from_slice(&800u32.to_le_bytes());
    bytes.extend_from_slice(&600u32.to_le_bytes());
    bytes.extend_from_slice(&33u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.resize(72, 0);
    bytes.extend_from_slice(&64u32.to_le_bytes());
    bytes.resize(80, 0);
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&0x0987_6543u32.to_le_bytes());
    fs::write(&source, &bytes).unwrap();

    let movie = kotama()
        .args(["resource", "apt-movie"])
        .arg(&source)
        .arg("--entry-offset")
        .arg("16")
        .output()
        .unwrap();
    assert!(
        movie.status.success(),
        "{}",
        String::from_utf8_lossy(&movie.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&movie.stdout).unwrap();
    assert_eq!(facts["frame_count"], 0);
    assert_eq!(facts["character_count"], 1);
    assert_eq!(facts["screen_width"], 800);
    assert_eq!(facts["screen_height"], 600);
    assert_eq!(facts["characters"][0]["type_name"], "sprite");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-apt-image-map")]
#[test]
fn apt_image_map_is_inspected() {
    let root = temp_dir("apt-image-map");
    let source = root.join("sample.dat");
    fs::write(&source, b"; comment\n19->1\n26 = 1\n23->1 (2 3 4 5)\n9->\n").unwrap();
    let map = kotama()
        .args(["resource", "apt-image-map"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(map.status.success());
    let facts: serde_json::Value = serde_json::from_slice(&map.stdout).unwrap();
    assert_eq!(facts["assignments"].as_array().unwrap().len(), 4);
    assert_eq!(facts["assignments"][0]["image_id"], 19);
    assert_eq!(facts["assignments"][0]["texture_id"], 1);
    assert_eq!(
        facts["assignments"][2]["rectangle"],
        serde_json::json!([2, 3, 4, 5])
    );
    assert_eq!(
        facts["assignments"][3]["texture_id"],
        serde_json::Value::Null
    );
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-pvz-reanim")]
#[test]
fn pvz_reanim_is_inspected() {
    use std::io::Write;
    let root = temp_dir("pvz-reanim");
    let source = root.join("sample.reanim.compiled");
    let mut body = Vec::new();
    body.extend_from_slice(&0xB393_B4C0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&11u32.to_le_bytes());
    body.extend_from_slice(&12.0f32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&12u32.to_le_bytes());
    body.extend_from_slice(b"anim_idle\0");
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zlib.write_all(&body).unwrap();
    let compressed = zlib.finish().unwrap();
    let mut bytes = 0xDEAD_FED4u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&compressed);
    fs::write(&source, &bytes).unwrap();

    let reanim = kotama()
        .args(["resource", "pvz-reanim"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        reanim.status.success(),
        "{}",
        String::from_utf8_lossy(&reanim.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&reanim.stdout).unwrap();
    assert_eq!(facts["track_count"], 11);
    assert_eq!(facts["fps"], 12.0);
    assert_eq!(facts["strings"][0], "anim_idle");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-pak")]
#[test]
fn pak_is_inspected() {
    let root = temp_dir("pak");
    let source = root.join("sample.pak");
    let mut data = Vec::new();
    data.extend_from_slice(&0xBAC0_4AC0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(0);
    data.push(5);
    data.extend_from_slice(b"hello");
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0xFF);
    data.extend_from_slice(b"abc");
    let encrypted: Vec<u8> = data.iter().map(|byte| byte ^ 0xF7).collect();
    fs::write(&source, &encrypted).unwrap();

    let pak = kotama()
        .args(["resource", "pak"])
        .arg(&source)
        .arg("--limit")
        .arg("1")
        .output()
        .unwrap();
    assert!(
        pak.status.success(),
        "{}",
        String::from_utf8_lossy(&pak.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&pak.stdout).unwrap();
    assert_eq!(facts["files"], 1);
    assert_eq!(facts["bytes"], 3);
    assert_eq!(facts["entries"][0]["name"], "hello");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-pak")]
#[test]
fn pak_entry_is_extracted() {
    let root = temp_dir("pak-extract");
    let source = root.join("sample.pak");
    let output = root.join("out.txt");
    let mut data = Vec::new();
    data.extend_from_slice(&0xBAC0_4AC0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(0);
    data.push(5);
    data.extend_from_slice(b"hello");
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0xFF);
    data.extend_from_slice(b"abc");
    let encrypted: Vec<u8> = data.iter().map(|byte| byte ^ 0xF7).collect();
    fs::write(&source, &encrypted).unwrap();

    let extracted = kotama()
        .args(["resource", "pak-extract"])
        .arg(&source)
        .arg("--entry")
        .arg("hello")
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(fs::read_to_string(&output).unwrap(), "abc");
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-pak")]
#[test]
fn pak_entries_are_batch_extracted() {
    let root = temp_dir("pak-extract-all");
    let source = root.join("sample.pak");
    let output = root.join("out");
    let mut data = Vec::new();
    data.extend_from_slice(&0xBAC0_4AC0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(0);
    data.push(9);
    data.extend_from_slice(b"dir\\hello");
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0xFF);
    data.extend_from_slice(b"abc");
    let encrypted: Vec<u8> = data.iter().map(|byte| byte ^ 0xF7).collect();
    fs::write(&source, &encrypted).unwrap();

    let extracted = kotama()
        .args(["resource", "pak-extract-all"])
        .arg(&source)
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(
        fs::read_to_string(output.join("dir").join("hello")).unwrap(),
        "abc"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(feature = "resource-pak")]
#[test]
fn pak_extract_all_rejects_parent_traversal() {
    let root = temp_dir("pak-extract-all-traversal");
    let source = root.join("sample.pak");
    let mut data = Vec::new();
    data.extend_from_slice(&0xBAC0_4AC0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.push(0);
    data.push(7);
    data.extend_from_slice(b"..\\evil");
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0xFF);
    data.extend_from_slice(b"abc");
    let encrypted: Vec<u8> = data.iter().map(|byte| byte ^ 0xF7).collect();
    fs::write(&source, &encrypted).unwrap();

    let extracted = kotama()
        .args(["resource", "pak-extract-all"])
        .arg(&source)
        .arg("--output-dir")
        .arg(root.join("out"))
        .output()
        .unwrap();
    assert!(!extracted.status.success());
    assert!(!root.join("evil").exists());
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
