//! kotama resource: identify, inspect and extract non-image resources.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kotama_resource::{
    identify, parse, parse_as, DetectionBasis, Extracted, Resource, ResourceError, ResourceKind,
};
use serde::Serialize;

const DEFAULT_MAX_OUTPUT: usize = 256 * 1024 * 1024;

#[derive(Serialize)]
struct IdentifyJson {
    kind: &'static str,
    basis: &'static str,
    enabled: bool,
}

#[derive(Serialize)]
struct InfoJson {
    kind: &'static str,
    compression: Option<&'static str>,
    version: Option<u8>,
    declared_length: Option<u32>,
    stored_length: Option<usize>,
    encoding: Option<&'static str>,
    size: Option<usize>,
    load_address: Option<u32>,
    entry: Option<u32>,
    archive_version: Option<&'static str>,
    entries: Option<usize>,
    chunks: Option<usize>,
    apt_entry_offset: Option<u32>,
    constants: Option<usize>,
}

#[derive(Serialize)]
struct EntryJson<'a> {
    name: &'a str,
    offset: u32,
    size: u32,
}

#[derive(Serialize)]
struct EntriesJson<'a> {
    kind: &'static str,
    count: usize,
    entries: Vec<EntryJson<'a>>,
}

#[derive(Serialize)]
struct ChunkJson {
    type_id: u32,
    name: Option<&'static str>,
    depth: u8,
    offset: u64,
    size: u32,
    has_subchunks: bool,
}

#[derive(Serialize)]
struct ChunksJson {
    kind: &'static str,
    count: usize,
    chunks: Vec<ChunkJson>,
}

#[derive(Serialize)]
struct AptConstantJson {
    type_id: u32,
    type_name: &'static str,
    value: serde_json::Value,
}

#[derive(Serialize)]
struct DdsJson {
    kind: &'static str,
    width: u32,
    height: u32,
    flags: u32,
    mipmaps: u32,
    pixel_format_flags: u32,
    fourcc: Option<String>,
    rgb_bit_count: u32,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
    alpha_mask: u32,
    caps: u32,
    caps2: u32,
    caps3: u32,
    caps4: u32,
}

#[derive(Serialize)]
struct TgaJson {
    kind: &'static str,
    id_length: u8,
    color_map_type: u8,
    image_type: u8,
    color_map_first: u16,
    color_map_length: u16,
    color_map_entry_size: u8,
    x_origin: u16,
    y_origin: u16,
    width: u16,
    height: u16,
    pixel_depth: u8,
    image_descriptor: u8,
}

#[derive(Serialize)]
struct Vp6Json {
    kind: &'static str,
    header_size: u32,
    codec: String,
    width: u16,
    height: u16,
    frame_count: u16,
}

#[derive(Serialize)]
struct AssetManifestJson {
    kind: &'static str,
    big_endian: bool,
    linked: bool,
    version: u16,
    stream_checksum: u32,
    all_types_hash: u32,
    asset_count: u32,
    total_instance_data_size: u32,
    max_instance_chunk_size: u32,
    max_relocation_chunk_size: u32,
    max_imports_chunk_size: u32,
    asset_reference_buffer_size: u32,
    referenced_manifest_name_buffer_size: u32,
    asset_name_buffer_size: u32,
    source_file_name_buffer_size: u32,
    names: Vec<String>,
}

#[derive(Serialize)]
struct GeometryStyleJson {
    kind: String,
    color: Vec<u8>,
}

#[derive(Serialize)]
struct GeometryJson {
    kind: &'static str,
    styles: Vec<GeometryStyleJson>,
    triangle_count: usize,
    line_count: usize,
    bounds: Option<Vec<f32>>,
}

#[derive(Serialize)]
struct AptJson {
    kind: &'static str,
    apt_data_entry_offset: u32,
    count: usize,
    entries: Vec<AptConstantJson>,
}

#[derive(Serialize)]
struct CsfLabelJson {
    name: String,
    values: Vec<String>,
}

#[derive(Serialize)]
struct CsfJson {
    kind: &'static str,
    version: u32,
    label_count: u32,
    string_count: u32,
    language: u32,
    labels: Vec<CsfLabelJson>,
}

#[derive(Serialize)]
struct MeshJson {
    version: u32,
    attributes: u32,
    mesh_name: String,
    container_name: String,
    num_tris: u32,
    num_vertices: u32,
    num_materials: u32,
    num_damage_stages: u32,
    sort_level: u32,
    prelit_version: u32,
    future_counts: u32,
    vertex_channels: u32,
    face_channels: u32,
    min: Vec<f32>,
    max: Vec<f32>,
    sphere_center: Vec<f32>,
    sphere_radius: f32,
    vertex_count: usize,
    normal_count: usize,
    triangle_count: usize,
    material_info: Option<Vec<u32>>,
    vertex_material_names: Vec<String>,
    texture_names: Vec<String>,
    user_text: Vec<String>,
    material_pass_count: usize,
    texture_stage_count: usize,
    texture_ids: Vec<u32>,
    stage_texcoord_count: usize,
}

#[derive(Serialize)]
struct ExtractJson {
    kind: &'static str,
    output: String,
    bytes_written: usize,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  kotama resource identify <path>\n  kotama resource info <path> [--kind swf|vbs|dos-com|big|w3d|apt-const|apt-geometry|csf]\n  kotama resource entries <path> [--kind big] [--limit <count>]\n  kotama resource chunks <path> [--kind w3d] [--limit <count>]\n  kotama resource mesh <path> [--kind w3d]\n  kotama resource apt <path> [--kind apt-const]\n  kotama resource geometry <path> [--kind apt-geometry]\n  kotama resource csf <path> [--kind csf] [--limit <count>]\n  kotama resource dds <path> [--kind dds]\n  kotama resource tga <path> [--kind tga]\n  kotama resource vp6 <path> [--kind vp6]\n  kotama resource manifest <path> [--kind asset-manifest]\n  kotama resource extract <path> --output <path> [--entry <name>] [--kind swf|vbs|dos-com|big|w3d|apt-const|apt-geometry|csf] [--max-output <bytes>]"
    );
    ExitCode::from(2)
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("kotama: resource: {error}");
    ExitCode::FAILURE
}

fn fail_kind(error: &ResourceError) -> ExitCode {
    match error {
        ResourceError::FeatureDisabled { .. } => {
            eprintln!("kotama: resource: {error}");
            ExitCode::from(3)
        }
        _ => fail(error),
    }
}

fn extension(path: &Path) -> Option<&str> {
    path.extension().and_then(|value| value.to_str())
}

fn kind_arg(args: &[String], index: &mut usize) -> Result<Option<ResourceKind>, ExitCode> {
    let Some(raw) = args.get(*index + 1) else {
        return Err(usage());
    };
    let Some(kind) = ResourceKind::parse(raw) else {
        return Err(usage());
    };
    *index += 1;
    Ok(Some(kind))
}

pub fn run(args: &[String]) -> ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "identify" => identify_command(&args[1..]),
        "info" => info_command(&args[1..]),
        "entries" => entries_command(&args[1..]),
        "chunks" => chunks_command(&args[1..]),
        "mesh" => mesh_command(&args[1..]),
        "apt" => apt_command(&args[1..]),
        "csf" => csf_command(&args[1..]),
        "dds" => dds_command(&args[1..]),
        "tga" => tga_command(&args[1..]),
        "vp6" => vp6_command(&args[1..]),
        "manifest" => manifest_command(&args[1..]),
        "geometry" => geometry_command(&args[1..]),
        "extract" => extract_command(&args[1..]),
        _ => usage(),
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn identify_command(args: &[String]) -> ExitCode {
    if args.len() != 1 {
        return usage();
    }
    let path = PathBuf::from(&args[0]);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let Some(found) = identify(&bytes, extension(&path)) else {
        return fail("unknown resource format");
    };
    let json = IdentifyJson {
        kind: found.kind.short(),
        basis: match found.basis {
            DetectionBasis::Magic => "magic",
            DetectionBasis::Extension => "extension",
        },
        enabled: found.enabled,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn parse_requested<'a>(
    bytes: &'a [u8],
    path: &Path,
    explicit: Option<ResourceKind>,
) -> Result<Resource<'a>, ResourceError> {
    match explicit {
        Some(kind) => parse_as(bytes, kind),
        None => parse(bytes, extension(path)),
    }
}

fn info_for(resource: &Resource<'_>) -> InfoJson {
    match resource {
        Resource::Swf(swf) => InfoJson {
            kind: "swf",
            compression: Some(match swf.compression {
                kotama_resource::swf::Compression::None => "none",
                kotama_resource::swf::Compression::Zlib => "zlib",
                kotama_resource::swf::Compression::Lzma => "lzma",
            }),
            version: Some(swf.version),
            declared_length: Some(swf.declared_length),
            stored_length: Some(swf.data.len()),
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::Vbs(vbs) => InfoJson {
            kind: "vbs",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: Some(vbs.encoding.short()),
            size: Some(vbs.text.len()),
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::DosCom(com) => InfoJson {
            kind: "dos-com",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: Some(com.size()),
            load_address: Some(kotama_resource::dos_com::LOAD_ADDRESS),
            entry: Some(kotama_resource::dos_com::ENTRY_ADDRESS),
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::Big(archive) => InfoJson {
            kind: "big",
            compression: None,
            version: None,
            declared_length: Some(archive.archive_size),
            stored_length: Some(archive.data.len()),
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: Some(archive.version.short()),
            entries: Some(archive.entries.len()),
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::W3d(file) => InfoJson {
            kind: "w3d",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: Some(file.data.len()),
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: Some(file.chunks.len()),
            apt_entry_offset: None,
            constants: None,
        },
        Resource::AptConst(file) => InfoJson {
            kind: "apt-const",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: Some(file.apt_data_entry_offset),
            constants: Some(file.entries.len()),
        },
        Resource::Csf(file) => InfoJson {
            kind: "csf",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: Some(file.labels.len()),
            chunks: None,
            apt_entry_offset: None,
            constants: Some(file.string_count as usize),
        },
        Resource::AptGeometry(_) => InfoJson {
            kind: "apt-geometry",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::Dds(_) => InfoJson {
            kind: "dds",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::Tga(_) => InfoJson {
            kind: "tga",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::Vp6(_) => InfoJson {
            kind: "vp6",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
        Resource::AssetManifest(_) => InfoJson {
            kind: "asset-manifest",
            compression: None,
            version: None,
            declared_length: None,
            stored_length: None,
            encoding: None,
            size: None,
            load_address: None,
            entry: None,
            archive_version: None,
            entries: None,
            chunks: None,
            apt_entry_offset: None,
            constants: None,
        },
    }
}

fn parse_info_options(args: &[String]) -> Result<(PathBuf, Option<ResourceKind>), ExitCode> {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return Err(usage());
    };
    let mut kind = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => kind = kind_arg(args, &mut index)?,
            _ => return Err(usage()),
        }
        index += 1;
    }
    Ok((PathBuf::from(path), kind))
}

fn info_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    match serde_json::to_string_pretty(&info_for(&resource)) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn entries_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut kind = None;
    let mut limit = 200usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                kind = match kind_arg(args, &mut index) {
                    Ok(kind) => kind,
                    Err(code) => return code,
                }
            }
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    return usage();
                };
                limit = parsed;
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let path = PathBuf::from(path);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Big(archive) = resource else {
        return fail("entries requires a BIG archive");
    };
    let entries = archive
        .entries
        .iter()
        .take(limit)
        .map(|entry| EntryJson {
            name: entry.name,
            offset: entry.offset,
            size: entry.size,
        })
        .collect();
    let json = EntriesJson {
        kind: "big",
        count: archive.entries.len(),
        entries,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn chunks_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut kind = None;
    let mut limit = 200usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                kind = match kind_arg(args, &mut index) {
                    Ok(kind) => kind,
                    Err(code) => return code,
                }
            }
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    return usage();
                };
                limit = parsed;
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let path = PathBuf::from(path);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::W3d(file) = resource else {
        return fail("chunks requires a W3D container");
    };
    let chunks = file
        .chunks
        .iter()
        .take(limit)
        .map(|chunk| ChunkJson {
            type_id: chunk.type_id,
            name: kotama_resource::w3d::chunk_name(chunk.type_id),
            depth: chunk.depth,
            offset: chunk.offset,
            size: chunk.size,
            has_subchunks: chunk.has_subchunks,
        })
        .collect();
    let json = ChunksJson {
        kind: "w3d",
        count: file.chunks.len(),
        chunks,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn mesh_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::W3d(file) = resource else {
        return fail("mesh requires a W3D container");
    };
    let Some(header) = file.mesh_header() else {
        return fail("W3D mesh_header3 not found or malformed");
    };
    let vertices = file.vertices();
    let normals = file.normals();
    let triangles = file.triangles();
    let json = MeshJson {
        version: header.version,
        attributes: header.attributes,
        mesh_name: header.mesh_name,
        container_name: header.container_name,
        num_tris: header.num_tris,
        num_vertices: header.num_vertices,
        num_materials: header.num_materials,
        num_damage_stages: header.num_damage_stages,
        sort_level: header.sort_level,
        prelit_version: header.prelit_version,
        future_counts: header.future_counts,
        vertex_channels: header.vertex_channels,
        face_channels: header.face_channels,
        min: vec![header.min.x, header.min.y, header.min.z],
        max: vec![header.max.x, header.max.y, header.max.z],
        sphere_center: vec![
            header.sphere_center.x,
            header.sphere_center.y,
            header.sphere_center.z,
        ],
        sphere_radius: header.sphere_radius,
        vertex_count: vertices.len(),
        normal_count: normals.len(),
        triangle_count: triangles.len(),
        material_info: file.material_info().map(|values| values.to_vec()),
        vertex_material_names: file.vertex_material_names(),
        texture_names: file.texture_names(),
        user_text: file.user_text(),
        material_pass_count: file.material_pass_count(),
        texture_stage_count: file.texture_stage_count(),
        texture_ids: file.texture_ids(),
        stage_texcoord_count: file.stage_texcoord_count(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn apt_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::AptConst(file) = resource else {
        return fail("apt requires an APT constant file");
    };
    let entries = file
        .entries
        .iter()
        .map(|entry| AptConstantJson {
            type_id: entry.type_id,
            type_name: entry.type_name(),
            value: match &entry.value {
                kotama_resource::apt::AptValue::None => serde_json::Value::Null,
                kotama_resource::apt::AptValue::String(value) => {
                    serde_json::Value::String(value.clone())
                }
                kotama_resource::apt::AptValue::Register(value)
                | kotama_resource::apt::AptValue::Lookup(value)
                | kotama_resource::apt::AptValue::Property(value) => serde_json::json!(value),
                kotama_resource::apt::AptValue::Boolean(value) => serde_json::json!(value),
                kotama_resource::apt::AptValue::Float(value) => serde_json::json!(value),
                kotama_resource::apt::AptValue::Integer(value) => serde_json::json!(value),
            },
        })
        .collect();
    let json = AptJson {
        kind: "apt-const",
        apt_data_entry_offset: file.apt_data_entry_offset,
        count: file.entries.len(),
        entries,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn csf_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut kind = None;
    let mut limit = 200usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                kind = match kind_arg(args, &mut index) {
                    Ok(kind) => kind,
                    Err(code) => return code,
                }
            }
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    return usage();
                };
                limit = parsed;
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let path = PathBuf::from(path);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Csf(file) = resource else {
        return fail("csf requires a CSF string table");
    };
    let json = CsfJson {
        kind: "csf",
        version: file.version,
        label_count: file.label_count,
        string_count: file.string_count,
        language: file.language,
        labels: file
            .labels
            .iter()
            .take(limit)
            .map(|label| CsfLabelJson {
                name: label.name.clone(),
                values: label
                    .strings
                    .iter()
                    .map(|value| value.value.clone())
                    .collect(),
            })
            .collect(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn geometry_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::AptGeometry(geometry) = resource else {
        return fail("geometry requires an APT .ru text file");
    };
    let json = GeometryJson {
        kind: "apt-geometry",
        styles: geometry
            .styles
            .iter()
            .map(|style| GeometryStyleJson {
                kind: style.kind.clone(),
                color: style.color.to_vec(),
            })
            .collect(),
        triangle_count: geometry.triangles.len(),
        line_count: geometry.lines,
        bounds: geometry.bounds().map(|value| value.to_vec()),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn dds_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Dds(info) = resource else {
        return fail("dds requires a DDS surface");
    };
    let json = DdsJson {
        kind: "dds",
        width: info.width,
        height: info.height,
        flags: info.flags,
        mipmaps: info.mipmaps,
        pixel_format_flags: info.pixel_format.flags,
        fourcc: info.pixel_format.fourcc,
        rgb_bit_count: info.pixel_format.rgb_bit_count,
        red_mask: info.pixel_format.red_mask,
        green_mask: info.pixel_format.green_mask,
        blue_mask: info.pixel_format.blue_mask,
        alpha_mask: info.pixel_format.alpha_mask,
        caps: info.caps,
        caps2: info.caps2,
        caps3: info.caps3,
        caps4: info.caps4,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn tga_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Tga(info) = resource else {
        return fail("tga requires a TGA image");
    };
    let json = TgaJson {
        kind: "tga",
        id_length: info.id_length,
        color_map_type: info.color_map_type,
        image_type: info.image_type,
        color_map_first: info.color_map_first,
        color_map_length: info.color_map_length,
        color_map_entry_size: info.color_map_entry_size,
        x_origin: info.x_origin,
        y_origin: info.y_origin,
        width: info.width,
        height: info.height,
        pixel_depth: info.pixel_depth,
        image_descriptor: info.image_descriptor,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn vp6_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Vp6(info) = resource else {
        return fail("vp6 requires a VP6 movie");
    };
    let json = Vp6Json {
        kind: "vp6",
        header_size: info.header_size,
        codec: info.codec,
        width: info.width,
        height: info.height,
        frame_count: info.frame_count,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn manifest_command(args: &[String]) -> ExitCode {
    let (path, kind) = match parse_info_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::AssetManifest(info) = resource else {
        return fail("manifest requires an asset manifest header");
    };
    let json = AssetManifestJson {
        kind: "asset-manifest",
        big_endian: info.big_endian,
        linked: info.linked,
        version: info.version,
        stream_checksum: info.stream_checksum,
        all_types_hash: info.all_types_hash,
        asset_count: info.asset_count,
        total_instance_data_size: info.total_instance_data_size,
        max_instance_chunk_size: info.max_instance_chunk_size,
        max_relocation_chunk_size: info.max_relocation_chunk_size,
        max_imports_chunk_size: info.max_imports_chunk_size,
        asset_reference_buffer_size: info.asset_reference_buffer_size,
        referenced_manifest_name_buffer_size: info.referenced_manifest_name_buffer_size,
        asset_name_buffer_size: info.asset_name_buffer_size,
        source_file_name_buffer_size: info.source_file_name_buffer_size,
        names: info.names,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn extract_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut kind = None;
    let mut output: Option<PathBuf> = None;
    let mut entry = None;
    let mut max_output = DEFAULT_MAX_OUTPUT;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                kind = match kind_arg(args, &mut index) {
                    Ok(kind) => kind,
                    Err(code) => return code,
                }
            }
            "--output" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                output = Some(PathBuf::from(value));
                index += 1;
            }
            "--entry" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                entry = Some(value.clone());
                index += 1;
            }
            "--max-output" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    return usage();
                };
                max_output = parsed;
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let Some(output) = output else {
        return usage();
    };
    if output.exists() {
        return fail(format!("refusing to overwrite {}", output.display()));
    }
    let path = PathBuf::from(path);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let payload = if let Some(entry) = entry {
        let Resource::Big(archive) = &resource else {
            return fail("--entry requires a BIG archive");
        };
        match archive.extract(&entry) {
            Some(bytes) => bytes.to_vec(),
            None => return fail(format!("BIG entry not found: {entry}")),
        }
    } else {
        match resource.extract(max_output) {
            Ok(Extracted::Bytes(bytes)) => bytes.into_owned(),
            Ok(Extracted::Text(text)) => text.as_bytes().to_vec(),
            Err(error) => return fail_kind(&error),
        }
    };
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
    {
        Ok(file) => file,
        Err(error) => return fail(format!("create {}: {error}", output.display())),
    };
    use std::io::Write;
    if let Err(error) = file.write_all(&payload) {
        return fail(format!("write {}: {error}", output.display()));
    }
    let json = ExtractJson {
        kind: resource.kind().short(),
        output: output.display().to_string(),
        bytes_written: payload.len(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}
