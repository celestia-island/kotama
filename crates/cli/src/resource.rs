//! kotama resource: identify, inspect and extract non-image resources.

use std::collections::HashMap;
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
struct AssetPropertyJson {
    name_hash: u32,
    type_hash: u32,
    value_or_offset: u32,
    name: Option<String>,
    property_type: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct AssetJson {
    kind: &'static str,
    id: String,
    version: u32,
    type_hash: Option<u32>,
    instance_hash: Option<u32>,
    data_size: u32,
    property_count: u32,
    unknown_28: u32,
    type_name: String,
    data_path: String,
    property_table_offset: usize,
    properties: Vec<AssetPropertyJson>,
}

#[derive(Serialize)]
struct AptCharacterJson {
    offset: u32,
    type_id: u32,
    type_name: &'static str,
    bounds: Option<Vec<f32>>,
    geometry: Option<u32>,
}

#[derive(Serialize)]
struct AptImportJson {
    movie: String,
    name: String,
    character: u32,
    pointer: u32,
}

#[derive(Serialize)]
struct AptExportJson {
    name: String,
    character: u32,
}

#[derive(Serialize)]
struct AptMovieJson {
    kind: &'static str,
    entry_offset: usize,
    frame_count: u32,
    character_count: u32,
    screen_width: u32,
    screen_height: u32,
    milliseconds_per_frame: u32,
    import_count: u32,
    export_count: u32,
    characters: Vec<AptCharacterJson>,
    imports: Vec<AptImportJson>,
    exports: Vec<AptExportJson>,
    texture_ids: Vec<u32>,
}

#[derive(Serialize)]
struct PvzReanimFrameJson {
    values: Vec<Option<f32>>,
    image: Option<String>,
    font: Option<String>,
    text: Option<String>,
}

#[derive(Serialize)]
struct PvzReanimTrackJson {
    name: String,
    frame_count: u32,
    frames: Vec<PvzReanimFrameJson>,
}

#[derive(Serialize)]
struct PvzReanimJson {
    kind: &'static str,
    uncompressed_size: u32,
    body_magic: u32,
    unknown_4: u32,
    track_count: u32,
    fps: f32,
    unknown_16: u32,
    track_count_2: u32,
    strings: Vec<String>,
    frame_counts: Vec<u32>,
    tracks: Vec<PvzReanimTrackJson>,
}

#[derive(Serialize)]
struct AptImageAssignmentJson {
    image_id: i32,
    texture_id: Option<i32>,
    rectangle: Option<Vec<i32>>,
}

#[derive(Serialize)]
struct AptImageMapJson {
    kind: &'static str,
    assignments: Vec<AptImageAssignmentJson>,
}

#[derive(Serialize)]
struct RelocationEntryJson {
    kind: u32,
    offset: u32,
}

#[derive(Serialize)]
struct RelocationJson {
    kind: &'static str,
    checksum: u32,
    entries: Vec<RelocationEntryJson>,
}

#[derive(Serialize)]
struct AssetReferenceJson {
    type_id: u32,
    instance_id: u32,
}

#[derive(Serialize)]
struct AssetManifestEntryJson {
    type_id: u32,
    instance_id: u32,
    type_hash: u32,
    instance_hash: u32,
    instance_size: u32,
    relocation_size: u32,
    imports_size: u32,
    name: String,
    source_name: String,
    references: Vec<AssetReferenceJson>,
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
    entries: Vec<AssetManifestEntryJson>,
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
struct PakEntryJson {
    name: String,
    size: u32,
    filetime: u64,
    offset: usize,
}

#[derive(Serialize)]
struct PakJson {
    kind: &'static str,
    files: usize,
    bytes: u64,
    entries: Vec<PakEntryJson>,
}

#[derive(Serialize)]
struct PakExtractAllJson {
    kind: &'static str,
    output_dir: String,
    files: usize,
    bytes: u64,
}

#[derive(Serialize)]
struct PakRepackJson {
    kind: &'static str,
    output: String,
    files: usize,
    bytes: u64,
}

#[derive(Serialize)]
struct ExtractJson {
    kind: &'static str,
    output: String,
    bytes_written: usize,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  kotama resource identify <path>\n  kotama resource info <path> [--kind swf|vbs|dos-com|big|w3d|apt-const|apt-geometry|csf]\n  kotama resource entries <path> [--kind big] [--limit <count>]\n  kotama resource chunks <path> [--kind w3d] [--limit <count>]\n  kotama resource mesh <path> [--kind w3d]\n  kotama resource apt <path> [--kind apt-const]\n  kotama resource geometry <path> [--kind apt-geometry]\n  kotama resource csf <path> [--kind csf] [--limit <count>]\n  kotama resource dds <path> [--kind dds]\n  kotama resource tga <path> [--kind tga]\n  kotama resource vp6 <path> [--kind vp6]\n  kotama resource manifest <path> [--kind asset-manifest]\n  kotama resource asset <path> [--kind asset] [--hash-map <tsv>]\n  kotama resource relocation <path> [--kind asset-relocation]\n  kotama resource apt-movie <path> [--entry-offset <N>] [--kind apt-movie]\n  kotama resource apt-image-map <path> [--kind apt-image-map]\n  kotama resource pvz-reanim <path> [--kind pvz-reanim]\n  kotama resource pak <path> [--kind pak] [--limit <count>] [--filter <text>]\n  kotama resource pak-extract <path> --entry <name> --output <path>\n  kotama resource pak-extract-all <path> --output-dir <dir> [--limit <count>] [--filter <text>]\n  kotama resource pak-repack <path> --input-dir <dir> --output <path>\n  kotama resource extract <path> --output <path> [--entry <name>] [--kind swf|vbs|dos-com|big|w3d|apt-const|apt-geometry|csf] [--max-output <bytes>]"
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
        "asset" => asset_command(&args[1..]),
        "relocation" => relocation_command(&args[1..]),
        "apt-movie" => apt_movie_command(&args[1..]),
        "apt-image-map" => apt_image_map_command(&args[1..]),
        "pvz-reanim" => pvz_reanim_command(&args[1..]),
        "pak" => pak_command(&args[1..]),
        "pak-extract" => pak_extract_command(&args[1..]),
        "pak-extract-all" => pak_extract_all_command(&args[1..]),
        "pak-repack" => pak_repack_command(&args[1..]),
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
        Resource::Asset(_) => InfoJson {
            kind: "asset",
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
        Resource::AssetRelocation(_) => InfoJson {
            kind: "asset-relocation",
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
        Resource::AptMovie(_) => InfoJson {
            kind: "apt-movie",
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
        Resource::AptImageMap(_) => InfoJson {
            kind: "apt-image-map",
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
        Resource::PvzReanim(_) => InfoJson {
            kind: "pvz-reanim",
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
        Resource::Pak(_) => InfoJson {
            kind: "pak",
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
        entries: info
            .entries
            .into_iter()
            .map(|entry| AssetManifestEntryJson {
                type_id: entry.type_id,
                instance_id: entry.instance_id,
                type_hash: entry.type_hash,
                instance_hash: entry.instance_hash,
                instance_size: entry.instance_size,
                relocation_size: entry.relocation_size,
                imports_size: entry.imports_size,
                name: entry.name,
                source_name: entry.source_name,
                references: entry
                    .references
                    .into_iter()
                    .map(|reference| AssetReferenceJson {
                        type_id: reference.type_id,
                        instance_id: reference.instance_id,
                    })
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

fn parse_asset_options(
    args: &[String],
) -> Result<(PathBuf, Option<ResourceKind>, Option<PathBuf>), ExitCode> {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return Err(usage());
    };
    let mut kind = None;
    let mut hash_map = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => kind = kind_arg(args, &mut index)?,
            "--hash-map" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(usage());
                };
                hash_map = Some(PathBuf::from(value));
                index += 1;
            }
            _ => return Err(usage()),
        }
        index += 1;
    }
    Ok((PathBuf::from(path), kind, hash_map))
}

fn read_hash_map(path: &Path) -> Result<HashMap<u32, String>, ExitCode> {
    let text = fs::read_to_string(path).map_err(fail)?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let Some((hash, text)) = line.split_once('\t') else {
            continue;
        };
        if let Ok(hash) = hash.parse::<u32>() {
            map.insert(hash, text.to_string());
        }
    }
    Ok(map)
}

fn parse_string_list(bytes: &[u8], table_offset: usize, raw: u32) -> Option<serde_json::Value> {
    let mut cursor = table_offset.checked_add(raw as usize)?;
    let mut strings = Vec::new();
    for _ in 0..64 {
        let Some(record) = bytes.get(cursor..cursor.checked_add(12)?) else {
            break;
        };
        let name = u32::from_le_bytes(record[0..4].try_into().ok()?);
        let kind = u32::from_le_bytes(record[4..8].try_into().ok()?);
        let value = u32::from_le_bytes(record[8..12].try_into().ok()?);
        if name == 0x6c82_7073 && kind == 0x5d44_8fd8 {
            cursor += 12;
            continue;
        }
        if name != 0xb151_a0eb || kind != 0 {
            break;
        }
        let pointer = value as usize;
        let Some(pointer_bytes) = bytes.get(pointer..pointer.checked_add(4)?) else {
            break;
        };
        let string_offset = u32::from_le_bytes(pointer_bytes.try_into().ok()?) as usize;
        if string_offset >= bytes.len() {
            break;
        }
        let Some(end) = bytes[string_offset..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let end = end + string_offset;
        let text = &bytes[string_offset..end];
        if text.is_empty()
            || !text
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            return None;
        }
        strings.push(String::from_utf8_lossy(text).to_string());
        cursor += 12;
    }
    (!strings.is_empty()).then(|| serde_json::json!(strings))
}

fn asset_property_value(
    bytes: &[u8],
    table_offset: usize,
    property_type: Option<&str>,
    raw: u32,
) -> Option<serde_json::Value> {
    let value_at = |size: usize| -> Option<&[u8]> {
        let start = table_offset.checked_add(raw as usize)?;
        bytes.get(start..start.checked_add(size)?)
    };
    match property_type {
        Some("float_t") => {
            let value = f32::from_le_bytes(value_at(4)?.try_into().ok()?);
            (value.is_finite()).then(|| serde_json::json!(value))
        }
        Some(
            "size_t" | "uint32_t" | "KindOfBitFlags" | "RadarPriorityType" | "EditorSortingType",
        ) => {
            let value = u32::from_le_bytes(value_at(4)?.try_into().ok()?);
            Some(serde_json::json!(value))
        }
        Some("bool") => Some(serde_json::json!(value_at(1)?[0] != 0)),
        Some("StringList") => parse_string_list(bytes, table_offset, raw),
        Some(kind)
            if kind.ends_with("WeakRef") || kind.ends_with("Ref") || kind.ends_with("Nugget") =>
        {
            let raw = value_at(8)?;
            let type_id = u32::from_le_bytes(raw[0..4].try_into().ok()?);
            let instance_id = u32::from_le_bytes(raw[4..8].try_into().ok()?);
            if type_id == 0 && instance_id == 0 {
                Some(serde_json::Value::Null)
            } else {
                Some(serde_json::json!({ "type_id": type_id, "instance_id": instance_id }))
            }
        }
        _ => Some(serde_json::json!(raw)),
    }
}

fn asset_command(args: &[String]) -> ExitCode {
    let (path, kind, hash_map_path) = match parse_asset_options(args) {
        Ok(values) => values,
        Err(code) => return code,
    };
    let hash_map = match hash_map_path {
        Some(path) => match read_hash_map(&path) {
            Ok(map) => Some(map),
            Err(code) => return code,
        },
        None => None,
    };
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::Asset(info) = resource else {
        return fail("asset requires an asset header");
    };
    let json = AssetJson {
        kind: "asset",
        id: info
            .id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(""),
        version: info.version,
        type_hash: info.type_hash,
        instance_hash: info.instance_hash,
        data_size: info.data_size,
        property_count: info.property_count,
        unknown_28: info.unknown_28,
        type_name: info.type_name,
        data_path: info.data_path,
        property_table_offset: info.property_table_offset,
        properties: info
            .properties
            .iter()
            .map(|property| {
                let property_type = hash_map
                    .as_ref()
                    .and_then(|map| map.get(&property.type_hash).cloned());
                let value = asset_property_value(
                    &bytes,
                    info.property_table_offset,
                    property_type.as_deref(),
                    property.value_or_offset,
                );
                AssetPropertyJson {
                    name_hash: property.name_hash,
                    type_hash: property.type_hash,
                    value_or_offset: property.value_or_offset,
                    name: hash_map
                        .as_ref()
                        .and_then(|map| map.get(&property.name_hash).cloned()),
                    property_type,
                    value,
                }
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

fn relocation_command(args: &[String]) -> ExitCode {
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
    let Resource::AssetRelocation(info) = resource else {
        return fail("relocation requires a relocation table");
    };
    let json = RelocationJson {
        kind: "asset-relocation",
        checksum: info.checksum,
        entries: info
            .entries
            .iter()
            .map(|entry| RelocationEntryJson {
                kind: entry.kind,
                offset: entry.offset,
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

fn apt_movie_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut entry_offset = 16usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--entry-offset" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                entry_offset = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => return usage(),
                };
                index += 1;
            }
            "--kind" => {
                let Some(kind) = args.get(index + 1) else {
                    return usage();
                };
                if kind != "apt-movie" {
                    return usage();
                }
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let info = match kotama_resource::apt_movie::parse(&bytes, entry_offset) {
        Ok(info) => info,
        Err(error) => return fail_kind(&error),
    };
    let json = AptMovieJson {
        kind: "apt-movie",
        entry_offset: info.entry_offset,
        frame_count: info.frame_count,
        character_count: info.character_count,
        screen_width: info.screen_width,
        screen_height: info.screen_height,
        milliseconds_per_frame: info.milliseconds_per_frame,
        import_count: info.import_count,
        export_count: info.export_count,
        characters: info
            .characters
            .iter()
            .map(|character| AptCharacterJson {
                offset: character.offset,
                type_id: character.type_id,
                type_name: character.type_name,
                bounds: character.bounds.map(|values| values.to_vec()),
                geometry: character.geometry,
            })
            .collect(),
        imports: info
            .imports
            .iter()
            .map(|import| AptImportJson {
                movie: import.movie.clone(),
                name: import.name.clone(),
                character: import.character,
                pointer: import.pointer,
            })
            .collect(),
        exports: info
            .exports
            .iter()
            .map(|export| AptExportJson {
                name: export.name.clone(),
                character: export.character,
            })
            .collect(),
        texture_ids: info.texture_ids.clone(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn apt_image_map_command(args: &[String]) -> ExitCode {
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
    let Resource::AptImageMap(map) = resource else {
        return fail("apt-image-map requires an APT image map");
    };
    let json = AptImageMapJson {
        kind: "apt-image-map",
        assignments: map
            .assignments
            .iter()
            .map(|assignment| AptImageAssignmentJson {
                image_id: assignment.image_id,
                texture_id: assignment.texture_id,
                rectangle: assignment.rectangle.map(|values| values.to_vec()),
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

fn pvz_reanim_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut xml = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--xml" => xml = true,
            "--kind" => {
                let Some(kind) = args.get(index + 1) else {
                    return usage();
                };
                if kind != "pvz-reanim" {
                    return usage();
                }
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let path = PathBuf::from(path);
    let kind = Some(ResourceKind::PvzReanim);
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let resource = match parse_requested(&bytes, &path, kind) {
        Ok(resource) => resource,
        Err(error) => return fail_kind(&error),
    };
    let Resource::PvzReanim(info) = resource else {
        return fail("pvz-reanim requires a Reanim container");
    };
    let xml_text = xml.then(|| kotama_resource::pvz_reanim::to_xml(&info));
    let json = PvzReanimJson {
        kind: "pvz-reanim",
        uncompressed_size: info.uncompressed_size,
        body_magic: info.body_magic,
        unknown_4: info.unknown_4,
        track_count: info.track_count,
        fps: info.fps,
        unknown_16: info.unknown_16,
        track_count_2: info.track_count_2,
        strings: info.strings,
        frame_counts: info.frame_counts,
        tracks: info
            .tracks
            .iter()
            .map(|track| PvzReanimTrackJson {
                name: track.name.clone(),
                frame_count: track.frame_count,
                frames: track
                    .frames
                    .iter()
                    .map(|frame| PvzReanimFrameJson {
                        values: frame.transform.values.to_vec(),
                        image: frame.elements.image.clone(),
                        font: frame.elements.font.clone(),
                        text: frame.elements.text.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    if let Some(text) = xml_text {
        print!("{text}");
        return ExitCode::SUCCESS;
    }
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn pak_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut limit = 20usize;
    let mut filter: Option<String> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                limit = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => return usage(),
                };
                index += 1;
            }
            "--filter" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                filter = Some(value.to_ascii_lowercase());
                index += 1;
            }
            "--kind" => {
                let Some(kind) = args.get(index + 1) else {
                    return usage();
                };
                if kind != "pak" {
                    return usage();
                }
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let pak = match kotama_resource::pak::parse(&bytes) {
        Ok(pak) => pak,
        Err(error) => return fail_kind(&error),
    };
    let filtered: Vec<_> = pak
        .entries
        .iter()
        .filter(|entry| {
            filter
                .as_ref()
                .is_none_or(|filter| entry.name.to_ascii_lowercase().contains(filter))
        })
        .collect();
    let json = PakJson {
        kind: "pak",
        files: filtered.len(),
        bytes: filtered.iter().map(|entry| u64::from(entry.size)).sum(),
        entries: filtered
            .into_iter()
            .take(limit)
            .map(|entry| PakEntryJson {
                name: entry.name.clone(),
                size: entry.size,
                filetime: entry.filetime,
                offset: entry.offset,
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

fn safe_pak_path(root: &Path, name: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for part in name.split(['\\', '/']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return None;
        }
        path.push(part);
    }
    Some(path)
}

fn pak_extract_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut entry_name: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--entry" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                entry_name = Some(value.clone());
                index += 1;
            }
            "--output" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                output = Some(PathBuf::from(value));
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let (Some(entry_name), Some(output)) = (entry_name, output) else {
        return usage();
    };
    if output.exists() {
        return fail("refusing to overwrite existing output");
    }
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let pak = match kotama_resource::pak::parse(&bytes) {
        Ok(pak) => pak,
        Err(error) => return fail_kind(&error),
    };
    let wanted = entry_name.replace('\\', "/");
    let Some(entry) = pak
        .entries
        .iter()
        .find(|entry| entry.name.replace('\\', "/") == wanted)
    else {
        return fail("PAK entry not found");
    };
    let decoded: Vec<u8> = bytes
        .iter()
        .map(|byte| byte ^ kotama_resource::pak::XOR_MASK)
        .collect();
    let Some(body) = decoded.get(entry.offset..entry.offset + entry.size as usize) else {
        return fail("PAK entry body is outside the file");
    };
    if let Some(parent) = output.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            return fail(error);
        }
    }
    if let Err(error) = fs::write(&output, body) {
        return fail(error);
    }
    let json = ExtractJson {
        kind: "pak-extract",
        output: output.display().to_string(),
        bytes_written: body.len(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn pak_extract_all_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut output_dir: Option<PathBuf> = None;
    let mut limit = usize::MAX;
    let mut filter: Option<String> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--output-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                output_dir = Some(PathBuf::from(value));
                index += 1;
            }
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                limit = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => return usage(),
                };
                index += 1;
            }
            "--filter" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                filter = Some(value.to_ascii_lowercase());
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let Some(output_dir) = output_dir else {
        return usage();
    };
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let pak = match kotama_resource::pak::parse(&bytes) {
        Ok(pak) => pak,
        Err(error) => return fail_kind(&error),
    };
    if let Err(error) = fs::create_dir_all(&output_dir) {
        return fail(error);
    }
    let Ok(root) = output_dir.canonicalize() else {
        return fail("cannot canonicalize output directory");
    };
    let decoded: Vec<u8> = bytes
        .iter()
        .map(|byte| byte ^ kotama_resource::pak::XOR_MASK)
        .collect();
    let mut written = 0usize;
    let mut bytes_written = 0u64;
    for entry in pak.entries.iter().take(limit) {
        if let Some(filter) = &filter {
            if !entry.name.to_ascii_lowercase().contains(filter) {
                continue;
            }
        }
        let Some(destination) = safe_pak_path(&root, &entry.name) else {
            return fail("refusing unsafe PAK entry path");
        };
        let Some(body) = decoded.get(entry.offset..entry.offset + entry.size as usize) else {
            return fail("PAK entry body is outside the file");
        };
        if let Some(parent) = destination.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                return fail(error);
            }
        }
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
        {
            Ok(file) => file,
            Err(error) => return fail(error),
        };
        if let Err(error) = std::io::Write::write_all(&mut file, body) {
            return fail(error);
        }
        written += 1;
        bytes_written += body.len() as u64;
    }
    let json = PakExtractAllJson {
        kind: "pak-extract-all",
        output_dir: output_dir.display().to_string(),
        files: written,
        bytes: bytes_written,
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn pak_repack_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut input_dir: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--input-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                input_dir = Some(PathBuf::from(value));
                index += 1;
            }
            "--output" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                output = Some(PathBuf::from(value));
                index += 1;
            }
            _ => return usage(),
        }
        index += 1;
    }
    let (Some(input_dir), Some(output)) = (input_dir, output) else {
        return usage();
    };
    if output.exists() {
        return fail("refusing to overwrite existing output");
    }
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let pak = match kotama_resource::pak::parse(&bytes) {
        Ok(pak) => pak,
        Err(error) => return fail_kind(&error),
    };
    let Ok(root) = input_dir.canonicalize() else {
        return fail("input directory is unavailable");
    };
    let mut plain = Vec::new();
    plain.extend_from_slice(&kotama_resource::pak::MAGIC.to_le_bytes());
    plain.extend_from_slice(&0u32.to_le_bytes());
    let mut bodies = Vec::new();
    for entry in &pak.entries {
        let Some(source) = safe_pak_path(&root, &entry.name) else {
            return fail("refusing unsafe PAK entry path");
        };
        let body = match fs::read(&source) {
            Ok(body) => body,
            Err(error) => return fail(error),
        };
        let name: Vec<u8> = entry
            .name
            .chars()
            .map(|character| character as u8)
            .collect();
        if name.len() > 255 {
            return fail("PAK entry name is too long");
        }
        plain.push(0);
        plain.push(name.len() as u8);
        plain.extend_from_slice(&name);
        plain.extend_from_slice(&(body.len() as u32).to_le_bytes());
        plain.extend_from_slice(&entry.filetime.to_le_bytes());
        bodies.extend_from_slice(&body);
    }
    plain.push(pak.catalog_terminator);
    plain.extend_from_slice(&bodies);
    let encoded: Vec<u8> = plain
        .iter()
        .map(|byte| byte ^ kotama_resource::pak::XOR_MASK)
        .collect();
    let reparsed = match kotama_resource::pak::parse(&encoded) {
        Ok(reparsed) => reparsed,
        Err(error) => return fail_kind(&error),
    };
    if reparsed.entries.len() != pak.entries.len() {
        return fail("repacked PAK entry count mismatch");
    }
    if let Some(parent) = output.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            return fail(error);
        }
    }
    if let Err(error) = fs::write(&output, &encoded) {
        return fail(error);
    }
    let json = PakRepackJson {
        kind: "pak-repack",
        output: output.display().to_string(),
        files: reparsed.entries.len(),
        bytes: encoded.len() as u64,
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
