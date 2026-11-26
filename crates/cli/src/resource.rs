//! kotama resource: identify, inspect and extract vendor-neutral resources.
//!
//! Only widely used, vendor-neutral formats live here. Parsers for engine- and
//! studio-specific formats are deliberately kept out of the published CLI; see
//! the examples directory.

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
struct StringHitJson {
    offset: usize,
    text: String,
}

#[derive(Serialize)]
struct StringsJson {
    kind: &'static str,
    count: usize,
    strings: Vec<StringHitJson>,
}

#[derive(Serialize)]
struct ExtractJson {
    kind: &'static str,
    output: String,
    bytes_written: usize,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  kotama resource identify <path>\n  kotama resource info <path> [--kind swf|vbs|dos-com|dds|tga]\n  kotama resource dds <path> [--kind dds]\n  kotama resource tga <path> [--kind tga]\n  kotama resource strings <path> [--min-len <count>] [--limit <count>]\n  kotama resource extract <path> --output <path> [--kind swf|vbs|dos-com] [--max-output <bytes>]"
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
        "strings" => strings_command(&args[1..]),
        "info" => info_command(&args[1..]),
        "dds" => dds_command(&args[1..]),
        "tga" => tga_command(&args[1..]),
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

fn strings_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        return usage();
    };
    let mut min_len = 4usize;
    let mut limit = 100usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--min-len" => {
                let Some(value) = args.get(index + 1) else {
                    return usage();
                };
                min_len = match value.parse::<usize>() {
                    Ok(value) => value,
                    Err(_) => return usage(),
                };
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
            _ => return usage(),
        }
        index += 1;
    }
    let bytes = match read_file(&PathBuf::from(path)) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let mut strings = Vec::new();
    let mut start: Option<usize> = None;
    for (offset, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(offset);
            }
        } else if let Some(begin) = start {
            if offset - begin >= min_len {
                strings.push(StringHitJson {
                    offset: begin,
                    text: String::from_utf8_lossy(&bytes[begin..offset]).to_string(),
                });
                if strings.len() == limit {
                    break;
                }
            }
            start = None;
        }
    }
    if let Some(begin) = start {
        if bytes.len() - begin >= min_len && strings.len() < limit {
            strings.push(StringHitJson {
                offset: begin,
                text: String::from_utf8_lossy(&bytes[begin..]).to_string(),
            });
        }
    }
    let json = StringsJson {
        kind: "strings",
        count: strings.len(),
        strings,
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
    let payload = match resource.extract(max_output) {
        Ok(Extracted::Bytes(bytes)) => bytes.into_owned(),
        Ok(Extracted::Text(text)) => text.as_bytes().to_vec(),
        Err(error) => return fail_kind(&error),
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
