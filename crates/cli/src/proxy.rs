//! kotama proxy: strict PE export inspection and forwarding-mirror generation.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use kotama_image::pe_export::{parse_pe_exports, PeExportTable};
use kotama_proxy::{manifest, mirror_def, MirrorExport, MirrorOptions};
use serde::Serialize;

#[derive(Serialize)]
struct InspectJson {
    input: String,
    ordinal_base: u16,
    export_count: usize,
    exports: Vec<MirrorExport>,
}

#[derive(Serialize)]
struct GenerateJson {
    output: String,
    library: String,
    backing: String,
    export_count: usize,
    built: bool,
}

fn usage() -> ExitCode {
    eprintln!("usage:\n  kotama proxy inspect <dll>\n  kotama proxy generate <dll> --output <dir> [--backing <name>] [--build]");
    ExitCode::from(2)
}

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("kotama: proxy: {message}");
    ExitCode::FAILURE
}

fn load(path: &Path) -> Result<(Vec<u8>, PeExportTable), String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let table = parse_pe_exports(&data)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("{} is not a PE image", path.display()))?;
    Ok((data, table))
}

fn pe_machine(data: &[u8]) -> Result<u16, String> {
    let offset = data
        .get(0x3c..0x40)
        .ok_or_else(|| "missing PE header offset".to_string())?;
    let offset = u32::from_le_bytes(offset.try_into().expect("four bytes")) as usize;
    let machine = data
        .get(offset + 4..offset + 6)
        .ok_or_else(|| "missing PE COFF header".to_string())?;
    Ok(u16::from_le_bytes(machine.try_into().expect("two bytes")))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    use std::io::Write;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

pub fn run(args: &[String]) -> ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "inspect" => {
            let Some(path) = args.get(1).map(PathBuf::from) else {
                return usage();
            };
            if args.len() != 2 {
                return usage();
            }
            match inspect(&path) {
                Ok(json) => match serde_json::to_string_pretty(&json) {
                    Ok(text) => {
                        println!("{text}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(error),
                },
                Err(error) => fail(error),
            }
        }
        "generate" => generate(&args[1..]),
        _ => usage(),
    }
}

fn inspect(path: &Path) -> Result<InspectJson, String> {
    let (data, table) = load(path)?;
    let input = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let options = MirrorOptions {
        library: "mirror.dll".to_string(),
        backing: "original.dll".to_string(),
    };
    let facts = manifest(&input, &data, &table, &options, None);
    Ok(InspectJson {
        input,
        ordinal_base: table.ordinal_base,
        export_count: table.entries.len(),
        exports: facts.exports,
    })
}

fn generate(args: &[String]) -> ExitCode {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut backing: Option<String> = None;
    let mut build = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                index += 1;
                output = args.get(index).map(PathBuf::from);
            }
            "--backing" => {
                index += 1;
                backing = args.get(index).cloned();
            }
            "--build" => build = true,
            other if input.is_none() && !other.starts_with('-') => {
                input = Some(PathBuf::from(other));
            }
            _ => return usage(),
        }
        index += 1;
    }
    let (Some(input), Some(output)) = (input, output) else {
        return usage();
    };
    let backing = backing.unwrap_or_else(|| {
        let stem = input
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "original".to_string());
        let extension = input
            .extension()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "dll".to_string());
        format!("{stem}_original.{extension}")
    });
    let options = MirrorOptions {
        library: "mirror.dll".to_string(),
        backing,
    };
    let result = (|| -> Result<GenerateJson, String> {
        let (data, table) = load(&input)?;
        let definition = mirror_def(&table, &options).map_err(|error| error.to_string())?;
        fs::create_dir_all(&output)
            .map_err(|error| format!("create output directory {}: {error}", output.display()))?;
        let def_path = output.join("proxy.def");
        let c_path = output.join("proxy.c");
        let manifest_path = output.join("manifest.json");
        let dll_path = output.join(&options.library);
        for path in [&def_path, &c_path, &manifest_path, &dll_path] {
            if path.exists() {
                return Err(format!("refusing to overwrite {}", path.display()));
            }
        }
        write_new(&def_path, definition.as_bytes())?;
        write_new(
            &c_path,
            b"/* Synthetic translation unit; exports come from proxy.def. */\nvoid kotama_proxy_anchor(void) {}\n",
        )?;
        if build {
            let target = match pe_machine(&data)? {
                0x014c => "x86-windows-gnu",
                0x8664 => "x86_64-windows-gnu",
                other => {
                    return Err(format!(
                        "cannot choose a Zig target for COFF machine {other:#06x}"
                    ))
                }
            };
            let zig = std::env::var_os("KOTAMA_ZIG").unwrap_or_else(|| "zig".into());
            let status = Command::new(&zig)
                .arg("cc")
                .arg("-target")
                .arg(target)
                .arg("-shared")
                .arg("-o")
                .arg(&dll_path)
                .arg(&c_path)
                .arg(&def_path)
                .status()
                .map_err(|error| format!("run zig cc: {error}"))?;
            if !status.success() {
                return Err(format!("zig cc failed with {status}"));
            }
        }
        let built = if build {
            Some(fs::read(&dll_path).map_err(|error| format!("read built DLL: {error}"))?)
        } else {
            None
        };
        let input_name = input
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| input.display().to_string());
        let facts = manifest(&input_name, &data, &table, &options, built.as_deref());
        let text = serde_json::to_vec_pretty(&facts).map_err(|error| error.to_string())?;
        write_new(&manifest_path, &text)?;
        Ok(GenerateJson {
            output: output.display().to_string(),
            library: options.library,
            backing: options.backing,
            export_count: table.entries.len(),
            built: build,
        })
    })();
    match result {
        Ok(json) => match serde_json::to_string_pretty(&json) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        },
        Err(error) => fail(error),
    }
}
