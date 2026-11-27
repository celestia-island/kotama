//! `kotama hook plan` — a preset's hook plan for a real binary, as JSON.

use std::path::Path;
use std::process::ExitCode;

use kotama_proxy::hook_plan::{plan_hooks, HookableSymbol};
use kotama_proxy::sdk_presets::{by_id, platform_of_container, Platform};
use serde::Serialize;

const USAGE: &str = "kotama hook plan <path> --preset <id>
    Plan the hooks a named preset would install on this binary.
    The platform is read off the container (PE → Windows names, ELF → POSIX names);
    names the other platform owns are listed as excused, not as errors.
    --list              list every preset id with its name counts";

#[derive(Serialize)]
struct PlanJson {
    path: String,
    container: &'static str,
    platform: &'static str,
    preset: &'static str,
    symbols: usize,
    hooks: Vec<HookJson>,
    excused: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct HookJson {
    group: u32,
    names: Vec<String>,
}

pub fn run(args: &[String]) -> ExitCode {
    let mut path: Option<&str> = None;
    let mut preset: Option<&str> = None;
    let mut list = false;
    let mut rest = args.iter();
    match rest.next().map(String::as_str) {
        Some("plan") => {}
        Some("--list") | Some("list") => list = true,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    let mut items = rest;
    while let Some(flag) = items.next() {
        match flag.as_str() {
            "--preset" => match items.next() {
                Some(value) => preset = Some(value),
                None => {
                    eprintln!("hook plan: --preset needs a value");
                    return ExitCode::from(2);
                }
            },
            "--list" => list = true,
            other if path.is_none() => path = Some(other),
            other => {
                eprintln!("hook plan: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    if list {
        return list_presets();
    }
    let (Some(path), Some(preset_id)) = (path, preset) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match plan(Path::new(path), preset_id) {
        Ok(json) => {
            match serde_json::to_string_pretty(&json) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("hook plan: {error}");
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("hook plan: {message}");
            ExitCode::FAILURE
        }
    }
}

fn list_presets() -> ExitCode {
    for preset in kotama_proxy::sdk_presets::PRESETS {
        println!(
            "{:<22} {:>3} names  {:>3} native  {:>3} posix  {}",
            preset.id,
            preset.names.len(),
            preset.names_for(Platform::Native).len(),
            preset.names_for(Platform::Posix).len(),
            preset.summary
        );
    }
    ExitCode::SUCCESS
}

fn plan(path: &Path, preset_id: &str) -> Result<PlanJson, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let Some(preset) = by_id(preset_id) else {
        let known: Vec<&str> = kotama_proxy::sdk_presets::PRESETS
            .iter()
            .map(|p| p.id)
            .collect();
        return Err(format!(
            "unknown preset `{preset_id}`; known: {}",
            known.join(", ")
        ));
    };
    let module = kotama_image::LoadedModule::parse(&data).map_err(|error| error.to_string())?;
    let container = module.container;
    let platform = platform_of_container(container);
    let symbols: Vec<HookableSymbol> = match container {
        kotama_image::Container::Pe32 | kotama_image::Container::Pe64 => {
            kotama_proxy::hook_plan::pe_hookable_symbols(&data).map_err(|e| e.0)?
        }
        kotama_image::Container::Elf32 | kotama_image::Container::Elf64 => {
            kotama_proxy::hook_plan::elf_hookable_symbols(&data).map_err(|e| e.0)?
        }
        other => return Err(format!("no hook plan for a {}", other.short())),
    };
    let selection = preset.selection_for(platform);
    let plan = plan_hooks(&symbols, &selection).map_err(|error| error.0)?;
    Ok(PlanJson {
        path: path.display().to_string(),
        container: container.short(),
        platform: match platform {
            Platform::Native => "windows",
            Platform::Posix => "posix",
            _ => "other",
        },
        preset: preset.id,
        symbols: symbols.len(),
        hooks: plan
            .hooks()
            .iter()
            .map(|(group, record)| HookJson {
                group: *group,
                names: record.names.clone(),
            })
            .collect(),
        excused: selection.not_on_platform.clone(),
        warnings: plan.warnings().to_vec(),
    })
}
