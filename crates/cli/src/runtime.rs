//! `kotama runtime mount` — a runtime's mount plan for a library on disk, as JSON.

use std::path::Path;
use std::process::ExitCode;

use kotama_proxy::hook_plan::HookSelection;
use kotama_runtime_mount::{self as mount, MountPoint, Role, Runtime};
use kotama_runtime_resolve::{
    exports_from_module, resolve_jni_invocation, resolve_lua_exports, resolve_quickjs_exports,
    verify_plan, ResolvedHook, Unresolved,
};
use serde::Serialize;

const ROLE_NAMES: [&str; 7] = [
    "state", "lookup", "call", "error", "memory", "data", "other",
];

const fn role_index(role: Role) -> usize {
    match role {
        Role::State => 0,
        Role::Lookup => 1,
        Role::Call => 2,
        Role::Error => 3,
        Role::Memory => 4,
        Role::Data => 5,
        Role::Other => 6,
    }
}

const USAGE: &str = "\
kotama runtime mount <path> --runtime lua|quickjs|jni
    Resolve a runtime's C ABI against this library's exports and verify a plan
    over every mount point of that runtime.
    jni resolves the Invocation API (the three exported JNI_* symbols); the
    JNIEnv slots need a live snapshot and are not read from a file.
    --list              list every runtime with its mount points per role";

#[derive(Serialize)]
struct ReportJson {
    path: String,
    container: &'static str,
    runtime: &'static str,
    exports: usize,
    planned: usize,
    resolved: Vec<ResolvedJson>,
    unresolved: Vec<String>,
    verification: VerificationJson,
}

#[derive(Serialize)]
struct ResolvedJson {
    group: u32,
    name: String,
    address: String,
    role: &'static str,
}

#[derive(Serialize)]
struct VerificationJson {
    complete: bool,
    addressed: usize,
    missing: Vec<u32>,
}

pub fn run(args: &[String]) -> ExitCode {
    let mut path: Option<&str> = None;
    let mut runtime: Option<&str> = None;
    let mut list = false;
    let mut rest = args.iter();
    match rest.next().map(String::as_str) {
        Some("mount") => {}
        Some("--list") | Some("list") => list = true,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    }
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--runtime" => match rest.next() {
                Some(value) => runtime = Some(value),
                None => {
                    eprintln!("runtime mount: --runtime needs a value");
                    return ExitCode::from(2);
                }
            },
            "--list" => list = true,
            other if path.is_none() => path = Some(other),
            other => {
                eprintln!("runtime mount: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    if list {
        return list_runtimes();
    }
    let (Some(path), Some(runtime)) = (path, runtime) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let runtime = match runtime {
        "lua" => Runtime::Lua,
        "quickjs" => Runtime::QuickJs,
        "jni" => Runtime::Jni,
        other => {
            eprintln!("runtime mount: unknown runtime `{other}`; known: lua, quickjs, jni");
            return ExitCode::from(2);
        }
    };
    match report(Path::new(path), runtime) {
        Ok(report) => {
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("runtime mount: {error}");
                    return ExitCode::FAILURE;
                }
            }
            if report.verification.complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("runtime mount: {message}");
            ExitCode::FAILURE
        }
    }
}

fn points_for(runtime: Runtime) -> Vec<MountPoint> {
    match runtime {
        Runtime::Lua => mount::lua_points(),
        Runtime::QuickJs => mount::quickjs_points(),
        Runtime::Jni => mount::jni_invocation_points(),
    }
}

fn report(path: &Path, runtime: Runtime) -> Result<ReportJson, String> {
    let data = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let module = kotama_image::LoadedModule::parse(&data).map_err(|error| error.to_string())?;
    let exports = exports_from_module(&module);
    let (resolved, unresolved): (Vec<ResolvedHook>, Vec<(String, Unresolved)>) = match runtime {
        Runtime::Lua => resolve_lua_exports(&exports),
        Runtime::QuickJs => resolve_quickjs_exports(&exports),
        Runtime::Jni => resolve_jni_invocation(&exports),
    };
    let points = points_for(runtime);
    let plan = mount::plan_runtime(
        &points,
        &HookSelection {
            all: true,
            ..Default::default()
        },
    )
    .map_err(|error| error.0)?;
    let verification = verify_plan(&plan, &resolved);
    let role_of = |group: u32| -> &'static str {
        points
            .iter()
            .find(|point| point.group == group)
            .map_or("?", |point| ROLE_NAMES[role_index(point.role)])
    };
    let name = match runtime {
        Runtime::Lua => "lua",
        Runtime::QuickJs => "quickjs",
        Runtime::Jni => "jni",
    };
    Ok(ReportJson {
        path: path.display().to_string(),
        container: module.container.short(),
        runtime: name,
        exports: exports.len(),
        planned: plan.hooks().len(),
        resolved: resolved
            .iter()
            .map(|hook| ResolvedJson {
                group: hook.group,
                name: hook.name.clone(),
                address: format!("0x{:x}", hook.address),
                role: role_of(hook.group),
            })
            .collect(),
        unresolved: unresolved
            .iter()
            .map(|(name, reason)| format!("{name}: {reason:?}"))
            .collect(),
        verification: VerificationJson {
            complete: verification.is_complete(),
            addressed: verification.addressed.len(),
            missing: verification.missing.clone(),
        },
    })
}

fn list_runtimes() -> ExitCode {
    for runtime in [Runtime::Lua, Runtime::QuickJs, Runtime::Jni] {
        let points = points_for(runtime);
        let name = match runtime {
            Runtime::Lua => "lua",
            Runtime::QuickJs => "quickjs",
            Runtime::Jni => "jni",
        };
        let mut roles: Vec<(&str, usize)> = Vec::new();
        for point in &points {
            let name = ROLE_NAMES[role_index(point.role)];
            match roles.iter_mut().find(|(role, _)| *role == name) {
                Some((_, count)) => *count += 1,
                None => roles.push((name, 1)),
            }
        }
        roles.sort_unstable();
        let breakdown: Vec<String> = roles
            .iter()
            .map(|(role, count)| format!("{role}={count}"))
            .collect();
        println!(
            "{name:<8} {:>3} points  {}",
            points.len(),
            breakdown.join(" ")
        );
    }
    ExitCode::SUCCESS
}
