//! kotama 命令行入口。
//!
//! 已实现：`analyze <path> [--decompile] [--limit N]`（静态管线 P0）。
//! 分期接线中：`live` / `pack` / `serve`（设计案 `_reports/reveng-toolkit-20261123/PLAN.md`）。

use std::path::Path;
use std::process::ExitCode;

use kotama::ABI_VERSION;
use kotama_backend_ghidra::GhidraOracle;
use kotama_decomp::decompile_function_bounded_with_exceptions;
use kotama_host::TargetProcess;
use kotama_image::LoadedModule;
use kotama_scan::call_graph;
use kotama_scan::discover;
use kotama_scan::string_xrefs;
use kotama_scan::vtables;
use serde::Serialize;

const USAGE: &str = "\
kotama — static dissection and live instrumentation for binaries

Usage: kotama <command> [options]

Commands:
  analyze <path>           Static pass: sections, imports, functions (with evidence), pseudo-C
                             --decompile        also emit pseudo-C for the first --limit functions
                             --limit <N>        how many functions to decompile (default 8)
                             --xref             also emit the function-level call graph
                             --strings          also emit string cross-references
                             --vtables          also emit the generic vtable scan
                             --rtti             also emit MSVC RTTI/vtable facts (PE/MSVC)
  oracle <path>            Run Ghidra headless and diff its function list against ours
  live attach <pid>        List modules of a running process (ELF + wine/native PE)
  live analyze <pid>       Parse the first wine/native PE module live and discover functions
  live scan <pid> --exact u32:N|f32:F|bytes:HEX [--then unchanged|changed|increased|decreased --times N]
                             Scan live memory (writable regions) and narrow
  live write <pid> <addr> u32:N|... --write   Write memory (requires --write)
  live trace <pid> <addr-hex> [--seconds N]  INT3 breakpoint hit counting (Linux)
  live launch --preload <so> -- <cmd...>    Own-launch with the payload agent (Linux)
  live freeze <pid> <addr> u32:N --seconds N --write   Pin a value
  live inject --payload <dll> [--transport pipe|tcp] [--pid <pid> | -- <cmd...>]
                             Launch or attach, inject, handshake (Windows)
  export <path>            Emit annotation scripts for other RE tools
                             --format idc|idapython|rizin   (required)
  serve                    Start the service surface (web UI + MCP)       (not wired yet)

Options:
  -h, --help              Print this help
  -V, --version           Print version and payload ABI version";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!(
                "kotama {} (payload ABI {ABI_VERSION})",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Some("analyze") => analyze(&args.collect::<Vec<_>>()),
        Some("oracle") => oracle(&args.collect::<Vec<_>>()),
        Some("export") => export(&args.collect::<Vec<_>>()),
        Some("live") => live(&args.collect::<Vec<_>>()),
        Some("pack") => pack(&args.collect::<Vec<_>>()),
        Some(command) => {
            eprintln!("kotama: unknown command `{command}`\n\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn oracle(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("kotama: oracle wants a path\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let module = match load_module(path) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let functions = discover(&module);

    let oracle = match GhidraOracle::from_env() {
        Ok(oracle) => oracle,
        Err(err) => {
            eprintln!("kotama: oracle lane unavailable: {err}");
            return ExitCode::from(3);
        }
    };
    eprintln!("# oracle: {}", oracle.describe());
    let work_root = std::env::temp_dir().join(format!("kotama-oracle-{}", std::process::id()));
    let result = (|| -> Result<serde_json::Value, String> {
        let theirs = oracle
            .function_list(Path::new(path), &work_root)
            .map_err(|e| e.to_string())?;
        let report = kotama_backend_ghidra::differential(&functions, &theirs, 25);
        #[derive(Serialize)]
        struct OnlyOurs {
            rva: String,
            evidence: Vec<&'static str>,
        }
        #[derive(Serialize)]
        struct OnlyTheirs {
            rva: String,
            name: String,
        }
        #[derive(Serialize)]
        struct OracleReport {
            binary: String,
            container: &'static str,
            ours: usize,
            ghidra: usize,
            matched: usize,
            jaccard: f64,
            only_ours: Vec<OnlyOurs>,
            only_ghidra: Vec<OnlyTheirs>,
        }
        serde_json::to_value(OracleReport {
            binary: std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone()),
            container: module.container.short(),
            ours: report.ours,
            ghidra: report.theirs,
            matched: report.matched,
            jaccard: report.jaccard,
            only_ours: report
                .only_ours
                .iter()
                .map(|(rva, evidence)| OnlyOurs {
                    rva: format!("0x{rva:x}"),
                    evidence: evidence.clone(),
                })
                .collect(),
            only_ghidra: report
                .only_theirs
                .iter()
                .map(|(rva, name)| OnlyTheirs {
                    rva: format!("0x{rva:x}"),
                    name: name.clone(),
                })
                .collect(),
        })
        .map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_dir_all(&work_root);
    match result {
        Ok(report) => {
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{json}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: oracle failed: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `analyze` 的 JSON 报告形状（确定性：全按 RVA / 名字排序）。
#[derive(Serialize)]
struct Report {
    module_id: String,
    container: &'static str,
    arch: &'static str,
    entry: Option<String>,
    sections: Vec<SectionJson>,
    imports: Vec<String>,
    function_count: usize,
    functions: Vec<FunctionJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<Vec<EdgeJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    string_xrefs: Option<Vec<StringXrefJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vtables: Option<Vec<VtableJson>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exceptions: Vec<ExceptionJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtti: Option<RttiJson>,
}

/// MSVC RTTI facts exposed by the CLI; deterministic order comes from the scanner.
#[derive(Serialize)]
struct RttiJson {
    vtables: Vec<RttiVtableJson>,
    type_descriptors: Vec<RttiTypeJson>,
}

#[derive(Serialize)]
struct RttiVtableJson {
    locator_ptr_rva: String,
    address_point: String,
    class_name: String,
    offset: u32,
    constructor_disp: u32,
    hierarchy_rva: String,
    bases: Vec<RttiBaseJson>,
    slots: Vec<String>,
}

#[derive(Serialize)]
struct RttiBaseJson {
    rva: String,
    class_name: String,
    num_contained_bases: u32,
    member_disp: i32,
    vbtable_disp: i32,
    vbase_disp: i32,
}

#[derive(Serialize)]
struct RttiTypeJson {
    rva: String,
    mangled: String,
    class_name: String,
}

/// 一条 PE64 exception/unwind 事实；地址全部是模块 RVA。
#[derive(Serialize)]
struct ExceptionJson {
    begin: String,
    end: String,
    unwind_info: Option<String>,
    flags: Option<u8>,
    prolog_size: Option<u8>,
    handler: Option<String>,
    chained_begin: Option<String>,
}

/// 一个识别出的 vtable（`--vtables` 时才有）。
#[derive(Serialize)]
struct VtableJson {
    rva: String,
    targets: Vec<String>,
}

/// 一条字符串引用（`--strings` 时才有）。
#[derive(Serialize)]
struct StringXrefJson {
    func: String,
    rva: String,
    text: String,
}

/// 一条函数级调用边（`--xref` 时才有）。
#[derive(Serialize)]
struct EdgeJson {
    from: String,
    to: String,
}

#[derive(Serialize)]
struct SectionJson {
    rva: String,
    size: u64,
    name: String,
    executable: bool,
}

#[derive(Serialize)]
struct FunctionJson {
    rva: String,
    size: u64,
    size_inferred: bool,
    name: Option<String>,
    evidence: Vec<&'static str>,
}

/// 找伴生 PDB：zig/mingw 产出 `<stem>.pdb`（替换扩展名），MSVC 也常见 `<file>.pdb`。
/// `live`：活体会话（Linux /proc+wine 与原生 Windows 共用 host facade）。
fn live(args: &[String]) -> ExitCode {
    let mut iter = args.iter();
    let Some(sub) = iter.next() else {
        eprintln!("kotama: live wants a subcommand\n\n{USAGE}");
        return ExitCode::from(2);
    };
    // launch / inject 不带 pid（自己拉起目标）；其余子命令第一个参数是 pid。
    let pid = if sub == "launch" || sub == "inject" {
        0
    } else {
        let Some(pid_raw) = iter.next() else {
            eprintln!("kotama: {sub} wants a pid");
            return ExitCode::from(2);
        };
        match pid_raw.parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => {
                eprintln!("kotama: pid must be a number, got {pid_raw:?}");
                return ExitCode::from(2);
            }
        }
    };
    // launch 自己拉起目标，不开既有 pid 的句柄；其余子命令按 pid 开。
    let open_process = || match TargetProcess::open(pid) {
        Ok(process) => process,
        Err(_) => {
            eprintln!("kotama: cannot open pid {pid} (gone or not permitted)");
            std::process::exit(2);
        }
    };

    match sub.as_str() {
        "scan" => {
            let args: Vec<String> = iter.cloned().collect();
            live_scan(open_process(), &args)
        }
        "write" => {
            let args: Vec<String> = iter.cloned().collect();
            live_write(open_process(), &args)
        }
        "freeze" => {
            let args: Vec<String> = iter.cloned().collect();
            live_freeze(open_process(), &args)
        }
        #[cfg(target_os = "linux")]
        "trace" => {
            let args: Vec<String> = iter.cloned().collect();
            live_trace(open_process(), &args)
        }
        #[cfg(not(target_os = "linux"))]
        "trace" => {
            eprintln!("kotama: live trace is currently Linux-only");
            ExitCode::FAILURE
        }
        #[cfg(target_os = "linux")]
        "launch" => {
            let args: Vec<String> = iter.cloned().collect();
            live_launch(&args)
        }
        #[cfg(not(target_os = "linux"))]
        "launch" => {
            eprintln!(
                "kotama: live launch is currently Linux-only; use the Windows injection lane"
            );
            ExitCode::FAILURE
        }
        #[cfg(target_os = "windows")]
        "inject" => {
            let args: Vec<String> = iter.cloned().collect();
            live_inject(&args)
        }
        #[cfg(not(target_os = "windows"))]
        "inject" => {
            eprintln!("kotama: live inject is currently Windows-only");
            ExitCode::FAILURE
        }
        "attach" => match open_process().modules() {
            Ok(modules) => {
                #[derive(Serialize)]
                struct ModuleJson {
                    base: String,
                    size: u64,
                    kind: &'static str,
                    path: String,
                }
                let modules: Vec<ModuleJson> = modules
                    .iter()
                    .map(|m| ModuleJson {
                        base: format!("0x{:x}", m.base),
                        size: m.size,
                        kind: match m.kind {
                            kotama_proto::ModuleKind::Elf => "elf",
                            kotama_proto::ModuleKind::WinePe => "wine-pe",
                            kotama_proto::ModuleKind::NativePe => "native-pe",
                        },
                        path: m.path.clone(),
                    })
                    .collect();
                match serde_json::to_string_pretty(&modules) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("kotama: {err}");
                        return ExitCode::FAILURE;
                    }
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("kotama: {err}");
                ExitCode::from(2)
            }
        },
        "analyze" => {
            let process = open_process();
            let Ok(image) = process.pe_image(None) else {
                eprintln!("kotama: no PE module in pid {pid}");
                return ExitCode::from(2);
            };
            let functions = kotama_scan::discover_with(
                kotama_scan::ScanView {
                    container: kotama_image::Container::Pe64,
                    arch: kotama_image::Arch::X86_64,
                    image_base: 0,
                    entry_rva: image.entry_rva,
                    sections: &image.sections,
                    symbols: &[],
                    dynamic_symbols: &[],
                    debug_functions: &[],
                },
                &image,
            );
            #[derive(Serialize)]
            struct LiveJson {
                pid: i32,
                image_base: String,
                module_id: String,
                function_count: usize,
                pdata_functions: usize,
            }
            let report = LiveJson {
                pid,
                image_base: format!("0x{:x}", image.base),
                module_id: image.module_id().to_hex(),
                function_count: functions.len(),
                pdata_functions: functions
                    .iter()
                    .filter(|f| f.evidence.contains(&kotama_scan::Evidence::Pdata))
                    .count(),
            };
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("kotama: {err}");
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("kotama: unknown live subcommand `{other}`");
            ExitCode::from(2)
        }
    }
}

/// `live launch --preload <so> -- <cmd...>`：own-launch 注入 + 握手巡检。
#[cfg(target_os = "linux")]
fn live_launch(args: &[String]) -> ExitCode {
    let Some(preload_index) = args.iter().position(|arg| arg == "--preload") else {
        eprintln!("kotama: launch wants --preload <payload.so>");
        return ExitCode::from(2);
    };
    let Some(payload) = args.get(preload_index + 1) else {
        eprintln!("kotama: --preload wants a path");
        return ExitCode::from(2);
    };
    let Some(split) = args.iter().position(|arg| arg == "--") else {
        eprintln!("kotama: launch wants -- before the command");
        return ExitCode::from(2);
    };
    let command: Vec<String> = args[split + 1..].to_vec();
    if command.is_empty() {
        eprintln!("kotama: launch wants a command after --");
        return ExitCode::from(2);
    }
    let mut launched = match kotama_host::launch::launch(payload, &command) {
        Ok(launched) => launched,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let report = match kotama_host::launch::probe(&mut launched, &command) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("kotama: {err}");
            let _ = launched.child.kill();
            return ExitCode::FAILURE;
        }
    };
    #[derive(Serialize)]
    struct LaunchJson {
        pid: i32,
        capabilities: Vec<&'static str>,
        module_count: usize,
        image_base: Option<String>,
        image_magic: Option<String>,
    }
    let json = LaunchJson {
        pid: report.pid,
        capabilities: report
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect(),
        module_count: report.module_count,
        image_base: report.image_base.map(|base| format!("0x{base:x}")),
        image_magic: report.image_magic.map(|bytes| {
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        }),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => {
            println!("{text}");
            let _ = launched.child.kill();
            let _ = launched.child.wait();
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `live inject`：拉起目标 → 显式授权注入 → 载荷回连 → 握手/巡检（Windows）。
#[cfg(target_os = "windows")]
fn live_inject(args: &[String]) -> ExitCode {
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::process::Command;
    use std::process::Stdio;
    use std::time::Duration;
    use std::time::Instant;

    use kotama_host::pipe::NamedPipeServer;
    use kotama_host::pipe::PipeConnection;
    use kotama_host::wire;

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    enum Lane {
        Pipe(NamedPipeServer),
        Tcp(TcpListener),
    }

    enum Transport {
        Pipe(PipeConnection),
        Tcp(TcpStream),
    }

    impl Read for Transport {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            match self {
                Self::Pipe(stream) => stream.read(buffer),
                Self::Tcp(stream) => stream.read(buffer),
            }
        }
    }

    impl Write for Transport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            match self {
                Self::Pipe(stream) => stream.write(buffer),
                Self::Tcp(stream) => stream.write(buffer),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            match self {
                Self::Pipe(stream) => stream.flush(),
                Self::Tcp(stream) => stream.flush(),
            }
        }
    }

    let mut payload: Option<String> = None;
    let mut transport = String::from("pipe");
    let mut attach_pid: Option<i32> = None;
    let mut command: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--payload" => payload = iter.next().cloned(),
            "--transport" => {
                transport = iter.next().cloned().unwrap_or_default();
            }
            "--pid" => {
                let Some(raw) = iter.next() else {
                    eprintln!("kotama: --pid wants a number");
                    return ExitCode::from(2);
                };
                match raw.parse::<i32>() {
                    Ok(pid) => attach_pid = Some(pid),
                    Err(_) => {
                        eprintln!("kotama: pid must be a number, got {raw:?}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--" => {
                command.extend(iter.cloned());
                break;
            }
            other => {
                eprintln!("kotama: live inject unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(payload) = payload else {
        eprintln!("kotama: live inject wants --payload <dll>");
        return ExitCode::from(2);
    };
    if !Path::new(&payload).is_file() {
        eprintln!("kotama: payload is not a file: {payload}");
        return ExitCode::from(2);
    }
    let payload = match std::path::absolute(&payload) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("kotama: cannot make payload absolute: {err}");
            return ExitCode::from(2);
        }
    };
    let (lane, child, pid, image_name) = if let Some(pid) = attach_pid {
        if !command.is_empty() {
            eprintln!("kotama: --pid and a launch command are mutually exclusive");
            return ExitCode::from(2);
        }
        if transport != "pipe" {
            eprintln!("kotama: --pid uses the deterministic named pipe; --transport tcp needs a launched target");
            return ExitCode::from(2);
        }
        if let Err(err) = TargetProcess::open(pid) {
            eprintln!("kotama: cannot open pid {pid}: {err}");
            return ExitCode::FAILURE;
        }
        let server = match NamedPipeServer::for_pid(pid) {
            Ok(server) => server,
            Err(err) => {
                eprintln!("kotama: default pipe for pid {pid}: {err}");
                return ExitCode::FAILURE;
            }
        };
        (Lane::Pipe(server), None, pid, String::new())
    } else {
        if command.is_empty() {
            eprintln!("kotama: live inject wants --pid <pid> or a target after --");
            return ExitCode::from(2);
        }
        let (lane, env_key, env_value) = match transport.as_str() {
            "pipe" => match NamedPipeServer::new() {
                Ok(server) => {
                    let name = server.name().to_string();
                    (Lane::Pipe(server), "KOTAMA_PAYLOAD_PIPE", name)
                }
                Err(err) => {
                    eprintln!("kotama: named pipe: {err}");
                    return ExitCode::FAILURE;
                }
            },
            "tcp" => match TcpListener::bind(("127.0.0.1", 0)) {
                Ok(listener) => match listener.local_addr() {
                    Ok(address) => (
                        Lane::Tcp(listener),
                        "KOTAMA_PAYLOAD_TCP",
                        address.port().to_string(),
                    ),
                    Err(err) => {
                        eprintln!("kotama: tcp address: {err}");
                        return ExitCode::FAILURE;
                    }
                },
                Err(err) => {
                    eprintln!("kotama: tcp listener: {err}");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("kotama: --transport wants pipe or tcp, got {other:?}");
                return ExitCode::from(2);
            }
        };
        let child = match Command::new(&command[0])
            .args(&command[1..])
            .env(env_key, &env_value)
            .env_remove(if env_key == "KOTAMA_PAYLOAD_PIPE" {
                "KOTAMA_PAYLOAD_TCP"
            } else {
                "KOTAMA_PAYLOAD_PIPE"
            })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => ChildGuard(child),
            Err(err) => {
                eprintln!("kotama: cannot launch target: {err}");
                return ExitCode::FAILURE;
            }
        };
        let pid = child.0.id() as i32;
        let lane = match lane {
            Lane::Pipe(mut server) => {
                server.expect_client(pid);
                Lane::Pipe(server)
            }
            other => other,
        };
        let image_name = Path::new(&command[0])
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        (lane, Some(child), pid, image_name)
    };
    let _child = child;
    let deadline = Instant::now() + Duration::from_secs(20);
    let (target, main_base) = loop {
        if let Ok(process) = TargetProcess::open(pid) {
            if let Ok(modules) = process.modules() {
                let module = if image_name.is_empty() {
                    process.main_module().ok()
                } else {
                    modules
                        .iter()
                        .find(|module| {
                            Path::new(&module.path)
                                .file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.eq_ignore_ascii_case(&image_name))
                        })
                        .cloned()
                };
                if let Some(module) = module {
                    break (process, module.base);
                }
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "kotama: pid {pid} never exposed {}",
                if image_name.is_empty() {
                    "a main module"
                } else {
                    image_name.as_str()
                }
            );
            return ExitCode::FAILURE;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let session = match kotama_host::control::Session::with_injection(target) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("kotama: injection capability: {err}");
            return ExitCode::FAILURE;
        }
    };
    let report = match session.inject(&payload, Duration::from_secs(15)) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("kotama: inject: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut stream = match lane {
        Lane::Pipe(server) => match server.accept(Duration::from_secs(20)) {
            Ok(stream) => Transport::Pipe(stream),
            Err(err) => {
                eprintln!("kotama: pipe accept: {err}");
                return ExitCode::FAILURE;
            }
        },
        Lane::Tcp(listener) => {
            if let Err(err) = listener.set_nonblocking(true) {
                eprintln!("kotama: tcp nonblocking: {err}");
                return ExitCode::FAILURE;
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        break Transport::Tcp(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            eprintln!("kotama: payload did not connect over tcp");
                            return ExitCode::FAILURE;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => {
                        eprintln!("kotama: tcp accept: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    };

    let ack = match wire::handshake(&mut stream) {
        Ok(ack) => ack,
        Err(err) => {
            eprintln!("kotama: handshake: {err}");
            return ExitCode::FAILURE;
        }
    };
    let modules = match wire::list_modules(&mut stream) {
        Ok(modules) => modules,
        Err(err) => {
            eprintln!("kotama: payload modules: {err}");
            return ExitCode::FAILURE;
        }
    };
    let payload_main = modules.first().map(|module| module.base).unwrap_or(0);
    let magic = match wire::read_memory(&mut stream, main_base, 2) {
        Ok(magic) => magic,
        Err(err) => {
            eprintln!("kotama: payload read: {err}");
            return ExitCode::FAILURE;
        }
    };
    if payload_main != main_base {
        eprintln!("kotama: payload main base does not match the target image");
        return ExitCode::FAILURE;
    }

    #[derive(Serialize)]
    struct InjectJson {
        pid: i32,
        transport: String,
        payload: String,
        module_base: String,
        remote_load_library: String,
        thread_id: u32,
        proto_version: u16,
        capabilities: Vec<&'static str>,
        payload_modules: usize,
        payload_main_base: String,
        target_main_base: String,
        image_magic: String,
    }
    let json = InjectJson {
        pid,
        transport,
        payload: payload.display().to_string(),
        module_base: format!("0x{:x}", report.module_base),
        remote_load_library: format!("0x{:x}", report.remote_load_library),
        thread_id: report.thread_id,
        proto_version: ack.proto_version,
        capabilities: ack
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect(),
        payload_modules: modules.len(),
        payload_main_base: format!("0x{payload_main:x}"),
        target_main_base: format!("0x{main_base:x}"),
        image_magic: magic.iter().map(|byte| format!("{byte:02x}")).collect(),
    };
    match serde_json::to_string_pretty(&json) {
        Ok(text) => println!("{text}"),
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// `live trace`：INT3 断点命中计数（ptrace；ELF / wine 宿主 PE 通吃）。
#[cfg(target_os = "linux")]
fn live_trace(process: kotama_host::TargetProcess, args: &[String]) -> ExitCode {
    let Some(address_raw) = args.first() else {
        eprintln!("kotama: trace wants a hex address");
        return ExitCode::from(2);
    };
    let Ok(address) = u64::from_str_radix(address_raw.trim_start_matches("0x"), 16) else {
        eprintln!("kotama: bad address {address_raw:?}");
        return ExitCode::from(2);
    };
    let seconds: u64 = args
        .iter()
        .position(|arg| arg == "--seconds")
        .and_then(|index| args.get(index + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let pid = process.pid();
    drop(process);
    let mut session = match kotama_host::trace::TraceSession::attach(pid) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    if let Err(err) = session.set_breakpoint(address) {
        eprintln!("kotama: {err}");
        return ExitCode::from(2);
    }
    let reports = match session.run(std::time::Duration::from_secs(seconds)) {
        Ok(reports) => reports,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = session.detach() {
        eprintln!("kotama: {err}");
        return ExitCode::FAILURE;
    }
    #[derive(Serialize)]
    struct TraceJson {
        breakpoints: Vec<BreakpointJson>,
    }
    #[derive(Serialize)]
    struct BreakpointJson {
        address: String,
        hits: u64,
    }
    let report = TraceJson {
        breakpoints: reports
            .iter()
            .map(|report| BreakpointJson {
                address: format!("0x{:x}", report.address),
                hits: report.hits,
            })
            .collect(),
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// 解析值规格：`u32:123` / `i32:-5` / `u64:8` / `f32:1.5` / `bytes:deadbeef`。
fn parse_value_spec(spec: &str) -> Result<kotama_host::scanner::Value, String> {
    let (kind, raw) = spec
        .split_once(':')
        .ok_or_else(|| format!("value spec wants kind:VALUE, got {spec:?}"))?;
    match kind {
        "u32" => raw
            .parse::<u32>()
            .map(kotama_host::scanner::Value::U32)
            .map_err(|e| e.to_string()),
        "i32" => raw
            .parse::<i32>()
            .map(kotama_host::scanner::Value::I32)
            .map_err(|e| e.to_string()),
        "u64" => raw
            .parse::<u64>()
            .map(kotama_host::scanner::Value::U64)
            .map_err(|e| e.to_string()),
        "f32" => raw
            .parse::<f32>()
            .map(kotama_host::scanner::Value::F32)
            .map_err(|e| e.to_string()),
        "bytes" => {
            let bytes = (0..raw.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(raw.get(i..i + 2).unwrap_or(""), 16)
                        .map_err(|e| format!("bad hex: {e}"))
                })
                .collect::<Result<Vec<u8>, String>>()?;
            Ok(kotama_host::scanner::Value::Bytes(bytes))
        }
        other => Err(format!("unknown value kind {other:?}")),
    }
}

/// `live scan`：首扫 + 可选续扫链，输出命中 JSON。
fn live_scan(process: kotama_host::TargetProcess, args: &[String]) -> ExitCode {
    use kotama_host::scanner;
    let mut exact: Option<kotama_host::scanner::Value> = None;
    let mut then: Option<String> = None;
    let mut times = 1usize;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--exact" => match iter.next().and_then(|v| parse_value_spec(v).ok()) {
                Some(value) => exact = Some(value),
                None => {
                    eprintln!("kotama: --exact wants u32:N|f32:F|bytes:HEX");
                    return ExitCode::from(2);
                }
            },
            "--then" => match iter.next() {
                Some(value) => then = Some(value.clone()),
                None => {
                    eprintln!("kotama: --then wants unchanged|changed|increased|decreased");
                    return ExitCode::from(2);
                }
            },
            "--times" => match iter.next().and_then(|v| v.parse().ok()) {
                Some(value) => times = value,
                None => {
                    eprintln!("kotama: --times wants a number");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("kotama: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(exact) = exact else {
        eprintln!("kotama: scan wants --exact");
        return ExitCode::from(2);
    };
    let mut session = match scanner::first_scan(&process, &exact) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    if let Some(predicate_name) = then {
        let predicate = match predicate_name.as_str() {
            "unchanged" => scanner::Predicate::Unchanged,
            "changed" => scanner::Predicate::Changed,
            "increased" => scanner::Predicate::Increased,
            "decreased" => scanner::Predicate::Decreased,
            other => {
                eprintln!("kotama: unknown predicate {other:?}");
                return ExitCode::from(2);
            }
        };
        for _ in 0..times {
            std::thread::sleep(std::time::Duration::from_millis(400));
            session = scanner::next_scan(&process, &session, &predicate);
        }
    }
    let hits: Vec<String> = session
        .hits
        .iter()
        .map(|h| format!("0x{:x}", h.address))
        .collect();
    #[derive(Serialize)]
    struct ScanJson {
        hits: Vec<String>,
        count: usize,
    }
    match serde_json::to_string_pretty(&ScanJson {
        hits,
        count: session.hits.len(),
    }) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `live write`：需要 `--write` 显式授权（否则 exit 3）。
fn live_write(process: kotama_host::TargetProcess, args: &[String]) -> ExitCode {
    let address = match args
        .first()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
    {
        Some(address) => address,
        None => {
            eprintln!("kotama: write wants a hex address");
            return ExitCode::from(2);
        }
    };
    let Some(spec) = args.get(1) else {
        eprintln!("kotama: write wants a value spec");
        return ExitCode::from(2);
    };
    let value = match parse_value_spec(spec) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    if !args.iter().any(|arg| arg == "--write") {
        eprintln!("kotama: write is capability-gated; pass --write to grant it for this command");
        return ExitCode::from(3);
    }
    let session = match kotama_host::control::Session::with_write(process) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let bytes = match &value {
        kotama_host::scanner::Value::U32(v) => v.to_le_bytes().to_vec(),
        kotama_host::scanner::Value::I32(v) => v.to_le_bytes().to_vec(),
        kotama_host::scanner::Value::U64(v) => v.to_le_bytes().to_vec(),
        kotama_host::scanner::Value::F32(v) => v.to_le_bytes().to_vec(),
        kotama_host::scanner::Value::Bytes(bytes) => bytes.clone(),
    };
    match session.write_bytes(address, &bytes) {
        Ok(()) => {
            println!("wrote {} bytes at {address:#x}", bytes.len());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `live freeze`：钉住一个值 `--seconds` 秒（需要 `--write`）。
fn live_freeze(process: kotama_host::TargetProcess, args: &[String]) -> ExitCode {
    let address = match args
        .first()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
    {
        Some(address) => address,
        None => {
            eprintln!("kotama: freeze wants a hex address");
            return ExitCode::from(2);
        }
    };
    let Some(spec) = args.get(1) else {
        eprintln!("kotama: freeze wants a value spec");
        return ExitCode::from(2);
    };
    let value = match parse_value_spec(spec) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let seconds: u64 = args
        .iter()
        .position(|arg| arg == "--seconds")
        .and_then(|index| args.get(index + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    if !args.iter().any(|arg| arg == "--write") {
        eprintln!("kotama: freeze is capability-gated; pass --write to grant it for this command");
        return ExitCode::from(3);
    }
    let session = match kotama_host::control::Session::with_write(process) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    match session.freeze(address, value, 20) {
        Ok(handle) => {
            println!("frozen {address:#x} for {seconds}s (Ctrl-C to abort early)");
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            drop(handle);
            println!("unfrozen");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `pack`：交叉编译载荷 + manifest（`kotama-pack` 的 CLI 面）。
fn pack(args: &[String]) -> ExitCode {
    let mut targets: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => match iter.next() {
                Some(value) => targets.push(value.clone()),
                None => {
                    eprintln!("kotama: --target wants a triple");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("kotama: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    if targets.is_empty() {
        targets.push(kotama_pack::default_target().to_string());
    }

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dist_root = repo_root.join("dist");
    let mut manifests: Vec<kotama_pack::Manifest> = Vec::new();
    for target in &targets {
        eprintln!("# pack: building {target} ...");
        match kotama_pack::pack_target(&repo_root, &dist_root, target) {
            Ok(manifest) => {
                eprintln!(
                    "# pack: {} -> {} ({} bytes, sha256 {}…)",
                    manifest.target,
                    dist_root
                        .join(&manifest.target)
                        .join(&manifest.file)
                        .display(),
                    manifest.size_bytes,
                    &manifest.sha256[..12]
                );
                manifests.push(manifest);
            }
            Err(err) => {
                eprintln!("kotama: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    match serde_json::to_string_pretty(&manifests) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kotama: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `export`：把我们的函数表（名字/边界/证据）导出成别的逆向工具能吃的标注脚本。
///
/// 地址纪律（互操作调研的核心教训）：IDA 车道在**脚本运行时**查询装载基址
/// （`get_imagebase()`），RVA + base 相加——VA/RVA 单位错配是导入脚本丢名字的第一大坑。
/// Rizin 没有等价的运行时查询口子，按静态 preferred base（image_base + RVA）发射，
/// 头注释写明「装载基址不同请 rebase」。
fn export(args: &[String]) -> ExitCode {
    let mut path: Option<String> = None;
    let mut format: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => match iter.next() {
                Some(value) => format = Some(value.clone()),
                None => {
                    eprintln!("kotama: --format wants idc|idapython|rizin");
                    return ExitCode::from(2);
                }
            },
            other if path.is_none() => path = Some(other.to_string()),
            other => {
                eprintln!("kotama: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("kotama: export wants a path\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let Some(format) = format else {
        eprintln!("kotama: export wants --format idc|idapython|rizin");
        return ExitCode::from(2);
    };

    let module = match load_module(&path) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let functions = discover(&module);
    let named: Vec<_> = functions
        .iter()
        .filter(|f| f.name.as_deref().is_some_and(|n| !n.is_empty()))
        .collect();

    match format.as_str() {
        "idc" => {
            println!("// kotama export (idc) — {} named functions", named.len());
            println!("// run inside IDA: File > Script file... (base queried at runtime)");
            println!("#include <idc.idc>");
            println!("static main() {{");
            println!("  auto base = get_imagebase();");
            for function in &named {
                let name = sanitize_symbol(function.name.as_deref().unwrap_or(""));
                let evidence: Vec<&str> = function.evidence.iter().map(|e| e.short()).collect();
                println!(
                    "  MakeFunction(base+0x{:x}, base+0x{:x}); MakeName(base+0x{:x}, \"{}\"); MakeComm(base+0x{:x}, \"kotama evidence: {}\");",
                    function.rva,
                    function.rva + function.size.max(1),
                    function.rva,
                    name,
                    function.rva,
                    evidence.join(",")
                );
            }
            println!("}}");
            ExitCode::SUCCESS
        }
        "idapython" => {
            println!(
                "# kotama export (idapython) — {} named functions",
                named.len()
            );
            println!("# run inside IDA: File > Script file... (base queried at runtime)");
            println!("import idaapi, ida_name, ida_funcs");
            println!("BASE = idaapi.get_imagebase()");
            for function in &named {
                let name = sanitize_symbol(function.name.as_deref().unwrap_or(""));
                let evidence: Vec<&str> = function.evidence.iter().map(|e| e.short()).collect();
                println!(
                    "ida_funcs.add_func(BASE + 0x{:x}, BASE + 0x{:x})",
                    function.rva,
                    function.rva + function.size.max(1)
                );
                println!("ida_name.set_name(BASE + 0x{:x}, \"{name}\")", function.rva);
                println!(
                    "idaapi.set_cmt(BASE + 0x{:x}, \"kotama evidence: {}\", 0)",
                    function.rva,
                    evidence.join(",")
                );
            }
            ExitCode::SUCCESS
        }
        "rizin" => {
            println!("# kotama export (rizin) — {} named functions", named.len());
            println!("# run: rizin -i <this-file> <binary>");
            println!(
                "# addresses = preferred image base {:#x} + RVA; rebase if your load differs",
                module.image_base
            );
            for function in &named {
                let name = sanitize_symbol(function.name.as_deref().unwrap_or(""));
                let absolute = module.image_base + function.rva;
                println!("f kotama.{name} {:#x} {absolute:#x}", function.size.max(1));
                println!("s {absolute:#x}; af; afn {name}");
            }
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("kotama: unknown export format `{other}` (want idc|idapython|rizin)");
            ExitCode::from(2)
        }
    }
}

/// IDA/Rizin 标识符消毒：非法字符换 `_`，空名兜底。
fn sanitize_symbol(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "kotama_unnamed".to_string()
    } else {
        cleaned
    }
}

fn companion_pdb(path: &str) -> Option<std::path::PathBuf> {
    let base = Path::new(path);
    [
        base.with_extension("pdb"),
        std::path::PathBuf::from(format!("{path}.pdb")),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// 装载一个二进制（含伴生 PDB 的自动发现；PDB 只提升证据，没有也不失败）。
fn load_module(path: &str) -> Result<LoadedModule, String> {
    let data = std::fs::read(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let mut module = LoadedModule::parse(&data).map_err(|err| format!("{path}: {err}"))?;
    if let Some(pdb) = companion_pdb(path) {
        match module.load_pdb(&pdb) {
            Ok(added) => eprintln!("# pdb: {} (+{added} procedures)", pdb.display()),
            Err(err) => eprintln!("# pdb: {pdb:?} ignored: {err}"),
        }
    }
    Ok(module)
}

fn analyze(args: &[String]) -> ExitCode {
    let mut path: Option<String> = None;
    let mut decompile = false;
    let mut xref = false;
    let mut strings = false;
    let mut vtables_flag = false;
    let mut rtti_flag = false;
    let mut limit: usize = 8;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--decompile" => decompile = true,
            "--xref" => xref = true,
            "--strings" => strings = true,
            "--vtables" => vtables_flag = true,
            "--rtti" => rtti_flag = true,
            "--limit" => match iter.next().and_then(|v| v.parse().ok()) {
                Some(value) => limit = value,
                None => {
                    eprintln!("kotama: --limit wants a number");
                    return ExitCode::from(2);
                }
            },
            other if path.is_none() => path = Some(other.to_string()),
            other => {
                eprintln!("kotama: unexpected argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("kotama: analyze wants a path\n\n{USAGE}");
        return ExitCode::from(2);
    };

    let module = match load_module(&path) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("kotama: {err}");
            return ExitCode::from(2);
        }
    };
    let functions = discover(&module);
    let exceptions = kotama_scan::exception_functions(&module);

    let report = Report {
        module_id: module.module_id().to_hex(),
        container: module.container.short(),
        arch: module.arch.short(),
        entry: module.entry_rva.map(|rva| format!("0x{rva:x}")),
        sections: module
            .sections
            .iter()
            .map(|s| SectionJson {
                rva: format!("0x{:x}", s.rva),
                size: s.size,
                name: s.name.clone(),
                executable: s.executable,
            })
            .collect(),
        imports: module
            .imports
            .iter()
            .map(|i| {
                if i.library.is_empty() {
                    i.name.clone()
                } else {
                    format!("{}!{}", i.library, i.name)
                }
            })
            .collect(),
        function_count: functions.len(),
        functions: functions
            .iter()
            .map(|f| FunctionJson {
                rva: format!("0x{:x}", f.rva),
                size: f.size,
                size_inferred: f.size_inferred,
                name: f.name.clone(),
                evidence: f.evidence.iter().map(|e| e.short()).collect(),
            })
            .collect(),
        edges: xref.then(|| {
            call_graph(&module, &functions)
                .into_iter()
                .map(|edge| EdgeJson {
                    from: format!("0x{:x}", edge.from),
                    to: format!("0x{:x}", edge.to),
                })
                .collect()
        }),
        vtables: vtables_flag.then(|| {
            vtables(&module, &functions)
                .into_iter()
                .map(|table| VtableJson {
                    rva: format!("0x{:x}", table.rva),
                    targets: table
                        .targets
                        .iter()
                        .map(|target| format!("0x{target:x}"))
                        .collect(),
                })
                .collect()
        }),
        exceptions: exceptions
            .iter()
            .map(|exception| ExceptionJson {
                begin: format!("0x{:x}", exception.runtime.begin_rva),
                end: format!("0x{:x}", exception.runtime.end_rva),
                unwind_info: (exception.runtime.unwind_info_rva != 0)
                    .then(|| format!("0x{:x}", exception.runtime.unwind_info_rva)),
                flags: exception.unwind.map(|unwind| unwind.flags),
                prolog_size: exception.unwind.map(|unwind| unwind.prolog_size),
                handler: exception
                    .unwind
                    .and_then(|unwind| unwind.handler_rva)
                    .map(|rva| format!("0x{rva:x}")),
                chained_begin: exception
                    .unwind
                    .and_then(|unwind| unwind.chained)
                    .map(|runtime| format!("0x{:x}", runtime.begin_rva)),
            })
            .collect(),
        rtti: rtti_flag.then(|| {
            let facts = kotama_scan::msvc_rtti::scan(&module);
            RttiJson {
                vtables: facts
                    .vtables
                    .iter()
                    .map(|table| RttiVtableJson {
                        locator_ptr_rva: format!("0x{:x}", table.locator_ptr_rva),
                        address_point: format!("0x{:x}", table.address_point),
                        class_name: table.locator.type_descriptor.class_name.clone(),
                        offset: table.locator.offset,
                        constructor_disp: table.locator.constructor_disp,
                        hierarchy_rva: format!("0x{:x}", table.locator.hierarchy.rva),
                        bases: table
                            .locator
                            .hierarchy
                            .bases
                            .iter()
                            .map(|base| RttiBaseJson {
                                rva: format!("0x{:x}", base.rva),
                                class_name: base.type_descriptor.class_name.clone(),
                                num_contained_bases: base.num_contained_bases,
                                member_disp: base.member_disp,
                                vbtable_disp: base.vbtable_disp,
                                vbase_disp: base.vbase_disp,
                            })
                            .collect(),
                        slots: table.slots.iter().map(|rva| format!("0x{rva:x}")).collect(),
                    })
                    .collect(),
                type_descriptors: facts
                    .type_descriptors
                    .iter()
                    .map(|descriptor| RttiTypeJson {
                        rva: format!("0x{:x}", descriptor.rva),
                        mangled: descriptor.mangled.clone(),
                        class_name: descriptor.class_name.clone(),
                    })
                    .collect(),
            }
        }),
        string_xrefs: strings.then(|| {
            string_xrefs(&module, &functions)
                .into_iter()
                .map(|xref| StringXrefJson {
                    func: format!("0x{:x}", xref.func_rva),
                    rva: format!("0x{:x}", xref.string_rva),
                    text: xref.text,
                })
                .collect()
        }),
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("kotama: report serialization failed: {err}");
            return ExitCode::FAILURE;
        }
    }

    if decompile {
        let space = module.address_space();
        let id = module.module_id();
        // 函数体上界 = 下一个函数起点；没有后继时退到所在节尾。只对推断出长度的
        // 函数生效（精确边界在发射器里优先）。
        let limit_of = |index: usize| -> Option<u64> {
            let next = functions.get(index + 1).map(|f| f.rva);
            match next {
                Some(rva) => Some(rva),
                None => module
                    .section_at(functions[index].rva)
                    .map(|s| s.rva + s.size),
            }
        };
        for (index, function) in functions.iter().take(limit).enumerate() {
            let body_limit = limit_of(index);
            let text = decompile_function_bounded_with_exceptions(
                &space,
                id,
                module.arch,
                function,
                body_limit,
                &exceptions,
            );
            println!();
            println!("{}", text.text);
        }
    }
    ExitCode::SUCCESS
}
