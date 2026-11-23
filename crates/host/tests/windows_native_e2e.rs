//! 原生 Windows 注入 / 传输车道 e2e（KOTAMA_LIVE_E2E=1 门控）。
//!
//! 阶段 A（launch-then-inject + 回环 TCP，TCP 车道保留给 wine）：宿主自拉起
//! spin.exe → 显式授权注入 dist/x86_64-pc-windows-gnu/kotama_agent.dll → 载荷回连 →
//! 握手 PROTO_VERSION → ListModules 主基址 == spin 基址 → ReadMemory 回 MZ →
//! 宿主 Toolhelp 枚举到 kotama_agent.dll；未授权注入的负对照在授权前跑。
//!
//! 阶段 B（原生命名管道默认车道）：宿主 CreateNamedPipeW → 同一注入路径 → 同样的
//! 断言，证明载荷真的在 spin.exe 内。kotama_load.exe 回归只证明 loader 自身进程内
//! 载荷可用并断言子进程退出码，不冒充对目标进程的远程注入。
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(unsafe_code)] // 句柄泄漏断言用 `GetProcessHandleCount`；调用点有 SAFETY 注。

use std::io::BufRead;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use kotama_host::control::Session;
use kotama_host::pipe::NamedPipeServer;
use kotama_host::stack;
use kotama_host::wire;
use kotama_host::HostError;
use kotama_host::TargetProcess;
use kotama_proto::Capability;
use kotama_proto::Request;
use kotama_proto::Response;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetProcessHandleCount;

fn live_enabled() -> bool {
    if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
        eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the native Windows injection e2e");
        return false;
    }
    true
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn spin_fixture() -> PathBuf {
    let fixture = repo_root().join("fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
    assert!(
        fixture.is_file(),
        "fixture missing: run tools/build_fixtures.py first ({})",
        fixture.display()
    );
    fixture
}

fn agent_dll() -> PathBuf {
    // 默认用 dist 里的 C agent；KOTAMA_WINDOWS_PAYLOAD_DLL 可换成 Rust payload（MSVC
    // cdylib）做同一车道的回归（例如验证它的 KOTAMA_PAYLOAD_PIPE 支持）。
    if let Some(path) = std::env::var_os("KOTAMA_WINDOWS_PAYLOAD_DLL") {
        let dll = PathBuf::from(path);
        assert!(
            dll.is_file(),
            "KOTAMA_WINDOWS_PAYLOAD_DLL is not a file: {}",
            dll.display()
        );
        return dll;
    }
    let dll = repo_root().join("dist/x86_64-pc-windows-gnu/kotama_agent.dll");
    assert!(
        dll.is_file(),
        "payload DLL missing: run tools/build_windows_agent.py with KOTAMA_ZIG ({})",
        dll.display()
    );
    dll
}

fn loader_exe() -> PathBuf {
    let loader = repo_root().join("dist/x86_64-pc-windows-gnu/kotama_load.exe");
    assert!(
        loader.is_file(),
        "loader missing: run tools/build_windows_agent.py with KOTAMA_ZIG ({})",
        loader.display()
    );
    loader
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn module_file_name_is(path: &str, name: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|file| file.to_str())
        .is_some_and(|file| file.eq_ignore_ascii_case(name))
}

fn find_module_base(modules: &[kotama_proto::ModuleInfo], name: &str) -> Option<u64> {
    modules
        .iter()
        .find(|module| module_file_name_is(&module.path, name))
        .map(|module| module.base)
}

fn wait_for_main_module(pid: i32, name: &str) -> (TargetProcess, u64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(process) = TargetProcess::open(pid) {
            if let Ok(modules) = process.modules() {
                if let Some(module) = modules
                    .iter()
                    .find(|module| module_file_name_is(&module.path, name))
                {
                    return (process, module.base);
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "pid {pid} never exposed a module named {name}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn accept_tcp_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<TcpStream, std::io::Error> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "payload did not connect over tcp in time",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
}

/// 阶段 A：TCP 车道的 launch-then-inject 闭环（旧车道，wine 也用它）。
#[test]
fn live_e2e_launch_then_inject_over_tcp() {
    if !live_enabled() {
        return;
    }
    let spin = spin_fixture();
    let dll = agent_dll();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let port = listener.local_addr().expect("listener addr").port();

    let child = ChildGuard(
        Command::new(&spin)
            .arg("30")
            .env("KOTAMA_PAYLOAD_TCP", port.to_string())
            .env_remove("KOTAMA_PAYLOAD_PIPE")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spin.exe"),
    );
    let pid = child.0.id() as i32;
    let (target, spin_base) = wait_for_main_module(pid, "spin.exe");

    // 负对照（活体会话形态）：未授权注入必须在任何注入原语之前被拒。
    {
        let read_only = Session::read_only(TargetProcess::open(pid).expect("reopen spin"));
        assert!(matches!(
            read_only.inject(&dll, Duration::from_secs(5)),
            Err(HostError::CapabilityDenied(_))
        ));
        eprintln!("# phase A negative control: unauthorized injection denied with CapabilityDenied before any VirtualAllocEx/CreateRemoteThread");
    }

    let session = Session::with_injection(TargetProcess::open(pid).expect("open inject target"))
        .expect("explicit injection grant");
    assert!(session.injection_allowed());
    let report = session
        .inject(&dll, Duration::from_secs(15))
        .expect("inject kotama_agent.dll");
    assert!(report.module_base > 0);
    assert_eq!(report.pid, pid);

    // 宿主 Toolhelp 必须枚举到注入的模块，且基址与注入报告一致。
    let modules = target.modules().expect("host module table");
    let agent_base = find_module_base(&modules, "kotama_agent.dll")
        .expect("kotama_agent.dll must be visible through Toolhelp");
    assert_eq!(agent_base, report.module_base);

    // 载荷回连 + 握手 + 只读巡检。
    let mut stream = accept_tcp_with_timeout(&listener, Duration::from_secs(15))
        .expect("payload did not connect over tcp");
    stream
        .set_nonblocking(false)
        .expect("blocking payload stream");
    let ack = wire::handshake(&mut stream).expect("handshake");
    assert_eq!(ack.proto_version, kotama_proto::PROTO_VERSION);
    assert_eq!(kotama_proto::PROTO_VERSION, 3);
    assert!(ack
        .capabilities
        .contains(&kotama_proto::Capability::ListModules));

    let payload_modules = wire::list_modules(&mut stream).expect("payload module list");
    assert_eq!(
        payload_modules.len(),
        1,
        "windows payload v1 reports the main image only"
    );
    assert_eq!(
        payload_modules[0].base, spin_base,
        "payload ListModules main base must equal spin.exe base"
    );
    let magic = wire::read_memory(&mut stream, spin_base, 2).expect("payload read of image head");
    assert_eq!(&magic, b"MZ");
    assert_eq!(
        target.read_absolute(spin_base, 2).expect("host read"),
        b"MZ"
    );
    eprintln!(
        "# phase A: pid={pid} spin_base={spin_base:#x} agent_base={agent_base:#x} remote_load_library={:#x} remote_thread={} proto={} payload_modules={} magic={:02x?}",
        report.remote_load_library,
        report.thread_id,
        ack.proto_version,
        payload_modules.len(),
        magic
    );
    drop(stream);
    drop(session);
}

/// 阶段 B：原生命名管道默认车道的 launch-then-inject 闭环。
#[test]
fn live_e2e_launch_then_inject_over_named_pipe() {
    if !live_enabled() {
        return;
    }
    let spin = spin_fixture();
    let dll = agent_dll();
    let server = NamedPipeServer::new().expect("CreateNamedPipeW");
    let pipe_name = server.name().to_string();
    assert!(pipe_name.starts_with(r"\\.\pipe\kotama-"));

    let child = ChildGuard(
        Command::new(&spin)
            .arg("30")
            .env("KOTAMA_PAYLOAD_PIPE", &pipe_name)
            .env_remove("KOTAMA_PAYLOAD_TCP")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spin.exe"),
    );
    let pid = child.0.id() as i32;
    let (target, spin_base) = wait_for_main_module(pid, "spin.exe");

    let session = Session::with_injection(TargetProcess::open(pid).expect("open inject target"))
        .expect("explicit injection grant");
    let report = session
        .inject(&dll, Duration::from_secs(15))
        .expect("inject kotama_agent.dll");
    let modules = target.modules().expect("host module table");
    let agent_base = find_module_base(&modules, "kotama_agent.dll")
        .expect("injected payload must be a module of spin.exe");
    assert_eq!(agent_base, report.module_base);

    let mut pipe = server
        .accept(Duration::from_secs(15))
        .expect("payload did not connect over the named pipe");
    let ack = wire::handshake(&mut pipe).expect("handshake");
    assert_eq!(ack.proto_version, kotama_proto::PROTO_VERSION);
    assert_eq!(kotama_proto::PROTO_VERSION, 3);

    // 加法能力 `StackSnapshot` 的向后兼容负对照：C agent 不声明它，宿主门禁在**发送前**
    // 就拒绝；绕过门禁直接发时，C agent 必须诚实回 Error（不是崩溃/静默），连接仍可用。
    assert!(
        !ack.supports(Capability::StackSnapshot),
        "C payload must not declare stack-snapshot: {:?}",
        ack.capabilities
    );
    assert!(matches!(
        wire::stack_snapshot(&mut pipe, &ack, 8),
        Err(HostError::CapabilityDenied(_))
    ));
    match wire::request(&mut pipe, &Request::StackSnapshot { max_frames: 8 }).expect("raw request")
    {
        Response::Error { message, .. } => assert!(
            message.contains("not supported"),
            "C payload must honestly refuse stack-snapshot, got: {message}"
        ),
        other => panic!("C payload answered stack-snapshot with {other:?}"),
    }

    let payload_modules = wire::list_modules(&mut pipe).expect("payload module list");
    assert_eq!(
        payload_modules[0].base, spin_base,
        "pipe lane: payload main base must equal spin.exe base"
    );
    let magic = wire::read_memory(&mut pipe, spin_base, 2).expect("payload read of image head");
    assert_eq!(&magic, b"MZ");
    // 目标仍活着：宿主侧还能读它的映像头。
    assert_eq!(
        target.read_absolute(spin_base, 2).expect("host read"),
        b"MZ"
    );
    eprintln!(
        "# phase B: pid={pid} pipe={pipe_name} spin_base={spin_base:#x} agent_base={agent_base:#x} proto={} payload_modules={} magic={:02x?}",
        ack.proto_version,
        payload_modules.len(),
        magic
    );
    drop(pipe);
    drop(session);
}

/// 已运行目标 + 无传输环境：payload 按自身 pid 回落到 `\\.\pipe\kotama-<pid>`。
#[test]
fn live_e2e_attach_then_inject_over_default_pid_pipe() {
    if !live_enabled() {
        return;
    }
    let spin = spin_fixture();
    let dll = agent_dll();
    let child = ChildGuard(
        Command::new(&spin)
            .arg("30")
            .env_remove("KOTAMA_PAYLOAD_PIPE")
            .env_remove("KOTAMA_PAYLOAD_TCP")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spin.exe without transport environment"),
    );
    let pid = child.0.id() as i32;
    let (target, spin_base) = wait_for_main_module(pid, "spin.exe");

    let server = NamedPipeServer::for_pid(pid).expect("deterministic default pipe");
    let pipe_name = server.name().to_string();
    assert!(pipe_name.ends_with(&format!("kotama-{pid}")));
    let session = Session::with_injection(TargetProcess::open(pid).expect("open inject target"))
        .expect("explicit injection grant");
    let report = session
        .inject(&dll, Duration::from_secs(15))
        .expect("inject into an already-running target");
    let modules = target.modules().expect("host module table");
    let agent_base = find_module_base(&modules, "kotama_agent.dll")
        .expect("injected payload must be visible through Toolhelp");
    assert_eq!(agent_base, report.module_base);

    let mut pipe = server
        .accept(Duration::from_secs(20))
        .expect("payload did not connect over the default pid pipe");
    let ack = wire::handshake(&mut pipe).expect("handshake");
    assert_eq!(ack.proto_version, kotama_proto::PROTO_VERSION);
    let payload_modules = wire::list_modules(&mut pipe).expect("payload module list");
    assert_eq!(payload_modules[0].base, spin_base);
    let magic = wire::read_memory(&mut pipe, spin_base, 2).expect("payload read of image head");
    assert_eq!(&magic, b"MZ");
    eprintln!(
        "# attach: pid={pid} pipe={pipe_name} spin_base={spin_base:#x} agent_base={agent_base:#x} proto={} magic={:02x?}",
        ack.proto_version,
        magic
    );
    drop(pipe);
    drop(session);
}

/// kotama_load.exe 回归：只证明 loader 自身进程内的载荷可用，并断言子进程退出码。
///
/// 这里**不**声称载荷进了子进程：载荷上报的主映像基址必须等于 kotama_load.exe 自己
/// 的主映像基址（loader 先 LoadLibrary 再 CreateProcess，载荷就活在 loader 里）。
#[test]
fn live_e2e_kotama_load_payload_lives_in_loader_and_child_exits_zero() {
    if !live_enabled() {
        return;
    }
    let loader = loader_exe();
    let dll = agent_dll();
    let spin = spin_fixture();
    let server = NamedPipeServer::new().expect("CreateNamedPipeW");
    let pipe_name = server.name().to_string();

    let mut child = ChildGuard(
        Command::new(&loader)
            .arg(&dll)
            .arg("--")
            .arg(&spin)
            .arg("3")
            .env("KOTAMA_PAYLOAD_PIPE", &pipe_name)
            .env_remove("KOTAMA_PAYLOAD_TCP")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn kotama_load.exe"),
    );
    let pid = child.0.id() as i32;
    let mut pipe = server
        .accept(Duration::from_secs(20))
        .expect("payload did not connect from kotama_load.exe");
    let ack = wire::handshake(&mut pipe).expect("handshake");
    assert_eq!(ack.proto_version, kotama_proto::PROTO_VERSION);

    let (loader_target, loader_base) = wait_for_main_module(pid, "kotama_load.exe");
    let payload_modules = wire::list_modules(&mut pipe).expect("payload module list");
    assert_eq!(
        payload_modules[0].base, loader_base,
        "loader regression: payload must live in the loader's own image, not the child"
    );
    let magic = wire::read_memory(&mut pipe, loader_base, 2).expect("read loader image head");
    assert_eq!(&magic, b"MZ");
    drop(pipe);
    drop(loader_target);

    // spin.exe 3 秒跑完退出 0；loader 透传子进程退出码（它自己的退出码就是证据）。
    let status = child.0.wait().expect("wait for kotama_load.exe");
    assert_eq!(
        status.code(),
        Some(0),
        "kotama_load.exe must forward spin.exe's zero exit code"
    );
    eprintln!(
        "# loader: pid={pid} loader_base={loader_base:#x} payload_base={:#x} proto={} child_exit={:?}",
        payload_modules[0].base,
        ack.proto_version,
        status.code()
    );
}
// ---- 外部栈回溯 + 载荷自抓（task-8：原生 Windows 栈快照 + dbghelp）----

/// 原生 MSVC 靶子（伴生 `spin.pdb` 提供 main/tick 的精确 RVA 范围）。
fn msvc_spin_fixture() -> PathBuf {
    let fixture = repo_root().join("fixtures/generated/x86_64-windows-msvc/-O0/spin.exe");
    assert!(
        fixture.is_file(),
        "fixture missing: run tools/build_fixtures.py --targets x86_64-windows-msvc --run ({})",
        fixture.display()
    );
    fixture
}

/// 从静态 PE + 伴生 PDB 取一个函数的 `(rva, size)` 范围（`pdb` crate 车道）。
fn pdb_function_range(exe: &Path, name: &str) -> (u64, u64) {
    let data = std::fs::read(exe).expect("read fixture image");
    let mut module = kotama_image::LoadedModule::parse(&data).expect("parse fixture image");
    let pdb = exe.with_extension("pdb");
    assert!(pdb.is_file(), "companion PDB missing: {}", pdb.display());
    module.load_pdb(&pdb).expect("load companion PDB");
    let symbol = module
        .debug_functions
        .iter()
        .find(|symbol| symbol.name == name)
        .unwrap_or_else(|| panic!("PDB has no procedure named {name}"));
    assert!(symbol.size > 0, "{name} has no size in the PDB");
    (symbol.rva, symbol.size)
}

/// 原生 MSVC Rust 载荷（自抓车道）；`KOTAMA_WINDOWS_PAYLOAD_DLL` 可覆盖。
fn msvc_payload_dll() -> PathBuf {
    if let Some(path) = std::env::var_os("KOTAMA_WINDOWS_PAYLOAD_DLL") {
        let dll = PathBuf::from(path);
        assert!(
            dll.is_file(),
            "KOTAMA_WINDOWS_PAYLOAD_DLL is not a file: {}",
            dll.display()
        );
        return dll;
    }
    let dll = repo_root().join("dist/x86_64-pc-windows-msvc/kotama_payload.dll");
    assert!(
        dll.is_file(),
        "MSVC payload DLL missing: run the pack lane or set KOTAMA_WINDOWS_PAYLOAD_DLL ({})",
        dll.display()
    );
    dll
}

/// 当前进程的句柄数（泄漏断言用）。
fn open_handle_count() -> u32 {
    let mut count = 0u32;
    // SAFETY: GetCurrentProcess 返回伪句柄；count 是有效的 u32 输出位置。
    let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    assert_ne!(ok, 0, "GetProcessHandleCount failed");
    count
}

/// 外部栈回溯（Toolhelp 线程 + SuspendThread/GetThreadContext + StackWalk64 + dbghelp）：
///
/// 断言链：
/// 1. 线程按 tid 升序、帧的 `rva == address - module_base` 自洽（确定性口径）；
/// 2. 某线程的某帧落在静态 PDB 的 `spin!main` 范围内，且 dbghelp 把它符号化成 `main`；
/// 3. `capture_threads_in_image` 的契约成立（若有结果，每条线程的 RIP 都在主映像内）；
/// 4. Resume 之后目标继续打印并正常退出（退出码 0）——线程没被留在挂起态；
/// 5. 成功路径与失败路径都不泄漏句柄（`GetProcessHandleCount` 前后对比）。
///
/// 注意：句柄数断言假设本测试文件单线程跑（`cargo test -- --test-threads=1`，台架
/// `tools/windows_bench.py` 就是这么跑的）。
#[test]
fn live_e2e_external_stack_walk_symbolizes_spin_main() {
    if !live_enabled() {
        return;
    }
    let spin = msvc_spin_fixture();
    let (main_rva, main_size) = pdb_function_range(&spin, "main");
    let (tick_rva, tick_size) = pdb_function_range(&spin, "tick");
    eprintln!("# pdb ranges: main={main_rva:#x}+{main_size:#x} tick={tick_rva:#x}+{tick_size:#x}");

    let mut child = ChildGuard(
        Command::new(&spin)
            .arg("6")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn native msvc spin.exe"),
    );
    let pid = child.0.id() as i32;
    let stdout = child.0.stdout.take().expect("stdout");
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = {
        let lines = Arc::clone(&lines);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                lines.lock().expect("lines lock").push(line);
            }
        })
    };
    // 等第一行心跳：说明已进入主循环，spin!main 在栈上。
    let deadline = Instant::now() + Duration::from_secs(20);
    while lines.lock().expect("lines lock").is_empty() {
        assert!(
            Instant::now() < deadline,
            "spin.exe printed no heartbeat; stack walk would be meaningless"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let (target, spin_base) = wait_for_main_module(pid, "spin.exe");

    // 成功路径的句柄泄漏基线。
    let handles_before = open_handle_count();
    let report = stack::capture_all_threads(&target, stack::DEFAULT_MAX_FRAMES)
        .expect("external stack walk of spin.exe");
    assert_eq!(report.pid, pid);
    assert_eq!(report.image_base, spin_base, "main image anchor");
    assert!(
        module_file_name_is(&report.image_path, "spin.exe"),
        "unexpected main image path: {}",
        report.image_path
    );
    assert!(!report.threads.is_empty(), "no thread stacks captured");
    assert!(
        report
            .threads
            .windows(2)
            .all(|pair| pair[0].thread_id < pair[1].thread_id),
        "threads must be sorted by tid: {:?}",
        report
            .threads
            .iter()
            .map(|thread| thread.thread_id)
            .collect::<Vec<_>>()
    );

    let mut main_frame = None;
    for thread in &report.threads {
        for frame in &thread.frames {
            if frame.module_base == 0 {
                assert_eq!(frame.rva, 0, "unknown-module frame must report rva 0");
            } else {
                assert_eq!(
                    frame.rva,
                    frame.address - frame.module_base,
                    "rva must equal address - module_base: {frame:?}"
                );
            }
            if frame.module_base == spin_base
                && frame.rva >= main_rva
                && frame.rva < main_rva + main_size
            {
                main_frame = Some((thread.thread_id, frame.clone()));
            }
        }
    }
    let (main_tid, frame) = main_frame.unwrap_or_else(|| {
        panic!(
            "no frame inside spin!main ({main_rva:#x}+{main_size:#x}); stacks: {:#?}",
            report.threads
        )
    });
    assert_eq!(
        frame.symbol.as_deref(),
        Some("main"),
        "dbghelp must resolve the spin!main frame: {frame:?}"
    );
    assert!(
        frame.displacement < main_size,
        "displacement {:#x} outside main (+{main_size:#x})",
        frame.displacement
    );
    eprintln!(
        "# external stack: threads={} tid={main_tid} rip={:#x} frames={} main_frame rva={:#x} symbol={:?}+{:#x}",
        report.threads.len(),
        report
            .threads
            .iter()
            .find(|thread| thread.thread_id == main_tid)
            .map_or(0, |thread| thread.rip),
        report
            .threads
            .iter()
            .find(|thread| thread.thread_id == main_tid)
            .map_or(0, |thread| thread.frames.len()),
        frame.rva,
        frame.symbol,
        frame.displacement
    );

    // 确定性：同一进程的线程集合稳定（spin.exe 不自建线程），且两次都按 tid 升序。
    let second = stack::capture_all_threads(&target, stack::DEFAULT_MAX_FRAMES)
        .expect("second external stack walk");
    let first_ids: Vec<u32> = report
        .threads
        .iter()
        .map(|thread| thread.thread_id)
        .collect();
    let second_ids: Vec<u32> = second
        .threads
        .iter()
        .map(|thread| thread.thread_id)
        .collect();
    assert_eq!(
        first_ids, second_ids,
        "thread set / ordering must be deterministic"
    );
    assert!(
        second
            .threads
            .windows(2)
            .all(|pair| pair[0].thread_id < pair[1].thread_id),
        "second capture must also be tid-sorted"
    );

    // RIP-in-main-image 过滤的契约（睡眠中的目标可能一条都没有：那是选择条件，不是失败）。
    match stack::capture_threads_in_image(&target, 32) {
        Ok(in_image) => {
            assert!(!in_image.threads.is_empty());
            for thread in &in_image.threads {
                assert!(thread.rip_in_image, "filter leaked a thread: {thread:?}");
                assert!(
                    thread.rip >= in_image.image_base
                        && thread.rip < in_image.image_base + in_image.image_size,
                    "RIP {:#x} outside the main image {:#x}+{:#x}",
                    thread.rip,
                    in_image.image_base,
                    in_image.image_size
                );
            }
            eprintln!(
                "# capture_threads_in_image: {} thread(s) inside spin.exe",
                in_image.threads.len()
            );
        }
        Err(HostError::Stack(message)) => {
            eprintln!(
                "# capture_threads_in_image: no thread inside spin.exe right now ({message})"
            );
        }
        Err(other) => panic!("unexpected capture_threads_in_image error: {other}"),
    }

    // 剩余 4 次 capture 一起算泄漏（共 6 次成功路径）。
    for _ in 0..4 {
        let _ = stack::capture_all_threads(&target, 16).expect("repeat capture");
    }
    let handles_after = open_handle_count();
    let success_delta = handles_after.saturating_sub(handles_before);
    assert!(
        success_delta <= 4,
        "success path leaks handles: +{success_delta} over 6 captures"
    );

    // Resume 之后目标必须继续跑完并正常退出（挂起恢复的活体证据）。
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        match child.0.try_wait().expect("try_wait spin.exe") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                panic!("spin.exe did not exit after the stack walk: threads left suspended?")
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let _ = sink.join();
    let printed = lines.lock().expect("lines lock").clone();
    assert_eq!(
        status.code(),
        Some(0),
        "target must exit 0 after ResumeThread: {printed:?}"
    );
    assert!(
        printed
            .iter()
            .filter(|line| line.starts_with("spin: "))
            .count()
            >= 3,
        "target must keep printing after the capture: {printed:?}"
    );

    // 失败路径（目标已退出，线程/模块表都拿不到）同样不许泄漏句柄。
    let dead_before = open_handle_count();
    for _ in 0..12 {
        assert!(
            stack::capture_all_threads(&target, 16).is_err(),
            "capturing a dead process must fail"
        );
    }
    let dead_delta = open_handle_count().saturating_sub(dead_before);
    assert!(
        dead_delta <= 4,
        "failure path leaks handles: +{dead_delta} over 12 failed captures"
    );
    eprintln!("# handle deltas: success=+{success_delta} failure=+{dead_delta}");
}

/// 载荷自抓（`StackSnapshot` 能力，加法协议）：注入原生 MSVC Rust 载荷 → 命名管道握手 →
/// `wire::stack_snapshot` → 帧的 module+RVA 必须在目标模块表里成立，且确定性可复现。
///
/// 载荷侧只回 module+RVA（不做 dbghelp 符号化：那会和目标自己的符号处理器抢进程级状态），
/// 因此这里断言的是模块归属与稳定性，不是符号名。
#[test]
fn live_e2e_payload_self_stack_snapshot_over_named_pipe() {
    if !live_enabled() {
        return;
    }
    let spin = msvc_spin_fixture();
    let dll = msvc_payload_dll();
    let server = NamedPipeServer::new().expect("CreateNamedPipeW");
    let pipe_name = server.name().to_string();

    let child = ChildGuard(
        Command::new(&spin)
            .arg("10")
            .env("KOTAMA_PAYLOAD_PIPE", &pipe_name)
            .env_remove("KOTAMA_PAYLOAD_TCP")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn native msvc spin.exe"),
    );
    let pid = child.0.id() as i32;
    let (target, spin_base) = wait_for_main_module(pid, "spin.exe");
    let session = Session::with_injection(TargetProcess::open(pid).expect("open inject target"))
        .expect("explicit injection grant");
    let report = session
        .inject(&dll, Duration::from_secs(20))
        .expect("inject the MSVC Rust payload");
    let modules = target.modules().expect("host module table");
    assert_eq!(
        find_module_base(&modules, "kotama_payload.dll").expect("payload module must be visible"),
        report.module_base
    );

    let mut pipe = server
        .accept(Duration::from_secs(20))
        .expect("payload did not connect over the named pipe");
    let ack = wire::handshake(&mut pipe).expect("handshake");
    assert_eq!(ack.proto_version, kotama_proto::PROTO_VERSION);
    assert!(
        ack.supports(Capability::StackSnapshot),
        "the windows Rust payload must declare stack-snapshot: {:?}",
        ack.capabilities
    );

    let stacks = wire::stack_snapshot(&mut pipe, &ack, 64).expect("payload self stack");
    assert_eq!(
        stacks.len(),
        1,
        "the payload only captures its own serving thread"
    );
    let captured = &stacks[0];
    assert_ne!(captured.thread_id, 0, "thread id must be reported");
    assert!(
        captured.frames.len() >= 3,
        "expected a real call chain, got {:?}",
        captured.frames
    );
    let mut payload_frames = 0usize;
    let mut resolved_frames = 0usize;
    for frame in &captured.frames {
        if frame.module_base == 0 {
            continue;
        }
        resolved_frames += 1;
        assert_eq!(
            frame.module_rva,
            frame.address - frame.module_base,
            "module_rva must equal address - module_base: {frame:?}"
        );
        let module = modules
            .iter()
            .find(|module| module.base == frame.module_base)
            .unwrap_or_else(|| {
                panic!(
                    "frame module {:#x} is not in pid {pid}'s module table",
                    frame.module_base
                )
            });
        assert!(
            frame.module_rva < module.size.max(1),
            "frame rva {:#x} outside module {} (size {:#x})",
            frame.module_rva,
            module.path,
            module.size
        );
        if module_file_name_is(&module.path, "kotama_payload.dll") {
            payload_frames += 1;
        }
    }
    assert!(
        resolved_frames >= 3,
        "most self-captured frames must resolve to modules: {:?}",
        captured.frames
    );
    assert!(
        payload_frames >= 1,
        "the call chain must include payload frames: {:?}",
        captured.frames
    );

    // 确定性：服务线程此刻阻塞在管道读上，两次自抓的 module+RVA 序列必须一致。
    let again = wire::stack_snapshot(&mut pipe, &ack, 64).expect("second payload self stack");
    let shape = |stacks: &[kotama_proto::ThreadStack]| -> Vec<(u64, u64)> {
        stacks
            .iter()
            .flat_map(|stack| {
                stack
                    .frames
                    .iter()
                    .map(|frame| (frame.module_base, frame.module_rva))
            })
            .collect()
    };
    assert_eq!(
        shape(&stacks),
        shape(&again),
        "payload self capture must be deterministic while the serving thread is blocked"
    );

    // 目标仍然活着、可读。
    assert_eq!(
        &target.read_absolute(spin_base, 2).expect("host read"),
        b"MZ"
    );
    eprintln!(
        "# payload self stack: pid={pid} modules={} frames={} resolved={resolved_frames} payload_frames={payload_frames} proto={} caps={:?}",
        modules.len(),
        captured.frames.len(),
        ack.proto_version,
        ack.capabilities
    );
    drop(pipe);
    drop(session);
}
