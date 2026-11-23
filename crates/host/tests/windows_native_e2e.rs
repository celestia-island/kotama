//! 原生 Windows 注入 / 传输车道 e2e（KOTAMA_LIVE_E2E=1 门控）。
//!
//! 阶段 A（launch-then-inject + 回环 TCP，TCP 车道保留给 wine）：宿主自拉起
//! spin.exe → 显式授权注入 dist/x86_64-windows-gnu/kotama_agent.dll → 载荷回连 →
//! 握手 PROTO_VERSION → ListModules 主基址 == spin 基址 → ReadMemory 回 MZ →
//! 宿主 Toolhelp 枚举到 kotama_agent.dll；未授权注入的负对照在授权前跑。
//!
//! 阶段 B（原生命名管道默认车道）：宿主 CreateNamedPipeW → 同一注入路径 → 同样的
//! 断言，证明载荷真的在 spin.exe 内。kotama_load.exe 回归只证明 loader 自身进程内
//! 载荷可用并断言子进程退出码，不冒充对目标进程的远程注入。
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use kotama_host::control::Session;
use kotama_host::pipe::NamedPipeServer;
use kotama_host::wire;
use kotama_host::HostError;
use kotama_host::TargetProcess;

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
    let dll = repo_root().join("dist/x86_64-windows-gnu/kotama_agent.dll");
    assert!(
        dll.is_file(),
        "payload DLL missing: run tools/build_windows_agent.py with KOTAMA_ZIG ({})",
        dll.display()
    );
    dll
}

fn loader_exe() -> PathBuf {
    let loader = repo_root().join("dist/x86_64-windows-gnu/kotama_load.exe");
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
