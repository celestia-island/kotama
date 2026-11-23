//! own-launch 注入车道：宿主预监听 unix socket → `LD_PRELOAD` 拉起目标 → 载荷回连 →
//! 按协议握手并经**进程内**通道读内存。
//!
//! 这是 P2 注入矩阵的 Linux own-launch 项闭环：载荷是我们编译的 cdylib
//! （`kotama-payload`），`bootstrap` 只在 `.init_array` 登记，线程连回本监听器。
//! 只读方法集（Hello / ListModules / ReadMemory）；写方法随宿主 capability 门禁成对开放。

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

use kotama_proto::Capability;
use kotama_proto::Frame;
use kotama_proto::Handshake;
use kotama_proto::Request;
use kotama_proto::Response;

use crate::HostError;

/// 一次 own-launch 会话的报告。
#[derive(Clone, Debug)]
pub struct LaunchReport {
    /// 目标 PID。
    pub pid: i32,
    /// 载荷上报的能力。
    pub capabilities: Vec<Capability>,
    /// 载荷枚举的模块数。
    pub module_count: usize,
    /// 主映像（命令里的那个文件）在载荷视角的基址。
    pub image_base: Option<u64>,
    /// 经载荷读回的主映像头 4 字节（ELF 应为 `7f 45 4c 46`）。
    pub image_magic: Option<Vec<u8>>,
}

/// 产物：目标子进程 + 会话流（调用方决定何时收尾）。
pub struct Launched {
    /// 目标子进程。
    pub child: Child,
    /// 与载荷的帧流。
    pub stream: UnixStream,
    /// socket 路径（Drop 清理）。
    socket: PathBuf,
}

impl Drop for Launched {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// 以 `LD_PRELOAD=<payload>` 拉起 `command`，等载荷回连并完成握手。
///
/// # Errors
/// socket 绑定 / 子进程拉起 / 握手超时或版本不匹配。
pub fn launch(payload: &str, command: &[String]) -> Result<Launched, HostError> {
    let socket_dir = std::env::temp_dir();
    let socket = socket_dir.join(format!("kotama-launch-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .map_err(|e| HostError::Proc(format!("bind {}: {e}", socket.display())))?;

    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .env("LD_PRELOAD", payload)
        .env("KOTAMA_PAYLOAD_SOCKET", &socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| HostError::Process(format!("spawn {:?}: {e}", command[0])))?;
    let _pid = child.id() as i32;

    // 接线窗口：载荷 25ms×200 重试连接，这里给 15s 上限。
    let (stream, _) =
        accept_with_timeout(&listener, std::time::Duration::from_secs(15)).map_err(|e| {
            let _ = child.kill();
            HostError::Proc(format!("payload did not connect: {e}"))
        })?;

    let mut launched = Launched {
        child,
        stream,
        socket,
    };
    // 握手：版本不匹配 = 拒绝（无回退）。
    let ack = request(
        &mut launched.stream,
        &Request::Hello(Handshake {
            proto_version: kotama_proto::PROTO_VERSION,
            abi_version: kotama::ABI_VERSION,
            capabilities: vec![Capability::ListModules, Capability::ReadMemory],
        }),
    )?;
    match ack {
        Response::HelloAck(handshake) => {
            if handshake.proto_version != kotama_proto::PROTO_VERSION {
                let _ = launched.child.kill();
                return Err(HostError::Process(format!(
                    "payload proto {} != host {}",
                    handshake.proto_version,
                    kotama_proto::PROTO_VERSION
                )));
            }
        }
        Response::Error { code, message } => {
            let _ = launched.child.kill();
            return Err(HostError::Process(format!(
                "handshake rejected: {code} {message}"
            )));
        }
        other => {
            let _ = launched.child.kill();
            return Err(HostError::Process(format!(
                "unexpected handshake reply: {other:?}"
            )));
        }
    }
    Ok(launched)
}

/// 完成一次「模块枚举 + 主映像头读回」巡检并产出报告。
///
/// # Errors
/// 任一请求失败。
pub fn probe(launched: &mut Launched, command: &[String]) -> Result<LaunchReport, HostError> {
    let modules = match request(&mut launched.stream, &Request::ListModules)? {
        Response::Modules(modules) => modules,
        Response::Error { code, message } => {
            return Err(HostError::Proc(format!("list_modules: {code} {message}")))
        }
        other => return Err(HostError::Proc(format!("unexpected reply: {other:?}"))),
    };
    let module_count = modules.len();
    let main_path = std::path::Path::new(&command[0])
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&command[0]));
    let image_base = modules
        .iter()
        .find(|module| {
            std::path::Path::new(&module.path)
                .canonicalize()
                .map(|p| p == main_path)
                .unwrap_or(module.path == command[0])
        })
        .map(|module| module.base);

    let image_magic = image_base.and_then(|base| {
        match request(
            &mut launched.stream,
            &Request::ReadMemory {
                address: base,
                length: 4,
            },
        ) {
            Ok(Response::Memory(bytes)) => Some(bytes),
            _ => None,
        }
    });

    // 能力从握手缓存在流里拿不到（无状态帧）——再要一次 Hello 不合适；报告里带载荷
    // 声明的静态能力集即可（与 payload 源一致）。
    Ok(LaunchReport {
        pid: launched.child.id() as i32,
        capabilities: vec![Capability::ListModules, Capability::ReadMemory],
        module_count,
        image_base,
        image_magic,
    })
}

fn accept_with_timeout(
    listener: &UnixListener,
    timeout: std::time::Duration,
) -> Result<(UnixStream, std::os::unix::net::SocketAddr), HostError> {
    listener
        .set_nonblocking(true)
        .map_err(|e| HostError::Proc(format!("listener nonblocking: {e}")))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(pair) => {
                let _ = listener.set_nonblocking(false);
                return Ok(pair);
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(HostError::Proc("accept timeout".into()));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(err) => return Err(HostError::Proc(format!("accept: {err}"))),
        }
    }
}

fn request<S: Read + Write>(stream: &mut S, request: &Request) -> Result<Response, HostError> {
    send_frame(stream, &Frame::Request(request.clone()))?;
    match recv_frame(stream) {
        Some(Frame::Response(response)) => Ok(response),
        _ => Err(HostError::Proc("frame stream closed".into())),
    }
}

fn send_frame<S: Write>(stream: &mut S, frame: &Frame) -> Result<(), HostError> {
    let bytes = kotama_proto::encode(frame).map_err(|e| HostError::Proc(format!("encode: {e}")))?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .map_err(|e| HostError::Proc(format!("send: {e}")))
}

fn recv_frame<S: Read>(stream: &mut S) -> Option<Frame> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).ok()?;
    let mut bytes = vec![0u8; u32::from_le_bytes(length) as usize];
    stream.read_exact(&mut bytes).ok()?;
    kotama_proto::decode(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// own-launch e2e（宿主机 + `KOTAMA_LIVE_E2E=1` + `KOTAMA_PAYLOAD_SO` 指向已构建的
    /// `libkotama_payload.so`）：LD_PRELOAD 注入 → 握手 → 载荷枚举模块 → 经**进程内**
    /// 通道读回主映像 ELF 头。
    #[test]
    fn live_e2e_own_launch_payload_roundtrip() {
        if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the live e2e");
            return;
        }
        let Ok(payload) = std::env::var("KOTAMA_PAYLOAD_SO") else {
            eprintln!("skip: set KOTAMA_PAYLOAD_SO=<libkotama_payload.so>");
            return;
        };
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-linux-gnu/-O2/spin")
            .canonicalize()
            .expect("fixture");
        let command = vec![fixture.to_string_lossy().into_owned(), "8".into()];

        let mut launched = launch(&payload, &command).expect("launch with payload");
        let report = probe(&mut launched, &command).expect("probe");
        let _ = launched.child.kill();
        let _ = launched.child.wait();

        assert!(report.module_count > 0, "payload saw no modules");
        let base = report.image_base.expect("main image module found");
        let magic = report.image_magic.expect("read back image head");
        assert_eq!(
            &magic, b"\x7fELF",
            "in-process read must return the ELF header"
        );
        assert!(base > 0);
    }
}

/// wine 宿主下的 windows 载荷会话（TCP 回环）。
pub struct WineLaunched {
    /// wine 子进程。
    pub child: Child,
    /// 与载荷的帧流（宿主侧 TCP）。
    pub stream: std::net::TcpStream,
    /// 监听端口（诊断用）。
    pub port: u16,
}

/// 在 wine 下以 `KOTAMA_PAYLOAD_TCP` 拉起目标并通过 **LoadLibrary 预载**载荷 dll。
///
/// wine 没有 `LD_PRELOAD` 的等价物，但宿主可以运行一个极小的 loader 子进程
/// （`kotama-load`）→ dll 的 `DllMain` 起线程回连宿主 TCP。这样载荷代码**真的在
/// 目标进程里跑**，与 linux 侧 own-launch 语义对齐。
///
/// # Errors
/// 监听 / 子进程 / 握手失败。
pub fn launch_wine(
    wine: &str,
    loader: &str,
    payload: &str,
    target: &[String],
) -> Result<WineLaunched, HostError> {
    // 端口：让内核挑一个空闲口再监听。
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| HostError::Proc(format!("tcp bind: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| HostError::Proc(format!("local_addr: {e}")))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|e| HostError::Proc(format!("nonblocking: {e}")))?;

    let mut child = Command::new(wine)
        .arg(loader)
        .arg(payload)
        .arg("--")
        .args(target)
        .env("KOTAMA_PAYLOAD_TCP", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| HostError::Process(format!("spawn {wine}: {e}")))?;

    let stream =
        accept_tcp_with_timeout(&listener, std::time::Duration::from_secs(20)).map_err(|e| {
            let _ = child.kill();
            HostError::Proc(format!("payload did not connect over tcp: {e}"))
        })?;
    stream
        .set_nonblocking(false)
        .map_err(|e| HostError::Proc(format!("tcp blocking: {e}")))?;

    let mut launched = WineLaunched {
        child,
        stream,
        port,
    };
    match request(
        &mut launched.stream,
        &Request::Hello(Handshake {
            proto_version: kotama_proto::PROTO_VERSION,
            abi_version: kotama::ABI_VERSION,
            capabilities: vec![Capability::ListModules, Capability::ReadMemory],
        }),
    )? {
        Response::HelloAck(_) => Ok(launched),
        Response::Error { code, message } => {
            let _ = launched.child.kill();
            Err(HostError::Process(format!(
                "handshake rejected: {code} {message}"
            )))
        }
        other => {
            let _ = launched.child.kill();
            Err(HostError::Process(format!(
                "unexpected handshake: {other:?}"
            )))
        }
    }
}

/// 对 windows 载荷做一次模块枚举巡检。
///
/// # Errors
/// 请求失败。
pub fn probe_wine(launched: &mut WineLaunched) -> Result<LaunchReport, HostError> {
    let modules = match request(&mut launched.stream, &Request::ListModules)? {
        Response::Modules(modules) => modules,
        Response::Error { code, message } => {
            return Err(HostError::Proc(format!("list_modules: {code} {message}")))
        }
        other => return Err(HostError::Proc(format!("unexpected reply: {other:?}"))),
    };
    Ok(LaunchReport {
        pid: launched.child.id() as i32,
        capabilities: vec![Capability::ListModules, Capability::ReadMemory],
        module_count: modules.len(),
        image_base: modules.first().map(|module| module.base),
        image_magic: None,
    })
}

fn accept_tcp_with_timeout(
    listener: &std::net::TcpListener,
    timeout: std::time::Duration,
) -> Result<std::net::TcpStream, HostError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(HostError::Proc("tcp accept timeout".into()));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(err) => return Err(HostError::Proc(format!("accept: {err}"))),
        }
    }
}

#[cfg(test)]
mod wine_tests {
    use super::*;

    /// wine 下 windows 载荷的 own-launch e2e（`KOTAMA_WINE_E2E=1`）。
    ///
    /// 依赖：`KOTAMA_WINE`（wine64 loader）、`KOTAMA_WINE_LOADER`（kotama-load.exe）、
    /// `KOTAMA_WINE_PAYLOAD`（kotama_agent.dll）。三者由 `tools/build_windows_agent.py`
    /// 产出。
    #[test]
    fn live_e2e_wine_payload_speaks_protocol() {
        if std::env::var_os("KOTAMA_WINE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_WINE_E2E=1 to run the wine payload e2e");
            return;
        }
        let Ok(wine) = std::env::var("KOTAMA_WINE") else {
            eprintln!("skip: set KOTAMA_WINE");
            return;
        };
        let Ok(loader) = std::env::var("KOTAMA_WINE_LOADER") else {
            eprintln!("skip: set KOTAMA_WINE_LOADER");
            return;
        };
        let Ok(payload) = std::env::var("KOTAMA_WINE_PAYLOAD") else {
            eprintln!("skip: set KOTAMA_WINE_PAYLOAD");
            return;
        };
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe")
            .canonicalize()
            .expect("fixture");
        // wine 要 windows 风格路径。
        let win_path = format!("Z:{}", fixture.to_string_lossy().replace('/', "\\"));
        let target = vec![win_path, "10".to_string()];

        let mut launched = launch_wine(&wine, &loader, &payload, &target).expect("wine launch");
        let report = probe_wine(&mut launched).expect("probe");
        let _ = launched.child.kill();
        let _ = launched.child.wait();

        assert!(report.module_count >= 1, "payload reported no modules");
        assert!(report.image_base.unwrap_or(0) > 0, "module base");
    }
}
