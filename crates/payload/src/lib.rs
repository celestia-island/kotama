//! 进程内载荷（own-launch 注入的 agent）。
//!
//! 平台注册（装载点只做登记，初始化延到自建线程——仓内 AGENTS 的 loader-lock 纪律）：
//! - Linux（`.init_array` + 裸 `pthread_create` + unix socket 回连）→ [`linux_agent`]
//! - Windows（`DllMain` + `CreateThread` + **TCP 回环**连接宿主）→ [`windows_agent`]
//!
//! 传输之上的协议层是**同一份**：msgpack 帧（[`kotama_proto`]），`serve` 循环 + `dispatch`
//! 只认 `Read + Write`，不认平台。windows 侧选 TCP 回环而非命名管道，是因为它能在
//! wine 下被 Linux 宿主原生接入验证（wine 如实映射 winsock 到宿主 TCP）——命名管道
//! 的 wine 实现宿主侧无入口，纯原生 Windows 再评估。
//!
//! P2/P3 口径只实现**只读**方法：`Hello` / `ListModules` / `ReadMemory`；`WriteMemory`
//! 显式回「未随门禁开放」，与宿主 capability 门禁成对。Windows 载荷另加**加法**能力
//! `StackSnapshot`（`RtlCaptureStackBackTrace` 自抓服务线程栈，只回 module+RVA，符号化
//! 留给宿主）；Linux 载荷不声明该能力，宿主因此不会发。

#![allow(unsafe_code)] // 平台原语与 C ABI 边界；逐调用 SAFETY 注。

use std::io::Read;
use std::io::Write;

use kotama_proto::Frame;
use kotama_proto::Handshake;
use kotama_proto::Request;
use kotama_proto::Response;

pub mod hook_guard;

#[cfg(target_os = "linux")]
pub mod linux_agent;
#[cfg(target_os = "windows")]
pub mod windows_agent;

/// 服务循环：收帧 → 应答 → 直到宿主断开（传输无关）。
pub(crate) fn serve<S>(mut stream: S)
where
    S: Read + Write,
{
    loop {
        let Some(frame) = recv_frame(&mut stream) else {
            return;
        };
        let Frame::Request(request) = frame else {
            return; // 载荷不收应答。
        };
        let response = dispatch(request);
        if send_frame(&mut stream, &Frame::Response(response)).is_err() {
            return;
        }
    }
}

/// 请求分发（只读方法集；传输无关）。
pub(crate) fn dispatch(request: Request) -> Response {
    match request {
        Request::Hello(their) => {
            if their.proto_version != kotama_proto::PROTO_VERSION {
                return Response::Error {
                    code: -32001,
                    message: format!(
                        "proto version mismatch: host {} vs payload {}",
                        their.proto_version,
                        kotama_proto::PROTO_VERSION
                    ),
                };
            }
            Response::HelloAck(Handshake {
                proto_version: kotama_proto::PROTO_VERSION,
                abi_version: kotama::ABI_VERSION,
                capabilities: capabilities(),
            })
        }
        Request::ListModules => match list_modules() {
            Ok(modules) => Response::Modules(modules),
            Err(message) => Response::Error {
                code: -32002,
                message,
            },
        },
        Request::ReadMemory { address, length } => match read_self(address, length) {
            Ok(bytes) => Response::Memory(bytes),
            Err(message) => Response::Error {
                code: -32003,
                message,
            },
        },
        Request::WriteMemory { .. } => Response::Error {
            code: -32004,
            message: "payload write lane ships with the host capability gate (P4)".into(),
        },
        Request::StackSnapshot { max_frames } => match stack_snapshot(max_frames) {
            Ok(stacks) => Response::Stacks(stacks),
            Err(message) => Response::Error {
                code: -32005,
                message,
            },
        },
    }
}

/// 本载荷在握手里声明的能力集。
///
/// Windows 载荷额外声明 `StackSnapshot`（自抓服务线程栈）；Linux 载荷没有该实现，
/// 不声明——能力表必须诚实，宿主据 [`kotama_proto::Handshake::supports`] 决定发不发。
#[cfg(target_os = "windows")]
fn capabilities() -> Vec<kotama_proto::Capability> {
    let mut capabilities = kotama_proto::READ_ONLY_CAPABILITIES.to_vec();
    capabilities.push(kotama_proto::Capability::StackSnapshot);
    capabilities
}

/// 非 Windows 载荷：只读能力集，不含 `StackSnapshot`。
#[cfg(target_os = "linux")]
fn capabilities() -> Vec<kotama_proto::Capability> {
    kotama_proto::READ_ONLY_CAPABILITIES.to_vec()
}

#[cfg(target_os = "windows")]
fn stack_snapshot(max_frames: u32) -> Result<Vec<kotama_proto::ThreadStack>, String> {
    windows_agent::capture_thread_stack(max_frames)
}

/// 没有自抓能力的平台如实拒绝（而不是假装成功）。
#[cfg(target_os = "linux")]
fn stack_snapshot(_max_frames: u32) -> Result<Vec<kotama_proto::ThreadStack>, String> {
    Err("stack snapshot is a windows payload capability; this payload does not declare it".into())
}

/// 单帧上限；peer 给的 u32 不能触发无界分配（与宿主侧一致）。
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// 单次 ReadMemory 上限；请求长度本身来自 peer，不能直接用于分配。
const MAX_READ_LEN: u32 = 64 * 1024 * 1024;

/// 传输帧（4 字节 LE 长度前缀 + msgpack；与宿主侧共用语义）。
pub(crate) fn send_frame<S>(stream: &mut S, frame: &Frame) -> Result<(), std::io::Error>
where
    S: Write,
{
    let bytes = kotama_proto::encode(frame).map_err(|e| std::io::Error::other(e.to_string()))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::other("frame too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)
}

pub(crate) fn recv_frame<S>(stream: &mut S) -> Option<Frame>
where
    S: Read,
{
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).ok()?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME_LEN {
        return None;
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).ok()?;
    kotama_proto::decode(&bytes).ok()
}

// ---- 平台内存/模块原语 ----

#[cfg(target_os = "linux")]
fn list_modules() -> Result<Vec<kotama_proto::ModuleInfo>, String> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| e.to_string())?;
    let mut elf: std::collections::BTreeMap<String, (u64, u64)> = std::collections::BTreeMap::new();
    for line in maps.lines() {
        let mut parts = line.splitn(2, ' ');
        let Some(range) = parts.next() else { continue };
        let Some((Some(start), Some(end))) = range.split_once('-').map(|(s, e)| {
            (
                u64::from_str_radix(s, 16).ok(),
                u64::from_str_radix(e, 16).ok(),
            )
        }) else {
            continue;
        };
        let rest = parts.next().unwrap_or_default();
        let mut fields = rest.split_whitespace();
        let perms = fields.next().unwrap_or_default();
        let _offset = fields.next();
        let path = fields.nth(2).unwrap_or("");
        if path.is_empty() || !perms.as_bytes().contains(&b'x') {
            continue;
        }
        let slot = elf.entry(path.to_string()).or_insert((start, end));
        slot.0 = slot.0.min(start);
        slot.1 = slot.1.max(end);
    }
    Ok(elf
        .into_iter()
        .map(|(path, (base, end))| kotama_proto::ModuleInfo {
            base,
            size: end.saturating_sub(base),
            kind: kotama_proto::ModuleKind::Elf,
            path,
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn read_self(address: u64, length: u32) -> Result<Vec<u8>, String> {
    if length > MAX_READ_LEN {
        return Err(format!("read length {length} exceeds limit {MAX_READ_LEN}"));
    }
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::open("/proc/self/mem").map_err(|e| e.to_string())?;
    let mut buffer = vec![0u8; length as usize];
    file.read_exact_at(&mut buffer, address)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

#[cfg(target_os = "windows")]
fn list_modules() -> Result<Vec<kotama_proto::ModuleInfo>, String> {
    // windows v1：主映像一条（GetModuleHandleW(NULL)）——枚举整表需要 PEB/toolhelp，
    // 随 windows 轮次补齐；能力上报保持诚实（见 dispatch 注释与 manifest）。
    // SAFETY: 空指针 = 主映像句柄；返回值判零。
    let module =
        unsafe { windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null()) };
    let base = module as u64;
    if base == 0 {
        return Err("GetModuleHandleW(NULL) failed".into());
    }
    Ok(vec![kotama_proto::ModuleInfo {
        base,
        size: 0,
        kind: if running_under_wine() {
            kotama_proto::ModuleKind::WinePe
        } else {
            kotama_proto::ModuleKind::NativePe
        },
        path: String::new(),
    }])
}

#[cfg(target_os = "windows")]
fn running_under_wine() -> bool {
    // wine 在 ntdll 暴露 wine_get_version；原生 Windows 没有该导出。这里只用于
    // 如实标记模块容器，不参与检测规避或能力开关。
    let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: 两个名称均为 NUL 结尾；句柄只在成功时传给 GetProcAddress。
    unsafe {
        let ntdll =
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(ntdll_name.as_ptr());
        !ntdll.is_null()
            && windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                c"wine_get_version".as_ptr().cast(),
            )
            .is_some()
    }
}

#[cfg(target_os = "windows")]
fn read_self(address: u64, length: u32) -> Result<Vec<u8>, String> {
    if length > MAX_READ_LEN {
        return Err(format!("read length {length} exceeds limit {MAX_READ_LEN}"));
    }
    // SAFETY: ReadProcessMemory 读自身句柄、目标缓冲长度匹配；返回值判定覆盖。
    unsafe {
        let current = windows_sys::Win32::System::Threading::GetCurrentProcess();
        let mut buffer = vec![0u8; length as usize];
        let mut read = 0usize;
        let ok = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            current,
            address as *const core::ffi::c_void,
            buffer.as_mut_ptr().cast(),
            length as usize,
            &mut read,
        );
        if ok == 0 || read != length as usize {
            return Err(format!("ReadProcessMemory at {address:#x} failed"));
        }
        Ok(buffer)
    }
}
