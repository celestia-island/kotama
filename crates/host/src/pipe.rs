//! 原生 Windows 命名管道服务端（载荷默认传输车道）。
//!
//! 设计要点：
//! - 名字唯一：\\.\pipe\kotama-<pid>-<seq>-<nanos>，并用 FILE_FLAG_FIRST_PIPE_INSTANCE
//!   防止名字被抢占；
//! - PIPE_REJECT_REMOTE_CLIENTS：只接受本机客户端（不做远程管道）；
//! - 重叠 I/O：CreateNamedPipeW 带 FILE_FLAG_OVERLAPPED，连接用「OVERLAPPED + 事件 +
//!   WaitForSingleObject」实现**可超时**的 ConnectNamedPipe，读写同样走重叠 I/O 并等待；
//! - 协议帧与 TCP / unix socket 车道完全一致（kotama-proto 的 msgpack + 4 字节 LE 长度
//!   前缀），本模块只提供字节流。
//!
//! TCP 车道保留给 wine（wine 的命名管道没有宿主侧入口），见 host 的 launch 模块。

#![allow(unsafe_code)] // Win32 C ABI；逐处 SAFETY 注。

use std::io::Read;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Pipes::PIPE_READMODE_BYTE;
use windows_sys::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS;
use windows_sys::Win32::System::Pipes::PIPE_TYPE_BYTE;
use windows_sys::Win32::System::Pipes::PIPE_WAIT;
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::IO::GetOverlappedResult;
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::HostError;

/// 管道缓冲区（协议帧小，64 KiB 足够一次往返；超长帧由宿主分片）。
const PIPE_BUFFER: u32 = 64 * 1024;

/// 一次性命名管道服务端：创建 → accept（可超时）→ 得到一个字节流。
pub struct NamedPipeServer {
    handle: OwnedHandle,
    event: OwnedHandle,
    name: String,
    expected_client: Option<u32>,
}

impl NamedPipeServer {
    /// 建一个唯一名字的命名管道实例（只接受本机客户端）。
    ///
    /// # Errors
    /// CreateNamedPipeW 或 CreateEventW 失败（名字被抢占 / 资源不足）。
    pub fn new() -> Result<Self, HostError> {
        Self::with_name(unique_name())
    }

    /// 为既有目标 PID 建一个确定性管道名 `\\\\.\\pipe\\kotama-<pid>`。
    ///
    /// 目标是已经在运行、无法再注入环境变量的进程时，payload 会用自身 pid
    /// 构造同一个名字回落连接；宿主必须在注入前先建好这个服务端实例。
    ///
    /// # Errors
    /// 名字已被占用（另一个会话正在注入同一 pid）或 CreateNamedPipeW 失败。
    pub fn for_pid(pid: i32) -> Result<Self, HostError> {
        let mut server = Self::with_name(format!(r"\\.\pipe\kotama-{pid}"))?;
        server.expect_client(pid);
        Ok(server)
    }

    /// 只接受来自指定 PID 的客户端连接（防止同机其他进程抢先连接）。
    pub fn expect_client(&mut self, pid: i32) {
        self.expected_client = u32::try_from(pid).ok();
    }

    fn with_name(name: String) -> Result<Self, HostError> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: wide 是 NUL 结尾的有效管道名；安全属性 NULL = 默认（当前用户）；
        // nMaxInstances = 1（单客户端）；缓冲区与超时均为值参数。
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                std::ptr::null(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(crate::windows::last_error(&format!(
                "CreateNamedPipeW {name}"
            )));
        }
        // SAFETY: raw 是刚返回的有效独占句柄。
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: 自动重置事件、初始未触发、匿名；返回句柄判空。
        let raw_event = unsafe { CreateEventW(std::ptr::null(), FALSE, FALSE, std::ptr::null()) };
        if raw_event.is_null() {
            return Err(crate::windows::last_error(&format!(
                "CreateEventW for {name}"
            )));
        }
        // SAFETY: raw_event 是刚返回的有效独占句柄。
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        Ok(Self {
            handle,
            event,
            name,
            expected_client: None,
        })
    }

    /// 管道全名（用于注入到目标进程的 KOTAMA_PAYLOAD_PIPE）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 等客户端连上来（带超时），成功后返回可读写的字节流。
    ///
    /// # Errors
    /// 连接超时、ConnectNamedPipe/GetOverlappedResult 失败。
    pub fn accept(self, timeout: Duration) -> Result<PipeConnection, HostError> {
        let mut overlapped = OVERLAPPED {
            hEvent: self.event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        // SAFETY: overlapped 是栈上有效结构、hEvent 指向本 server 存活的事件；
        // handle 是监听端管道句柄。
        let connected = unsafe { ConnectNamedPipe(self.handle.as_raw_handle(), &mut overlapped) };
        if connected == 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_PIPE_CONNECTED) => {}
                Some(ERROR_IO_PENDING) => {
                    let wait_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
                    // SAFETY: overlapped 已交给内核；事件会在完成/失败时被置位。
                    let waited =
                        unsafe { WaitForSingleObject(self.event.as_raw_handle(), wait_ms) };
                    if waited != WAIT_OBJECT_0 {
                        return Err(HostError::Win32(format!(
                            "named pipe {}: no client within {timeout:?} (wait status {waited})",
                            self.name
                        )));
                    }
                    let mut transferred = 0u32;
                    // SAFETY: overlapped 与上面 ConnectNamedPipe 是同一结构；句柄存活。
                    let completed = unsafe {
                        GetOverlappedResult(
                            self.handle.as_raw_handle(),
                            &overlapped,
                            &mut transferred,
                            FALSE,
                        )
                    };
                    if completed == 0 {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error().map(|code| code as u32)
                            != Some(ERROR_PIPE_CONNECTED)
                        {
                            return Err(HostError::Win32(format!(
                                "ConnectNamedPipe {}: {error}",
                                self.name
                            )));
                        }
                    }
                }
                _ => {
                    return Err(HostError::Win32(format!(
                        "ConnectNamedPipe {}: {error}",
                        self.name
                    )))
                }
            }
        }
        if let Some(expected) = self.expected_client {
            let mut client_pid = 0u32;
            // SAFETY: handle 已连接；client_pid 是可写栈变量。
            let ok = unsafe {
                GetNamedPipeClientProcessId(self.handle.as_raw_handle(), &mut client_pid)
            };
            if ok == 0 {
                return Err(crate::windows::last_error(&format!(
                    "GetNamedPipeClientProcessId {}",
                    self.name
                )));
            }
            if client_pid != expected {
                return Err(HostError::Win32(format!(
                    "named pipe {}: client pid {client_pid} != target pid {expected}",
                    self.name
                )));
            }
        }
        Ok(PipeConnection {
            handle: self.handle,
            event: self.event,
        })
    }
}

/// 已连接的命名管道字节流（实现 Read + Write，供 wire 模块的协议层复用）。
pub struct PipeConnection {
    handle: OwnedHandle,
    event: OwnedHandle,
}

impl PipeConnection {
    fn transfer(&mut self, buffer: &mut [u8], write: bool) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut overlapped = OVERLAPPED {
            hEvent: self.event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer 指针/长度匹配且本次调用独占；overlapped 在栈上、event 存活；
        // 句柄是已连接的本机管道。
        let completed = unsafe {
            if write {
                WriteFile(
                    self.handle.as_raw_handle(),
                    buffer.as_ptr(),
                    length,
                    std::ptr::null_mut(),
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    self.handle.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    length,
                    std::ptr::null_mut(),
                    &mut overlapped,
                )
            }
        };
        finish_io(
            self.handle.as_raw_handle(),
            self.event.as_raw_handle(),
            &mut overlapped,
            completed,
        )
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.transfer(buffer, false)
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut copy = buffer.to_vec();
        self.transfer(&mut copy, true)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // 字节流管道无用户态缓冲。
    }
}

/// 完成一次重叠 I/O：立即完成或等事件后再取结果；对端关闭按 EOF（Ok(0)）上报。
fn finish_io(
    handle: HANDLE,
    event: HANDLE,
    overlapped: &mut OVERLAPPED,
    completed: i32,
) -> std::io::Result<usize> {
    let mut transferred = 0u32;
    if completed == 0 {
        let error = std::io::Error::last_os_error();
        if is_pipe_closed(&error) {
            return Ok(0);
        }
        if error.raw_os_error().map(|code| code as u32) != Some(ERROR_IO_PENDING) {
            return Err(error);
        }
        // SAFETY: event 与 overlapped 属于同一次已提交的重叠 I/O；u32::MAX = INFINITE。
        let waited = unsafe { WaitForSingleObject(event, u32::MAX) };
        if waited != WAIT_OBJECT_0 {
            return Err(std::io::Error::other(format!(
                "named pipe overlapped wait failed: status {waited}"
            )));
        }
    }
    // SAFETY: overlapped 用于上面那次 I/O 调用，句柄存活；FALSE = 不等待。
    let ok = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, FALSE) };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        if is_pipe_closed(&error) {
            return Ok(0);
        }
        return Err(error);
    }
    Ok(transferred as usize)
}

/// 对端关闭（断管 / 未连接）在流语义里就是 EOF。
fn is_pipe_closed(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|code| code as u32),
        Some(ERROR_BROKEN_PIPE) | Some(ERROR_PIPE_NOT_CONNECTED)
    )
}

/// 唯一管道名：pid + 进程内序号 + 纳秒时间戳。
fn unique_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!(r"\\.\pipe\kotama-{}-{sequence}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Foundation::GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::CreateFileW;
    use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;

    fn client_open(name: &str) -> OwnedHandle {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: wide 是 NUL 结尾管道名；OPEN_EXISTING + 空模板参数。
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                // SAFETY: raw 是刚返回的有效独占句柄。
                return unsafe { OwnedHandle::from_raw_handle(raw) };
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client could not open {name}: {}",
                std::io::Error::last_os_error()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn client_write(handle: &OwnedHandle, bytes: &[u8]) {
        let mut offset = 0;
        while offset < bytes.len() {
            let mut written = 0u32;
            // SAFETY: 客户端句柄是同步管道；缓冲区指针/长度匹配。
            let ok = unsafe {
                WriteFile(
                    handle.as_raw_handle(),
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "client WriteFile failed");
            assert!(written > 0, "client WriteFile wrote 0 bytes");
            offset += written as usize;
        }
    }

    fn client_read_exact(handle: &OwnedHandle, bytes: &mut [u8]) {
        let mut offset = 0;
        while offset < bytes.len() {
            let mut read = 0u32;
            // SAFETY: 同上，读缓冲指针/长度匹配。
            let ok = unsafe {
                ReadFile(
                    handle.as_raw_handle(),
                    bytes[offset..].as_mut_ptr(),
                    (bytes.len() - offset) as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "client ReadFile failed");
            assert!(read > 0, "client ReadFile read 0 bytes");
            offset += read as usize;
        }
    }

    #[test]
    fn unique_names_never_collide() {
        let first = NamedPipeServer::new().expect("first server");
        let second = NamedPipeServer::new().expect("second server");
        assert!(first.name().starts_with(r"\\.\pipe\kotama-"));
        assert!(second.name().starts_with(r"\\.\pipe\kotama-"));
        assert_ne!(first.name(), second.name());
    }

    #[test]
    fn accept_without_client_times_out() {
        let server = NamedPipeServer::new().expect("server");
        assert!(matches!(
            server.accept(Duration::from_millis(150)),
            Err(HostError::Win32(_))
        ));
    }

    #[test]
    fn client_pid_mismatch_is_rejected() {
        let server = NamedPipeServer::for_pid(999_999).expect("server");
        let name = server.name().to_string();
        let client = std::thread::spawn(move || client_open(&name));
        let result = server.accept(Duration::from_secs(5));
        assert!(result.is_err(), "a client from another pid was accepted");
        let _ = client.join();
    }

    #[test]
    fn server_and_client_roundtrip_bytes() {
        let server = NamedPipeServer::new().expect("server");
        let name = server.name().to_string();
        let client = std::thread::spawn(move || {
            let handle = client_open(&name);
            client_write(&handle, b"ping");
            let mut reply = [0u8; 4];
            client_read_exact(&handle, &mut reply);
            reply
        });
        let mut connection = server.accept(Duration::from_secs(10)).expect("accept");
        let mut request = [0u8; 4];
        connection.read_exact(&mut request).expect("server read");
        assert_eq!(&request, b"ping");
        connection.write_all(b"pong").expect("server write");
        connection.flush().expect("flush");
        assert_eq!(client.join().expect("client thread"), *b"pong");
    }
}
