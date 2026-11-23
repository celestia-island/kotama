#![allow(unsafe_code)] // C ABI 边界；安全论据见各 SAFETY 注。

//! Windows 载荷注册与传输：DllMain 登记 + CreateThread +
//! **命名管道（KOTAMA_PAYLOAD_PIPE，原生默认）** / **回环 TCP（KOTAMA_PAYLOAD_TCP，wine）**。
//!
//! 车道选择：环境里设了 KOTAMA_PAYLOAD_PIPE 就走管道，否则退回 KOTAMA_PAYLOAD_TCP。
//! 宿主每次只设一个：原生 Windows 用管道（见 host 的 pipe 模块），wine 用 TCP——wine
//! 把 winsock 如实映射到宿主 TCP，而命名管道在 wine 里没有宿主侧入口。协议帧在两侧
//! 完全一致（crate 根的 serve/dispatch 与 kotama-proto），传输层只提供 Read + Write。
//!
//! DllMain 纪律（仓内 AGENTS）：DLL_PROCESS_ATTACH 只 CreateThread——不在 loader
//! lock 里碰 std 锁；WinSock 初始化 / 管道连接都在工作线程。

use std::io::Read;
use std::io::Write;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::Networking::WinSock::connect;
use windows_sys::Win32::Networking::WinSock::recv;
use windows_sys::Win32::Networking::WinSock::send;
use windows_sys::Win32::Networking::WinSock::socket;
use windows_sys::Win32::Networking::WinSock::WSACleanup;
use windows_sys::Win32::Networking::WinSock::WSAStartup;
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Networking::WinSock::IN_ADDR;
use windows_sys::Win32::Networking::WinSock::IN_ADDR_0;
use windows_sys::Win32::Networking::WinSock::SOCKADDR;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
use windows_sys::Win32::Networking::WinSock::SOCKET;
use windows_sys::Win32::Networking::WinSock::SOCK_STREAM;
use windows_sys::Win32::Networking::WinSock::WSADATA;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::CreateThread;

/// 登记点：DllMain。attach 只起线程；detach 不做事（宿主收线 = 静默退出）。
#[no_mangle]
pub extern "system" fn DllMain(
    _instance: *mut core::ffi::c_void,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: 入口与参数均为 C 兼容形态；线程句柄交给进程生命周期（不关闭、
        // 不 join——进程退出即回收，无泄漏语义）。
        unsafe {
            let _ = CreateThread(
                std::ptr::null(),
                0,
                Some(agent_thread),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            );
        }
        return TRUE;
    }
    FALSE
}

/// 工作线程入口：选传输（管道优先）→ 连宿主 → 进协议循环。
unsafe extern "system" fn agent_thread(_param: *mut core::ffi::c_void) -> u32 {
    if let Ok(name) = std::env::var("KOTAMA_PAYLOAD_PIPE") {
        if let Some(mut stream) = PipeAgent::connect(&name) {
            super::serve(&mut stream);
        }
        return 0;
    }
    let Ok(port) = std::env::var("KOTAMA_PAYLOAD_TCP") else {
        return 0; // 不是 kotama 拉起的进程。
    };
    let Ok(port): Result<u16, _> = port.parse() else {
        return 0;
    };
    let mut stream = match TcpAgent::connect(port) {
        Some(stream) => stream,
        None => return 0,
    };
    super::serve(&mut stream);
    0
}

/// 命名管道客户端（同步 I/O；实现 Read + Write 即可复用协议层）。
struct PipeAgent {
    handle: HANDLE,
}

impl PipeAgent {
    /// 连 \\.\pipe\...（重试窗口给宿主 CreateNamedPipeW 留时间）。
    fn connect(name: &str) -> Option<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for _ in 0..200 {
            // SAFETY: wide 是 NUL 结尾管道名；OPEN_EXISTING + 空模板参数；句柄判非法。
            let handle = unsafe {
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
            if handle != INVALID_HANDLE_VALUE {
                return Some(Self { handle });
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        None
    }
}

impl Drop for PipeAgent {
    fn drop(&mut self) {
        // SAFETY: handle 由 PipeAgent 独占；CloseHandle 只关一次。
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl Read for PipeAgent {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut read = 0u32;
        // SAFETY: 同步管道句柄；缓冲区指针/长度匹配，read 是有效输出位置。
        let ok = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr(),
                length,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return Err(std::io::Error::other("named pipe read failed"));
        }
        Ok(read as usize)
    }
}

impl Write for PipeAgent {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut written = 0u32;
        // SAFETY: 同上；buffer 指针只读、长度匹配。
        let ok = unsafe {
            WriteFile(
                self.handle,
                buffer.as_ptr(),
                length,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return Err(std::io::Error::other("named pipe write failed"));
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // 字节流管道无用户态缓冲。
    }
}

/// 极薄的 winsock TCP 客户端（wine 车道；实现 Read/Write 即可复用协议层）。
struct TcpAgent {
    descriptor: SOCKET,
}

impl TcpAgent {
    /// 连 127.0.0.1:port（重试窗口给宿主监听留时间）。
    fn connect(port: u16) -> Option<Self> {
        // SAFETY: WSAStartup 缓冲按 WSADATA 尺寸零初始化；socket/connect 参数为
        // 值形态或指向栈上 sockaddr_in；失败路径成对 WSACleanup。
        unsafe {
            let mut data: WSADATA = std::mem::zeroed();
            if WSAStartup(0x0202, &mut data) != 0 {
                return None;
            }
            let descriptor = socket(AF_INET as i32, SOCK_STREAM, 0);
            if descriptor == SOCKET::MAX {
                WSACleanup();
                return None;
            }
            let address = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: port.to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: 0x0100_007f, // 127.0.0.1（网络序）
                    },
                },
                sin_zero: [0; 8],
            };
            for _ in 0..200 {
                if connect(
                    descriptor,
                    &address as *const SOCKADDR_IN as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                ) == 0
                {
                    return Some(Self { descriptor });
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            WSACleanup();
            None
        }
    }
}

impl Read for TcpAgent {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: recv 的指针/长度来自切片；返回值按 winsock 语义翻译。
        let received = unsafe {
            recv(
                self.descriptor,
                buf.as_mut_ptr().cast(),
                buf.len() as i32,
                0,
            )
        };
        if received <= 0 {
            return Err(std::io::Error::other("winsock recv closed"));
        }
        Ok(received as usize)
    }
}

impl Write for TcpAgent {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: send 的指针/长度来自切片。
        let sent = unsafe { send(self.descriptor, buf.as_ptr().cast(), buf.len() as i32, 0) };
        if sent <= 0 {
            return Err(std::io::Error::other("winsock send failed"));
        }
        Ok(sent as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // TCP 流无用户态缓冲。
    }
}
