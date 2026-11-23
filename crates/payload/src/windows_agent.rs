#![allow(unsafe_code)] // C ABI 边界；安全论据见各 SAFETY 注。

//! Windows 载荷注册与传输：`DllMain` 登记 + `CreateThread` + **TCP 回环**连接宿主。
//!
//! 为什么 TCP 而不是命名管道：载荷要在 wine 下被 Linux 宿主**原生验证**——wine 把
//! winsock 如实映射到宿主 TCP，宿主 `TcpListener::accept` 直连；命名管道在 wine 里的
//! 实现宿主侧无入口。原生 Windows 落地时如需管道形态，传输层是可替换的（协议层在
//! crate 根，传输无关）。
//!
//! DllMain 纪律（仓内 AGENTS）：`DLL_PROCESS_ATTACH` 只 `CreateThread`——不在 loader
//! lock 里碰 std 锁；WinSock 初始化在工作线程。

use std::io::Read;
use std::io::Write;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::FALSE;
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
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::CreateThread;

/// 登记点：`DllMain`。attach 只起线程；detach 不做事（宿主收线 = 静默退出）。
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

/// 工作线程入口：WinSock → 连宿主 → 进协议循环。
unsafe extern "system" fn agent_thread(_param: *mut core::ffi::c_void) -> u32 {
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

/// 极薄的 winsock TCP 客户端（实现 Read/Write 即可复用协议层）。
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
