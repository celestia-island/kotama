//! 原生 Windows x64→x64 远程注入：显式 capability 门禁 → 参数校验 → LoadLibraryW 远程线程。
//!
//! 授权 API 在 control::Session::with_injection；未授权会话调用
//! control::Session::inject 时，在任何 Win32 注入原语（VirtualAllocEx /
//! CreateRemoteThread）之前就返回 HostError::CapabilityDenied——负对照钉的就是它。
//!
//! 注入流程（教科书 LoadLibrary 注入；不做 manual map / 免杀 / 反检测 / 持久化）：
//! 1. 校验 DLL：绝对路径、文件存在、PE 机器位与目标一致且为 AMD64；
//! 2. 本机 GetProcAddress 取 LoadLibraryW，按所在宿主模块的文件名 + 导出 RVA 映射到
//!    目标进程（kernel32 的转发导出可能落在 kernelbase，故按「含该地址的模块」算 RVA）；
//! 3. VirtualAllocEx + WriteProcessMemory 写入 UTF-16 DLL 路径；
//! 4. CreateRemoteThread 调 LoadLibraryW，WaitForSingleObject 带超时；
//! 5. 线程退出后才 VirtualFreeEx；未退出时**绝不**释放（宁可有界泄漏，也不留
//!    use-after-free 给仍在跑的远程线程）。
//!
//! 句柄全部 RAII：进程句柄由 TargetProcess 持有、注入句柄由 Session 持有、远程线程
//! 句柄由局部 OwnedHandle 持有。DllMain 纪律不在本模块：载荷侧 DllMain 仍只
//! CreateThread。

#![allow(unsafe_code)] // Win32 C ABI；逐处 SAFETY 注。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::Memory::VirtualAllocEx;
use windows_sys::Win32::System::Memory::VirtualFreeEx;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::MEM_RELEASE;
use windows_sys::Win32::System::Memory::MEM_RESERVE;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::Threading::CreateRemoteThread;
use windows_sys::Win32::System::Threading::GetExitCodeThread;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::Threading::LPTHREAD_START_ROUTINE;

use crate::HostError;
use crate::TargetProcess;

/// 64 位 PE 的 IMAGE_FILE_MACHINE_AMD64。
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// 一次成功注入的报告。
#[derive(Clone, Debug)]
pub struct InjectionReport {
    /// 目标 PID。
    pub pid: i32,
    /// 被注入 DLL 的绝对路径。
    pub dll: PathBuf,
    /// 目标进程内远程 LoadLibraryW 入口的绝对地址。
    pub remote_load_library: u64,
    /// 远程线程 ID。
    pub thread_id: u32,
    /// 远程 UTF-16 路径缓冲的地址（线程退出后已释放；超时路径会保留）。
    pub remote_path: u64,
    /// 远程线程退出码（LoadLibraryW 返回值被 Win32 截成 32 位；仅诊断用）。
    pub thread_exit_code: u32,
    /// 载荷模块在目标内的基址（Toolhelp 复核，真相来源）。
    pub module_base: u64,
}

#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static TEST_ALLOCATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static TEST_THREADS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 远程线程尚未退出时保留的路径缓冲守卫。
///
/// armed = false 表示「故意不释放」：远程线程可能还在读这段路径，此刻
/// VirtualFreeEx 就是 use-after-free。超时路径走这个分支，进程退出时由内核回收。
struct RemoteAllocation<'a> {
    handle: &'a OwnedHandle,
    address: *mut c_void,
    armed: bool,
}

impl Drop for RemoteAllocation<'_> {
    fn drop(&mut self) {
        if !self.armed || self.address.is_null() {
            return;
        }
        // SAFETY: address 是本模块 VirtualAllocEx 成功返回的基址，释放时 size 必须为 0；
        // handle 在本次调用期间存活（借用）。
        unsafe {
            let _ = VirtualFreeEx(self.handle.as_raw_handle(), self.address, 0, MEM_RELEASE);
        }
    }
}

/// 注入一个 DLL（只在显式授权会话内可达）。
///
/// # Errors
/// 参数校验失败（相对路径 / 文件缺失 / 非 PE / 机器位不匹配）、Win32 调用失败、
/// 远程线程超时未退出或线程已退出但模块未出现在目标模块表里。
pub(crate) fn inject_dll(
    process: &TargetProcess,
    writer: &OwnedHandle,
    dll: &Path,
    timeout: Duration,
) -> Result<InjectionReport, HostError> {
    let (dll_machine, wide_path) = validate_dll(dll)?;
    let target_machine = module_machine(process)?;
    if target_machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(HostError::Inject(format!(
            "target pid {} main module machine {target_machine:#x} is not x64 ({IMAGE_FILE_MACHINE_AMD64:#x}); only x64-to-x64 injection is supported",
            process.pid()
        )));
    }
    if dll_machine != target_machine {
        return Err(HostError::Inject(format!(
            "payload DLL {} machine {dll_machine:#x} does not match target machine {target_machine:#x}",
            dll.display()
        )));
    }

    let remote_load_library = remote_load_library(process)?;
    let path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    #[cfg(test)]
    TEST_ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: null 让内核选址；长度 = UTF-16 路径字节数；保护 = 读写（远程线程只读路径）。
    let remote_path = unsafe {
        VirtualAllocEx(
            writer.as_raw_handle(),
            std::ptr::null(),
            path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_path.is_null() {
        return Err(crate::windows::last_error(&format!(
            "VirtualAllocEx pid {} {path_bytes} bytes",
            process.pid()
        )));
    }
    // 从这里起，任何提前返回都由 Drop 释放（除非超时主动解除武装）。
    let mut allocation = RemoteAllocation {
        handle: writer,
        address: remote_path,
        armed: true,
    };

    let mut written = 0usize;
    // SAFETY: 目标缓冲是刚分配的 path_bytes 可写页；源缓冲是 wide_path 的完整切片；
    // written 是有效输出位置。
    let write_ok = unsafe {
        WriteProcessMemory(
            writer.as_raw_handle(),
            remote_path,
            wide_path.as_ptr().cast(),
            path_bytes,
            &mut written,
        )
    };
    if write_ok == 0 || written != path_bytes {
        return Err(HostError::Win32(format!(
            "WriteProcessMemory pid {} at {remote_path:?}: wrote {written}/{path_bytes}",
            process.pid()
        )));
    }

    #[cfg(test)]
    TEST_THREADS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: 地址来自本机真实 LoadLibraryW 导出 + 目标同模块 RVA；调用约定与
    // LPTHREAD_START_ROUTINE 一致（system ABI，单指针参数，返回值低 32 位即线程退出码）。
    // 我们不在本进程执行该指针，只把它交给 CreateRemoteThread。
    let start: LPTHREAD_START_ROUTINE = unsafe {
        std::mem::transmute::<usize, LPTHREAD_START_ROUTINE>(remote_load_library as usize)
    };
    let mut thread_id = 0u32;
    // SAFETY: 参数均为值或本进程栈上的可写位置；start 只在目标进程解析。
    let raw_thread = unsafe {
        CreateRemoteThread(
            writer.as_raw_handle(),
            std::ptr::null(),
            0,
            start,
            remote_path as *const c_void,
            0,
            &mut thread_id,
        )
    };
    if raw_thread.is_null() {
        return Err(crate::windows::last_error(&format!(
            "CreateRemoteThread pid {} at {remote_load_library:#x}",
            process.pid()
        )));
    }
    // SAFETY: 刚返回的线程句柄由本作用域独占；OwnedHandle 在函数返回或错误时关闭。
    let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread) };

    let wait_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: thread 是存活的线程句柄；wait_ms 已夹取到 u32。
    let waited = unsafe { WaitForSingleObject(thread.as_raw_handle(), wait_ms) };
    if waited != WAIT_OBJECT_0 {
        // 远程线程可能仍在 LoadLibraryW 里读路径 —— 释放就是 use-after-free。
        allocation.armed = false;
        return Err(HostError::Inject(format!(
            "remote thread {thread_id} in pid {} did not exit within {timeout:?} (wait status {waited}); remote path buffer at {remote_path:?} intentionally left allocated",
            process.pid()
        )));
    }

    let mut thread_exit_code = 0u32;
    // SAFETY: 线程已退出；exit code 是有效输出位置。
    let exit_ok = unsafe { GetExitCodeThread(thread.as_raw_handle(), &mut thread_exit_code) };
    if exit_ok == 0 {
        return Err(crate::windows::last_error(&format!(
            "GetExitCodeThread pid {} thread {thread_id}",
            process.pid()
        )));
    }
    // 退出码只是 LowPart(HMODULE) 的诊断值：x64 模块基址的低 32 位完全可能是 0。
    // 模块表（Toolhelp）才是成功真相；只有模块确实找不到时，退出码 0 才用来给出
    // “LoadLibraryW 返回 NULL”这一更精确的错误。
    let module_result = wait_for_module(process, dll, Duration::from_secs(5));
    let module_base = match module_result {
        Ok(base) => base,
        Err(error) if thread_exit_code == 0 => {
            return Err(HostError::Inject(format!(
                "LoadLibraryW({}) returned NULL in pid {} (thread {thread_id}): {error}",
                dll.display(),
                process.pid()
            )));
        }
        Err(error) => return Err(error),
    };
    Ok(InjectionReport {
        pid: process.pid(),
        dll: dll.to_path_buf(),
        remote_load_library,
        thread_id,
        remote_path: remote_path as u64,
        thread_exit_code,
        module_base,
    })
}

/// 校验 DLL 路径与 PE 机器位，返回（机器位, NUL 结尾的 UTF-16 路径）。
fn validate_dll(dll: &Path) -> Result<(u16, Vec<u16>), HostError> {
    if !dll.is_absolute() {
        return Err(HostError::Inject(format!(
            "payload DLL path must be absolute: {}",
            dll.display()
        )));
    }
    if !dll.is_file() {
        return Err(HostError::Inject(format!(
            "payload DLL not found: {}",
            dll.display()
        )));
    }
    let bytes = std::fs::read(dll).map_err(|error| {
        HostError::Inject(format!("read payload DLL {}: {error}", dll.display()))
    })?;
    let machine = read_pe_machine(&bytes).ok_or_else(|| {
        HostError::Inject(format!("payload DLL is not a PE file: {}", dll.display()))
    })?;
    let mut wide: Vec<u16> = dll.as_os_str().encode_wide().collect();
    wide.push(0);
    Ok((machine, wide))
}

/// 从 PE 头读 COFF Machine（0x8664 = x64）。
fn read_pe_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 0x40 || bytes.first() != Some(&b'M') || bytes.get(1) != Some(&b'Z') {
        return None;
    }
    let lfanew = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if bytes.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes(bytes.get(lfanew + 4..lfanew + 6)?.try_into().ok()?);
    Some(machine)
}

/// 目标主映像的 PE 机器位（读活体进程内存里的 PE 头）。
fn module_machine(process: &TargetProcess) -> Result<u16, HostError> {
    let modules = process.modules()?;
    let main = modules
        .iter()
        .find(|module| module.path.to_ascii_lowercase().ends_with(".exe"))
        .or_else(|| modules.first())
        .ok_or_else(|| {
            HostError::Inject(format!("target pid {} exposes no PE module", process.pid()))
        })?;
    let header = process.read_absolute(main.base, 0x400)?;
    read_pe_machine(&header).ok_or_else(|| {
        HostError::PeParse(format!(
            "no PE header at target-main {:#x} (pid {})",
            main.base,
            process.pid()
        ))
    })
}

/// 计算目标进程内 LoadLibraryW 的绝对地址（本机导出 RVA + 目标同模块基址）。
fn remote_load_library(process: &TargetProcess) -> Result<u64, HostError> {
    let mut kernel32_name: Vec<u16> = "kernel32.dll".encode_utf16().collect();
    kernel32_name.push(0);
    // SAFETY: 名称 NUL 结尾；返回值判空。
    let host_kernel32 = unsafe { GetModuleHandleW(kernel32_name.as_ptr()) };
    if host_kernel32.is_null() {
        return Err(HostError::Win32(
            "GetModuleHandleW(kernel32.dll) returned NULL".into(),
        ));
    }
    // SAFETY: 句柄来自上一行；c"LoadLibraryW" 是 NUL 结尾 ASCII 名。
    let load_library = unsafe { GetProcAddress(host_kernel32, c"LoadLibraryW".as_ptr().cast()) };
    let Some(load_library) = load_library else {
        return Err(HostError::Win32(
            "GetProcAddress(kernel32!LoadLibraryW) returned NULL".into(),
        ));
    };
    let host_va = load_library as usize as u64;

    // forwarder 导出可能落在 kernelbase：按「包含该地址的宿主模块」算 RVA 才正确。
    let host = TargetProcess::open(std::process::id() as i32)?;
    let host_modules = host.modules()?;
    let host_module = host_modules
        .iter()
        .find(|module| host_va >= module.base && host_va < module.base.saturating_add(module.size))
        .ok_or_else(|| {
            HostError::Inject(format!(
                "LoadLibraryW at {host_va:#x} is outside every host module"
            ))
        })?;
    let rva = host_va - host_module.base;

    let target_modules = process.modules()?;
    let target_module = target_modules
        .iter()
        .find(|module| same_module_name(&module.path, &host_module.path))
        .ok_or_else(|| {
            HostError::Inject(format!(
                "target pid {} lacks module {} needed to resolve LoadLibraryW RVA {rva:#x}",
                process.pid(),
                host_module.path
            ))
        })?;
    Ok(target_module.base + rva)
}

/// 两个模块路径是否是同一 DLL（按文件名比较，路径前缀/大小写不敏感）。
fn same_module_name(left: &str, right: &str) -> bool {
    fn file_name(path: &str) -> Option<String> {
        Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.to_ascii_lowercase())
    }
    file_name(left) == file_name(right) && file_name(left).is_some()
}

/// 等模块出现在目标模块表里（Toolhelp 快照的极短滞后用重试吸收）。
fn wait_for_module(
    process: &TargetProcess,
    dll: &Path,
    timeout: Duration,
) -> Result<u64, HostError> {
    let name = dll
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| HostError::Inject(format!("DLL has no file name: {}", dll.display())))?;
    let deadline = Instant::now() + timeout;
    loop {
        let modules = process.modules()?;
        if let Some(module) = modules
            .iter()
            .find(|module| same_module_name(&module.path, name))
        {
            return Ok(module.base);
        }
        if Instant::now() >= deadline {
            return Err(HostError::Inject(format!(
                "remote LoadLibraryW completed but {name} is not in pid {} module table after {timeout:?}",
                process.pid()
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Session;
    use windows_sys::Win32::System::Memory::VirtualAllocEx;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn reset_primitives() {
        TEST_ALLOCATIONS.store(0, std::sync::atomic::Ordering::Relaxed);
        TEST_THREADS.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn primitives() -> (u64, u64) {
        (
            TEST_ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
            TEST_THREADS.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    fn synthetic_pe(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let lfanew = 0x80u32;
        bytes[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn read_pe_machine_parses_x64_and_x86_headers() {
        assert_eq!(read_pe_machine(&synthetic_pe(0x8664)), Some(0x8664));
        assert_eq!(read_pe_machine(&synthetic_pe(0x014c)), Some(0x014c));
        assert_eq!(read_pe_machine(b"not a PE"), None);
        assert_eq!(read_pe_machine(&[0u8; 0x100]), None);
    }

    #[test]
    fn unauthorized_sessions_are_denied_before_injection_primitives() {
        let _guard = lock();
        reset_primitives();
        let fake = std::env::temp_dir().join("kotama-never-injected.dll");

        let read_only =
            Session::read_only(TargetProcess::open(std::process::id() as i32).expect("open self"));
        assert!(!read_only.injection_allowed());
        assert!(matches!(
            read_only.inject(&fake, Duration::from_secs(1)),
            Err(HostError::CapabilityDenied(_))
        ));

        let write_only = Session::with_write(
            TargetProcess::open(std::process::id() as i32).expect("reopen self"),
        )
        .expect("with_write self");
        assert!(!write_only.injection_allowed());
        assert!(matches!(
            write_only.inject(&fake, Duration::from_secs(1)),
            Err(HostError::CapabilityDenied(_))
        ));

        assert_eq!(
            primitives(),
            (0, 0),
            "denied injection must not reach VirtualAllocEx/CreateRemoteThread"
        );
    }

    #[test]
    fn authorized_injection_validates_arguments_before_allocating() {
        let _guard = lock();
        reset_primitives();
        let session = Session::with_injection(
            TargetProcess::open(std::process::id() as i32).expect("open self"),
        )
        .expect("with_injection");
        assert!(session.injection_allowed());

        // 相对路径。
        assert!(matches!(
            session.inject(Path::new("kotama_agent.dll"), Duration::from_secs(1)),
            Err(HostError::Inject(_))
        ));
        // 绝对路径但文件不存在。
        let missing = std::env::temp_dir().join("kotama-agent-does-not-exist.dll");
        assert!(matches!(
            session.inject(&missing, Duration::from_secs(1)),
            Err(HostError::Inject(_))
        ));
        // 存在、绝对、但不是 x64（模拟 i686 DLL）。
        let fake = std::env::temp_dir().join(format!("kotama-fake-x86-{}.dll", std::process::id()));
        std::fs::write(&fake, synthetic_pe(0x014c)).expect("write fake dll");
        let result = session.inject(&fake, Duration::from_secs(1));
        let _ = std::fs::remove_file(&fake);
        assert!(
            matches!(result, Err(HostError::Inject(ref message)) if message.contains("machine")),
            "unexpected result: {result:?}"
        );

        assert_eq!(
            primitives(),
            (0, 0),
            "arguments must be validated before VirtualAllocEx/CreateRemoteThread"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn target_machine_reports_amd64_for_host() {
        let process = TargetProcess::open(std::process::id() as i32).expect("open self");
        assert_eq!(
            module_machine(&process).expect("machine"),
            IMAGE_FILE_MACHINE_AMD64
        );
    }

    #[test]
    fn remote_allocation_guard_frees_only_when_armed() {
        let _guard = lock();
        let pid = std::process::id() as i32;
        let writer = crate::windows::open_injector(pid).expect("open injector self");
        let process = TargetProcess::open(pid).expect("open self");

        // SAFETY: 在自身进程分配一页；返回非空即由下面的守卫释放。
        let armed = unsafe {
            VirtualAllocEx(
                writer.as_raw_handle(),
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!armed.is_null(), "VirtualAllocEx failed");
        {
            let _allocation = RemoteAllocation {
                handle: &writer,
                address: armed,
                armed: true,
            };
        }
        assert!(
            process.read_absolute(armed as u64, 1).is_err(),
            "armed guard must release the remote buffer"
        );

        // SAFETY: 同上；这次模拟超时路径：解除武装后不释放。
        let leaked = unsafe {
            VirtualAllocEx(
                writer.as_raw_handle(),
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!leaked.is_null(), "VirtualAllocEx failed");
        {
            let mut allocation = RemoteAllocation {
                handle: &writer,
                address: leaked,
                armed: true,
            };
            allocation.armed = false;
        }
        assert!(
            process.read_absolute(leaked as u64, 1).is_ok(),
            "disarmed guard must not free a buffer the remote thread may still read"
        );
        {
            let _cleanup = RemoteAllocation {
                handle: &writer,
                address: leaked,
                armed: true,
            };
        }
    }
}
