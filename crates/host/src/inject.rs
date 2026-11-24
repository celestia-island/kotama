//! 原生 Windows 远程注入（x64→x64 与 x64→x86/WOW64）：显式 capability 门禁 → 参数校验 →
//! LoadLibraryW 远程线程。
//!
//! 授权 API 在 control::Session::with_injection；未授权会话调用
//! control::Session::inject 时，在任何 Win32 注入原语（VirtualAllocEx /
//! CreateRemoteThread）之前就返回 HostError::CapabilityDenied——负对照钉的就是它。
//!
//! 注入流程（教科书 LoadLibrary 注入；不做 manual map / 免杀 / 反检测 / 持久化）：
//! 1. 校验 DLL：绝对路径、文件存在、PE 机器位与目标一致（AMD64 或 I386）；
//! 2. 同位宽：本机 GetProcAddress 取 LoadLibraryW，按所在宿主模块的文件名 + 导出 RVA 映射到
//!    目标进程（kernel32 的转发导出可能落在 kernelbase，故按「含该地址的模块」算 RVA）；
//!    跨位宽（x64 宿主 → WOW64 目标）：目标里的 kernel32 是另一份二进制，改读目标进程
//!    内存里的 PE 导出表（只读）解析 LoadLibraryW，转发导出递归到被转发模块；
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
/// 32 位 PE 的 IMAGE_FILE_MACHINE_I386。
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
/// 宿主自身的 COFF 机器位：同位宽时可按本机导出 RVA 映射到目标，跨位宽则不行。
const HOST_MACHINE: u16 = if cfg!(target_arch = "x86_64") {
    IMAGE_FILE_MACHINE_AMD64
} else if cfg!(target_arch = "x86") {
    IMAGE_FILE_MACHINE_I386
} else {
    0
};

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
    if !matches!(
        target_machine,
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_I386
    ) {
        return Err(HostError::Inject(format!(
            "target pid {} main module machine {target_machine:#x} is neither x64 ({IMAGE_FILE_MACHINE_AMD64:#x}) nor x86 ({IMAGE_FILE_MACHINE_I386:#x}); only x86 and x64 targets are supported",
            process.pid()
        )));
    }
    if dll_machine != target_machine {
        return Err(HostError::Inject(format!(
            "payload DLL {} machine {dll_machine:#x} does not match target machine {target_machine:#x}",
            dll.display()
        )));
    }

    let remote_load_library = remote_load_library(process, target_machine)?;
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

/// 计算目标进程内 LoadLibraryW 的绝对地址。
///
/// 同位宽：本机导出 RVA + 目标同模块基址。跨位宽（x64 宿主 → WOW64 目标）：目标里的
/// kernel32 是另一份二进制，导出 RVA 与本机不同，改为读目标进程内存里的导出表。
fn remote_load_library(process: &TargetProcess, target_machine: u16) -> Result<u64, HostError> {
    if target_machine != HOST_MACHINE {
        return remote_export(process, "kernel32.dll", "LoadLibraryW", 0);
    }
    remote_load_library_same_bitness(process)
}

/// 按目标进程内存里的 PE 导出表解析 `dll!proc` 的绝对地址；只读，不调用本机 API。
///
/// 转发导出（`KERNELBASE.LoadLibraryW`）递归到被转发的模块，最多 4 层。
fn remote_export(
    process: &TargetProcess,
    dll: &str,
    proc_name: &str,
    depth: usize,
) -> Result<u64, HostError> {
    const MAX_FORWARDERS: usize = 4;
    if depth > MAX_FORWARDERS {
        return Err(HostError::Inject(format!(
            "export forwarder chain for {dll}!{proc_name} exceeds {MAX_FORWARDERS} hops in pid {}",
            process.pid()
        )));
    }
    let module = process
        .modules()?
        .into_iter()
        .find(|module| same_module_name(&module.path, dll))
        .ok_or_else(|| {
            HostError::Inject(format!(
                "target pid {} lacks module {dll} needed to resolve {proc_name}",
                process.pid()
            ))
        })?;
    let base = module.base;
    let dos = process.read_absolute(base, 0x40)?;
    let Some(lfanew) = read_u32(&dos, 0x3C) else {
        return Err(HostError::PeParse(format!(
            "module {dll} at {base:#x} in pid {} has no e_lfanew",
            process.pid()
        )));
    };
    // 签名 + 文件头 + 可选头（PE32+ 可选头最长 0xF0）。
    let headers = process.read_absolute(base + u64::from(lfanew), 24 + 0xF0)?;
    let Some((dir_rva, dir_size)) = pe_export_directory(&headers) else {
        return Err(HostError::PeParse(format!(
            "module {dll} at {base:#x} in pid {} has no export directory",
            process.pid()
        )));
    };
    if dir_rva == 0 || dir_size == 0 {
        return Err(HostError::PeParse(format!(
            "module {dll} at {base:#x} in pid {} exports nothing",
            process.pid()
        )));
    }
    let size = usize::try_from(dir_size).map_err(|_| {
        HostError::PeParse(format!(
            "export directory size {dir_size:#x} overflows usize"
        ))
    })?;
    let export = process.read_absolute(base + u64::from(dir_rva), size)?;
    match find_export(&export, dir_rva, dir_size, proc_name) {
        Ok(ExportEntry::Function(rva)) => Ok(base + u64::from(rva)),
        Ok(ExportEntry::Forwarder(target)) => {
            let (forwarded_dll, forwarded_proc) = target.split_once('.').ok_or_else(|| {
                HostError::PeParse(format!("malformed export forwarder {target:?}"))
            })?;
            remote_export(
                process,
                &format!("{forwarded_dll}.dll"),
                forwarded_proc,
                depth + 1,
            )
        }
        Err(error) => Err(error),
    }
}

/// 导出目录里的一个条目：函数 RVA，或转发字符串（`DLL.Func`）。
#[derive(Debug, PartialEq, Eq)]
enum ExportEntry {
    Function(u32),
    Forwarder(String),
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// NT 头（`PE\0\0` + 文件头 + 可选头）里的导出目录 (RVA, size)。
fn pe_export_directory(headers: &[u8]) -> Option<(u32, u32)> {
    if headers.get(..4)? != b"PE\0\0" {
        return None;
    }
    let optional_size = usize::from(read_u16(headers, 20)?);
    let data_directory = 24
        + match read_u16(headers, 24)? {
            0x10B => 96,
            0x20B => 112,
            _ => return None,
        };
    if optional_size < data_directory - 24 + 8 {
        return None;
    }
    Some((
        read_u32(headers, data_directory)?,
        read_u32(headers, data_directory + 4)?,
    ))
}

/// 在导出目录镜像里按名字找条目。`export` 是模块里 [dir_rva, dir_rva + dir_size) 的内容，
/// 名称表 / 序号表 / 函数表 / 名称字符串按 PE 规范都落在这段里。
fn find_export(
    export: &[u8],
    dir_rva: u32,
    dir_size: u32,
    proc_name: &str,
) -> Result<ExportEntry, HostError> {
    let malformed = || HostError::PeParse("malformed export directory".into());
    // RVA → 镜像内偏移；越界即视为损坏。
    let at = |rva: u32| {
        usize::try_from(rva.checked_sub(dir_rva)?)
            .ok()
            .filter(|offset| *offset <= export.len())
    };
    let functions = at(read_u32(export, 0x1C).ok_or_else(malformed)?).ok_or_else(malformed)?;
    let names = at(read_u32(export, 0x20).ok_or_else(malformed)?).ok_or_else(malformed)?;
    let ordinals = at(read_u32(export, 0x24).ok_or_else(malformed)?).ok_or_else(malformed)?;
    let count = read_u32(export, 0x18).ok_or_else(malformed)? as usize;
    for index in 0..count {
        let name_offset =
            at(read_u32(export, names + index * 4).ok_or_else(malformed)?).ok_or_else(malformed)?;
        let ordinal = usize::from(read_u16(export, ordinals + index * 2).ok_or_else(malformed)?);
        let function_rva = read_u32(export, functions + ordinal * 4).ok_or_else(malformed)?;
        if c_str_at(export, name_offset) != Some(proc_name) {
            continue;
        }
        if dir_rva <= function_rva && function_rva < dir_rva.saturating_add(dir_size) {
            let forwarder = at(function_rva)
                .and_then(|offset| c_str_at(export, offset))
                .ok_or_else(malformed)?;
            return Ok(ExportEntry::Forwarder(forwarder.to_owned()));
        }
        return Ok(ExportEntry::Function(function_rva));
    }
    Err(HostError::Inject(format!(
        "export {proc_name} not found among {count} named entries"
    )))
}

/// 镜像 `offset` 处的 NUL 结尾 ASCII 字符串。
fn c_str_at(bytes: &[u8], offset: usize) -> Option<&str> {
    let rest = bytes.get(offset..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// 同位宽：本机导出 RVA + 目标同模块基址。
fn remote_load_library_same_bitness(process: &TargetProcess) -> Result<u64, HostError> {
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

    fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_nt(magic: u16, optional: usize, export: Option<(u32, u32)>) -> Vec<u8> {
        let mut headers = vec![0u8; 24 + optional.max(96) + 16 * 8];
        headers[0..4].copy_from_slice(b"PE\0\0");
        write_u16(&mut headers, 20, optional as u16);
        write_u16(&mut headers, 24, magic);
        if let Some((rva, size)) = export {
            let directory = 24 + if magic == 0x10b { 96 } else { 112 };
            write_u32(&mut headers, directory, rva);
            write_u32(&mut headers, directory + 4, size);
        }
        headers
    }

    #[test]
    fn export_directory_is_located_in_pe32_and_pe32_plus_headers() {
        for (machine, magic, optional) in [(0x014cu16, 0x10bu16, 96usize), (0x8664, 0x20b, 112)] {
            let mut headers = synthetic_nt(magic, optional + 16 * 8, Some((0x1000, 0x80)));
            write_u16(&mut headers, 4, machine);
            assert_eq!(pe_export_directory(&headers), Some((0x1000, 0x80)));
            assert_eq!(pe_export_directory(&headers[..24 + optional + 4]), None);
        }
        assert_eq!(pe_export_directory(b"not a PE"), None);
        assert_eq!(
            pe_export_directory(&synthetic_nt(0x10b, 96 - 8, Some((1, 2)))),
            None,
            "optional header too small for the data directory"
        );
    }

    #[test]
    fn find_export_resolves_functions_forwarders_and_rejects_damage() {
        let dir_rva = 0x1000u32;
        let mut image = vec![0u8; 0x80];
        write_u32(&mut image, 0x18, 2); // NumberOfNames
        write_u32(&mut image, 0x1C, dir_rva + 0x28); // AddressOfFunctions
        write_u32(&mut image, 0x20, dir_rva + 0x30); // AddressOfNames
        write_u32(&mut image, 0x24, dir_rva + 0x38); // AddressOfNameOrdinals
        write_u32(&mut image, 0x28, 0x2000); // functions[0]
        write_u32(&mut image, 0x2C, dir_rva + 0x50); // functions[1] → forwarder string
        write_u32(&mut image, 0x30, dir_rva + 0x60); // names[0] → "Alpha"
        write_u32(&mut image, 0x34, dir_rva + 0x66); // names[1] → "Beta"
        write_u16(&mut image, 0x38, 0); // ordinals[0]
        write_u16(&mut image, 0x3A, 1); // ordinals[1]
        image[0x50..0x60].copy_from_slice(b"KERNELBASE.Beta\0");
        image[0x60..0x6B].copy_from_slice(b"Alpha\0Beta\0");
        assert!(
            matches!(
                find_export(&image, dir_rva, 0x80, "Alpha"),
                Ok(ExportEntry::Function(0x2000))
            ),
            "plain export must resolve to its RVA"
        );
        assert!(
            matches!(
                find_export(&image, dir_rva, 0x80, "Beta"),
                Ok(ExportEntry::Forwarder(ref name)) if name == "KERNELBASE.Beta"
            ),
            "forwarder export must resolve to its DLL.Proc string"
        );
        assert!(find_export(&image, dir_rva, 0x80, "Gamma").is_err());
        assert!(
            find_export(&image[..0x40], dir_rva, 0x80, "Alpha").is_err(),
            "truncated image must error instead of panicking"
        );
        let mut dangling = image.clone();
        write_u32(&mut dangling, 0x30, 0x7FFF_FFF0); // name RVA outside the image
        assert!(find_export(&dangling, dir_rva, 0x80, "Alpha").is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn export_table_resolution_matches_get_proc_address_on_host() {
        let process = TargetProcess::open(std::process::id() as i32).expect("open self");
        let resolved = remote_export(&process, "kernel32.dll", "LoadLibraryW", 0)
            .expect("resolve kernel32!LoadLibraryW through the export table");
        let mut kernel32_name: Vec<u16> = "kernel32.dll".encode_utf16().collect();
        kernel32_name.push(0);
        // SAFETY: NUL-terminated name; handle checked for null.
        let handle = unsafe { GetModuleHandleW(kernel32_name.as_ptr()) };
        assert!(!handle.is_null());
        // SAFETY: handle from GetModuleHandleW; c"LoadLibraryW" is NUL-terminated ASCII.
        let expected = unsafe { GetProcAddress(handle, c"LoadLibraryW".as_ptr().cast()) }
            .map(|function| function as usize as u64)
            .expect("GetProcAddress(kernel32!LoadLibraryW)");
        assert_eq!(resolved, expected);
        assert!(
            remote_export(&process, "kernel32.dll", "KotamaNoSuchExport", 0).is_err(),
            "unknown export must be an error"
        );
        assert!(
            remote_export(&process, "kotama-no-such-module.dll", "LoadLibraryW", 0).is_err(),
            "unknown module must be an error"
        );
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
        // 存在、绝对、但机器位与 x64 宿主不符（模拟 i686 DLL 注入 x64 进程）。
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
