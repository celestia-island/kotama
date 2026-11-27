//! 原生 Windows 进程 backend：Win32 句柄、Toolhelp 模块与 VirtualQueryEx 区域。
//!
//! 本模块只提供平台原语；`TargetProcess` 的公共 facade、`ProcessImage` 的 RVA
//! 语义和 capability 门禁都在 crate 共享层。句柄一律由 `OwnedHandle` 接管，
//! 写内存只在调用方已经构造 `control::Session::with_write` 后可达。

#![allow(unsafe_code)] // Win32 C ABI；每处调用的指针、长度与句柄来源见邻近 SAFETY 注。

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;

use kotama_proto::ModuleInfo;
use kotama_proto::ModuleKind;
use windows_sys::Win32::Foundation::ERROR_BAD_LENGTH;
use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Module32FirstW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Module32NextW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32;
use windows_sys::Win32::System::Memory::VirtualProtectEx;
use windows_sys::Win32::System::Memory::VirtualQueryEx;
use windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY;
use windows_sys::Win32::System::Memory::PAGE_GUARD;
use windows_sys::Win32::System::Memory::PAGE_NOACCESS;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::Memory::PAGE_WRITECOPY;
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;
use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
use windows_sys::Win32::System::Threading::PROCESS_CREATE_THREAD;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
use windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION;
use windows_sys::Win32::System::Threading::PROCESS_VM_READ;
use windows_sys::Win32::System::Threading::PROCESS_VM_WRITE;

use crate::scanner::Region;
use crate::scanner::MAX_REGION_SNAPSHOT;
use crate::HostError;
use crate::ProcessImage;
use crate::TargetProcess;

const READ_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
const WRITE_ACCESS: u32 = READ_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
/// 远程注入用权限位：写内存 + VirtualAllocEx + CreateRemoteThread 各一项。
const INJECT_ACCESS: u32 = WRITE_ACCESS | PROCESS_CREATE_THREAD;

impl TargetProcess {
    /// 以查询 + 只读内存权限打开一个原生 Windows 进程。
    ///
    /// # Errors
    /// PID 无效、进程不存在或当前用户无权访问。
    pub fn open(pid: i32) -> Result<Self, HostError> {
        let handle = open_handle(pid, READ_ACCESS)?;
        Ok(Self { pid, handle })
    }

    /// 读一段进程内存（绝对地址）。
    ///
    /// # Errors
    /// 地址未映射、跨越不可读页或只读到部分内容。
    pub fn read_absolute(&self, address: u64, length: usize) -> Result<Vec<u8>, HostError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; length];
        let mut read = 0usize;
        // SAFETY: self.handle 是存活的进程句柄；buffer 的指针与长度来自同一个 Vec，
        // read 是有效的 usize 输出位置。Win32 不写越调用方给出的长度。
        let ok = unsafe {
            ReadProcessMemory(
                self.handle.as_raw_handle(),
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                length,
                &mut read,
            )
        };
        if ok == 0 {
            return Err(last_error(&format!(
                "ReadProcessMemory pid {} at {address:#x}+{length}",
                self.pid
            )));
        }
        if read != length {
            return Err(HostError::Win32(format!(
                "ReadProcessMemory pid {} at {address:#x}: short read {read}/{length}",
                self.pid
            )));
        }
        Ok(buffer)
    }

    /// 用 Toolhelp 枚举原生 PE 模块；`SNAPMODULE32` 同时覆盖 WOW64 的 32 位模块。
    ///
    /// # Errors
    /// 快照创建或模块遍历失败（进程在枚举期间退出也按错误报告）。
    pub fn modules(&self) -> Result<Vec<ModuleInfo>, HostError> {
        let snapshot = module_snapshot(self.pid)?;
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: snapshot 有效；entry 是指定过 dwSize 的可写 MODULEENTRY32W。
        let mut ok = unsafe { Module32FirstW(snapshot.as_raw_handle(), &mut entry) };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                return Ok(Vec::new());
            }
            return Err(HostError::Win32(format!("Module32FirstW: {error}")));
        }

        let mut modules = Vec::new();
        loop {
            let base = entry.modBaseAddr as u64;
            if base != 0 {
                let path_len = entry
                    .szExePath
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(entry.szExePath.len());
                modules.push(ModuleInfo {
                    base,
                    size: u64::from(entry.modBaseSize),
                    kind: ModuleKind::NativePe,
                    path: String::from_utf16_lossy(&entry.szExePath[..path_len]),
                });
            }
            entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            // SAFETY: 与 Module32FirstW 相同；entry 在每次调用后重新完整填充。
            ok = unsafe { Module32NextW(snapshot.as_raw_handle(), &mut entry) };
            if ok == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    break;
                }
                return Err(HostError::Win32(format!("Module32NextW: {error}")));
            }
        }
        modules.sort_by_key(|module| (module.base, module.path.clone()));
        Ok(modules)
    }

    /// 取进程真实映像路径（QueryFullProcessImageNameW）。
    ///
    /// # Errors
    /// 进程句柄失效或路径查询失败。
    pub fn image_path(&self) -> Result<std::path::PathBuf, HostError> {
        let mut buffer = vec![0u16; 32 * 1024];
        let mut size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: handle 是存活的进程句柄；buffer 可写且长度由 size 给出。
        let ok = unsafe {
            QueryFullProcessImageNameW(
                self.handle.as_raw_handle(),
                0,
                buffer.as_mut_ptr(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err(last_error(&format!(
                "QueryFullProcessImageNameW pid {}",
                self.pid
            )));
        }
        Ok(std::path::PathBuf::from(String::from_utf16_lossy(
            &buffer[..size as usize],
        )))
    }

    /// 取进程主镜像：用真实映像路径精确匹配 Toolhelp 条目，而不是猜最低基址。
    ///
    /// # Errors
    /// 模块枚举失败，或进程没有任何模块。
    pub fn main_module(&self) -> Result<ModuleInfo, HostError> {
        let image = self.image_path()?;
        let image = image.to_string_lossy();
        let modules = self.modules()?;
        modules
            .iter()
            .find(|module| module.path.eq_ignore_ascii_case(&image))
            .or_else(|| {
                modules
                    .iter()
                    .find(|module| module.path.to_ascii_lowercase().ends_with(".exe"))
            })
            .or_else(|| modules.first())
            .cloned()
            .ok_or_else(|| HostError::Process(format!("pid {} has no modules", self.pid)))
    }

    /// 取主 EXE（或指定基址）的原生 PE 活体映像，供同一静态发现管线使用。
    ///
    /// # Errors
    /// 无 PE 模块、头解析失败、整像读取失败或映像超过缓存上限。
    pub fn pe_image(&self, base_hint: Option<u64>) -> Result<ProcessImage<'_>, HostError> {
        let modules = self.modules()?;
        let module = match base_hint {
            Some(base) => modules
                .iter()
                .find(|module| module.base == base)
                .ok_or_else(|| HostError::PeParse(format!("no native PE at {base:#x}")))?,
            None => modules
                .iter()
                .find(|module| module.path.to_ascii_lowercase().ends_with(".exe"))
                .or_else(|| modules.first())
                .ok_or_else(|| HostError::PeParse("no native PE module found".into()))?,
        };
        ProcessImage::from_pe_on_disk(self, module.base, Some(&module.path))
    }
}

/// 打开独立写句柄。Windows 句柄权限不能在打开后升级，所以 with_write 必须重开。
pub(crate) fn open_writer(pid: i32) -> Result<OwnedHandle, HostError> {
    open_handle(pid, WRITE_ACCESS)
}

/// 打开独立注入句柄（PROCESS_CREATE_THREAD + 写内存权限）。
///
/// 只有显式授权过的会话（control::Session::with_injection）才会走到这里。
pub(crate) fn open_injector(pid: i32) -> Result<OwnedHandle, HostError> {
    open_handle(pid, INJECT_ACCESS)
}

fn open_handle(pid: i32, access: u32) -> Result<OwnedHandle, HostError> {
    let pid = u32::try_from(pid).map_err(|_| HostError::Process(format!("invalid pid {pid}")))?;
    // SAFETY: OpenProcess 不借用调用方指针；FALSE 禁止句柄继承。
    let raw = unsafe { OpenProcess(access, FALSE, pid) };
    if raw.is_null() {
        return Err(last_error(&format!(
            "OpenProcess pid {pid} access {access:#x}"
        )));
    }
    // SAFETY: raw 是刚返回、非空且由调用方独占拥有的 HANDLE；此后由 OwnedHandle 关闭。
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn module_snapshot(pid: i32) -> Result<OwnedHandle, HostError> {
    let pid = u32::try_from(pid).map_err(|_| HostError::Process(format!("invalid pid {pid}")))?;
    for _ in 0..8 {
        // SAFETY: flags/pid 是值参数；返回句柄由本函数接管。
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BAD_LENGTH as i32) {
                // 模块表在枚举期间变化；MSDN 指定的有限重试。
                continue;
            }
            return Err(HostError::Win32(format!(
                "CreateToolhelp32Snapshot pid {pid}: {error}"
            )));
        }
        // SAFETY: raw 是新快照的有效独占句柄。
        return Ok(unsafe { OwnedHandle::from_raw_handle(raw) });
    }
    Err(HostError::Win32(format!(
        "CreateToolhelp32Snapshot pid {pid}: module table stayed busy"
    )))
}

/// 用 VirtualQueryEx 枚举已提交的可写区域，保持与 Linux scanner 相同的合并语义。
pub(crate) fn writable_regions(process: &TargetProcess) -> Result<Vec<Region>, HostError> {
    let mut system = SYSTEM_INFO::default();
    // SAFETY: system 是有效的可写 SYSTEM_INFO；GetSystemInfo 不保留指针。
    unsafe { GetSystemInfo(&mut system) };
    let maximum = system.lpMaximumApplicationAddress as u64;
    let mut address = 0u64;
    let mut regions = Vec::new();

    while address < maximum {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: info 是正确尺寸的可写结构；进程句柄在调用期间存活。
        let queried = unsafe {
            VirtualQueryEx(
                process.handle.as_raw_handle(),
                address as *const c_void,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            // 到达用户地址空间顶端或目标恰好退出；返回已枚举部分，与快照读竞争语义一致。
            break;
        }
        let base = info.BaseAddress as u64;
        let size = info.RegionSize as u64;
        let next = base.saturating_add(size);
        if next <= address {
            return Err(HostError::Win32(format!(
                "VirtualQueryEx made no progress at {address:#x}"
            )));
        }
        if info.State == MEM_COMMIT && size <= MAX_REGION_SNAPSHOT && is_writable(info.Protect) {
            regions.push(Region {
                start: base,
                end: next,
            });
        }
        address = next;
    }

    regions.sort_by_key(|region| region.start);
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    for region in regions {
        match merged.last_mut() {
            Some(last) if last.end == region.start => last.end = region.end,
            _ => merged.push(region),
        }
    }
    Ok(merged)
}

/// 写一段已授权进程内存；只读页临时提升后必须恢复原保护。
pub(crate) fn write_memory(
    handle: &OwnedHandle,
    address: u64,
    bytes: &[u8],
) -> Result<(), HostError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let mut info = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: 与 writable_regions 相同；address 只用于查询，不做本地解引用。
    let queried = unsafe {
        VirtualQueryEx(
            handle.as_raw_handle(),
            address as *const c_void,
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        return Err(last_error(&format!("VirtualQueryEx at {address:#x}")));
    }
    let region_start = info.BaseAddress as u64;
    let region_end = region_start.saturating_add(info.RegionSize as u64);
    let write_end = address
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| HostError::Win32(format!("write range overflows at {address:#x}")))?;
    if info.State != MEM_COMMIT
        || address < region_start
        || write_end > region_end
        || info.Protect & PAGE_GUARD != 0
        || info.Protect & 0xff == PAGE_NOACCESS
    {
        return Err(HostError::Win32(format!(
            "write at {address:#x}+{} is outside one committed writable-capable region",
            bytes.len()
        )));
    }

    if is_writable(info.Protect) {
        return write_direct(handle, address, bytes);
    }

    let new_protection = if is_executable(info.Protect) {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };
    let mut old_protection = 0u32;
    // SAFETY: 范围已验证落在单个已提交区域；old_protection 是有效输出位置。
    let changed = unsafe {
        VirtualProtectEx(
            handle.as_raw_handle(),
            address as *const c_void,
            bytes.len(),
            new_protection,
            &mut old_protection,
        )
    };
    if changed == 0 {
        return Err(last_error(&format!("VirtualProtectEx at {address:#x}")));
    }

    let write_result = write_direct(handle, address, bytes);
    let mut ignored = 0u32;
    // SAFETY: 恢复的是同一段范围与 VirtualProtectEx 返回的真实旧保护。
    let restored = unsafe {
        VirtualProtectEx(
            handle.as_raw_handle(),
            address as *const c_void,
            bytes.len(),
            old_protection,
            &mut ignored,
        )
    };
    if restored == 0 {
        let restore_error = std::io::Error::last_os_error();
        return Err(HostError::Win32(format!(
            "VirtualProtectEx restore at {address:#x}: {restore_error}; write={write_result:?}"
        )));
    }
    write_result
}

fn write_direct(handle: &OwnedHandle, address: u64, bytes: &[u8]) -> Result<(), HostError> {
    let mut written = 0usize;
    // SAFETY: handle 已由 with_write 授予写权限；bytes 的指针与长度一致，written 有效。
    let ok = unsafe {
        WriteProcessMemory(
            handle.as_raw_handle(),
            address as *const c_void,
            bytes.as_ptr().cast(),
            bytes.len(),
            &mut written,
        )
    };
    if ok == 0 {
        return Err(last_error(&format!(
            "WriteProcessMemory at {address:#x}+{}",
            bytes.len()
        )));
    }
    if written != bytes.len() {
        return Err(HostError::Win32(format!(
            "WriteProcessMemory at {address:#x}: short write {written}/{}",
            bytes.len()
        )));
    }
    Ok(())
}

fn is_writable(protection: u32) -> bool {
    protection & PAGE_GUARD == 0
        && matches!(
            protection & 0xff,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
}

fn is_executable(protection: u32) -> bool {
    matches!(
        protection & 0xff,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

pub(crate) fn last_error(context: &str) -> HostError {
    HostError::Win32(format!("{context}: {}", std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Child;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use kotama_image::LoadedModule;
    use windows_sys::Win32::System::Memory::VirtualAlloc;
    use windows_sys::Win32::System::Memory::VirtualFree;
    use windows_sys::Win32::System::Memory::VirtualProtect;
    use windows_sys::Win32::System::Memory::VirtualQuery;
    use windows_sys::Win32::System::Memory::MEM_RELEASE;
    use windows_sys::Win32::System::Memory::MEM_RESERVE;
    use windows_sys::Win32::System::Memory::PAGE_READONLY;

    use super::*;
    use crate::control;
    use crate::scanner;

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Allocation(*mut c_void);

    impl Drop for Allocation {
        fn drop(&mut self) {
            // SAFETY: 本测试 VirtualAlloc 返回的独占页；MEM_RELEASE 时 size 必须为 0。
            unsafe {
                let _ = VirtualFree(self.0, 0, MEM_RELEASE);
            }
        }
    }

    fn spin_fixture() -> PathBuf {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
        assert!(
            fixture.is_file(),
            "fixture missing: run tools/build_fixtures.py first: {}",
            fixture.display()
        );
        fixture
    }

    fn live_enabled() -> bool {
        if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the native Windows live e2e");
            return false;
        }
        true
    }

    fn wait_for_spin(pid: i32) -> (TargetProcess, ModuleInfo) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(process) = TargetProcess::open(pid) {
                if let Ok(modules) = process.modules() {
                    if let Some(main) = modules.iter().find(|module| {
                        module.kind == ModuleKind::NativePe
                            && Path::new(&module.path)
                                .file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.eq_ignore_ascii_case("spin.exe"))
                    }) {
                        return (process, main.clone());
                    }
                }
            }
            if Instant::now() >= deadline {
                panic!("spin.exe did not expose a native PE module within 15s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn main_module_selects_the_exe() {
        let process = TargetProcess::open(std::process::id() as i32).expect("open self");
        let main = process.main_module().expect("main module");
        assert!(
            main.path.to_ascii_lowercase().ends_with(".exe"),
            "main module path is not an exe: {}",
            main.path
        );
        let image = process.image_path().expect("image path");
        assert!(
            main.path.eq_ignore_ascii_case(&image.to_string_lossy()),
            "main module {} != image path {}",
            main.path,
            image.display()
        );
        assert_ne!(main.base, 0, "main module base is zero");
    }

    /// 原生只读闭环：Toolhelp 主映像 → ProcessImage → 静态/活体身份与发现一致。
    #[test]
    fn live_e2e_native_pe_identity() {
        if !live_enabled() {
            return;
        }
        let fixture = spin_fixture();
        let mut child = ChildGuard(
            std::process::Command::new(&fixture)
                .arg("20")
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn native spin.exe"),
        );
        let pid = child.0.id() as i32;
        let (target, main) = wait_for_spin(pid);
        let image = target.pe_image(Some(main.base)).expect("native PE image");
        let live_id = image.module_id();
        let static_id = LoadedModule::parse(&std::fs::read(&fixture).unwrap())
            .unwrap()
            .module_id();
        assert_eq!(
            live_id, static_id,
            "content-addressed identity must survive static→native-live"
        );

        let functions = kotama_scan::discover_with(
            kotama_scan::ScanView {
                container: kotama_image::Container::Pe64,
                arch: kotama_image::Arch::X86_64,
                image_base: 0,
                entry_rva: image.entry_rva,
                sections: &image.sections,
                symbols: image.empty_symbols(),
                dynamic_symbols: image.empty_symbols(),
                debug_functions: image.empty_symbols(),
                eh_frame_functions: image.empty_symbols(),
            },
            &image,
        );
        assert!(
            functions
                .iter()
                .any(|function| function.evidence.contains(&kotama_scan::Evidence::Pdata)),
            "native live discovery should find pdata-backed functions"
        );
        let header = target.read_absolute(main.base, 2).expect("read MZ");
        assert_eq!(&header, b"MZ");
        let _ = child.0.kill();
        let _ = child.0.wait();
    }

    /// 只读页必须经 VirtualProtectEx 临时提升，并在写入后恢复原 PAGE_READONLY。
    #[test]
    fn write_memory_restores_read_only_protection() {
        // SAFETY: 在当前测试进程分配一页；返回非空即由 Allocation 独占管理。
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        assert!(!page.is_null(), "VirtualAlloc failed");
        let allocation = Allocation(page);
        let mut old = 0u32;
        // SAFETY: page 是刚分配的一整页，old 是有效输出位置。
        let protected = unsafe { VirtualProtect(page, 4096, PAGE_READONLY, &mut old) };
        assert_ne!(protected, 0, "VirtualProtect to PAGE_READONLY failed");

        let process = TargetProcess::open(std::process::id() as i32).expect("open self");
        let session = control::Session::with_write(process).expect("write-capable self session");
        session
            .write_bytes(page as u64, &0x5a5a_a5a5u32.to_le_bytes())
            .expect("write through temporary protection");

        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: page 仍由 allocation 持有，info 是正确尺寸的可写结构。
        let queried = unsafe {
            VirtualQuery(
                page,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        assert_ne!(queried, 0);
        assert_eq!(
            info.Protect & 0xff,
            PAGE_READONLY,
            "protection not restored"
        );
        // SAFETY: page 至少含已写入的 u32；页仍存活且已验证可读。
        let value = unsafe { std::ptr::read_unaligned(page.cast::<u32>()) };
        assert_eq!(value, 0x5a5a_a5a5);
        drop(allocation);
    }

    /// 原生 CE 等价闭环：diff 定位 → capability 负对照 → freeze 钉住目标自己的输出。
    #[test]
    fn live_e2e_native_scan_freeze_pins_target_output() {
        if !live_enabled() {
            return;
        }
        let fixture = spin_fixture();
        let mut child = ChildGuard(
            std::process::Command::new(&fixture)
                .arg("30")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn native spin.exe"),
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
        let (target, main) = wait_for_spin(pid);

        {
            let read_only = TargetProcess::open(pid).expect("reopen read-only");
            let session = control::Session::read_only(read_only);
            assert!(matches!(
                session.write_bytes(main.base, &[0u8]),
                Err(HostError::CapabilityDenied(_))
            ));
            assert!(matches!(
                session.freeze(main.base, scanner::Value::U32(0x7f7f_7f7f), 20),
                Err(HostError::CapabilityDenied(_))
            ));
        }

        let before = scanner::Snapshot::capture(&target).expect("snapshot A");
        std::thread::sleep(Duration::from_millis(1600));
        let after = scanner::Snapshot::capture(&target).expect("snapshot B");
        let image_end = main.base + main.size;
        let candidates: Vec<scanner::Change> = scanner::diff(&before, &after)
            .into_iter()
            .filter(|change| change.address >= main.base && change.address < image_end)
            .filter(|change| change.new > change.old && change.new - change.old < 64)
            .collect();
        assert!(
            !candidates.is_empty(),
            "hot_counter word not found in native image range"
        );
        let counter_address = candidates[0].address;
        let current = target
            .read_absolute(counter_address, 4)
            .expect("read counter");
        let frozen = u32::from_le_bytes([current[0], current[1], current[2], current[3]]);
        let write_session = control::Session::with_write(target).expect("with_write");
        let handle = write_session
            .freeze(counter_address, scanner::Value::U32(frozen), 20)
            .expect("freeze");

        let before_freeze_count = lines.lock().expect("lines lock").len();
        std::thread::sleep(Duration::from_millis(4000));
        let all_lines = lines.lock().expect("lines lock").clone();
        drop(handle);
        let _ = child.0.kill();
        let _ = child.0.wait();
        let _ = sink.join();
        let printed: Vec<u32> = all_lines
            .iter()
            .filter_map(|line| {
                line.strip_prefix("spin: ")
                    .and_then(|value| value.parse().ok())
            })
            .collect();
        let after_freeze: Vec<u32> = printed[before_freeze_count.min(printed.len())..].to_vec();
        assert!(
            after_freeze.len() >= 3,
            "not enough post-freeze lines: {printed:?}"
        );
        assert!(
            after_freeze.iter().all(|value| *value <= frozen + 8),
            "output not pinned: after_freeze={after_freeze:?} frozen={frozen} all={printed:?}"
        );
        assert!(
            printed.len() >= 2 && printed[1] > printed[0],
            "pre-freeze growth missing: {printed:?}"
        );
    }
}
