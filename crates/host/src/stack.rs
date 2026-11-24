//! 原生 Windows 外部栈回溯：Toolhelp 线程枚举 + SuspendThread/GetThreadContext +
//! StackWalk64（dbghelp）+ SymFromAddrW 符号化。
//!
//! 流程（逐线程；顺序固定）：
//! 1. `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` 枚举全部线程，按 `th32OwnerProcessID`
//!    过滤出目标 pid，**按 tid 升序**去重；
//! 2. `OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)`；
//! 3. `SuspendThread` → `GetThreadContext`（拿 RIP/RSP/RBP）→ 判 RIP 是否落在主 PE 映像内；
//! 4. `StackWalk64` 逐帧展开：读内存回调走 `ReadProcessMemory`，函数表 / 模块基址回调直接
//!    绑定 dbghelp 的 `SymFunctionTableAccess64` / `SymGetModuleBase64`；
//! 5. 符号化：`SymInitializeW(hTargetProcess, 模块目录, FALSE)` + 逐模块
//!    `SymLoadModuleExW`（FALSE = 不入侵式枚举，模块表由宿主 Toolhelp 提供）+
//!    `SymFromAddrW`；`SymCleanup` 在 `SymbolSession` 的 Drop 里；
//! 6. 无论成功失败都必须 `ResumeThread`：`SuspendedThread` 的 Drop 是兜底，正常路径
//!    还会显式 resume 并把失败上报成错误。
//!
//! 确定性（与静态管线同一口径）：线程按 tid 升序；帧按栈序（由内向外）；每帧的稳定字段是
//! `module_path + rva + symbol + displacement`，`address` 只作诊断。
//!
//! **不是冻结机制**：本模块只为「取一次上下文 + 展开一次栈」短暂挂起单个线程，随即恢复。
//! 冻结仍是 [`crate::control::Session::freeze`] 的写内存线程——不能把 SuspendThread 当冻结
//! 默认机制用（挂起整个进程会让目标失去响应，语义也不对）。
//!
//! dbghelp 是**进程级单线程** API（MSDN：并发调用会内存损坏），因此整段符号化会话由
//! `SYMBOL_LOCK` 串行化：一次 capture 期间独占，`SymCleanup` 后释放。

#![allow(unsafe_code)] // Win32 / dbghelp C ABI；逐处调用的指针、句柄与生命周期见邻近 SAFETY 注。

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;

use kotama_proto::ModuleInfo;
use kotama_proto::ModuleKind;
use windows_sys::Win32::Foundation::ERROR_BAD_LENGTH;
use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::Debug::StackWalk64;
use windows_sys::Win32::System::Diagnostics::Debug::SymCleanup;
use windows_sys::Win32::System::Diagnostics::Debug::SymFromAddrW;
use windows_sys::Win32::System::Diagnostics::Debug::SymFunctionTableAccess64;
use windows_sys::Win32::System::Diagnostics::Debug::SymGetModuleBase64;
use windows_sys::Win32::System::Diagnostics::Debug::SymInitializeW;
use windows_sys::Win32::System::Diagnostics::Debug::SymLoadModuleExW;
use windows_sys::Win32::System::Diagnostics::Debug::SymSetOptions;
use windows_sys::Win32::System::Diagnostics::Debug::ADDRESS64;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;
use windows_sys::Win32::System::Diagnostics::Debug::MAX_SYM_NAME;
use windows_sys::Win32::System::Diagnostics::Debug::STACKFRAME64;
use windows_sys::Win32::System::Diagnostics::Debug::SYMBOL_INFOW;
use windows_sys::Win32::System::Diagnostics::Debug::SYMBOL_INFO_PACKAGEW;
use windows_sys::Win32::System::Diagnostics::Debug::SYMOPT_DEFERRED_LOADS;
use windows_sys::Win32::System::Diagnostics::Debug::SYMOPT_FAIL_CRITICAL_ERRORS;
use windows_sys::Win32::System::Diagnostics::Debug::SYMOPT_NO_PROMPTS;
use windows_sys::Win32::System::Diagnostics::Debug::SYMOPT_UNDNAME;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32First;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32Next;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::System::Threading::OpenThread;
use windows_sys::Win32::System::Threading::ResumeThread;
use windows_sys::Win32::System::Threading::SuspendThread;
use windows_sys::Win32::System::Threading::THREAD_GET_CONTEXT;
use windows_sys::Win32::System::Threading::THREAD_QUERY_INFORMATION;
use windows_sys::Win32::System::Threading::THREAD_SUSPEND_RESUME;

use crate::HostError;
use crate::TargetProcess;

/// 默认最多回溯的帧数（超过就截断，保证单次 capture 有界）。
pub const DEFAULT_MAX_FRAMES: usize = 64;

/// `IMAGE_FILE_MACHINE_AMD64`（`StackWalk64` 的 machinetype 参数；本模块只做 x64）。
const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;

/// 一帧外部栈：模块 + RVA + 符号 + 符号内偏移。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackFrame {
    /// 帧的绝对地址（诊断用；确定性比较请用 `module_base + rva`）。
    pub address: u64,
    /// 帧所属模块的 Win32 全路径（Toolhelp）；空 = 不在任何已知模块内。
    pub module_path: String,
    /// 模块加载基址；0 = 未知模块。
    pub module_base: u64,
    /// 模块内偏移（`address - module_base`；未知模块为 0）。
    pub rva: u64,
    /// dbghelp 解析出的符号名（`SymFromAddrW` + `SYMOPT_UNDNAME`）；`None` = 无符号信息。
    pub symbol: Option<String>,
    /// 符号内偏移（无符号时为 0）。
    pub displacement: u64,
}

/// 一个线程的栈：线程标识 + 捕获点 + 帧列表（由内向外）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadStack {
    /// 线程 ID（Toolhelp 的 `th32ThreadID`）。
    pub thread_id: u32,
    /// 捕获点的指令指针（`CONTEXT::Rip`）。
    pub rip: u64,
    /// 捕获点是否落在主 PE 映像内（即该线程此刻在跑目标自己的代码）。
    pub rip_in_image: bool,
    /// 帧列表，由内向外；空 = 展开失败（已计入 [`StackReport::skipped_threads`]）。
    pub frames: Vec<StackFrame>,
}

/// 一次外部栈回溯的结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackReport {
    /// 目标 PID。
    pub pid: i32,
    /// 做主映像判定的 PE 基址。
    pub image_base: u64,
    /// 主映像大小（字节）。
    pub image_size: u64,
    /// 主映像路径（Toolhelp 全路径）。
    pub image_path: String,
    /// 线程栈，**按 tid 升序**。
    pub threads: Vec<ThreadStack>,
    /// 打开 / 挂起 / 取上下文 / 展开失败的线程数（这些线程不出现在 `threads` 里）。
    pub skipped_threads: u32,
}

/// 回溯目标进程的**全部**线程，每线程一栈。
///
/// 输出确定性：`report.threads` 按 tid 升序，每线程的 `frames` 按栈序（由内向外），
/// 帧的稳定字段是 `module_path + rva + symbol + displacement`。
///
/// # Errors
/// 模块表 / 线程表枚举失败、找不到主 PE 映像、线程表为空，或所有线程都展开不出帧。
pub fn capture_all_threads(
    process: &TargetProcess,
    max_frames: usize,
) -> Result<StackReport, HostError> {
    capture(process, max_frames, ThreadFilter::All)
}

/// 只回溯**当前 RIP 落在主 PE 映像内**的线程（即正在跑目标代码的线程）。
///
/// 用途 = 挑出「活着在算」的线程做一次快照；等价地，正在内核里等待的线程（RIP 在
/// ntdll/kernel32）不出现在结果里——这是选择条件，不是失败。需要完整线程表时用
/// [`capture_all_threads`]（它的 [`ThreadStack::rip_in_image`] 已标注每条线程属于哪类）。
///
/// # Errors
/// 与 [`capture_all_threads`] 相同；此外若一条线程都没有满足条件时返回错误（空结果对
/// 调用方没有诊断价值，显式失败更诚实）。
pub fn capture_threads_in_image(
    process: &TargetProcess,
    max_frames: usize,
) -> Result<StackReport, HostError> {
    capture(process, max_frames, ThreadFilter::InMainImage)
}

/// 线程筛选条件。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ThreadFilter {
    /// 全部线程。
    All,
    /// 只保留 RIP 落在主 PE 映像内的线程。
    InMainImage,
}

fn capture(
    process: &TargetProcess,
    max_frames: usize,
    filter: ThreadFilter,
) -> Result<StackReport, HostError> {
    let max_frames = max_frames.max(1);
    let modules = process.modules()?;
    let main = main_image(&modules).ok_or_else(|| {
        HostError::Stack(format!(
            "pid {} exposes no native PE module to anchor the stack walk",
            process.pid()
        ))
    })?;
    let mut thread_ids = enumerate_threads(process.pid())?;
    // 自身进程：挂起调用线程就无法再恢复（resume 也在同一线程上）。取自身栈不是本 API 的
    // 目标，直接跳过当前线程即可避免自死锁。
    if process.pid() == std::process::id() as i32 {
        // SAFETY: GetCurrentThreadId 无参数、无指针，返回当前线程 id。
        let current = unsafe { GetCurrentThreadId() };
        thread_ids.retain(|thread_id| *thread_id != current);
    }
    if thread_ids.is_empty() {
        return Err(HostError::Stack(format!(
            "pid {} has no enumerable threads (process already exited?)",
            process.pid()
        )));
    }

    let session = SymbolSession::open(process, &modules, main)?;
    let mut report = StackReport {
        pid: process.pid(),
        image_base: main.base,
        image_size: main.size,
        image_path: main.path.clone(),
        threads: Vec::new(),
        skipped_threads: 0,
    };
    let image_end = main.base.saturating_add(main.size);
    for thread_id in thread_ids {
        let Ok(mut thread) = SuspendedThread::open(thread_id) else {
            report.skipped_threads += 1;
            continue;
        };
        if thread.suspend().is_err() {
            report.skipped_threads += 1;
            continue;
        }
        let Ok(context) = thread.context() else {
            // guard 的 Drop 会 resume；这条线程只是没能取到上下文。
            report.skipped_threads += 1;
            continue;
        };
        let rip = context.Rip;
        let in_image = rip >= main.base && rip < image_end;
        let selected = filter == ThreadFilter::All || in_image;
        let frames = if selected {
            walk(&session, &thread, &context, &modules, max_frames)
        } else {
            Vec::new()
        };
        // 显式恢复：失败就上报（guard 的 Drop 还会再兜一次）。
        if thread.resume().is_err() {
            report.skipped_threads += 1;
            continue;
        }
        if selected {
            report.threads.push(ThreadStack {
                thread_id,
                rip,
                rip_in_image: in_image,
                frames,
            });
        }
    }
    if report.threads.is_empty() {
        return Err(HostError::Stack(format!(
            "pid {}: no thread matched the {} filter ({} skipped)",
            process.pid(),
            match filter {
                ThreadFilter::All => "all",
                ThreadFilter::InMainImage => "main-image-rip",
            },
            report.skipped_threads
        )));
    }
    if filter == ThreadFilter::All && report.threads.iter().all(|thread| thread.frames.is_empty()) {
        return Err(HostError::Stack(format!(
            "pid {}: StackWalk64 produced no frames for {} thread(s)",
            process.pid(),
            report.threads.len()
        )));
    }
    Ok(report)
}

/// 主 PE 映像：优先 `.exe`，否则第一个原生 PE 模块。
fn main_image(modules: &[ModuleInfo]) -> Option<&ModuleInfo> {
    let native = || {
        modules
            .iter()
            .filter(|module| module.kind == ModuleKind::NativePe)
    };
    native()
        .clone()
        .find(|module| is_executable_image(&module.path))
        .or_else(|| native().next())
}

fn is_executable_image(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

/// 枚举某 pid 的线程 id（升序去重）。
fn enumerate_threads(pid: i32) -> Result<Vec<u32>, HostError> {
    let snapshot = thread_snapshot()?;
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: snapshot 是存活快照句柄；entry 已按结构尺寸设置 dwSize。
    let mut advanced = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    if advanced == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            return Ok(Vec::new());
        }
        return Err(HostError::Win32(format!("Thread32First: {error}")));
    }
    let owner = u32::try_from(pid).unwrap_or(u32::MAX);
    let mut thread_ids = Vec::new();
    loop {
        if entry.th32OwnerProcessID == owner {
            thread_ids.push(entry.th32ThreadID);
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        // SAFETY: 与 Thread32First 相同；entry 在每次调用后重新完整填充。
        advanced = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
        if advanced == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(HostError::Win32(format!("Thread32Next: {error}")));
        }
    }
    thread_ids.sort_unstable();
    thread_ids.dedup();
    Ok(thread_ids)
}

/// 线程快照（`TH32CS_SNAPTHREAD` 拿全系统的线程表，再按 owner pid 过滤）。
fn thread_snapshot() -> Result<OwnedHandle, HostError> {
    for _ in 0..8 {
        // SAFETY: flags/pid 都是值参数；返回句柄由本函数接管。
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BAD_LENGTH as i32) {
                // 线程表在枚举期间变化；MSDN 给出的有限重试。
                continue;
            }
            return Err(HostError::Win32(format!(
                "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD): {error}"
            )));
        }
        // SAFETY: raw 是刚返回的有效独占快照句柄。
        return Ok(unsafe { OwnedHandle::from_raw_handle(raw) });
    }
    Err(HostError::Win32(
        "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD): thread table stayed busy".into(),
    ))
}

/// 被挂起的线程句柄：**Drop 必 restore**（显式 resume 之外的最后一道保险）。
struct SuspendedThread {
    handle: OwnedHandle,
    suspended: bool,
}

impl SuspendedThread {
    fn open(thread_id: u32) -> Result<Self, HostError> {
        let access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION;
        // SAFETY: OpenThread 只取值参数；FALSE 禁止句柄继承。
        let raw = unsafe { OpenThread(access, FALSE, thread_id) };
        if raw.is_null() {
            return Err(crate::windows::last_error(&format!(
                "OpenThread {thread_id} access {access:#x}"
            )));
        }
        // SAFETY: raw 是刚返回、非空且由本结构独占拥有的线程句柄。
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            suspended: false,
        })
    }

    fn suspend(&mut self) -> Result<(), HostError> {
        // SAFETY: handle 是本结构独占的存活线程句柄。
        let previous = unsafe { SuspendThread(self.handle.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(crate::windows::last_error(&format!(
                "SuspendThread {:#x}",
                self.handle.as_raw_handle() as usize
            )));
        }
        self.suspended = true;
        Ok(())
    }

    fn context(&self) -> Result<CONTEXT, HostError> {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FULL_AMD64,
            ..CONTEXT::default()
        };
        // SAFETY: 线程已被挂起（调用方保证）；context 是正确类型的可写结构。
        let ok = unsafe { GetThreadContext(self.handle.as_raw_handle(), &mut context) };
        if ok == 0 {
            return Err(crate::windows::last_error(&format!(
                "GetThreadContext {:#x}",
                self.handle.as_raw_handle() as usize
            )));
        }
        Ok(context)
    }

    fn resume(&mut self) -> Result<(), HostError> {
        if !self.suspended {
            return Ok(());
        }
        // SAFETY: 与 suspend 成对；handle 存活。
        let previous = unsafe { ResumeThread(self.handle.as_raw_handle()) };
        if previous == u32::MAX {
            // 保持 suspended = true，让 Drop 再试一次（宁可在 Drop 里重试也不留挂起线程）。
            return Err(crate::windows::last_error(&format!(
                "ResumeThread {:#x}",
                self.handle.as_raw_handle() as usize
            )));
        }
        self.suspended = false;
        Ok(())
    }
}

impl Drop for SuspendedThread {
    fn drop(&mut self) {
        if self.suspended {
            // SAFETY: 只对确实由本结构 suspend 过的线程调用一次；Drop 里无法上报错误，
            // 但这是「无论如何都要恢复」的最后保障。
            unsafe {
                ResumeThread(self.handle.as_raw_handle());
            }
            self.suspended = false;
        }
    }
}

/// dbghelp 会话锁：dbghelp 全进程单线程，必须在整个会话期间独占。
static SYMBOL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 一次 dbghelp 会话（`SymInitializeW` → 逐模块 `SymLoadModuleExW` → `SymCleanup`）。
struct SymbolSession {
    process: HANDLE,
    _lock: std::sync::MutexGuard<'static, ()>,
    initialized: bool,
}

impl SymbolSession {
    fn open(
        process: &TargetProcess,
        modules: &[ModuleInfo],
        main: &ModuleInfo,
    ) -> Result<Self, HostError> {
        let lock = SYMBOL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let handle = process.handle.as_raw_handle() as HANDLE;
        let search_path: Vec<u16> = module_directory(&main.path)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: handle 是存活的进程句柄（查询 + 读内存）；search_path 是 NUL 结尾的
        // UTF-16 模块目录；FALSE = 不入侵式枚举（模块表由 Toolhelp 提供）。
        unsafe {
            SymSetOptions(
                SYMOPT_UNDNAME
                    | SYMOPT_DEFERRED_LOADS
                    | SYMOPT_FAIL_CRITICAL_ERRORS
                    | SYMOPT_NO_PROMPTS,
            );
            if SymInitializeW(handle, search_path.as_ptr(), FALSE) == 0 {
                return Err(crate::windows::last_error(&format!(
                    "SymInitializeW pid {} search path {}",
                    process.pid(),
                    module_directory(&main.path)
                )));
            }
        }
        let session = Self {
            process: handle,
            _lock: lock,
            initialized: true,
        };
        // 主映像先载：它的符号就是本模块的交付物，载不上直接失败（Drop 会 SymCleanup）。
        if !load_module(handle, main) {
            let error = HostError::Stack(format!(
                "dbghelp SymLoadModuleExW {} at {:#x}",
                main.path, main.base
            ));
            drop(session);
            return Err(error);
        }
        // 其余模块尽力而为：系统 DLL 通常没有伴生 PDB，但 x64 展开需要它们的 .pdata。
        for module in modules {
            if module.base != main.base {
                let _ = load_module(handle, module);
            }
        }
        Ok(session)
    }
}

impl Drop for SymbolSession {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: 与 SymInitializeW 同一进程句柄；每个会话只 cleanup 一次。
            unsafe {
                SymCleanup(self.process);
            }
            self.initialized = false;
        }
    }
}

/// 把一个模块（base + size + 磁盘路径）交给 dbghelp；失败只影响该模块的符号。
fn load_module(handle: HANDLE, module: &ModuleInfo) -> bool {
    if module.path.is_empty() || module.size == 0 {
        return false;
    }
    let wide: Vec<u16> = module
        .path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let size = u32::try_from(module.size).unwrap_or(u32::MAX);
    // SAFETY: handle 是会话里的进程句柄；wide 是 NUL 结尾映像路径；base/size 来自
    // 同一进程的 Toolhelp 模块表；空文件句柄 / 空 MODLOAD_DATA / 0 flags。
    let loaded = unsafe {
        SymLoadModuleExW(
            handle,
            std::ptr::null_mut(),
            wide.as_ptr(),
            std::ptr::null(),
            module.base,
            size,
            std::ptr::null(),
            0,
        )
    };
    loaded != 0
}

/// `SymLoadModuleExW` 需要的映像路径（取目录部分；没有目录时返回空串）。
fn module_directory(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// StackWalk64 的读内存回调（签名与 `ReadProcessMemory` 不同，必须包一层）。
///
/// # Safety
/// 由 dbghelp 调用：`process` 是本会话的进程句柄，`buffer` 至少可写 `size` 字节。
unsafe extern "system" fn read_process_memory(
    process: HANDLE,
    base: u64,
    buffer: *mut c_void,
    size: u32,
    read: *mut u32,
) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let mut transferred = 0usize;
    // SAFETY: 调用方（dbghelp）给出可写缓冲与长度；transferred 是有效输出位置。
    let ok = unsafe {
        ReadProcessMemory(
            process,
            base as *const c_void,
            buffer,
            size as usize,
            &mut transferred,
        )
    };
    if ok == 0 {
        return 0;
    }
    if !read.is_null() {
        // SAFETY: dbghelp 传了非空 DWORD 输出位置（上面已判空）。
        unsafe {
            *read = u32::try_from(transferred).unwrap_or(u32::MAX);
        }
    }
    1
}

/// 从挂起线程的上下文出发，用 StackWalk64 展开一栈。
///
/// 展开在 dbghelp 说「没有更多帧」时自然结束；某帧的符号缺失只让该帧的 `symbol` 为
/// `None`，不影响其余帧（模块归属由 Toolhelp 模块表兜底）。
fn walk(
    session: &SymbolSession,
    thread: &SuspendedThread,
    context: &CONTEXT,
    modules: &[ModuleInfo],
    max_frames: usize,
) -> Vec<StackFrame> {
    let mut frame = STACKFRAME64 {
        AddrPC: address64(context.Rip),
        AddrFrame: address64(context.Rbp),
        AddrStack: address64(context.Rsp),
        ..STACKFRAME64::default()
    };
    let mut context_record = *context;
    let mut frames = Vec::new();
    let mut previous = None;
    for _ in 0..max_frames {
        // SAFETY: frame/context_record 都是本栈帧内存活的可写值；线程已挂起；进程句柄
        // 存活；三个回调分别是本模块的 ReadProcessMemory 包装与 dbghelp 自带的函数表 /
        // 模块基址解析（签名逐一匹配）。
        let advanced = unsafe {
            StackWalk64(
                IMAGE_FILE_MACHINE_AMD64,
                session.process,
                thread.handle.as_raw_handle() as HANDLE,
                &mut frame,
                std::ptr::addr_of_mut!(context_record).cast(),
                Some(read_process_memory),
                Some(SymFunctionTableAccess64),
                Some(SymGetModuleBase64),
                None,
            )
        };
        if advanced == 0 {
            break;
        }
        let pc = frame.AddrPC.Offset;
        if pc == 0 {
            break;
        }
        if previous == Some(pc) {
            // 没有推进（展开信息缺失时会出现）：停在这里而不是无限循环。
            break;
        }
        previous = Some(pc);
        frames.push(symbolize(session.process, pc, modules));
    }
    frames
}

fn address64(offset: u64) -> ADDRESS64 {
    ADDRESS64 {
        Offset: offset,
        Segment: 0,
        Mode: windows_sys::Win32::System::Diagnostics::Debug::AddrModeFlat,
    }
}

/// 一帧的模块归属 + dbghelp 符号。
fn symbolize(handle: HANDLE, address: u64, modules: &[ModuleInfo]) -> StackFrame {
    let module = modules
        .iter()
        .find(|module| is_inside(address, module.base, module.size));
    let (module_base, module_path, rva) = match module {
        Some(module) => (module.base, module.path.clone(), address - module.base),
        None => {
            // Toolhelp 没枚举到、但 dbghelp 认识（极少见）：仍然给出基址 + RVA。
            // SAFETY: 会话期内的只读查询；address 只是值。
            let base = unsafe { SymGetModuleBase64(handle, address) };
            if base == 0 || address < base {
                (0, String::new(), 0)
            } else {
                (base, String::new(), address - base)
            }
        }
    };
    let mut package = SYMBOL_INFO_PACKAGEW::default();
    package.si.SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
    package.si.MaxNameLen = MAX_SYM_NAME;
    let mut displacement = 0u64;
    // SAFETY: package 的 si 之后紧邻名称缓冲（`SYMBOL_INFO_PACKAGEW` 的契约：dbghelp 从
    // `si.Name` 起写）；displacement 是有效输出位置。
    let resolved = unsafe { SymFromAddrW(handle, address, &mut displacement, &mut package.si) };
    let symbol = if resolved == 0 {
        None
    } else {
        let length = (package.si.NameLen as usize).min(MAX_SYM_NAME as usize);
        // dbghelp 从 `si.Name` 起连续写名字符（`SYMBOL_INFOW` 末尾的 `Name[1]` 与包结构里
        // 紧随其后的 `name` 缓冲在内存里是同一段），因此必须从 `si.Name` 读、而不是从
        // `package.name` 读——后者差一个字符（首字符落在 si 的尾字节里）。
        // SAFETY: dbghelp 在本次调用里把 NameLen 个 u16 写在 `si.Name` 起始处；包结构总长
        // 足以容纳（`si` 末尾对齐后与 `name` 相连，Name 偏移 + 2*2000 < 总长）。
        let chars = unsafe { std::slice::from_raw_parts(package.si.Name.as_ptr(), length) };
        let name = String::from_utf16_lossy(chars);
        (!name.is_empty()).then_some(name)
    };
    StackFrame {
        address,
        module_path,
        module_base,
        rva,
        displacement: if symbol.is_some() { displacement } else { 0 },
        symbol,
    }
}

fn is_inside(address: u64, base: u64, size: u64) -> bool {
    size != 0 && address >= base && address < base.saturating_add(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 线程表必须包含当前线程且按 tid 升序（确定性口径的单元级钉子）。
    #[test]
    fn enumerate_threads_is_sorted_and_contains_current() {
        // SAFETY: GetCurrentThreadId 无参数。
        let current = unsafe { GetCurrentThreadId() };
        let thread_ids = enumerate_threads(std::process::id() as i32).expect("thread table");
        assert!(
            thread_ids.contains(&current),
            "current thread {current} missing from {thread_ids:?}"
        );
        assert!(
            thread_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "thread ids must be strictly ascending: {thread_ids:?}"
        );
    }

    /// RAII 钉子：只 suspend、不显式 resume，Drop 之后线程必须继续跑。
    #[test]
    fn suspended_thread_guard_resumes_on_drop() {
        let (tid_sender, tid_receiver) = std::sync::mpsc::channel();
        let (go_sender, go_receiver) = std::sync::mpsc::channel::<()>();
        let (done_sender, done_receiver) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            tid_sender
                .send(unsafe { GetCurrentThreadId() })
                .expect("report tid");
            go_receiver.recv().expect("resume signal");
            done_sender.send(()).expect("report progress");
        });
        let tid = tid_receiver.recv().expect("worker tid");
        {
            let mut thread = SuspendedThread::open(tid).expect("OpenThread");
            thread.suspend().expect("SuspendThread");
            let context = thread.context().expect("GetThreadContext");
            assert_ne!(context.Rip, 0, "suspended thread must have a RIP");
            // 故意不调用 thread.resume()：离开作用域时 Drop 必须恢复线程。
        }
        go_sender.send(()).expect("send go");
        done_receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("worker must continue after the guard is dropped");
        worker.join().expect("join worker");
    }

    /// `capture_threads_in_image` 的**正例**：本进程里有一条线程正在跑本映像的代码时，
    /// 它必须被选中，且结果里每条线程的 RIP 都真的落在主映像范围内。
    ///
    /// 用忙等线程而不是目标长跑靶：睡眠中的靶子 RIP 在内核里，按定义不该被选中，
    /// 那样只能测到负例。这里不需要 PDB，只验证选择与帧归属。
    #[test]
    fn capture_threads_in_image_selects_a_thread_running_this_image() {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        });
        let process = crate::TargetProcess::open(std::process::id() as i32).expect("open self");
        let mut captured = None;
        for _ in 0..40 {
            match capture_threads_in_image(&process, 16) {
                Ok(report) => {
                    captured = Some(report);
                    break;
                }
                Err(HostError::Stack(_)) => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => panic!("unexpected capture error: {error}"),
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        worker.join().expect("join busy thread");
        let report = captured.expect("a busy in-image thread must be selected");
        for thread in &report.threads {
            assert!(thread.rip_in_image, "filter leaked a thread: {thread:?}");
            assert!(
                thread.rip >= report.image_base
                    && thread.rip < report.image_base + report.image_size,
                "RIP {:#x} outside image {:#x}+{:#x}",
                thread.rip,
                report.image_base,
                report.image_size
            );
            assert!(
                !thread.frames.is_empty(),
                "selected thread must yield frames"
            );
        }
    }

    /// 帧归属判定：半开区间，且 size == 0 的模块永远不命中。
    #[test]
    fn frame_ownership_uses_half_open_image_range() {
        assert!(is_inside(0x1000, 0x1000, 0x100));
        assert!(is_inside(0x10ff, 0x1000, 0x100));
        assert!(!is_inside(0x1100, 0x1000, 0x100));
        assert!(!is_inside(0x0fff, 0x1000, 0x100));
        assert!(!is_inside(0x1000, 0x1000, 0));
    }

    /// 模块目录（SymInitializeW 的搜索路径）取父目录；没有父目录时退化成空串。
    #[test]
    fn module_directory_is_the_parent_folder() {
        assert_eq!(module_directory(r"D:\fixtures\spin.exe"), r"D:\fixtures");
        assert_eq!(module_directory("spin.exe"), "");
    }
}
