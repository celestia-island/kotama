//! P3 写车道与冻结：**capability 门禁 + host 侧冻结线程**。
//!
//! 门禁语义（设计案 §1 裁决 4 的落地形态）：
//! - [`Session::read_only`] = 默认：一切写操作（写内存 / 冻结）返回
//!   [`HostError::CapabilityDenied`]——负对照测试钉住，不是「文档约定」而是构造保证；
//! - [`Session::with_write`] 显式授权：`/proc/<pid>/mem` 以读写模式重开（这一步本身就会
//!   因权限失败——PTRACE_MODE_ATTACH 不满足时直接建不出写句柄）。
//!
//! 冻结 = host 侧高频重写线程（P3 形态；P4 的进程内冻结随载荷车道接管）。注意冻结线程
//! Drop 即停、写失败（目标退出）即退——不留僵尸线程。
//!
//! Windows 另有**远程注入**能力：它同样默认关闭，且不随 with_write 一起打开——
//! 唯一授权入口是 with_injection；未授权会话调用 inject 时，在任何
//! VirtualAllocEx / CreateRemoteThread 之前就返回 CapabilityDenied。

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::OwnedHandle;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::scanner::Value;
use crate::HostError;
use crate::TargetProcess;

#[cfg(target_os = "linux")]
type Writer = File;
#[cfg(target_os = "windows")]
type Writer = OwnedHandle;

/// 带能力门禁的会话。
pub struct Session {
    process: TargetProcess,
    /// `Some` = 写能力已授予（读写模式句柄）。
    writer: Option<Writer>,
    /// Windows：远程注入能力是否已显式授予。with_write 只给写内存，不隐含注入。
    #[cfg(target_os = "windows")]
    injection: bool,
}

impl Session {
    /// 只读会话（默认态）。
    #[must_use]
    pub fn read_only(process: TargetProcess) -> Self {
        Self {
            process,
            writer: None,
            #[cfg(target_os = "windows")]
            injection: false,
        }
    }

    /// 显式授予写能力的会话：Linux 重开 `/proc/<pid>/mem`，Windows 另开带
    /// `PROCESS_VM_WRITE|PROCESS_VM_OPERATION` 的进程句柄。
    ///
    /// # Errors
    /// 重开失败 = 权限不满足（或进程已消失）。
    pub fn with_write(process: TargetProcess) -> Result<Self, HostError> {
        #[cfg(target_os = "linux")]
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{}/mem", process.pid()))
            .map_err(|e| HostError::Process(format!("open mem rw pid {}: {e}", process.pid())))?;
        #[cfg(target_os = "windows")]
        let writer = crate::windows::open_writer(process.pid())?;
        Ok(Self {
            process,
            writer: Some(writer),
            #[cfg(target_os = "windows")]
            injection: false,
        })
    }

    /// 显式授予远程注入能力的会话（Windows 原生车道）。
    ///
    /// 这是**唯一**的注入授权入口：with_write 只给写内存，不给远程线程；CLI / 服务面
    /// 将来必须用一个显式开关才能走到这里。
    ///
    /// # Errors
    /// 打开带 PROCESS_CREATE_THREAD 的进程句柄失败（权限不足 / 进程已退出）。
    #[cfg(target_os = "windows")]
    pub fn with_injection(process: TargetProcess) -> Result<Self, HostError> {
        let writer = crate::windows::open_injector(process.pid())?;
        Ok(Self {
            process,
            writer: Some(writer),
            injection: true,
        })
    }

    /// 注入能力是否已显式授予。
    #[cfg(target_os = "windows")]
    #[must_use]
    pub const fn injection_allowed(&self) -> bool {
        self.injection
    }

    /// 把一个 DLL 远程注入目标进程（LoadLibraryW 远程线程；x64→x64）。
    ///
    /// # Errors
    /// 未授权（[HostError::CapabilityDenied]，负对照钉的就是它）或注入失败
    /// （见 crate::inject::inject_dll 的校验与超时语义）。
    #[cfg(target_os = "windows")]
    pub fn inject(
        &self,
        dll: &Path,
        timeout: Duration,
    ) -> Result<crate::inject::InjectionReport, HostError> {
        if !self.injection {
            return Err(HostError::CapabilityDenied(
                "remote injection requires an explicitly granted session (with_injection); read-only and write sessions never inject",
            ));
        }
        let writer = self.writer.as_ref().ok_or(HostError::CapabilityDenied(
            "unreachable: with_injection always carries an injection handle",
        ))?;
        crate::inject::inject_dll(&self.process, writer, dll, timeout)
    }

    /// 内部进程句柄（扫描 / 快照走只读通道）。
    #[must_use]
    pub const fn process(&self) -> &TargetProcess {
        &self.process
    }

    /// 写能力是否已授予。
    #[must_use]
    pub const fn write_allowed(&self) -> bool {
        self.writer.is_some()
    }

    /// 在目标进程里分配一块可执行内存，返回基址。
    ///
    /// `near` 是选址提示：rel32 只能跳 ±2 GB，trampoline 必须住在目标函数旁边。
    /// 内核不保证 honoring 提示；调用方用返回的基址算距离。
    ///
    /// 只在 Windows 实现；Linux 的等价物（远程 mmap）不在本方法内。
    ///
    /// # Errors
    /// 未授权、非 Windows、或分配失败。
    pub fn alloc_remote(&self, size: usize, near: Option<u64>) -> Result<u64, HostError> {
        #[cfg(target_os = "windows")]
        {
            let writer = self.writer.as_ref().ok_or(HostError::CapabilityDenied(
                "alloc requires an explicitly granted session (with_write)",
            ))?;
            crate::windows::alloc_remote(writer, size, near)
        }
    }

    /// 写一段内存。    ///
    /// # Errors
    /// 未授权（[`HostError::CapabilityDenied`]，负对照钉的就是它）或写入失败。
    pub fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), HostError> {
        let writer = self
            .writer
            .as_ref()
            .ok_or(HostError::CapabilityDenied("write requires an explicitly granted session (with_write); read-only sessions never write"))?;
        write_at(writer, address, bytes)
    }

    /// 安装一个钩子：先写 trampoline，再写入口的跳转。
    ///
    /// 顺序是契约的一半。一个线程在两次写之间进入函数时，必须落进**完整的**
    /// trampoline（它跳回 `entry + overwrite`），而不是半个跳转。trampoline 先落地
    /// 就保证了这一点：在跳转写入之前，入口仍是原指令，走原路。
    ///
    /// [`Install`](kotama_scan::install::Install) 由 `kotama_scan::install::plan` 从字节算出，
    /// 不在这里重算：这个方法只负责写，不负责判断入口能不能放跳转。
    ///
    /// # Errors
    /// 未授权（[`HostError::CapabilityDenied`]）或任一写入失败。trampoline 写入成功
    /// 而跳转写入失败时，trampoline 留在目标里（无害：没人跳进去），错误原样返回。
    pub fn install_hook(&self, install: &kotama_scan::install::Install) -> Result<(), HostError> {
        self.write_bytes(install.trampoline.address, &install.trampoline.bytes)?;
        self.write_bytes(install.jump.address, &install.jump.bytes)
    }

    /// 卸载一个钩子：把原始字节写回入口。trampoline 不回收。
    ///
    /// # Errors
    /// 未授权或写入失败。
    pub fn uninstall_hook(&self, install: &kotama_scan::install::Install) -> Result<(), HostError> {
        self.write_bytes(install.jump.address, &install.original)
    }

    /// 冻结一个值：后台线程按 `interval_ms` 周期重写。    ///
    /// 返回 [`FreezeHandle`]；丢弃即停止冻结。目标进程退出时线程自行结束。
    ///
    /// # Errors
    /// 未授权或首次写入失败。
    pub fn freeze(
        &self,
        address: u64,
        value: Value,
        interval_ms: u64,
    ) -> Result<FreezeHandle, HostError> {
        // 先同步写一次：把「未授权」和「地址不可写」在启动线程前暴露出来。
        let initial = encode_value(&value);
        self.write_bytes(address, &initial)?;

        let writer = clone_writer(
            self.writer
                .as_ref()
                .ok_or(HostError::CapabilityDenied("unreachable: checked above"))?,
            self.process.pid(),
        )?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let interval = Duration::from_millis(interval_ms.max(1));
            while !stop_flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                if write_at(&writer, address, &initial).is_err() {
                    break; // 目标退出 / 权限消失：安静收工。
                }
            }
        });
        Ok(FreezeHandle {
            stop,
            join: Some(join),
        })
    }
}

/// 冻结句柄：Drop 即停。
pub struct FreezeHandle {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for FreezeHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn write_at(writer: &Writer, address: u64, bytes: &[u8]) -> Result<(), HostError> {
    writer
        .write_all_at(bytes, address)
        .map_err(|e| HostError::Proc(format!("write {address:#x}+{}: {e}", bytes.len())))
}

#[cfg(target_os = "windows")]
fn write_at(writer: &Writer, address: u64, bytes: &[u8]) -> Result<(), HostError> {
    crate::windows::write_memory(writer, address, bytes)
}

#[cfg(target_os = "linux")]
fn clone_writer(writer: &Writer, _pid: i32) -> Result<Writer, HostError> {
    writer
        .try_clone()
        .map_err(|e| HostError::Proc(format!("clone mem handle: {e}")))
}

#[cfg(target_os = "windows")]
fn clone_writer(_writer: &Writer, pid: i32) -> Result<Writer, HostError> {
    // OwnedHandle 没有 try_clone；为冻结线程独立 OpenProcess，生命周期互不借用。
    crate::windows::open_writer(pid)
}

/// 值 → 字节（写入用）。
fn encode_value(value: &Value) -> Vec<u8> {
    match value {
        Value::U32(v) => v.to_le_bytes().to_vec(),
        Value::I32(v) => v.to_le_bytes().to_vec(),
        Value::U64(v) => v.to_le_bytes().to_vec(),
        Value::F32(v) => v.to_le_bytes().to_vec(),
        Value::Bytes(bytes) => bytes.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 门禁负对照（P3 验收判据）：只读会话**必须**拒绝写，且错误类型可判。
    #[test]
    fn read_only_session_refuses_writes() {
        let Ok(process) = TargetProcess::open(std::process::id() as i32) else {
            eprintln!("skip: cannot open self");
            return;
        };
        let session = Session::read_only(process);
        assert!(matches!(
            session.write_bytes(0x1000, &[1u8]),
            Err(HostError::CapabilityDenied(_))
        ));
        assert!(!session.write_allowed());
    }
}
