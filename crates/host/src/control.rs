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

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::scanner::Value;
use crate::HostError;
use crate::TargetProcess;

/// 带能力门禁的会话。
pub struct Session {
    process: TargetProcess,
    /// `Some` = 写能力已授予（读写模式句柄）。
    writer: Option<File>,
}

impl Session {
    /// 只读会话（默认态）。
    #[must_use]
    pub fn read_only(process: TargetProcess) -> Self {
        Self {
            process,
            writer: None,
        }
    }

    /// 显式授予写能力的会话：`/proc/<pid>/mem` 以读写模式重开。
    ///
    /// # Errors
    /// 重开失败 = 权限不满足（或进程已消失）。
    pub fn with_write(process: TargetProcess) -> Result<Self, HostError> {
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{}/mem", process.pid()))
            .map_err(|e| HostError::Process(format!("open mem rw pid {}: {e}", process.pid())))?;
        Ok(Self {
            process,
            writer: Some(writer),
        })
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

    /// 写一段内存。
    ///
    /// # Errors
    /// 未授权（[`HostError::CapabilityDenied`]，负对照钉的就是它）或写入失败。
    pub fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), HostError> {
        let writer = self
            .writer
            .as_ref()
            .ok_or(HostError::CapabilityDenied("write requires an explicitly granted session (with_write); read-only sessions never write"))?;
        writer
            .write_all_at(bytes, address)
            .map_err(|e| HostError::Proc(format!("write {address:#x}+{}: {e}", bytes.len())))
    }

    /// 冻结一个值：后台线程按 `interval_ms` 周期重写。
    ///
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

        let writer = self
            .writer
            .as_ref()
            .ok_or(HostError::CapabilityDenied("unreachable: checked above"))?
            .try_clone()
            .map_err(|e| HostError::Proc(format!("clone mem handle: {e}")))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let interval = Duration::from_millis(interval_ms.max(1));
            while !stop_flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                if writer.write_all_at(&initial, address).is_err() {
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
