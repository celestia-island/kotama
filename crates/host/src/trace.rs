//! P4 trace 车道：ptrace 软件断点（INT3）。
//!
//! 形态：附加目标 → 在指定地址下 `0xCC` → 持续运行捕获命中（恢复原字节 → 单步执行
//! 原指令 → 重新装回 INT3 → 继续）→ 到时卸下全部断点并分离。这是「谁在执行这个地址」
//! 的最小真实现，不是采样近似。
//!
//! 进程格式无关：ptrace 作用在 Linux 进程上，ELF 与 wine 宿主 PE 一视同仁。
//!
//! 安全性：本模块是 kotama 中第一个 `unsafe` 密集区（ptrace 是 C ABI）。约束：
//! - 只对自己的会话 pid 发 ptrace 请求，参数由 [`TraceSession`] 的状态派生；
//! - `PTRACE_PEEKDATA` 的 -1/errno 歧义按 man 语义处理（调用前后清 errno 再比对）；
//! - 一切失败路径都走 [`HostError`]，不 panic 跨 FFI；
//! - 会话 Drop 保证分离（尽力而为；目标已死时分离失败按静默处理）。

#![allow(unsafe_code)] // ptrace C ABI；安全性论据见模块文档。

use std::collections::BTreeMap;

use crate::HostError;

/// 一个已装载的断点（地址 + 被替换出的原字节）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Breakpoint {
    /// 断点地址（任意对齐；INT3 写在字节粒度上）。
    address: u64,
    /// 原字节（恢复用）。
    original: u8,
}

/// 一次命中的统计。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HitReport {
    /// 断点地址。
    pub address: u64,
    /// 命中次数。
    pub hits: u64,
}

/// ptrace 会话：附加 → 下断点 → 跑 → 分离。
pub struct TraceSession {
    pid: i32,
    breakpoints: BTreeMap<u64, Breakpoint>,
}

impl TraceSession {
    /// 附加到目标进程（`PTRACE_ATTACH` + 等待就位）。
    ///
    /// # Errors
    /// 附加失败（权限 / 进程不存在 / 已被别的 tracer 持有）。
    pub fn attach(pid: i32) -> Result<Self, HostError> {
        let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
        if rc == -1 {
            return Err(HostError::Process(format!(
                "PTRACE_ATTACH {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
            return Err(HostError::Process(format!(
                "waitpid after attach: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            pid,
            breakpoints: BTreeMap::new(),
        })
    }

    /// 目标 PID。
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// 在某地址装载断点（读所在 8 字节字 → 低 8 位替换为 `0xCC` → 写回）。
    ///
    /// # Errors
    /// peek/poke 失败（地址未映射）。
    pub fn set_breakpoint(&mut self, address: u64) -> Result<(), HostError> {
        if self.breakpoints.contains_key(&address) {
            return Ok(());
        }
        let aligned = address & !7;
        let offset = (address & 7) as usize;
        let word = peek_word(self.pid, aligned)?;
        let original = ((word as u64) >> (8 * offset)) as u8;
        let patched = ((word as u64) & !(0xffu64 << (8 * offset))) | (0xccu64 << (8 * offset));
        poke_word(self.pid, aligned, patched as libc::c_long)?;
        self.breakpoints
            .insert(address, Breakpoint { address, original });
        Ok(())
    }

    /// 持续运行 `duration`，收集断点命中。
    ///
    /// 事件循环：`waitpid(WNOHANG)` 轮询（2ms 间隔）+ 到时退出；SIGTRAP 时按
    /// RIP−1 定位断点 → 恢复原字节 → 单步 → 重装 INT3 → 继续；其他信号按原信号转发。
    ///
    /// # Errors
    /// 目标死亡前未产生任何事件不算错误（返回已收集的命中）。
    pub fn run(&mut self, duration: std::time::Duration) -> Result<Vec<HitReport>, HostError> {
        let mut hits: BTreeMap<u64, u64> = BTreeMap::new();
        let deadline = std::time::Instant::now() + duration;
        // 先继续运行（附加后目标停在就位点）。
        self.continue_all(0)?;
        while std::time::Instant::now() < deadline {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if rc == 0 {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            if rc == -1 {
                // 目标不在了：收工返回已收集的命中。
                break;
            }
            if libc::WIFSTOPPED(status) {
                let signal = libc::WSTOPSIG(status);
                if signal == libc::SIGTRAP {
                    if let Some(report) = self.handle_trap(&mut hits)? {
                        let _ = report;
                    }
                    continue;
                }
                // 非断点信号：原样转发，保持目标语义。
                self.continue_all(signal)?;
            } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                break;
            }
        }
        // 收停：ptrace 的 DETACH / POKE 要求 tracee 处于停止态；run 结束时它可能在跑
        // 或停在未处理的 trap 上。标准套路：注入 SIGSTOP → 收停（路上把残留 trap
        // 处理掉）→ 之后 detach 才合法（e2e 实踩：目标最后停挂在 SIGTRAP 上）。
        if !self.alive() {
            return Ok(collect(hits));
        }
        if let Err(err) = self.hold_with_sigstop(&mut hits) {
            let _ = err; // 收停失败（目标恰好在退出）：按现状收工。
        }
        Ok(collect(hits))
    }

    /// tracee 是否仍在（`kill(0)` 探测）。
    fn alive(&self) -> bool {
        unsafe { libc::kill(self.pid, 0) == 0 }
    }

    /// 注入 SIGSTOP 并等待收停；路上的 SIGTRAP 按断点往返处理。
    fn hold_with_sigstop(&mut self, hits: &mut BTreeMap<u64, u64>) -> Result<(), HostError> {
        for _ in 0..32 {
            let rc = unsafe { libc::kill(self.pid, libc::SIGSTOP) };
            if rc == -1 {
                return Err(HostError::Proc("kill SIGSTOP failed".into()));
            }
            let mut status = 0;
            if unsafe { libc::waitpid(self.pid, &mut status, 0) } == -1 {
                return Err(HostError::Proc("waitpid for SIGSTOP failed".into()));
            }
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                return Ok(());
            }
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP {
                let _ = self.handle_trap(hits)?;
                continue;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(HostError::Proc("target exited while holding".into()));
            }
        }
        Err(HostError::Proc("could not reach a SIGSTOP hold".into()))
    }

    /// 处理一次 SIGTRAP：断点往返（恢复 → 单步 → 重装）。
    fn handle_trap(&mut self, hits: &mut BTreeMap<u64, u64>) -> Result<Option<u64>, HostError> {
        let rip = get_regs_rip(self.pid)?;
        // INT3 执行后 RIP 指向下一条；断点地址 = RIP − 1。
        let address = rip.wrapping_sub(1);
        let Some(breakpoint) = self.breakpoints.get(&address).copied() else {
            // 不是我们的断点（别的 SIGTRAP 源）：当普通信号继续。
            self.continue_all(libc::SIGTRAP)?;
            return Ok(None);
        };
        *hits.entry(address).or_insert(0) += 1;
        // 恢复原字节。
        let aligned = address & !7;
        let offset = (address & 7) as usize;
        let word = peek_word(self.pid, aligned)? as u64;
        let restored =
            (word & !(0xffu64 << (8 * offset))) | (u64::from(breakpoint.original) << (8 * offset));
        poke_word(self.pid, aligned, restored as libc::c_long)?;
        // 回退 RIP 到断点地址并单步执行原指令。
        set_regs_rip(self.pid, address)?;
        let step = unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, self.pid, 0, 0) };
        if step == -1 {
            return Err(HostError::Proc(format!(
                "PTRACE_SINGLESTEP: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut status = 0;
        if unsafe { libc::waitpid(self.pid, &mut status, 0) } == -1 {
            return Err(HostError::Proc("waitpid after single-step failed".into()));
        }
        // 重新装回 INT3 并继续。
        let word = peek_word(self.pid, aligned)? as u64;
        let patched = (word & !(0xffu64 << (8 * offset))) | (0xccu64 << (8 * offset));
        poke_word(self.pid, aligned, patched as libc::c_long)?;
        self.continue_all(0)?;
        Ok(Some(address))
    }

    fn continue_all(&self, signal: i32) -> Result<(), HostError> {
        let rc = unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, 0, signal) };
        if rc == -1 {
            return Err(HostError::Proc(format!(
                "PTRACE_CONT: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// 分离：恢复全部原字节后 `PTRACE_DETACH`。目标已死时静默。
    ///
    /// # Errors
    /// 恢复或分离失败（目标存活时的失败才是错误）。
    pub fn detach(mut self) -> Result<(), HostError> {
        let result = self.restore_all();
        let rc = unsafe { libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0) };
        if rc == -1 {
            let error = std::io::Error::last_os_error();
            // ESRCH = 目标已退出：恢复无意义，静默成功。
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(HostError::Proc(format!("PTRACE_DETACH: {error}")));
            }
        }
        result
    }

    fn restore_all(&mut self) -> Result<(), HostError> {
        let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
        for address in addresses {
            let Some(breakpoint) = self.breakpoints.get(&address).copied() else {
                continue;
            };
            let aligned = address & !7;
            let offset = (address & 7) as usize;
            // 目标已死（ESRCH）= 无字节可恢复，跳过（detach 路径语义）。
            let Ok(word) = peek_word(self.pid, aligned) else {
                continue;
            };
            let restored = (word as u64 & !(0xffu64 << (8 * offset)))
                | (u64::from(breakpoint.original) << (8 * offset));
            if poke_word(self.pid, aligned, restored as libc::c_long).is_err() {
                continue;
            }
        }
        self.breakpoints.clear();
        Ok(())
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        // 尽力而为的恢复 + 分离；错误吞掉（Drop 不能 panic）。
        let _ = self.restore_all();
        unsafe {
            let _ = libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0);
        }
    }
}

/// `PTRACE_PEEKDATA`：读一个机器字（-1/errno 歧义按 man 语义处理）。
fn collect(hits: BTreeMap<u64, u64>) -> Vec<HitReport> {
    hits.into_iter()
        .map(|(address, hits)| HitReport { address, hits })
        .collect()
}

fn peek_word(pid: i32, address: u64) -> Result<libc::c_long, HostError> {
    unsafe {
        // man 语义：PEEK 的 -1 是合法数据；先清 errno 再判变化。
        *libc::__errno_location() = 0;
        let word = libc::ptrace(libc::PTRACE_PEEKDATA, pid, address as *mut libc::c_void, 0);
        let errno = *libc::__errno_location();
        if word == -1 && errno != 0 {
            return Err(HostError::Proc(format!(
                "PEEKDATA {address:#x}: {}",
                std::io::Error::from_raw_os_error(errno)
            )));
        }
        Ok(word)
    }
}

/// `PTRACE_POKEDATA`：写一个机器字。
fn poke_word(pid: i32, address: u64, word: libc::c_long) -> Result<(), HostError> {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEDATA,
            pid,
            address as *mut libc::c_void,
            word as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(HostError::Proc(format!(
            "POKEDATA {address:#x}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `PTRACE_GETREGS` 取 RIP。
fn get_regs_rip(pid: i32) -> Result<u64, HostError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) };
    if rc == -1 {
        return Err(HostError::Proc(format!(
            "GETREGS: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(regs.rip)
}

/// `PTRACE_SETREGS` 回退 RIP。
fn set_regs_rip(pid: i32, rip: u64) -> Result<(), HostError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) };
    if rc == -1 {
        return Err(HostError::Proc(format!(
            "GETREGS: {}",
            std::io::Error::last_os_error()
        )));
    }
    regs.rip = rip;
    let rc = unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &regs) };
    if rc == -1 {
        return Err(HostError::Proc(format!(
            "SETREGS: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 活体 trace e2e（宿主机 + `KOTAMA_LIVE_E2E=1`）：ELF spin(-O0) 的 `tick`
    /// 每秒执行 10 次——断点 3 秒应命中 ≥ 15 次，且分离后目标继续活到自然退出。
    #[test]
    fn live_e2e_breakpoint_counts_tick_hits() {
        if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
            eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the live e2e");
            return;
        }
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-linux-gnu/-O0/spin");
        if !fixture.exists() {
            panic!("fixture missing: run tools/build_fixtures.py first");
        }
        let fixture = fixture.canonicalize().expect("canonicalize fixture");
        let data = std::fs::read(&fixture).unwrap();
        let module = kotama_image::LoadedModule::parse(&data).unwrap();
        let functions = kotama_scan::discover(&module);
        let tick = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("tick"))
            .expect("tick symbol present at -O0");
        // 绝对地址：非 PIE ELF 的 symtab 值已是绝对地址；PIE（zig 默认 ET_DYN）运行时
        // 基址由装载器定——我们用自己的 image_base 口径（最小 LOAD vaddr）换算：
        // 绝对 = 进程基址 + (symtab_addr - image_base)。这里直接用子进程的 /proc/maps
        // 找基址（第一个可执行映射的文件偏移 0 页）。
        let mut child = std::process::Command::new(&fixture)
            .arg("8")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn spin");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(700));

        // 映像基址 = 与目标二进制同路径的映射的最小起始（r-x 段的 file-offset 非 0，
        // 早期「exec+offset==0」的判法会选错映射——PEEKDATA EIO 实抓）。
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        let load_base = crate::parse_maps(&maps)
            .iter()
            .filter(|entry| entry.path == fixture.to_string_lossy())
            .map(|entry| entry.start)
            .min()
            .expect("image base mapping");
        let absolute = load_base + tick.rva;

        let mut session = TraceSession::attach(pid).expect("attach");
        session.set_breakpoint(absolute).expect("set breakpoint");
        let reports = session.run(std::time::Duration::from_secs(3)).expect("run");
        session.detach().expect("detach");

        assert!(!reports.is_empty(), "no hits recorded");
        assert!(reports[0].hits >= 15, "hits: {reports:?}");
        // 分离后目标应活着自然退出（退出码 0）。
        let status = child.wait().expect("wait");
        assert!(status.success(), "target died or misbehaved: {status}");
    }
}
