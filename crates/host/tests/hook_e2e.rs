//! 活体钩子 e2e：在 hookme.exe 里把 `beat` 换成一个返回常量的桩，看 stdout 变了。
//!
//! 这是「挂载」第四环的终点证据：`discover` 找到函数 → `install::plan` 从字节算出
//! trampoline 与跳转 → `Session::install_hook` 写进去 → 目标进程的行为变了。
//! 桩是 `mov eax, imm32; ret`，常量 0x5A5A（23130）——一个 beat 自己永远不会返回的值
//! （它返回 1..4）。`hookme.c` 的 beat 序言是纯栈操作，没有 RIP-relative 指令，
//! 所以能整段搬进 trampoline；spin 的 main 在第 4 字节就有一条，plan 正确地拒绝它。
//!
//! `KOTAMA_LIVE_E2E=1` 门控，与其他活体测试同一条账。

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kotama_host::control::Session;
use kotama_host::TargetProcess;
use kotama_scan::install::plan;

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn target_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/generated/x86_64-windows-gnu/-O2/hookme.exe")
}

/// 等到 stdout 出现第一行心跳：证明 main 已进入循环，tick 正在被调。
fn wait_first_beat(reader: &mut BufReader<std::process::ChildStdout>) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => panic!("hookme exited before its first beat"),
            Ok(_) => {
                if line.contains("hookme:") {
                    return line;
                }
            }
        }
        assert!(Instant::now() < deadline, "no first beat within 15s");
    }
}

/// 活体钩子：钩住 tick，spin 的下一次心跳打出桩的常量。
///
/// 等到第一拍（钩前）后安装，再等下一拍：它必须是 23130。第一拍是什么不重要，
/// 第二拍是。两拍之间安装，所以「行为变了」只能归因于钩子。
///
/// mutate: hook-not-installed (a no-op install_hook leaves tick alone; the
/// second beat never reads 23130 and the equality fails).
#[test]
fn a_installed_hook_changes_what_the_target_prints() {
    if std::env::var_os("KOTAMA_LIVE_E2E").is_none() {
        eprintln!("skip: set KOTAMA_LIVE_E2E=1 to run the native hook e2e");
        return;
    }
    let target = target_path();
    assert!(target.is_file(), "fixture missing: {}", target.display());
    let mut child = ChildGuard(
        Command::new(&target)
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn hookme"),
    );
    let stdout = child.0.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let first = wait_first_beat(&mut reader);
    assert!(first.contains("hookme:"), "{first}");

    let pid = child.0.id() as i32;
    let session =
        Session::with_write(TargetProcess::open(pid).expect("open hookme")).expect("with_write");

    // 找到 hookme 自己的映像和 beat：映像里第一个定义的函数（rva 最小、带 CallTarget
    // 证据、plan 得出来）。不能按名字找——夹具是 -s 的，没有符号表。
    let modules = session.process().modules().expect("modules");
    let base = modules
        .iter()
        .find(|m| m.path.to_ascii_lowercase().ends_with("hookme.exe"))
        .expect("hookme.exe in the module list")
        .base;
    let data = std::fs::read(&target).expect("read hookme.exe");
    let module = kotama_image::LoadedModule::parse(&data).expect("parse hookme");
    let functions = kotama_scan::discover(&module);
    // beat 是映像里第一个定义的函数：rva 最小、带 CallTarget 证据、plan 得出来。
    // 不能按名字找——夹具是 -s 的，没有符号表。
    let mut candidates: Vec<&kotama::FunctionEntry> = functions
        .iter()
        .filter(|f| f.evidence.contains(&kotama::Evidence::CallTarget) && f.rva < 0x1000 + 0x100)
        .collect();
    candidates.sort_by_key(|f| f.rva);
    let beat = *candidates.first().expect("beat: the first called function");
    let entry = base + beat.rva;
    use kotama::AddressSpace as _;
    let space = module.address_space();
    let end = beat.rva + beat.size;
    let code = space
        .read(beat.rva, (end - beat.rva) as usize)
        .expect("read beat")
        .to_vec();
    // 一次分配两页，都在 entry 附近（rel32 ±2 GB）：第一页放桩，第二页放 trampoline。
    // 两次分配同一个 hint 会撞页。
    let pages = session
        .alloc_remote(0x2000, Some(entry))
        .expect("alloc two pages near entry");
    let stub_addr = pages;
    let trampoline_addr = pages + 0x1000;
    // 桩必须遵守 beat 的 ABI：它替代的是整个函数，所以要做 beat 的序言
    // （push rbp; push rax; mov rbp,rsp），设返回值，再做 beat 的 epilogue
    // （add rsp,8; pop rbp; ret）。第一版的桩只有 `mov eax; ret`，栈不平衡，
    // 调用者回到垃圾地址——安装成功了，行为却没变，因为 beat 根本没返回。
    let stub: Vec<u8> = [
        0x55, 0x50, 0x48, 0x89, 0xE5, // push rbp; push rax; mov rbp, rsp
        0xB8, 0x5A, 0x5A, 0x00, 0x00, // mov eax, 0x5A5A
        0x48, 0x83, 0xC4, 0x08, 0x5D, 0xC3, // add rsp, 8; pop rbp; ret
    ]
    .to_vec();
    session.write_bytes(stub_addr, &stub).expect("write stub");
    let install = plan(&code, &[], entry, stub_addr, trampoline_addr).expect("plan the hook");

    session.install_hook(&install).expect("install");

    // 下一拍必须是桩的常量。
    // 下一拍必须是桩的常量。stdout 是行缓冲的，安装前可能已有一行在管道里，
    // 所以读到出现 0x5A5A 为止，而不是只看紧接着的那一行。
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => panic!("hookme exited before a hooked beat"),
            Ok(_) => {
                if let Some(n) = line
                    .trim()
                    .strip_prefix("hookme: ")
                    .and_then(|s| s.parse::<i32>().ok())
                {
                    if n == 0x5A5A {
                        break;
                    }
                }
            }
        }
        assert!(Instant::now() < deadline, "no hooked beat within 5s");
    }
    // 卸载：写回原字节，下一拍回到 tick 自己的值。
    session.uninstall_hook(&install).expect("uninstall");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if let Some(n) = line
                    .trim()
                    .strip_prefix("hookme: ")
                    .and_then(|s| s.parse::<i32>().ok())
                {
                    assert_ne!(
                        n, 0x5A5A,
                        "after uninstall the beat is tick's own again; line {line:?}"
                    );
                    break;
                }
            }
        }
        assert!(Instant::now() < deadline, "no unhooked beat within 5s");
    }
}
