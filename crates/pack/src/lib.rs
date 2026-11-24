//! 载荷打包：交叉编译 `kotama-payload` + 产出 manifest。
//!
//! 「不留脚手架」的验收口径：**pack 的产物必须能直接进 own-launch e2e 跑通**——
//! manifest 不是摆设，`live launch --preload dist/<triple>/…so` 用的是 pack 出来的那颗。
//!
//! 支持面：`x86_64-linux-gnu` / `i686-linux-gnu` 走 Rust cdylib；
//! `x86_64-pc-windows-gnu` 走 zig cc 的 C agent + `kotama_load.exe`；
//! `x86_64/i686-pc-windows-msvc` 走 Rust cdylib。其它目标显式拒绝，不产出空产物假装可用。
//!
//! manifest 确定性：无时间戳、字段排序稳定、符号表升序——同源码两次 pack 逐字节相同
//! （除编译器自身非确定性外；`sha256` 如实记录产物）。

use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

/// 打包错误。
#[derive(Debug)]
pub enum PackError {
    /// cargo 构建失败。
    Build {
        /// 目标 triple。
        target: String,
        /// stderr 尾部（够定位即可）。
        tail: String,
    },
    /// 产物找不到（构建声称成功但文件不在预期位置）。
    MissingArtifact {
        /// 目标 triple。
        target: String,
        /// 预期路径。
        path: String,
    },
    /// 目标不受支持（含原因与指引）。
    Unsupported {
        /// 目标 triple。
        target: String,
        /// 不支持的原因（与指引）。
        reason: String,
    },
    /// manifest 写出失败。
    Io(String),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build { target, tail } => {
                write!(f, "cargo build for {target} failed:\n{tail}")
            }
            Self::MissingArtifact { target, path } => {
                write!(f, "artifact for {target} not found at {path}")
            }
            Self::Unsupported { target, reason } => {
                write!(f, "target {target} unsupported: {reason}")
            }
            Self::Io(msg) => write!(f, "io: {msg}"),
        }
    }
}

impl std::error::Error for PackError {}

/// 一个产物的 manifest。
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// 目标 triple。
    pub target: String,
    /// 产物文件名（相对 manifest 所在目录）。
    pub file: String,
    /// 产物字节数。
    pub size_bytes: u64,
    /// 产物 sha256（hex）。
    pub sha256: String,
    /// 载荷 ABI（与根包 [`kotama::ABI_VERSION`] 同源）。
    pub abi_version: u16,
    /// wire 协议版本（握手无回退）。
    pub proto_version: u16,
    /// 载荷能力（与 payload 源同源声明）。
    pub capabilities: Vec<&'static str>,
    /// 入场机制（cdylib 无导出入口——装载即登记）。
    pub entry: &'static str,
    /// 载荷的动态导出符号（cdylib 通常为空；留字段供 hook 原语时代的导出面）。
    pub exports: Vec<String>,
}

/// 载荷实现形态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PayloadKind {
    /// Rust cdylib（cargo 构建）。
    RustCdylib,
    /// C agent（zig cc 构建）+ wine 装载器。
    CWindowsAgent,
}

/// 支持的目标与其构建方式。
fn target_plan(target: &str) -> Result<(PayloadKind, &'static str), PackError> {
    // 注意 triple 词汇是 rust 的（`x86_64-unknown-linux-gnu`），不是 clang/zig 的短形。
    match target {
        "x86_64-unknown-linux-gnu" => Ok((PayloadKind::RustCdylib, "libkotama_payload.so")),
        "i686-unknown-linux-gnu" => Ok((PayloadKind::RustCdylib, "libkotama_payload.so")),
        "x86_64-pc-windows-gnu" | "i686-pc-windows-gnu" => {
            Ok((PayloadKind::CWindowsAgent, "kotama_agent.dll"))
        }
        "x86_64-pc-windows-msvc" | "i686-pc-windows-msvc" => {
            Ok((PayloadKind::RustCdylib, "kotama_payload.dll"))
        }
        other => Err(PackError::Unsupported {
            target: other.to_string(),
            reason: "linux-gnu (rust cdylib) and x86_64-pc-windows-gnu (C agent) only".into(),
        }),
    }
}

/// 打包一个目标：构建 → 拷到 dist → 写 manifest。
///
/// `repo_root` = 仓根（cargo 在这里跑）；`dist_root` = dist 目录（默认 `<repo>/dist`）。
///
/// # Errors
/// 构建 / 产物定位 / manifest 写出失败。
pub fn pack_target(
    repo_root: &Path,
    dist_root: &Path,
    target: &str,
) -> Result<Manifest, PackError> {
    // 入口统一规范化：调用方常传来带 `..` 的编译期路径（CARGO_MANIFEST_DIR/../..），
    // 不规范化会让 is_file / create_dir_all 落在不同字面路径上（实踩）。
    let repo_root = &lexical_normalize(repo_root);
    let dist_root = &lexical_normalize(dist_root);
    let (kind, artifact_name) = target_plan(target)?;
    if kind == PayloadKind::CWindowsAgent {
        return pack_windows_agent(repo_root, dist_root, target);
    }

    // cargo build（inherit 环境：CARGO_TARGET_DIR 等照常生效）。
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .arg("build")
            .arg("--release")
            .arg("-p")
            .arg("kotama-payload")
            .arg("--target")
            .arg(target)
            .current_dir(repo_root)
            .output()
            .map_err(|e| PackError::Build {
                target: target.into(),
                tail: e.to_string(),
            })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let start = stderr.len().saturating_sub(1500);
        return Err(PackError::Build {
            target: target.into(),
            tail: stderr[start..].to_string(),
        });
    }

    // 定位产物（尊重 CARGO_TARGET_DIR）。
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("target"));
    let built = target_dir.join(target).join("release").join(artifact_name);
    if !built.is_file() {
        return Err(PackError::MissingArtifact {
            target: target.into(),
            path: built.display().to_string(),
        });
    }

    // dist 布局 + manifest。
    let out_dir = dist_root.join(target);
    std::fs::create_dir_all(&out_dir).map_err(|e| PackError::Io(e.to_string()))?;
    let out_file = out_dir.join(artifact_name);
    std::fs::copy(&built, &out_file).map_err(|e| PackError::Io(e.to_string()))?;
    let bytes = std::fs::read(&out_file).map_err(|e| PackError::Io(e.to_string()))?;
    let sha256 = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    // 导出面：用自家 image 管线读产物的 dynsym（自吃狗粮）。
    let exports = match kotama_image::LoadedModule::parse(&bytes) {
        Ok(module) => module
            .dynamic_symbols
            .iter()
            .map(|symbol| symbol.name.clone())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    let manifest = Manifest {
        target: target.to_string(),
        file: artifact_name.to_string(),
        size_bytes: bytes.len() as u64,
        sha256,
        abi_version: kotama::ABI_VERSION,
        proto_version: kotama_proto::PROTO_VERSION,
        capabilities: payload_capabilities(target),
        entry: if target.ends_with("-pc-windows-msvc") {
            "dllmain+loadlibrary"
        } else {
            "init_array"
        },
        exports,
    };
    let manifest_path = out_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| PackError::Io(e.to_string()))?;
    std::fs::write(&manifest_path, json + "\n").map_err(|e| PackError::Io(e.to_string()))?;
    Ok(manifest)
}

/// manifest 能力与载荷握手共用同一份声明，写/冻结不随只读包静默开放。
///
/// 只有 MSVC 的 Rust payload 声明了 `stack-snapshot`；GNU C agent 与 Linux cdylib
/// 都没有该实现，manifest 必须和各自握手保持一致。
fn payload_capabilities(target: &str) -> Vec<&'static str> {
    let mut capabilities: Vec<&'static str> = kotama_proto::READ_ONLY_CAPABILITIES
        .iter()
        .map(|capability| capability.as_str())
        .collect();
    if target.ends_with("-pc-windows-msvc") {
        capabilities.push(kotama_proto::Capability::StackSnapshot.as_str());
    }
    capabilities
}

/// 构建脚本解释器：Windows 的 `python3` 常是商店占位符，优先用可配置的 `python`。
fn python_launcher() -> String {
    std::env::var("KOTAMA_PYTHON").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") {
            "python".into()
        } else {
            "python3".into()
        }
    })
}

/// windows 载荷打包：跑 `tools/build_windows_agent.py`（zig cc 出 dll + loader）。
fn pack_windows_agent(
    repo_root: &Path,
    dist_root: &Path,
    target: &str,
) -> Result<Manifest, PackError> {
    // 子进程写 NFS 目录、父进程立刻读到，在这块存储上不可靠（close-to-open 下
    // 父进程 dentry 缓存可能仍缺席，实踩多次）。绕法：让脚本产出到本地 /tmp，
    // 由本进程拷贝进 dist —— 读的是 /tmp，写的是 dist，无跨进程可见性问题。
    let script = repo_root.join("tools/build_windows_agent.py");
    static NEXT_STAGING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT_STAGING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = std::env::temp_dir().join(format!(
        "kotama-win-agent-{target}-{}-{sequence}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| PackError::Io(e.to_string()))?;

    let zig_target = match target {
        "x86_64-pc-windows-gnu" => "x86_64-windows-gnu",
        "i686-pc-windows-gnu" => "x86-windows-gnu",
        _ => unreachable!("target_plan admitted a non-windows-gnu C agent"),
    };
    let output = std::process::Command::new(python_launcher())
        .arg(&script)
        .arg("--target")
        .arg(zig_target)
        .arg("--out-dir")
        .arg(&staging)
        .current_dir(repo_root)
        .output()
        .map_err(|e| PackError::Build {
            target: target.into(),
            tail: e.to_string(),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = stderr
            .chars()
            .skip(stderr.chars().count().saturating_sub(1200))
            .collect();
        return Err(PackError::Build {
            target: target.into(),
            tail,
        });
    }

    let agent = staging.join("kotama_agent.dll");
    let loader = staging.join("kotama_load.exe");
    if !agent.is_file() || !loader.is_file() {
        let probe: Vec<String> = std::fs::read_dir(&staging)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        return Err(PackError::MissingArtifact {
            target: target.into(),
            path: format!("{} (present: {:?})", staging.display(), probe),
        });
    }

    let out_dir = lexical_normalize(&dist_root.join(target));
    std::fs::create_dir_all(&out_dir).map_err(|e| PackError::Io(e.to_string()))?;
    let out_agent = out_dir.join("kotama_agent.dll");
    let out_loader = out_dir.join("kotama_load.exe");
    std::fs::copy(&agent, &out_agent).map_err(|e| PackError::Io(e.to_string()))?;
    std::fs::copy(&loader, &out_loader).map_err(|e| PackError::Io(e.to_string()))?;

    let bytes = std::fs::read(&out_agent).map_err(|e| PackError::Io(e.to_string()))?;
    let sha256 = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let exports = match kotama_image::LoadedModule::parse(&bytes) {
        Ok(module) => module
            .dynamic_symbols
            .iter()
            .map(|symbol| symbol.name.clone())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    let manifest = Manifest {
        target: target.to_string(),
        file: "kotama_agent.dll".to_string(),
        size_bytes: bytes.len() as u64,
        sha256,
        abi_version: kotama::ABI_VERSION,
        proto_version: kotama_proto::PROTO_VERSION,
        capabilities: payload_capabilities(target),
        entry: "dllmain+loadlibrary",
        exports,
    };
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| PackError::Io(e.to_string()))?;
    std::fs::write(out_dir.join("manifest.json"), json + "\n")
        .map_err(|e| PackError::Io(e.to_string()))?;
    Ok(manifest)
}

/// 词法规范化路径（吃掉 `..` 与 `.`，不需要路径真实存在）。
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// 默认目标（宿主）。
#[must_use]
pub fn default_target() -> &'static str {
    match (cfg!(target_os = "windows"), cfg!(target_arch = "x86_64")) {
        (true, true) => "x86_64-pc-windows-gnu",
        (true, false) => "i686-pc-windows-gnu",
        (false, true) => "x86_64-unknown-linux-gnu",
        (false, false) => "i686-unknown-linux-gnu",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows 会锁定正在执行/装载的 PE；真机 pack e2e 共用 dist，必须进程内串行。
    #[cfg(target_os = "windows")]
    static PACK_E2E_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn windows_target_routes_to_the_c_agent() {
        // windows 载荷是 C agent（zig cc 构建），不是 rust cdylib；未知 triple 仍拒绝。
        for target in ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"] {
            let (kind, name) = target_plan(target).unwrap();
            assert_eq!(kind, PayloadKind::CWindowsAgent);
            assert_eq!(name, "kotama_agent.dll");
        }
        assert!(matches!(
            target_plan("aarch64-unknown-linux-gnu"),
            Err(PackError::Unsupported { .. })
        ));
    }

    #[test]
    fn msvc_targets_map_to_the_rust_payload() {
        for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
            let (kind, name) = target_plan(target).unwrap();
            assert_eq!(kind, PayloadKind::RustCdylib);
            assert_eq!(name, "kotama_payload.dll");
        }
    }

    #[test]
    fn manifest_capabilities_come_from_the_wire_declaration() {
        assert_eq!(
            payload_capabilities("x86_64-unknown-linux-gnu"),
            ["list-modules", "read-memory"]
        );
        assert_eq!(
            payload_capabilities("x86_64-pc-windows-gnu"),
            ["list-modules", "read-memory"]
        );
        assert_eq!(
            payload_capabilities("x86_64-pc-windows-msvc"),
            ["list-modules", "read-memory", "stack-snapshot"]
        );
    }

    #[test]
    fn linux_targets_map_to_so() {
        assert_eq!(
            target_plan("x86_64-unknown-linux-gnu").unwrap().1,
            "libkotama_payload.so"
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn default_target_is_the_native_windows_lane() {
        assert_eq!(default_target(), "x86_64-pc-windows-gnu");
    }

    /// pack 产物功能验收（宿主机 + `KOTAMA_PACK_E2E=1`）：打出的 .so 必须能直接进
    /// own-launch（这是「pack 不产摆设」的判据——manifest 里的 sha256 即被注入的那颗）。
    #[cfg(target_os = "linux")]
    #[test]
    fn pack_artifact_works_in_own_launch() {
        if std::env::var_os("KOTAMA_PACK_E2E").is_none() {
            eprintln!("skip: set KOTAMA_PACK_E2E=1 to run the pack e2e");
            return;
        }
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let dist = repo.join("dist");
        let manifest = pack_target(&repo, &dist, "x86_64-unknown-linux-gnu").expect("pack");
        let payload = dist.join(&manifest.target).join(&manifest.file);
        assert!(payload.is_file());
        // sha256 复核：manifest 记录的就是盘上这颗。
        let bytes = std::fs::read(&payload).unwrap();
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, manifest.sha256);

        // 打包产物直接进 own-launch。
        let fixture = repo
            .join("fixtures/generated/x86_64-linux-gnu/-O2/spin")
            .canonicalize()
            .expect("fixture");
        let command = vec![fixture.to_string_lossy().into_owned(), "6".into()];
        let payload_arg = payload.to_string_lossy().into_owned();
        let mut launched = kotama_host::launch::launch(&payload_arg, &command).expect("launch");
        let report = kotama_host::launch::probe(&mut launched, &command).expect("probe");
        let _ = launched.child.kill();
        let _ = launched.child.wait();
        let magic = report.image_magic.expect("magic");
        assert_eq!(
            &magic, b"\x7fELF",
            "packed artifact must serve in-process reads"
        );
    }

    /// 32 位 windows-gnu pack e2e：在 64 位 Windows 的 WOW64 下装载并运行 32 位 spin。
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn pack_windows_gnu_x86_artifact_loads_natively() {
        if std::env::var_os("KOTAMA_PACK_E2E").is_none() {
            eprintln!("skip: set KOTAMA_PACK_E2E=1 to run the 32-bit Windows pack e2e");
            return;
        }
        let _serial = PACK_E2E_LOCK.lock().expect("pack e2e lock");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let dist = repo.join("dist");
        let manifest = pack_target(&repo, &dist, "i686-pc-windows-gnu").expect("pack x86");
        let out_dir = dist.join(&manifest.target);
        let fixture = repo
            .join("fixtures/generated/x86-windows-gnu/-O2/spin.exe")
            .canonicalize()
            .expect("32-bit fixture missing: run tools/build_fixtures.py first");
        let output = std::process::Command::new(out_dir.join("kotama_load.exe"))
            .arg(out_dir.join(&manifest.file))
            .arg("--")
            .arg(&fixture)
            .arg("1")
            .output()
            .expect("run the 32-bit loader");
        assert!(
            output.status.success(),
            "32-bit loader failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("spin: "));
    }

    /// MSVC pack e2e：构建 Rust cdylib，并复用 windows-gnu loader 做原生 LoadLibrary 回归。
    /// 这里验证的是 loader 自身内的载荷登记，不冒充对 spin.exe 的远程注入。
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn pack_windows_msvc_artifact_loads_natively() {
        if std::env::var_os("KOTAMA_PACK_E2E").is_none() {
            eprintln!("skip: set KOTAMA_PACK_E2E=1 to run the MSVC pack e2e");
            return;
        }
        let _serial = PACK_E2E_LOCK.lock().expect("pack e2e lock");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let dist = repo.join("dist");
        let manifest = pack_target(&repo, &dist, "x86_64-pc-windows-msvc").expect("pack msvc");
        assert_eq!(manifest.proto_version, kotama_proto::PROTO_VERSION);
        assert_eq!(manifest.entry, "dllmain+loadlibrary");
        assert!(manifest.capabilities.contains(&"stack-snapshot"));
        let agent = dist.join(&manifest.target).join(&manifest.file);
        assert!(agent.is_file());

        // loader 属于 windows-gnu C agent 包；缺了就通过公开 pack 入口补建。
        let gnu_target = "x86_64-pc-windows-gnu";
        let loader = dist.join(gnu_target).join("kotama_load.exe");
        if !loader.is_file() {
            pack_target(&repo, &dist, gnu_target).expect("pack loader lane");
        }
        let fixture = repo
            .join("fixtures/generated/x86_64-windows-gnu/-O2/spin.exe")
            .canonicalize()
            .expect("fixture missing: run tools/build_fixtures.py first");
        let output = std::process::Command::new(&loader)
            .arg(&agent)
            .arg("--")
            .arg(&fixture)
            .arg("1")
            .output()
            .expect("load the MSVC Rust payload");
        assert!(
            output.status.success(),
            "loader failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("spin: "));
    }

    /// Windows pack e2e（`KOTAMA_PACK_E2E=1` + `KOTAMA_ZIG`）：重新打包 C agent，
    /// 校验 manifest 哈希，再用产出的 loader 在原生 Windows 真机 LoadLibrary 并拉起 spin。
    #[cfg(target_os = "windows")]
    #[test]
    fn pack_windows_artifact_loads_natively() {
        if std::env::var_os("KOTAMA_PACK_E2E").is_none() {
            eprintln!("skip: set KOTAMA_PACK_E2E=1 to run the Windows pack e2e");
            return;
        }
        let _serial = PACK_E2E_LOCK.lock().expect("pack e2e lock");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let dist = repo.join("dist");
        let manifest = pack_target(&repo, &dist, "x86_64-pc-windows-gnu").expect("pack");
        assert_eq!(manifest.proto_version, kotama_proto::PROTO_VERSION);
        assert!(!manifest.capabilities.contains(&"stack-snapshot"));
        let out_dir = dist.join(&manifest.target);
        let agent = out_dir.join(&manifest.file);
        let loader = out_dir.join("kotama_load.exe");
        let fixture = repo
            .join("fixtures/generated/x86_64-windows-gnu/-O2/spin.exe")
            .canonicalize()
            .expect("fixture missing: run tools/build_fixtures.py first");

        let bytes = std::fs::read(&agent).unwrap();
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&bytes);
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, manifest.sha256);

        let output = std::process::Command::new(&loader)
            .arg(&agent)
            .arg("--")
            .arg(&fixture)
            .arg("1")
            .output()
            .expect("run kotama_load with the packed agent");
        assert!(
            output.status.success(),
            "loader failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.lines().any(|line| line.starts_with("spin: ")),
            "target did not run after payload load: {stdout:?}"
        );
    }
}
