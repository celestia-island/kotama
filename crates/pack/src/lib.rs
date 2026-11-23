//! 载荷打包：交叉编译 `kotama-payload` + 产出 manifest。
//!
//! 「不留脚手架」的验收口径：**pack 的产物必须能直接进 own-launch e2e 跑通**——
//! manifest 不是摆设，`live launch --preload dist/<triple>/…so` 用的是 pack 出来的那颗。
//!
//! 支持面（P4 首版）：`x86_64-linux-gnu`（本机 cargo 原生目标，零额外工具链）与
//! `x86-linux-gnu`（需 rustup 目标在位，缺了给明确指引）。**Windows 目标显式拒绝**：
//! 载荷的 windows agent 是命名管道车道（wine 下宿主侧无法直连验证），随专用轮交付——
//! 不产出空的 `.dll` 假装可用。
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
        "x86_64-pc-windows-gnu" => Ok((PayloadKind::CWindowsAgent, "kotama_agent.dll")),
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
        proto_version: 2,
        capabilities: vec!["list-modules", "read-memory"],
        entry: "init_array",
        exports,
    };
    let manifest_path = out_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| PackError::Io(e.to_string()))?;
    std::fs::write(&manifest_path, json + "\n").map_err(|e| PackError::Io(e.to_string()))?;
    Ok(manifest)
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
    let staging = std::env::temp_dir().join(format!("kotama-win-agent-{target}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| PackError::Io(e.to_string()))?;

    let output = std::process::Command::new("python3")
        .arg(&script)
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
        proto_version: 2,
        capabilities: vec!["list-modules", "read-memory"],
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
    if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-gnu"
    } else {
        "i686-unknown-linux-gnu"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_target_routes_to_the_c_agent() {
        // windows 载荷是 C agent（zig cc 构建），不是 rust cdylib；未知 triple 仍拒绝。
        let (kind, name) = target_plan("x86_64-pc-windows-gnu").unwrap();
        assert_eq!(kind, PayloadKind::CWindowsAgent);
        assert_eq!(name, "kotama_agent.dll");
        assert!(matches!(
            target_plan("aarch64-unknown-linux-gnu"),
            Err(PackError::Unsupported { .. })
        ));
    }

    #[test]
    fn linux_targets_map_to_so() {
        assert_eq!(
            target_plan("x86_64-unknown-linux-gnu").unwrap().1,
            "libkotama_payload.so"
        );
    }

    /// pack 产物功能验收（宿主机 + `KOTAMA_PACK_E2E=1`）：打出的 .so 必须能直接进
    /// own-launch（这是「pack 不产摆设」的判据——manifest 里的 sha256 即被注入的那颗）。
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
}
