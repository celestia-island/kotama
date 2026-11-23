//! Ghidra headless 外接车道：把 Ghidra 当**差分 oracle**，不当依赖（设计案 §1 裁决 2/§4.5）。
//!
//! 职责边界：只经子进程与文件交互（`analyzeHeadless` + postScript），不链接、不 vendored、
//! 不进产物。Ghidra 本体 Apache-2.0；其 `GPL/` 目录的辅助程序不在本车道的调用面里。
//!
//! 差分口径（P1 第一版）：**函数入口集合的 Jaccard**。两边各自给出「函数入口 RVA 集合」，
//! 对齐方式 = Ghidra 入口减去程序 image base 得 RVA（ELF PIE 的 0x100000 基、PE 的
//! 0x140000000/0x400000 基都由脚本侧用 `getImageBase` 归一）。
//! 输出双方独有集合（各截前 25 条）供人工/智能体裁定「谁错」。
//!
//! 环境发现（都不设也能跑，只要路径在默认位）：
//! - `KOTAMA_GHIDRA_HOME`：Ghidra 安装目录（Linux 默认扫 `/mnt/work/ghidra/ghidra_*`
//!   取字典序最大；Windows 必须显式设置）。
//! - `KOTAMA_JDK_HOME`：JDK 目录（Linux 默认 `/mnt/work/jdk`；Ghidra 12.2 要 JDK 25）。
//! - `KOTAMA_GHIDRA_SCRIPTS`：postScript 目录（默认相对仓根 `support/ghidra`）。

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use kotama::FunctionEntry;

/// oracle 车道错误。
#[derive(Debug)]
pub enum OracleError {
    /// 本机没有 Ghidra / JDK（车道不可用，调用方应降级为 skip）。
    Environment(String),
    /// analyzeHeadless 跑了但失败。
    Run {
        /// 子进程退出码。
        code: i32,
        /// stderr 末尾（截尾几行，够定位即可）。
        tail: String,
    },
    /// 输出清单解析失败。
    Parse(String),
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Environment(msg) => write!(f, "ghidra environment: {msg}"),
            Self::Run { code, tail } => write!(f, "analyzeHeadless exit {code}: {tail}"),
            Self::Parse(msg) => write!(f, "function-list parse: {msg}"),
        }
    }
}

impl std::error::Error for OracleError {}

/// Ghidra 报告的一个函数。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GhidraFunction {
    /// 入口 RVA（已减 image base）。
    pub rva: u64,
    /// Ghidra 认得的名字（`FUN_…` 表示无符号）。
    pub name: String,
}

/// 差分报告。
#[derive(Clone, Debug)]
pub struct DiffReport {
    /// 我方入口数。
    pub ours: usize,
    /// Ghidra 入口数。
    pub theirs: usize,
    /// 双方一致（入口重合）的数量。
    pub matched: usize,
    /// 入口集合 Jaccard（交集 / 并集，0–1）。
    pub jaccard: f64,
    /// 只有我方有的入口（升序，已截断）。
    pub only_ours: Vec<(u64, Vec<&'static str>)>,
    /// 只有 Ghidra 有的入口（升序，已截断）。
    pub only_theirs: Vec<(u64, String)>,
}

/// 一次可复用的 oracle 会话（目录解析一次，跑多个二进制）。
pub struct GhidraOracle {
    ghidra_home: PathBuf,
    jdk_home: PathBuf,
    scripts_dir: PathBuf,
}

impl GhidraOracle {
    /// 按环境发现装配；找不到就报 [`OracleError::Environment`]。
    ///
    /// # Errors
    /// Ghidra / JDK / 脚本目录缺失时返回环境错误。
    pub fn from_env() -> Result<Self, OracleError> {
        let ghidra_home = resolve_ghidra_home()?;
        let jdk_home = resolve_jdk_home()?;
        let scripts_dir = resolve_scripts_dir()?;
        Ok(Self {
            ghidra_home,
            jdk_home,
            scripts_dir,
        })
    }

    /// 装配信息（诊断用）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "ghidra={} jdk={} scripts={}",
            self.ghidra_home.display(),
            self.jdk_home.display(),
            self.scripts_dir.display()
        )
    }

    /// 跑一次 headless，返回 Ghidra 的函数清单。
    ///
    /// `work_root` 是本次运行的临时目录（调用方负责清理；项目目录建在其下）。
    ///
    /// # Errors
    /// 子进程失败或清单解析失败。
    pub fn function_list(
        &self,
        binary: &Path,
        work_root: &Path,
    ) -> Result<Vec<GhidraFunction>, OracleError> {
        let project_dir = work_root.join("proj");
        std::fs::create_dir_all(&project_dir).map_err(|e| {
            OracleError::Environment(format!("mkdir {}: {e}", project_dir.display()))
        })?;
        let listing = work_root.join("functions.txt");
        let path = path_with_jdk(&self.jdk_home)?;

        let status = headless_command(&self.ghidra_home, &self.jdk_home)
            .arg(&project_dir)
            .arg("KotamaOracle")
            .arg("-import")
            .arg(binary)
            .arg("-scriptPath")
            .arg(&self.scripts_dir)
            .arg("-postScript")
            .arg("KotamaFunctionList.java")
            .arg(&listing)
            .arg("-deleteProject")
            .env("JAVA_HOME", &self.jdk_home)
            .env("PATH", path)
            .output()
            .map_err(|e| OracleError::Run {
                code: -1,
                tail: e.to_string(),
            })?;

        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr).into_owned();
            let all: Vec<&str> = stderr.lines().collect();
            let start = all.len().saturating_sub(5);
            return Err(OracleError::Run {
                code: status.status.code().unwrap_or(-1),
                tail: all[start..].join("\n"),
            });
        }
        parse_function_list(&listing)
    }
}

/// 我方函数表 vs Ghidra 清单的入口集合差分。
#[must_use]
pub fn differential(ours: &[FunctionEntry], theirs: &[GhidraFunction], cap: usize) -> DiffReport {
    let our_set: BTreeSet<u64> = ours.iter().map(|f| f.rva).collect();
    let their_set: BTreeSet<u64> = theirs.iter().map(|f| f.rva).collect();
    let matched = our_set.intersection(&their_set).count();
    let union = our_set.union(&their_set).count();
    let jaccard = if union == 0 {
        1.0
    } else {
        matched as f64 / union as f64
    };
    DiffReport {
        ours: our_set.len(),
        theirs: their_set.len(),
        matched,
        jaccard,
        only_ours: our_set
            .difference(&their_set)
            .take(cap)
            .map(|rva| {
                let evidence = ours
                    .iter()
                    .find(|f| f.rva == *rva)
                    .map(|f| f.evidence.iter().map(|e| e.short()).collect())
                    .unwrap_or_default();
                (*rva, evidence)
            })
            .collect(),
        only_theirs: their_set
            .difference(&our_set)
            .take(cap)
            .filter_map(|rva| {
                theirs
                    .iter()
                    .find(|f| f.rva == *rva)
                    .map(|f| (*rva, f.name.clone()))
            })
            .collect(),
    }
}

/// 解析 postScript 输出：每行 `<rva 十进制>\t<name>`，`#` 开头是注释。
fn parse_function_list(path: &Path) -> Result<Vec<GhidraFunction>, OracleError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| OracleError::Parse(format!("read {}: {e}", path.display())))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (rva, name) = line
            .split_once('\t')
            .ok_or_else(|| OracleError::Parse(format!("line without tab: {line:?}")))?;
        let rva: u64 = rva
            .parse()
            .map_err(|_| OracleError::Parse(format!("bad rva: {rva:?}")))?;
        if rva == 0 {
            continue;
        }
        out.push(GhidraFunction {
            rva,
            name: name.to_string(),
        });
    }
    out.sort_by(|a, b| (a.rva, &a.name).cmp(&(b.rva, &b.name)));
    out.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
    Ok(out)
}

/// 当前平台的 Ghidra headless 启动器。
///
/// Windows 的 zip 同时带 POSIX shell 脚本与 `.bat`；必须选后者，不能直接执行无扩展名脚本。
fn analyze_headless(ghidra_home: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };
    ghidra_home.join("support").join(name)
}

/// 当前平台的 Java 可执行文件。
fn java_executable(jdk_home: &Path) -> PathBuf {
    let name = if cfg!(windows) { "java.exe" } else { "java" };
    jdk_home.join("bin").join(name)
}

/// 创建 headless 命令；Windows 批处理显式经 `cmd.exe` 启动。
///
/// Ghidra 12.2 的 `launch.bat` 用 `for /f` 捕获 `LaunchSupport` 输出的 JDK 路径。
/// 非 ASCII 路径会在这一步错码，因此只有这种路径直接调用同一个官方
/// `AnalyzeHeadless` 入口；ASCII 路径仍走标准 `analyzeHeadless.bat`。
fn headless_command(ghidra_home: &Path, jdk_home: &Path) -> Command {
    #[cfg(windows)]
    {
        if !jdk_home.as_os_str().is_ascii() {
            direct_headless_command(ghidra_home, jdk_home)
        } else {
            let mut command = Command::new("cmd.exe");
            command
                .arg("/D")
                .arg("/S")
                .arg("/C")
                .arg(analyze_headless(ghidra_home));
            command
        }
    }
    #[cfg(not(windows))]
    {
        let _ = jdk_home;
        Command::new(analyze_headless(ghidra_home))
    }
}

/// Windows 非 ASCII JDK 路径的 headless 入口，复刻 `launch.bat` 的必要 JVM 参数。
#[cfg(windows)]
fn direct_headless_command(ghidra_home: &Path, jdk_home: &Path) -> Command {
    let mut command = Command::new(java_executable(jdk_home));
    for argument in [
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        "-Dfile.encoding=UTF8",
        "-Duser.country=US",
        "-Duser.language=en",
        "-Dsun.java2d.opengl=false",
        "-Dsun.java2d.d3d=false",
        "-Dlog4j.skipJansi=true",
        "-Xshare:off",
        "-XX:+UseCompactObjectHeaders",
        "--enable-native-access=ALL-UNNAMED",
        "--sun-misc-unsafe-memory-access=allow",
        "-XX:ParallelGCThreads=2",
        "-XX:CICompilerCount=2",
        "-Xmx2G",
    ] {
        command.arg(argument);
    }
    command
        .arg("-cp")
        .arg(
            ghidra_home
                .join("Ghidra")
                .join("Framework")
                .join("Utility")
                .join("lib")
                .join("Utility.jar"),
        )
        .arg("ghidra.Ghidra")
        .arg("ghidra.app.util.headless.AnalyzeHeadless");
    command
}

/// 把所选 JDK 放到 `PATH` 最前，并用平台规则保留原条目（Windows `;`，Unix `:`）。
fn path_with_jdk(jdk_home: &Path) -> Result<OsString, OracleError> {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(jdk_home.join("bin")).chain(std::env::split_paths(&existing));
    std::env::join_paths(paths)
        .map_err(|error| OracleError::Environment(format!("construct PATH: {error}")))
}

fn resolve_ghidra_home() -> Result<PathBuf, OracleError> {
    if let Ok(home) = std::env::var("KOTAMA_GHIDRA_HOME") {
        let path = PathBuf::from(home);
        let headless = analyze_headless(&path);
        if headless.is_file() {
            return Ok(path);
        }
        return Err(OracleError::Environment(format!(
            "KOTAMA_GHIDRA_HOME={path:?} has no {}",
            headless.display()
        )));
    }
    #[cfg(windows)]
    {
        Err(OracleError::Environment(
            "set KOTAMA_GHIDRA_HOME to the native Windows Ghidra installation".into(),
        ))
    }
    #[cfg(not(windows))]
    {
        let mut candidates: Vec<PathBuf> = std::fs::read_dir("/mnt/work/ghidra")
            .map_err(|e| OracleError::Environment(format!("/mnt/work/ghidra: {e}")))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("ghidra_"))
            })
            .collect();
        candidates.sort();
        candidates
            .into_iter()
            .next_back()
            .ok_or_else(|| OracleError::Environment("no /mnt/work/ghidra/ghidra_*".into()))
    }
}

fn resolve_jdk_home() -> Result<PathBuf, OracleError> {
    if let Ok(home) = std::env::var("KOTAMA_JDK_HOME") {
        let path = PathBuf::from(home);
        let java = java_executable(&path);
        if java.is_file() {
            return Ok(path);
        }
        return Err(OracleError::Environment(format!(
            "KOTAMA_JDK_HOME={path:?} has no {}",
            java.display()
        )));
    }
    #[cfg(windows)]
    {
        Err(OracleError::Environment(
            "set KOTAMA_JDK_HOME to a native Windows JDK 25 installation".into(),
        ))
    }
    #[cfg(not(windows))]
    {
        let default = PathBuf::from("/mnt/work/jdk");
        if java_executable(&default).is_file() {
            return Ok(default);
        }
        Err(OracleError::Environment(
            "no JDK at /mnt/work/jdk (set KOTAMA_JDK_HOME)".into(),
        ))
    }
}

fn resolve_scripts_dir() -> Result<PathBuf, OracleError> {
    if let Ok(dir) = std::env::var("KOTAMA_GHIDRA_SCRIPTS") {
        return Ok(PathBuf::from(dir));
    }
    // 开发态：CLI 常在仓根或 crates/* 下跑。
    for candidate in [
        "support/ghidra",
        "../support/ghidra",
        "../../support/ghidra",
    ] {
        let path = PathBuf::from(candidate);
        if path.join("KotamaFunctionList.java").exists() {
            return Ok(path);
        }
    }
    Err(OracleError::Environment(
        "support/ghidra not found (run from repo root or set KOTAMA_GHIDRA_SCRIPTS)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotama::Evidence;
    use std::collections::BTreeSet;

    fn entry(rva: u64) -> FunctionEntry {
        let mut evidence = BTreeSet::new();
        evidence.insert(Evidence::Symtab);
        FunctionEntry {
            rva,
            size: 16,
            size_inferred: false,
            name: None,
            evidence,
        }
    }

    fn ghidra(rva: u64, name: &str) -> GhidraFunction {
        GhidraFunction {
            rva,
            name: name.to_string(),
        }
    }

    #[test]
    fn differential_counts_match_and_both_sides() {
        let ours = vec![entry(0x1000), entry(0x2000), entry(0x3000)];
        let theirs = vec![
            ghidra(0x1000, "a"),
            ghidra(0x2000, "b"),
            ghidra(0x4000, "FUN_4"),
        ];
        let report = differential(&ours, &theirs, 25);
        assert_eq!(report.matched, 2);
        assert_eq!(report.ours, 3);
        assert_eq!(report.theirs, 3);
        assert!((report.jaccard - 2.0 / 4.0).abs() < 1e-9);
        assert_eq!(report.only_ours.len(), 1);
        assert_eq!(report.only_ours[0].0, 0x3000);
        assert_eq!(report.only_theirs.len(), 1);
        assert_eq!(report.only_theirs[0].1, "FUN_4");
    }

    #[test]
    fn empty_sets_are_full_agreement() {
        let report = differential(&[], &[], 25);
        assert_eq!(report.jaccard, 1.0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_batch_launcher_through_cmd() {
        let headless = analyze_headless(Path::new(r"C:\tools\ghidra"));
        assert!(headless.ends_with(Path::new("support").join("analyzeHeadless.bat")));
        assert_eq!(
            java_executable(Path::new(r"C:\tools\jdk")),
            Path::new(r"C:\tools\jdk").join("bin").join("java.exe")
        );

        let command = headless_command(Path::new(r"C:\tools\ghidra"), Path::new(r"C:\tools\jdk"));
        assert_eq!(command.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[..3], ["/D", "/S", "/C"]);
        assert_eq!(args[3], headless.as_os_str());
    }

    #[cfg(windows)]
    #[test]
    fn non_ascii_jdk_path_bypasses_batch_encoding_bug() {
        let ghidra = Path::new(r"D:\工具\ghidra");
        let jdk = Path::new(r"D:\工具\jdk");
        let command = headless_command(ghidra, jdk);
        assert_eq!(command.get_program(), java_executable(jdk).as_os_str());

        let args: Vec<_> = command.get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new(
            "-Djava.system.class.loader=ghidra.GhidraClassLoader"
        )));
        let classpath = args
            .iter()
            .position(|arg| *arg == "-cp")
            .expect("classpath argument");
        assert_eq!(
            args[classpath + 1],
            ghidra
                .join("Ghidra")
                .join("Framework")
                .join("Utility")
                .join("lib")
                .join("Utility.jar")
                .as_os_str()
        );
        assert_eq!(args[args.len() - 2], "ghidra.Ghidra");
        assert_eq!(
            args[args.len() - 1],
            "ghidra.app.util.headless.AnalyzeHeadless"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_uses_shell_launcher_directly() {
        let headless = analyze_headless(Path::new("/opt/ghidra"));
        assert!(headless.ends_with(Path::new("support").join("analyzeHeadless")));
        assert_eq!(
            java_executable(Path::new("/opt/jdk")),
            Path::new("/opt/jdk").join("bin").join("java")
        );

        let command = headless_command(Path::new("/opt/ghidra"), Path::new("/opt/jdk"));
        assert_eq!(command.get_program(), headless.as_os_str());
        assert_eq!(command.get_args().count(), 0);
    }

    #[test]
    fn jdk_path_precedes_and_preserves_existing_entries() {
        let jdk = if cfg!(windows) {
            Path::new(r"C:\tools\jdk with spaces")
        } else {
            Path::new("/opt/jdk with spaces")
        };
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let existing_entries: Vec<_> = std::env::split_paths(&existing).collect();

        let joined = path_with_jdk(jdk).expect("platform PATH encoding");
        let entries: Vec<_> = std::env::split_paths(&joined).collect();
        assert_eq!(entries.first(), Some(&jdk.join("bin")));
        assert_eq!(&entries[1..], existing_entries.as_slice());
    }

    /// 原生 Windows + 真实 Ghidra 的 PE 车道；普通 cargo test 不要求安装 Ghidra。
    #[cfg(windows)]
    #[test]
    fn live_windows_pe_function_list() {
        if std::env::var_os("KOTAMA_GHIDRA_E2E").is_none() {
            eprintln!("skip: set KOTAMA_GHIDRA_E2E=1 to run the native Ghidra oracle");
            return;
        }
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/loops.exe");
        assert!(fixture.is_file(), "fixture missing: {}", fixture.display());
        let oracle = GhidraOracle::from_env().expect("native Ghidra environment");
        let work_root =
            std::env::temp_dir().join(format!("kotama-oracle-live-{}", std::process::id()));
        let result = oracle.function_list(&fixture, &work_root);
        let _ = std::fs::remove_dir_all(&work_root);
        let functions = result.expect("headless function list");

        // 不断言 CRT 全量函数数；只钉住夹具自身入口与 RVA 归一化。
        assert!(
            functions
                .iter()
                .any(|function| function.rva == 0x1000 && function.name == "main"),
            "main at RVA 0x1000 missing: {functions:?}"
        );
    }

    #[test]
    fn parses_postscript_listing() {
        let dir = std::env::temp_dir().join(format!("kotama-oracle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("functions.txt");
        std::fs::write(
            &list,
            "# generated\n4096\tmain\n4096\tmain\n8192\tFUN_2000\n0\tzero-skipped\n",
        )
        .unwrap();
        let parsed = parse_function_list(&list).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].rva, 0x1000);
        assert_eq!(parsed[0].name, "main");
        assert_eq!(parsed[1].rva, 0x2000);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
