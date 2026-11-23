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
//! - `KOTAMA_GHIDRA_HOME`：Ghidra 安装目录（默认扫 `/mnt/work/ghidra/ghidra_*` 取字典序最大）。
//! - `KOTAMA_JDK_HOME`：JDK 目录（默认 `/mnt/work/jdk`；Ghidra 12.2 要 JDK 25）。
//! - `KOTAMA_GHIDRA_SCRIPTS`：postScript 目录（默认相对仓根 `support/ghidra`）。

use std::collections::BTreeSet;
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
        let headless = self.ghidra_home.join("support").join("analyzeHeadless");

        let status = Command::new(&headless)
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
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.jdk_home.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
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

fn resolve_ghidra_home() -> Result<PathBuf, OracleError> {
    if let Ok(home) = std::env::var("KOTAMA_GHIDRA_HOME") {
        let path = PathBuf::from(home);
        if path.join("support").join("analyzeHeadless").exists() {
            return Ok(path);
        }
        return Err(OracleError::Environment(format!(
            "KOTAMA_GHIDRA_HOME={path:?} has no support/analyzeHeadless"
        )));
    }
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

fn resolve_jdk_home() -> Result<PathBuf, OracleError> {
    if let Ok(home) = std::env::var("KOTAMA_JDK_HOME") {
        return Ok(PathBuf::from(home));
    }
    let default = PathBuf::from("/mnt/work/jdk");
    if default.join("bin").join("java").exists() {
        return Ok(default);
    }
    Err(OracleError::Environment(
        "no JDK at /mnt/work/jdk (set KOTAMA_JDK_HOME)".into(),
    ))
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
