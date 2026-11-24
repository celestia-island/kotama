//! P3 内存扫描 / 快照 / 冻结车道（host 侧）。
//!
//! 设计口径（设计案 §5.3 的 `scan` / `snapshot` / `freeze` 能力）：
//! - **首轮快照在宿主侧做**（读 `/proc/<pid>/mem`），续扫只对命中地址重读——CE 的性能秘诀；
//! - 扫描只在**可写区域**里做（只读代码/常量不会是数值的藏身处）；
//! - 会话**记住每命中的上轮值**，`Increased/Decreased` 才有真历史可比（CE 同款语义）；
//! - 一切写操作（写内存 / 冻结）走 [`crate::Session`] 的 **capability 门禁**：
//!   默认只读会话，写操作必须 `Err(HostError::CapabilityDenied)`——负对照测试钉住。
//!
//! 确定性：扫描与 diff 的输出按地址升序。

use std::collections::BTreeMap;

use crate::HostError;
#[cfg(target_os = "linux")]
use crate::MapEntry;
use crate::TargetProcess;

/// 单区域快照上限（超大可写区——JIT 堆一类——快照要设界）。
pub(crate) const MAX_REGION_SNAPSHOT: u64 = 64 * 1024 * 1024;
/// 首扫命中数上限（保险丝：全零区扫 `u32:0` 会命中百万级）。
const MAX_HITS: usize = 200_000;
/// 快照 diff 报告的差异字数上限。
const MAX_DIFF_REPORT: usize = 10_000;

/// 一个可写区域。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    /// 起始绝对地址。
    pub start: u64,
    /// 结束（不含）。
    pub end: u64,
}

impl Region {
    /// 大小（字节）。
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// 枚举目标进程的可写区域（Linux = maps；Windows = VirtualQueryEx；排除超大区）。
///
/// # Errors
/// Linux maps 读取失败；Windows 区域枚举遇到不前进的异常布局时失败。
pub fn writable_regions(process: &TargetProcess) -> Result<Vec<Region>, HostError> {
    #[cfg(target_os = "windows")]
    {
        crate::windows::writable_regions(process)
    }

    #[cfg(target_os = "linux")]
    {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", process.pid()))
            .map_err(|e| HostError::Proc(format!("maps: {e}")))?;
        let mut out: Vec<Region> = crate::parse_maps(&maps)
            .iter()
            .filter(|entry: &&MapEntry| entry.readable && entry.writable)
            .filter(|entry| entry.end.saturating_sub(entry.start) <= MAX_REGION_SNAPSHOT)
            .map(|entry| Region {
                start: entry.start,
                end: entry.end,
            })
            .collect();
        // maps 分裂的相邻同类区合并。
        out.sort_by_key(|region| region.start);
        let mut merged: Vec<Region> = Vec::with_capacity(out.len());
        for region in out {
            match merged.last_mut() {
                Some(last) if last.end == region.start => last.end = region.end,
                _ => merged.push(region),
            }
        }
        Ok(merged)
    }
}

/// 一次区域快照（区域起始地址 → 字节）。
pub struct Snapshot {
    /// 地址 → 区域字节。
    pub regions: BTreeMap<u64, Vec<u8>>,
}

impl Snapshot {
    /// 抓取当前所有可写区域的快照（单区域读取失败 = 跳过，竞争窗口内被 munmap 属常态）。
    ///
    /// # Errors
    /// 区域枚举失败。
    pub fn capture(process: &TargetProcess) -> Result<Self, HostError> {
        let mut regions = BTreeMap::new();
        for region in writable_regions(process)? {
            let size = usize::try_from(region.size()).unwrap_or(usize::MAX);
            if let Ok(bytes) = process.read_absolute(region.start, size) {
                regions.insert(region.start, bytes);
            }
        }
        Ok(Self { regions })
    }

    /// 读取快照里某地址的 `N` 字节。
    #[must_use]
    pub fn read(&self, address: u64, length: usize) -> Option<&[u8]> {
        let (&start, bytes) = self.regions.range(..=address).next_back()?;
        let offset = usize::try_from(address - start).ok()?;
        bytes.get(offset..offset.checked_add(length)?)
    }
}

/// 两次快照间一个 8 字节字的变化。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Change {
    /// 变化字的起始地址。
    pub address: u64,
    /// 旧值（8 字节，LE）。
    pub old: u64,
    /// 新值（8 字节，LE）。
    pub new: u64,
}

/// 两次快照的 diff：报告值发生变化的 8 字节字（「什么东西在变」的最快答案）。
#[must_use]
pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut out = Vec::new();
    for (&start, old_bytes) in &before.regions {
        let Some(new_bytes) = after.regions.get(&start) else {
            continue;
        };
        let common = old_bytes.len().min(new_bytes.len()) / 8 * 8;
        for offset in (0..common).step_by(8) {
            let mut old_word = [0u8; 8];
            let mut new_word = [0u8; 8];
            old_word.copy_from_slice(&old_bytes[offset..offset + 8]);
            new_word.copy_from_slice(&new_bytes[offset..offset + 8]);
            if old_word != new_word {
                out.push(Change {
                    address: start + offset as u64,
                    old: u64::from_le_bytes(old_word),
                    new: u64::from_le_bytes(new_word),
                });
                if out.len() >= MAX_DIFF_REPORT {
                    out.sort_by_key(|change| change.address);
                    return out;
                }
            }
        }
    }
    out.sort_by_key(|change| change.address);
    out
}

/// 扫描值的类型与取值。
#[derive(Clone, PartialEq, Debug)]
pub enum Value {
    /// 32 位无符号。
    U32(u32),
    /// 32 位有符号。
    I32(i32),
    /// 64 位无符号。
    U64(u64),
    /// 32 位浮点。
    F32(f32),
    /// 字节串（AOB）。
    Bytes(Vec<u8>),
}

impl Value {
    /// 字节宽。
    #[must_use]
    pub fn width(&self) -> usize {
        match self {
            Self::U32(_) | Self::I32(_) | Self::F32(_) => 4,
            Self::U64(_) => 8,
            Self::Bytes(bytes) => bytes.len(),
        }
    }

    /// 自然对齐（1/4/8）。
    #[must_use]
    pub const fn alignment(&self) -> u64 {
        match self {
            Self::U32(_) | Self::I32(_) | Self::F32(_) => 4,
            Self::U64(_) => 8,
            Self::Bytes(_) => 1,
        }
    }

    /// 从字节解出同型值。
    #[must_use]
    pub fn from_bytes(&self, bytes: &[u8]) -> Option<Value> {
        match self {
            Self::U32(_) => bytes
                .get(..4)
                .map(|b| Self::U32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
            Self::I32(_) => bytes
                .get(..4)
                .map(|b| Self::I32(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
            Self::U64(_) => bytes.get(..8).map(|b| {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(b);
                Self::U64(u64::from_le_bytes(raw))
            }),
            Self::F32(_) => bytes
                .get(..4)
                .map(|b| Self::F32(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
            Self::Bytes(pattern) => bytes.get(..pattern.len()).map(|b| Self::Bytes(b.to_vec())),
        }
    }

    /// 数值化（u64 视域；浮点走位模式）。
    #[must_use]
    fn as_key(&self) -> u64 {
        match self {
            Self::U32(value) => u64::from(*value),
            Self::I32(value) => (i64::from(*value)) as u64,
            Self::U64(value) => *value,
            Self::F32(value) => u64::from(value.to_bits()),
            Self::Bytes(bytes) => bytes
                .iter()
                .fold(0u64, |acc, b| acc.rotate_left(8) ^ u64::from(*b)),
        }
    }
}

/// 续扫谓词。
#[derive(Clone, PartialEq, Debug)]
pub enum Predicate {
    /// 值等于给定值。
    Exact(Value),
    /// 值未变（相对上一轮）。
    Unchanged,
    /// 值变了（相对上一轮）。
    Changed,
    /// 值变大（数值型，相对上一轮）。
    Increased,
    /// 值变小（数值型，相对上一轮）。
    Decreased,
}

/// 一次命中（地址 + 上轮值——增/减判断的历史就在这）。
#[derive(Clone, PartialEq, Debug)]
pub struct ScanHit {
    /// 命中地址。
    pub address: u64,
    /// 上轮看到的值。
    pub value: Value,
}

/// 一个正在收窄的扫描会话。
#[derive(Clone)]
pub struct ScanSession {
    /// 类型模板（宽度与对齐）。
    pub kind: Value,
    /// 当前命中集（升序，带上轮值）。
    pub hits: Vec<ScanHit>,
}

/// 首扫：在全部可写区域里找精确值。
///
/// # Errors
/// 区域枚举失败。
pub fn first_scan(process: &TargetProcess, value: &Value) -> Result<ScanSession, HostError> {
    let width = value.width();
    let alignment = value.alignment();
    let mut hits = Vec::new();
    for region in writable_regions(process)? {
        let size = usize::try_from(region.size()).unwrap_or(usize::MAX);
        let Ok(bytes) = process.read_absolute(region.start, size) else {
            continue;
        };
        let mut offset = 0usize;
        while let Some(window) = bytes.get(offset..offset.saturating_add(width)) {
            if let Some(found) = value.from_bytes(window) {
                if found == *value {
                    hits.push(ScanHit {
                        address: region.start + offset as u64,
                        value: found,
                    });
                    if hits.len() >= MAX_HITS {
                        return Ok(ScanSession {
                            kind: value.clone(),
                            hits,
                        });
                    }
                }
            }
            offset += alignment as usize;
        }
    }
    Ok(ScanSession {
        kind: value.clone(),
        hits,
    })
}

/// 续扫：对命中集重读，按谓词过滤并**刷新历史值**（下一轮增/减判断的依据）。
///
/// 单地址读取失败 = 剔除（区域被 munmap 属常态）。
#[must_use]
pub fn next_scan(
    process: &TargetProcess,
    session: &ScanSession,
    predicate: &Predicate,
) -> ScanSession {
    let width = session.kind.width();
    let mut hits = Vec::new();
    for hit in &session.hits {
        let Ok(bytes) = process.read_absolute(hit.address, width) else {
            continue;
        };
        let Some(current) = session.kind.from_bytes(&bytes) else {
            continue;
        };
        let keep = match predicate {
            Predicate::Exact(value) => &current == value,
            Predicate::Unchanged => current == hit.value,
            Predicate::Changed => current != hit.value,
            Predicate::Increased | Predicate::Decreased => {
                let ordering = current.as_key().cmp(&hit.value.as_key());
                matches!(
                    (predicate, ordering),
                    (Predicate::Increased, std::cmp::Ordering::Greater)
                        | (Predicate::Decreased, std::cmp::Ordering::Less)
                )
            }
        };
        if keep {
            // 存「当前」值：增/减的历史永远是「上一轮」，CE 同款。
            hits.push(ScanHit {
                address: hit.address,
                value: current,
            });
        }
    }
    ScanSession {
        kind: session.kind.clone(),
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_from_bytes_roundtrip() {
        let value = Value::U32(0xdead_beef);
        let parsed = value.from_bytes(&0xdead_beef_u32.to_le_bytes()).unwrap();
        assert_eq!(parsed, value);
        assert_eq!(Value::Bytes(vec![1, 2]).width(), 2);
        assert_eq!(Value::U64(0).alignment(), 8);
    }

    #[test]
    fn snapshot_read_spans_regions() {
        let mut regions = BTreeMap::new();
        regions.insert(0x1000u64, vec![1u8, 2, 3, 4, 5, 6, 7, 8]);
        let snapshot = Snapshot { regions };
        assert_eq!(snapshot.read(0x1002, 3), Some(&[3u8, 4, 5][..]));
        assert_eq!(snapshot.read(0x0fff, 1), None);
        assert_eq!(snapshot.read(0x1008, 1), None);
    }

    #[test]
    fn diff_reports_changed_words_sorted() {
        let mut before = BTreeMap::new();
        before.insert(0x2000u64, vec![0u8; 16]);
        let mut after = BTreeMap::new();
        after.insert(0x2000u64, {
            let mut bytes = vec![0u8; 16];
            bytes[0] = 9;
            bytes[11] = 7;
            bytes
        });
        let changes = diff(&Snapshot { regions: before }, &Snapshot { regions: after });
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].address, 0x2000);
        assert_eq!(changes[1].address, 0x2008);
    }

    #[test]
    fn increased_decreased_use_previous_value_history() {
        let value = Value::U32(0);
        let hit = |address: u64, v: u32| ScanHit {
            address,
            value: Value::U32(v),
        };
        // 历史 10 → 当前 12：Increased 过、Decreased 不过、Changed 过、Unchanged 不过。
        let session = ScanSession {
            kind: value.clone(),
            hits: vec![hit(0x1000, 10)],
        };
        let mut after = session.clone();
        after.hits[0].value = Value::U32(12);
        assert!(compare(&session, &after, &Predicate::Increased));
        assert!(!compare(&session, &after, &Predicate::Decreased));
        assert!(compare(&session, &after, &Predicate::Changed));
        assert!(!compare(&session, &after, &Predicate::Unchanged));
    }

    /// 纯逻辑比较垫片：给测试用（真车道走 `next_scan`）。
    fn compare(before: &ScanSession, after: &ScanSession, predicate: &Predicate) -> bool {
        let hit = &before.hits[0];
        let current = &after.hits[0].value;
        match predicate {
            Predicate::Exact(_) => false,
            Predicate::Unchanged => current == &hit.value,
            Predicate::Changed => current != &hit.value,
            Predicate::Increased | Predicate::Decreased => {
                let ordering = current.as_key().cmp(&hit.value.as_key());
                matches!(
                    (predicate, ordering),
                    (Predicate::Increased, std::cmp::Ordering::Greater)
                        | (Predicate::Decreased, std::cmp::Ordering::Less)
                )
            }
        }
    }
}
