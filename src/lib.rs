//! 静态与动态管线共用的映像模型。
//!
//! 这个 crate 只放**身份与数据**：不读文件、不开进程、不碰网络、不做 I/O。
//! 它承载三条不变量：
//!
//! 1. 地址一律用模块相对地址（RVA）；运行期基址属于会话，不属于事实。
//! 2. 模块身份 = 代码段内容的指纹，跨 ASLR、重启与换机器稳定，重新编译才变。
//! 3. 注释、类型与命名挂在 [`FuncKey`] 上，因此可以在节点之间共享同一条知识。
//!
//! 静态文件映像、活体进程视图与内存快照都必须实现 [`AddressSpace`]——
//! 函数发现、控制流复原与反编译因此对三者跑同一条管线。

#![forbid(unsafe_code)]

use std::fmt;
use std::fmt::Write as _;

/// 宿主侧与目标侧共用的有线协议版本。
///
/// 载荷（注入库）与宿主握手时比对；不一致一律拒绝装载，不做兼容回退。
pub const ABI_VERSION: u16 = 1;

/// 一个模块（PE / ELF / Mach-O 映像）的内容指纹。
///
/// 由规范化后的代码段字节计算 sha256：同一份二进制在任何机器、任何加载基址下
/// 都得到同一个值，重新编译才会变——正是"知识可以跨机器复用"所需要的语义。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId([u8; 32]);

impl ModuleId {
    /// 从原始 32 字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 原始字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 小写十六进制表示，用于 [`FuncKey`] 的 URI 形式与日志。
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            // 写入 String 不会失败；expect 只是把不可能分支写死。
            write!(out, "{byte:02x}").expect("writing into a String cannot fail");
        }
        out
    }
}

impl fmt::Debug for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 完整 64 位十六进制在日志里太长；前 8 字节足够定位。
        write!(f, "ModuleId({}…)", &self.to_hex()[..16])
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 函数身份：模块指纹 + 模块相对地址。
///
/// ASLR、重启、换机器都不变；换模块（重新编译）则整条身份作废——这是正确行为，
/// 因为旧结论对新二进制不再成立。URI 形式（`kotama://<模块指纹>/<rva>`）是智能体
/// 之间、以及会话与知识库之间互相引用的稳定指称。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FuncKey {
    /// 所属模块。
    pub module: ModuleId,
    /// 函数入口的模块相对地址。
    pub rva: u64,
}

impl FuncKey {
    /// 构造一个函数身份。
    #[must_use]
    pub const fn new(module: ModuleId, rva: u64) -> Self {
        Self { module, rva }
    }
}

impl fmt::Display for FuncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kotama://{}/{:x}", self.module, self.rva)
    }
}

/// 一段内存的访问权限。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Perms {
    /// 可读。
    pub read: bool,
    /// 可写。
    pub write: bool,
    /// 可执行。
    pub execute: bool,
}

/// 映像中的一段连续映射（PE 段、ELF 段，或活体进程的一段已映射区域）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment {
    /// 段在模块地址空间中的起始相对地址。
    pub rva: u64,
    /// 段长度（字节）。
    pub size: u64,
    /// 访问权限。
    pub perms: Perms,
}

impl Segment {
    /// 段末端的相对地址（不含）。
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.rva.saturating_add(self.size)
    }

    /// 该段是否完整覆盖 `[rva, rva + len)`。
    #[must_use]
    pub const fn contains(&self, rva: u64, len: usize) -> bool {
        let Some(last) = rva.checked_add(len as u64) else {
            return false;
        };
        rva >= self.rva && last <= self.end()
    }
}

/// 可按 RVA 读字节的地址空间。
///
/// 三种实现：文件映像（装载器给出）、活体进程（注入载荷回读）、内存快照（我们自己抓的）。
/// 只要实现了它，函数发现与控制流复原就能直接跑——不需要为"离线 / 活体"写两套。
pub trait AddressSpace {
    /// 已枚举的段，按 RVA 升序。
    fn segments(&self) -> &[Segment];

    /// 读取 `[rva, rva + len)`；越界或不可读时返回 `None`。
    fn read(&self, rva: u64, len: usize) -> Option<&[u8]>;

    /// 找到覆盖该地址的段。
    fn segment_at(&self, rva: u64) -> Option<&Segment> {
        self.segments()
            .iter()
            .find(|segment| segment.contains(rva, 1))
    }
}

/// 一条证据：谁说这里有个函数。
///
/// 这是**数据**，不是扫描器的一部分——反编译器、差分 oracle、前端都只读它，
/// 不该为此依赖整个扫描实现（架构审查 2026-11-23 的结论）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Evidence {
    /// ELF symtab 函数符号。
    Symtab,
    /// ELF dynsym 导出函数。
    Dynsym,
    /// DWARF `DW_TAG_subprogram`（ELF `-g` 的精确边界）。
    Dwarf,
    /// PDB 子程序符号（PE 伴生 `.pdb` 的精确边界）。
    Pdb,
    /// PE64 `.pdata` RUNTIME_FUNCTION。
    Pdata,
    /// 映像入口点。
    Entry,
    /// 直接 call 目标。
    CallTarget,
    /// 非执行节里的函数指针（回调表 / vtable / 手写分派表）。
    PointerTarget,
    /// 代码里的绝对地址立即数（`push offset` / `mov reg, offset` / 静态回调注册）。
    ImmediateTarget,
}

impl Evidence {
    /// JSON / CLI 短名。
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Symtab => "sym",
            Self::Dynsym => "dynsym",
            Self::Dwarf => "dwarf",
            Self::Pdb => "pdb",
            Self::Pdata => "pdata",
            Self::Entry => "entry",
            Self::CallTarget => "call",
            Self::PointerTarget => "pointer",
            Self::ImmediateTarget => "immediate",
        }
    }
}

/// 发现的一个函数（入口 + 长度 + 名字 + 证据集合）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FunctionEntry {
    /// 入口 RVA。
    pub rva: u64,
    /// 长度（字节）；推断补齐时也填数值，但见 `size_inferred`。
    pub size: u64,
    /// 长度是否来自「到下一个条目的距离」推断（而非符号 / pdata 精确边界）。
    pub size_inferred: bool,
    /// 已知名字（symtab / dynsym / 调试信息）。
    pub name: Option<String>,
    /// 证据集合。
    pub evidence: std::collections::BTreeSet<Evidence>,
}

impl FunctionEntry {
    /// 找到函数体内某地址对应的函数入口（条目需按 RVA 升序）。
    #[must_use]
    pub fn containing(functions: &[Self], address: u64) -> Option<u64> {
        let index = functions.partition_point(|entry| entry.rva <= address);
        let entry = index.checked_sub(1).map(|i| &functions[i])?;
        let end = entry.rva.saturating_add(entry.size.max(1));
        (address < end).then_some(entry.rva)
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressSpace, FuncKey, ModuleId, Perms, Segment};

    fn segment(rva: u64, size: u64) -> Segment {
        Segment {
            rva,
            size,
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
        }
    }

    #[test]
    fn module_id_hex_is_lowercase_and_stable() {
        let id = ModuleId::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1,
        ]);
        assert_eq!(id.to_hex().len(), 64);
        assert!(id.to_hex().starts_with("deadbeef"));
        assert!(id.to_hex().ends_with("01"));
    }

    #[test]
    fn func_key_renders_as_uri() {
        let id = ModuleId::from_bytes([0xab; 32]);
        let key = FuncKey::new(id, 0x1a30);
        assert_eq!(format!("{key}"), format!("kotama://{}/1a30", id));
    }

    #[test]
    fn segment_contains_is_half_open() {
        let seg = segment(0x1000, 0x200);
        assert!(seg.contains(0x1000, 0));
        assert!(seg.contains(0x1000, 0x200));
        assert!(!seg.contains(0x0fff, 1));
        assert!(!seg.contains(0x1000, 0x201));
    }

    #[test]
    fn segment_contains_rejects_overflowing_range() {
        let seg = segment(0x1000, 0x200);
        assert!(!seg.contains(u64::MAX, 2));
    }

    #[test]
    fn segment_end_saturates() {
        assert_eq!(segment(u64::MAX, 2).end(), u64::MAX);
    }

    struct SingleSegment;

    impl AddressSpace for SingleSegment {
        fn segments(&self) -> &[Segment] {
            // 借一个静态段，避免在测试里再造一个分配器。
            static SEGMENTS: &[Segment] = &[Segment {
                rva: 0x1000,
                size: 0x10,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
            }];
            SEGMENTS
        }

        fn read(&self, _rva: u64, _len: usize) -> Option<&[u8]> {
            None
        }
    }

    #[test]
    fn segment_at_matches_only_mapped_addresses() {
        let space = SingleSegment;
        assert!(space.segment_at(0x1000).is_some());
        assert!(space.segment_at(0x100f).is_some());
        assert!(space.segment_at(0x1010).is_none());
    }
}
