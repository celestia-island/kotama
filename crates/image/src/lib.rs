//! 映像装载：把 ELF / PE 文件变成 [`kotama::AddressSpace`] 加一份模块事实。
//!
//! P0 范围（x86 / x64 的 ELF 与 PE）：段表、节表、符号（ELF symtab / ELF dynsym）、
//! PE 可执行节导出、导入表、入口点、以及**内容寻址的模块指纹**。PDB / DWARF 调试信息在
//! 后续阶段接入。
//!
//! 地址约定：一切地址是「映像相对地址」（RVA）。ELF 用节/符号的 vaddr 直接当 RVA
//! （PIE 与 ET_EXEC 都成立：我们从不声称真实加载基址）；PE 的 object 表示本来就是
//! 映像相对的。运行期基址属于会话，不属于这里。
//!
//! 确定性：同一字节序列两次装载得到逐字段相同的 [`LoadedModule`]（所有集合按地址
//! 排序，无时间戳）——差分与知识库复用的前提。

pub mod eh_frame;
pub mod elf_export;
pub mod macho_unwind;
pub mod pe_export;

use std::collections::BTreeMap;
use std::fmt;

use gimli::Dwarf;
use gimli::EndianSlice;
use gimli::LittleEndian;
use kotama::{AddressSpace, ModuleId, Perms, Segment};
use object::read::Object;
use object::read::ObjectSection;
use object::read::ObjectSegment;
use object::read::ObjectSymbol;
use object::FileKind;
use object::NameOrOrdinal;

/// 装载错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    /// 输入不是 kotama 能识别的容器。
    UnsupportedFormat,
    /// 容器已识别，但它不是可装载的映像（目标文件 / 导入桩 / 归档 /
    /// 通用二进制 / 共享缓存）。携带格式短名。
    NotLoadable(&'static str),
    /// 容器结构损坏，object 无法解析。
    Parse(String),
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => f.write_str("unsupported container"),
            Self::NotLoadable(kind) => {
                write!(f, "recognised {kind} file is not a loadable image")
            }
            Self::Parse(msg) => write!(f, "parse failed: {msg}"),
        }
    }
}

impl std::error::Error for ImageError {}

/// identity v1 共享配方：sha256 over `"kotama-id-v1"` + 每个执行节
/// `name|rva|len\n` 头 + 节字节（**按虚拟尺寸零填充 / 截断**）。
///
/// 静态侧（文件映像，raw 可能短于 virtual）与活体侧（进程内存，天然满尺寸）
/// 都走这一个函数——两侧产出同一个 [`ModuleId`] 是「内容寻址身份跨静态/动态」
/// 的验收断言（`kotama-host` 的活体 e2e 钉住）。
pub fn module_id_from_sections(sections: &[(String, u64, u64, Vec<u8>)]) -> ModuleId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kotama-id-v1");
    for (name, rva, size, bytes) in sections {
        hasher.update(format!("{name}|{rva}|{size}\n"));
        let target = usize::try_from(*size).unwrap_or(usize::MAX);
        let have = &bytes[..target.min(bytes.len())];
        hasher.update(have);
        // 零填充到虚拟尺寸（活体侧天然满长，静态侧补齐）。
        if have.len() < target {
            hasher.update(vec![0u8; target - have.len()]);
        }
    }
    ModuleId::from_bytes(hasher.finalize().into())
}

/// PDB 装载错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdbError {
    /// 打不开文件。
    Open(String),
    /// 结构解析失败。
    Parse(String),
    /// PE 没有可用于认证伴生 PDB 的 CodeView/RSDS 身份。
    IdentityUnavailable,
    /// PDB 的 GUID/age 与 PE 的 CodeView/RSDS 身份不匹配。
    IdentityMismatch {
        /// PE 声明的身份。
        expected: PdbIdentity,
        /// PDB 实际身份。
        actual: PdbIdentity,
    },
}

impl fmt::Display for PdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(msg) => write!(f, "pdb open: {msg}"),
            Self::Parse(msg) => write!(f, "pdb parse: {msg}"),
            Self::IdentityUnavailable => {
                f.write_str("pdb identity unavailable: PE has no CodeView/RSDS record")
            }
            Self::IdentityMismatch { expected, actual } => write!(
                f,
                "pdb identity mismatch: image {expected:?}, pdb {actual:?}"
            ),
        }
    }
}

impl std::error::Error for PdbError {}

/// 容器格式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Container {
    /// 64 位 ELF。
    Elf64,
    /// 32 位 ELF。
    Elf32,
    /// 64 位 PE。
    Pe64,
    /// 32 位 PE。
    Pe32,
    /// 64 位 Mach-O。
    MachO64,
    /// 32 位 Mach-O。
    MachO32,
    /// 64 位 Mach-O universal (fat) binary.
    MachOFat64,
    /// 32 位 Mach-O universal (fat) binary.
    MachOFat32,
    /// Mach-O dyld shared cache.
    DyldCache,
    /// WebAssembly module.
    Wasm,
    /// 64 位 XCOFF。
    Xcoff64,
    /// 32 位 XCOFF。
    Xcoff32,
    /// COFF object file.
    Coff,
    /// COFF bigobj object file.
    CoffBig,
    /// Windows short import file.
    CoffImport,
    /// Unix ar archive.
    Archive,
}

impl Container {
    /// 短名（进 JSON 报告）。
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::Elf64 => "elf64",
            Self::Elf32 => "elf32",
            Self::Pe64 => "pe64",
            Self::Pe32 => "pe32",
            Self::MachO64 => "macho64",
            Self::MachO32 => "macho32",
            Self::MachOFat64 => "macho-fat64",
            Self::MachOFat32 => "macho-fat32",
            Self::DyldCache => "dyld-cache",
            Self::Wasm => "wasm",
            Self::Xcoff64 => "xcoff64",
            Self::Xcoff32 => "xcoff32",
            Self::Coff => "coff",
            Self::CoffBig => "coff-big",
            Self::CoffImport => "coff-import",
            Self::Archive => "archive",
        }
    }

    /// Whether the container is a fully loaded executable image with segments.
    ///
    /// Object files, import stubs and archives are recognised but carry no
    /// loadable address space, so they are identified and then rejected.
    #[must_use]
    pub const fn is_loadable(self) -> bool {
        matches!(
            self,
            Self::Elf64 | Self::Elf32 | Self::Pe64 | Self::Pe32 | Self::MachO64 | Self::MachO32
        )
    }
}

/// 指令集架构。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    /// x86-64。
    X86_64,
    /// x86（32 位）。
    X86,
    /// A recognised architecture that this toolkit cannot disassemble.
    ///
    /// The container and its symbols are still reported; only instruction-level
    /// work (scan / decomp) is refused. Carries the canonical architecture name.
    Other(&'static str),
}

impl Arch {
    /// iced 反汇编器要求的位宽（32 / 64）。
    ///
    /// Returns 0 for [`Arch::Other`]: callers must gate on
    /// [`Arch::is_disassemblable`] before touching instruction decoding.
    #[must_use]
    pub const fn bitness(self) -> u32 {
        match self {
            Self::X86_64 => 64,
            Self::X86 => 32,
            Self::Other(_) => 0,
        }
    }

    /// True when instruction-level analysis is possible for this architecture.
    ///
    /// True for x86 through the iced decoder and for every architecture that has a
    /// lifter crate. The named architectures are the same ones `is_aarch64`,
    /// `is_riscv64` and `is_arm32` recognise, so this predicate cannot drift from them.
    /// `bitness` is a separate question: it reports the x86 decoder's operand width
    /// and is 0 for the lifter architectures.
    #[must_use]
    pub fn is_disassemblable(self) -> bool {
        matches!(self, Self::X86_64 | Self::X86)
            || self.is_aarch64()
            || self.is_riscv64()
            || self.is_arm32()
    }
    /// True for the 64-bit ARM architecture (Aarch64 / A64 instructions).
    ///
    /// Identified by its canonical name rather than a product or vendor, so any
    /// container carrying A64 code (ELF, Mach-O, PE, raw) qualifies.
    #[must_use]
    pub fn is_aarch64(self) -> bool {
        matches!(self, Self::Other("aarch64") | Self::Other("aarch64_ilp32"))
    }

    /// True for the 64-bit RISC-V architecture (RV64 with or without the C extension).
    ///
    /// Identified by its canonical name, so any container carrying RV64 code
    /// (ELF, Mach-O, PE, raw) qualifies.
    #[must_use]
    pub fn is_riscv64(self) -> bool {
        matches!(
            self,
            Self::Other("riscv64") | Self::Other("riscv64gc") | Self::Other("riscv64imafdc")
        )
    }

    /// True for the 32-bit ARM architecture (A32 or Thumb, in any container).
    ///
    /// Identified by its canonical name, so any container carrying ARM code
    /// (ELF32, Mach-O, PE, raw) qualifies.
    #[must_use]
    pub fn is_arm32(self) -> bool {
        matches!(
            self,
            Self::Other("arm") | Self::Other("armv7") | Self::Other("thumb")
        )
    }
    /// 短名（进 JSON 报告）。
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
            Self::Other(name) => name,
        }
    }
}

/// 一条符号记录（函数符号；ELF symtab / dynsym 或 PE 导出）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SymbolInfo {
    /// 符号指向的 RVA。
    pub rva: u64,
    /// 符号声称的函数长度（ELF st_size；PE 导出无长度则 0）。
    pub size: u64,
    /// 符号名（空串 = 匿名）。
    pub name: String,
}

impl SymbolInfo {
    /// 排序键：先地址后名字，保证确定性。
    fn sort_key(&self) -> (u64, &str) {
        (self.rva, self.name.as_str())
    }
}

/// 节的元信息（地址空间之外还带名字与执行位）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SectionInfo {
    /// 节起始 RVA。
    pub rva: u64,
    /// 节长度。
    pub size: u64,
    /// 节名。
    pub name: String,
    /// 是否可执行（SectionKind::Text）。
    pub executable: bool,
}

/// 一条导入（名字；PE 带 `library!name` 形态）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportInfo {
    /// 导入库（ELF 的 DT_NEEDED 或 PE 的 DLL 名；可为空）。
    pub library: String,
    /// 导入符号名。
    pub name: String,
}

/// PE 数据目录的一项（RVA + 字节数）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DataDirectory {
    /// 目录起始 RVA。
    pub rva: u64,
    /// 目录字节数。
    pub size: u64,
}

/// 一条 PE 资源记录（类型 → 名称/ID → language 的叶子）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeResource {
    /// 资源类型 ID；命名类型时为 0。
    pub type_id: u32,
    /// 命名资源类型（UTF-16 名称已解码）。
    pub type_name: Option<String>,
    /// 资源 ID；命名资源时为 0。
    pub id: u32,
    /// 命名资源（UTF-16 名称已解码）。
    pub name: Option<String>,
    /// 语言 ID。
    pub language: u32,
    /// 数据项 CodePage。
    pub code_page: u32,
    /// 资源数据 RVA。
    pub rva: u64,
    /// 资源数据字节数。
    pub size: u64,
}

/// PE `RT_VERSION` 的 fixed file info 与 StringFileInfo。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PeVersionInfo {
    /// FileVersionMS / FileVersionLS。
    pub file_version: Option<(u32, u32)>,
    /// ProductVersionMS / ProductVersionLS。
    pub product_version: Option<(u32, u32)>,
    /// StringFileInfo 的键值（已去除尾随 NUL）。
    pub strings: BTreeMap<String, String>,
}

/// PE CodeView/RSDS 与 PDB 共有的身份。
///
/// `guid` 使用 UUID canonical 字节序（RSDS 的前三个小端字段已归一），
/// 因而可直接与 `pdb` crate 的 `Uuid::as_bytes()` 比较。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PdbIdentity {
    /// PDB GUID。
    pub guid: [u8; 16],
    /// 链接器写入的 PDB age。
    pub age: u32,
}

/// PE64 `RUNTIME_FUNCTION` 的完整三项（地址均为 RVA）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct RuntimeFunction {
    /// 函数起始 RVA。
    pub begin_rva: u32,
    /// 函数结束 RVA（不含）。
    pub end_rva: u32,
    /// `.xdata` 中 `UNWIND_INFO` 的 RVA；0 表示无展开数据。
    pub unwind_info_rva: u32,
}

/// PE64 `.xdata` 中与本管线相关的展开/异常事实。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnwindInfo {
    /// `UNWIND_INFO.Version`。
    pub version: u8,
    /// `UNWIND_INFO.Flags` 原始位（EHANDLER/UHANDLER/CHAININFO 等）。
    pub flags: u8,
    /// 函数 prolog 字节数。
    pub prolog_size: u8,
    /// 展开操作码数量。
    pub unwind_code_count: u8,
    /// 帧寄存器编号（0 = 无帧寄存器）。
    pub frame_register: u8,
    /// 帧寄存器缩放前的偏移字段。
    pub frame_offset: u8,
    /// EHANDLER/UHANDLER 的异常处理例程 RVA。
    pub handler_rva: Option<u32>,
    /// CHAININFO 尾随的链式 `RUNTIME_FUNCTION`。
    pub chained: Option<RuntimeFunction>,
}

/// 一条异常目录记录及其可选 `.xdata` 事实。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExceptionFunction {
    /// 完整异常目录记录。
    pub runtime: RuntimeFunction,
    /// 成功解析的展开信息；`unwind_info_rva != 0` 时仍可能因损坏而为 `None`。
    pub unwind: Option<UnwindInfo>,
}

/// 装载完成的模块：地址空间 + 模块事实。
#[derive(Debug)]
pub struct LoadedModule {
    /// 容器格式。
    pub container: Container,
    /// 指令集架构。
    pub arch: Arch,
    /// 入口 RVA（无入口的工件为 `None`）。
    pub entry_rva: Option<u64>,
    /// 地址空间里的段（有字节背书的节）。
    pub segments: Vec<Segment>,
    /// 全部节的元信息（含无背书的 debug 节）。
    pub sections: Vec<SectionInfo>,
    /// ELF symtab 里的已定义函数符号（非 strip 二进制有）。
    pub symbols: Vec<SymbolInfo>,
    /// ELF dynsym 里导出的函数符号。
    pub dynamic_symbols: Vec<SymbolInfo>,
    /// 导入表。
    pub imports: Vec<ImportInfo>,
    /// DWARF `DW_TAG_subprogram` 的子程序（名字 + 精确边界；`-g` 编译的 ELF 有）。
    pub debug_functions: Vec<SymbolInfo>,
    /// Frame-section FDE ranges (`__eh_frame` / `.eh_frame`),带精确长度、无名字。
    ///
    /// 全 strip 的 ELF 只剩这张表能给出函数边界，所以它单独一份、不与
    /// `debug_functions` 混在一起：来源不同，证据等级也不同。
    pub eh_frame_functions: Vec<SymbolInfo>,
    /// PE exception directory（DataDirectory 索引 3）；不依赖节名。
    pub exception_directory: Option<DataDirectory>,
    /// PE 资源目录中的叶子资源（DataDirectory 索引 2）。
    pub resources: Vec<PeResource>,
    /// PE `RT_VERSION`（资源类型 16）解析结果。
    pub version_info: Option<PeVersionInfo>,
    /// PE CodeView/RSDS 中的伴生 PDB 身份。
    pub pdb_identity: Option<PdbIdentity>,
    /// 归一基址（ELF = 最小 LOAD 段 vaddr；PE = ImageBase）。解码文件里的原始指针时
    /// 用它换回 RVA（PE 的 vtable 槽就是原始绝对地址）。
    pub image_base: u64,
    /// R_X86_64_RELATIVE 一类自相对重定位：`(写入位置 RVA, 目标 RVA)`。
    /// PIE 的 vtable / GOT 在文件里是 0，真实指针只存在于重定位的 addend——
    /// vtable 扫描靠它，不靠读文件字节。
    pub relative_relocations: Vec<(u64, u64)>,
    /// 文件字节。
    pub data: Vec<u8>,
    /// 节字节的背书范围：`(rva, size, 文件内偏移)`，按 RVA 升序。
    backing: Vec<BackingRange>,
}

/// 一段有文件字节背书的范围。
#[derive(Clone, Copy, Debug)]
struct BackingRange {
    rva: u64,
    size: u64,
    offset: usize,
}

impl BackingRange {
    fn end(&self) -> u64 {
        self.rva.saturating_add(self.size)
    }

    fn contains(&self, rva: u64, len: u64) -> bool {
        let Some(last) = rva.checked_add(len) else {
            return false;
        };
        rva >= self.rva && last <= self.end()
    }
}

/// 文件映像地址空间：读必须完整落在**单个**背书范围内。
///
/// 跨节读取返回 `None`（调用方按节切分）；这不是限制而是契约——
/// 段权限本来就是按节粒度的。
#[derive(Debug)]
pub struct FileAddressSpace<'a> {
    backing: &'a [BackingRange],
    data: &'a [u8],
    segments: &'a [Segment],
}

impl AddressSpace for FileAddressSpace<'_> {
    fn segments(&self) -> &[Segment] {
        self.segments
    }

    fn read(&self, rva: u64, len: usize) -> Option<&[u8]> {
        let len64 = u64::try_from(len).ok()?;
        let range = self.backing.iter().find(|r| r.contains(rva, len64))?;
        let start = range.offset + usize::try_from(rva - range.rva).ok()?;
        self.data.get(start..start + len)
    }
}

/// 归一基址：ELF = 最小 LOAD 段 vaddr（gcc PIE 为 0、zig/lld PIE 为 0x100000、
/// ET_EXEC 为 0x400000 一类）；PE = OptionalHeader 的 ImageBase（按偏移直读——
/// `object::File` 没有暴露到 `PeFile` 的下钻口）。解析失败退 0（地址保持原样）。
fn image_base(file: &object::File<'_>, data: &[u8], container: Container) -> u64 {
    match container {
        Container::Elf64 | Container::Elf32 => file
            .segments()
            .map(|segment| segment.address())
            .min()
            .unwrap_or(0),
        Container::Pe64 | Container::Pe32 => pe_image_base(data),
        // Mach-O: the lowest NON-ZERO segment vmaddr is the image base. A
        // `__PAGEZERO` segment sits at 0 with a huge size and must be skipped,
        // otherwise every RVA keeps its absolute link-time address.
        Container::MachO64 | Container::MachO32 => file
            .segments()
            .map(|segment| segment.address())
            .filter(|address| *address != 0)
            .min()
            .unwrap_or(0),
        // Not loadable: identify() rejects these before from_object runs.
        Container::MachOFat64
        | Container::MachOFat32
        | Container::DyldCache
        | Container::Wasm
        | Container::Xcoff64
        | Container::Xcoff32
        | Container::Coff
        | Container::CoffBig
        | Container::CoffImport
        | Container::Archive => 0,
    }
}

/// Canonical short name for an architecture this toolkit cannot disassemble.
#[must_use]
fn arch_name(arch: object::Architecture) -> &'static str {
    use object::Architecture as A;
    match arch {
        A::Aarch64 => "aarch64",
        A::Arm => "arm",
        A::Riscv64 => "riscv64",
        A::Riscv32 => "riscv32",
        A::PowerPc64 => "powerpc64",
        A::PowerPc => "powerpc",
        A::Mips64 => "mips64",
        A::Mips => "mips",
        A::Sparc64 => "sparc64",
        A::S390x => "s390x",
        A::LoongArch64 => "loongarch64",
        A::Wasm32 => "wasm32",
        A::Wasm64 => "wasm64",
        A::X86_64_X32 => "x86_64_x32",
        A::Avr => "avr",
        A::Msp430 => "msp430",
        A::Bpf => "bpf",
        A::Csky => "csky",
        A::Sbf => "sbf",
        A::Xtensa => "xtensa",
        A::Aarch64_Ilp32 => "aarch64_ilp32",
        _ => "unknown",
    }
}

/// 直读 PE OptionalHeader 的 ImageBase。
fn pe_image_base(data: &[u8]) -> u64 {
    let read_u32 = |offset: usize| -> Option<u32> {
        data.get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let parse = || -> Option<u64> {
        // DOS 头 e_lfanew → "PE\0\0" + COFF 20 字节 → OptionalHeader。
        let pe_offset = read_u32(0x3c)? as usize;
        let signature = data.get(pe_offset..pe_offset + 4)?;
        if signature != b"PE\0\0" {
            return None;
        }
        let optional = pe_offset + 4 + 20;
        let magic = read_u32(optional)? & 0xffff;
        match magic {
            // PE32+：ImageBase 是 optional+24 的 u64。
            0x20b => data.get(optional + 24..optional + 32).map(|bytes| {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(bytes);
                u64::from_le_bytes(raw)
            }),
            // PE32：ImageBase 是 optional+28 的 u32。
            0x10b => read_u32(optional + 28).map(u64::from),
            _ => None,
        }
    };
    parse().unwrap_or(0)
}

/// 读取 PE 数据目录；索引 3 = exception，6 = debug。
fn pe_data_directory(data: &[u8], container: Container, index: u32) -> Option<DataDirectory> {
    if !matches!(container, Container::Pe64 | Container::Pe32) {
        return None;
    }
    let read_u16 = |offset: usize| -> Option<u16> {
        data.get(offset..offset.checked_add(2)?)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        data.get(offset..offset.checked_add(4)?)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let pe_offset = read_u32(0x3c)? as usize;
    if data.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = pe_offset.checked_add(4 + 20)?;
    let (number_offset, directories_offset) = match read_u16(optional)? {
        0x10b => (92usize, 96usize),
        0x20b => (108usize, 112usize),
        _ => return None,
    };
    if index >= read_u32(optional.checked_add(number_offset)?)? {
        return None;
    }
    let entry = optional
        .checked_add(directories_offset)?
        .checked_add(index as usize * 8)?;
    let rva = u64::from(read_u32(entry)?);
    let size = u64::from(read_u32(entry.checked_add(4)?)?);
    (rva != 0 && size != 0).then_some(DataDirectory { rva, size })
}

fn resource_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
}

fn resource_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn resource_name(
    data: &[u8],
    backing: &[BackingRange],
    base: u64,
    offset: u32,
    limit: u64,
) -> Option<String> {
    let relative = u64::from(offset & 0x7fff_ffff);
    if relative.checked_add(2)? > limit {
        return None;
    }
    let header = read_backed(data, backing, base.checked_add(relative)?, 2)?;
    let length = resource_u16(header, 0)? as usize;
    let total = 2usize.checked_add(length.checked_mul(2)?)?;
    if relative.checked_add(total as u64)? > limit {
        return None;
    }
    let bytes = read_backed(data, backing, base.checked_add(relative)?, total)?;
    let mut units = Vec::with_capacity(length);
    for index in 0..length {
        let offset = 2 + index * 2;
        units.push(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
    }
    String::from_utf16(&units).ok()
}

fn resource_directory(
    data: &[u8],
    backing: &[BackingRange],
    base: u64,
    offset: u64,
    limit: u64,
) -> Option<(u16, u16)> {
    if offset.checked_add(16)? > limit {
        return None;
    }
    let bytes = read_backed(data, backing, base.checked_add(offset)?, 16)?;
    Some((resource_u16(bytes, 12)?, resource_u16(bytes, 14)?))
}

#[allow(clippy::too_many_arguments)]
fn walk_resource_directory(
    data: &[u8],
    backing: &[BackingRange],
    base: u64,
    offset: u64,
    limit: u64,
    depth: u8,
    type_id: u32,
    type_name: Option<&str>,
    resource_id: u32,
    resource_name_value: Option<&str>,
    output: &mut Vec<PeResource>,
    visited: &mut Vec<u64>,
) {
    if depth > 2 || visited.contains(&offset) {
        return;
    }
    visited.push(offset);
    let Some((named, identified)) = resource_directory(data, backing, base, offset, limit) else {
        return;
    };
    let count = named.saturating_add(identified);
    for index in 0..count {
        let entry_offset = offset
            .checked_add(16)
            .and_then(|value| value.checked_add(u64::from(index) * 8));
        let Some(entry_offset) = entry_offset else {
            continue;
        };
        if entry_offset.checked_add(8).is_none_or(|end| end > limit) {
            continue;
        }
        let Some(entry) = read_backed(data, backing, base.saturating_add(entry_offset), 8) else {
            continue;
        };
        let name_or_id = resource_u32(entry, 0).unwrap_or(0);
        let child = resource_u32(entry, 4).unwrap_or(0) & 0x7fff_ffff;
        let is_directory = resource_u32(entry, 4).unwrap_or(0) & 0x8000_0000 != 0;
        let has_name = name_or_id & 0x8000_0000 != 0;
        let entry_name = has_name
            .then(|| resource_name(data, backing, base, name_or_id, limit))
            .flatten();
        let entry_id = if has_name { 0 } else { name_or_id };
        if is_directory {
            let child_offset = u64::from(child);
            if child_offset >= limit {
                continue;
            }
            let next_type_id = if depth == 0 { entry_id } else { type_id };
            let next_resource_id = if depth == 1 { entry_id } else { resource_id };
            let next_type_name = if depth == 0 {
                entry_name.clone()
            } else {
                type_name.map(ToOwned::to_owned)
            };
            let next_resource_name = if depth == 1 {
                entry_name.clone()
            } else {
                resource_name_value.map(ToOwned::to_owned)
            };
            walk_resource_directory(
                data,
                backing,
                base,
                child_offset,
                limit,
                depth + 1,
                next_type_id,
                next_type_name.as_deref(),
                next_resource_id,
                next_resource_name.as_deref(),
                output,
                visited,
            );
        } else if depth == 2 {
            let data_offset = u64::from(child);
            if data_offset.checked_add(16).is_none_or(|end| end > limit) {
                continue;
            }
            let Some(record) = read_backed(data, backing, base.saturating_add(data_offset), 16)
            else {
                continue;
            };
            let rva = resource_u32(record, 0).unwrap_or(0);
            let size = resource_u32(record, 4).unwrap_or(0);
            if rva == 0 || size == 0 {
                continue;
            }
            output.push(PeResource {
                type_id,
                type_name: type_name.map(ToOwned::to_owned),
                id: resource_id,
                name: resource_name_value.map(ToOwned::to_owned),
                language: if has_name { 0 } else { name_or_id },
                code_page: resource_u32(record, 8).unwrap_or(0),
                rva: u64::from(rva),
                size: u64::from(size),
            });
        }
    }
}

fn parse_resource_tree(
    data: &[u8],
    backing: &[BackingRange],
    directory: DataDirectory,
) -> Vec<PeResource> {
    let limit = directory.size;
    let mut resources = Vec::new();
    let mut visited = Vec::new();
    walk_resource_directory(
        data,
        backing,
        directory.rva,
        0,
        limit,
        0,
        0,
        None,
        0,
        None,
        &mut resources,
        &mut visited,
    );
    resources.sort_by(|a, b| {
        (
            a.type_name.as_deref().unwrap_or_default(),
            a.type_id,
            a.name.as_deref().unwrap_or_default(),
            a.id,
            a.language,
            a.rva,
        )
            .cmp(&(
                b.type_name.as_deref().unwrap_or_default(),
                b.type_id,
                b.name.as_deref().unwrap_or_default(),
                b.id,
                b.language,
                b.rva,
            ))
    });
    resources.dedup_by(|a, b| a == b);
    resources
}

fn pe_resources(data: &[u8], backing: &[BackingRange], container: Container) -> Vec<PeResource> {
    pe_data_directory(data, container, 2)
        .map(|directory| parse_resource_tree(data, backing, directory))
        .unwrap_or_default()
}

fn version_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
}

fn version_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn version_utf16_z(bytes: &[u8], start: usize, end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut offset = start;
    while offset.checked_add(2)? <= end {
        let unit = version_u16(bytes, offset)?;
        offset += 2;
        if unit == 0 {
            return Some((String::from_utf16(&units).ok()?, offset));
        }
        units.push(unit);
    }
    None
}

fn version_align(offset: usize) -> usize {
    offset
        .checked_add(3)
        .map(|value| value & !3)
        .unwrap_or(usize::MAX)
}

fn parse_version_block(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: u8,
    info: &mut PeVersionInfo,
) {
    if depth > 8 || start.checked_add(6).is_none_or(|value| value > end) {
        return;
    }
    let length = version_u16(bytes, start).unwrap_or(0) as usize;
    let value_length = version_u16(bytes, start + 2).unwrap_or(0) as usize;
    let value_type = version_u16(bytes, start + 4).unwrap_or(0);
    let Some(block_end) = start
        .checked_add(length)
        .filter(|value| *value <= end && *value > start)
    else {
        return;
    };
    let Some((key, after_key)) = version_utf16_z(bytes, start + 6, block_end) else {
        return;
    };
    let value_start = version_align(after_key).min(block_end);
    let mut children_start = value_start;
    if key == "VS_VERSION_INFO" {
        if value_start
            .checked_add(52)
            .is_some_and(|value| value <= block_end)
            && version_u32(bytes, value_start) == Some(0xfeef_04bd)
        {
            info.file_version =
                version_u32(bytes, value_start + 8).zip(version_u32(bytes, value_start + 12));
            info.product_version =
                version_u32(bytes, value_start + 16).zip(version_u32(bytes, value_start + 20));
            children_start = version_align(value_start + 52);
        }
    } else if value_length > 0 && value_type == 1 && key != "VS_VERSION_INFO" {
        let value_bytes = if value_type == 1 {
            value_length.saturating_mul(2)
        } else {
            value_length
        };
        let value_end = value_start.saturating_add(value_bytes).min(block_end);
        if value_type == 1 {
            if let Some((value, _)) = version_utf16_z(bytes, value_start, value_end) {
                info.strings.insert(key, value);
            }
        }
        children_start = version_align(value_end);
    }
    let mut child = children_start;
    while child.checked_add(6).is_some_and(|value| value <= block_end) {
        let child_length = version_u16(bytes, child).unwrap_or(0) as usize;
        if child_length == 0 {
            break;
        }
        let Some(next) = child
            .checked_add(child_length)
            .filter(|value| *value <= block_end)
        else {
            break;
        };
        parse_version_block(bytes, child, next, depth + 1, info);
        child = version_align(next);
    }
}

/// Parse a VS_VERSIONINFO resource blob.
#[must_use]
pub fn parse_vs_version_info(bytes: &[u8]) -> Option<PeVersionInfo> {
    if bytes.len() < 6 {
        return None;
    }
    let mut info = PeVersionInfo::default();
    parse_version_block(bytes, 0, bytes.len(), 0, &mut info);
    (info.file_version.is_some() || info.product_version.is_some() || !info.strings.is_empty())
        .then_some(info)
}

fn pe_version_info(
    data: &[u8],
    backing: &[BackingRange],
    resources: &[PeResource],
) -> Option<PeVersionInfo> {
    let resource = resources.iter().find(|resource| resource.type_id == 16)?;
    let size = usize::try_from(resource.size).ok()?;
    let bytes = read_backed(data, backing, resource.rva, size)?;
    parse_vs_version_info(bytes)
}

/// 从文件背书范围读取 RVA；与 FileAddressSpace 一样不跨范围。
fn read_backed<'a>(
    data: &'a [u8],
    backing: &[BackingRange],
    rva: u64,
    len: usize,
) -> Option<&'a [u8]> {
    let range = backing
        .iter()
        .find(|range| range.contains(rva, len as u64))?;
    let start = range
        .offset
        .checked_add(usize::try_from(rva.checked_sub(range.rva)?).ok()?)?;
    data.get(start..start.checked_add(len)?)
}

/// 从 PE debug directory 提取 CodeView/RSDS 的 GUID+age。
fn pe_pdb_identity(
    data: &[u8],
    backing: &[BackingRange],
    container: Container,
) -> Option<PdbIdentity> {
    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
    const DEBUG_DIRECTORY_SIZE: u64 = 28;
    let directory = pe_data_directory(data, container, 6)?;
    let read_u32 = |bytes: &[u8], offset: usize| -> Option<u32> {
        bytes
            .get(offset..offset.checked_add(4)?)
            .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    for index in 0..(directory.size / DEBUG_DIRECTORY_SIZE) {
        let rva = directory
            .rva
            .checked_add(index.checked_mul(DEBUG_DIRECTORY_SIZE)?)?;
        let Some(entry) = read_backed(data, backing, rva, DEBUG_DIRECTORY_SIZE as usize) else {
            continue;
        };
        if read_u32(entry, 12)? != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size = read_u32(entry, 16)? as usize;
        if size < 24 {
            continue;
        }
        let address = u64::from(read_u32(entry, 20)?);
        let pointer = read_u32(entry, 24)? as usize;
        let record = if pointer != 0 {
            data.get(pointer..pointer.checked_add(size)?)
        } else {
            read_backed(data, backing, address, size)
        };
        let Some(record) = record else { continue };
        if record.get(..4)? != b"RSDS" {
            continue;
        }
        let raw: [u8; 16] = record.get(4..20)?.try_into().ok()?;
        // RSDS 的 GUID 是 Windows 三字段小端布局；Uuid::as_bytes 是 canonical 布局。
        let guid = [
            raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9],
            raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ];
        return Some(PdbIdentity {
            guid,
            age: read_u32(record, 20)?,
        });
    }
    None
}

/// GUID 必须一致；DBI age 在位时精确匹配，老 PDB 按 PDBI 语义允许更新 age。
fn authenticate_pdb(
    expected: PdbIdentity,
    guid: [u8; 16],
    pdbi_age: u32,
    dbi_age: Option<u32>,
) -> Result<(), PdbError> {
    let actual = PdbIdentity {
        guid,
        age: dbi_age.unwrap_or(pdbi_age),
    };
    let age_matches = if dbi_age.is_some() {
        actual.age == expected.age
    } else {
        actual.age >= expected.age
    };
    if guid != expected.guid || !age_matches {
        return Err(PdbError::IdentityMismatch { expected, actual });
    }
    Ok(())
}

/// 从 `.debug_*` 节提取 `DW_TAG_subprogram`（名字 + low_pc/high_pc 精确边界）。
///
/// 这是「strip 了 symtab 但留着调试信息」的二进制拿精确边界的通道；对未 strip 的
/// ELF 它与 symtab 互为印证（差分口径见 oracle）。没有 `.debug_info` 就返回空。
/// 只处理 x86/x64 的小端（[`Arch`] 门已保证），压缩节（SHF_COMPRESSED）暂不支持——
/// 读不出来就当没有，不报错。
/// Frame-section FDE ranges as function entries (no names, exact lengths).
///
/// Both container families spell the section differently and both spellings are
/// tried. A missing section is not an error: most PE files have none, and a
/// Mach-O linked for compact unwinding may carry only a lone CIE.
fn frame_functions(file: &object::File<'_>, base: u64) -> Vec<SymbolInfo> {
    let Some(section) = file
        .section_by_name("__eh_frame")
        .or_else(|| file.section_by_name(".eh_frame"))
    else {
        return Vec::new();
    };
    let Ok(data) = section.data() else {
        return Vec::new();
    };
    // The FDE initial location is PC-relative, so the section's own address is
    // part of the input, not just the bytes.
    // `Section::address()` is already the link-time address in both containers,
    // so it is the pcrel base as-is; adding `base` again shifts every range.
    let ranges = crate::eh_frame::function_ranges(data, section.address());
    ranges
        .into_iter()
        .filter_map(|range| {
            let rva = range.start.checked_sub(base)?;
            Some(SymbolInfo {
                rva,
                size: range.length,
                name: String::new(),
            })
        })
        .collect()
}

fn dwarf_functions(file: &object::File<'_>, base: u64) -> Vec<SymbolInfo> {
    let load = |id: gimli::SectionId| -> Result<EndianSlice<'_, LittleEndian>, gimli::Error> {
        let bytes: &[u8] = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(bytes, LittleEndian))
    };
    let dwarf = match Dwarf::load(load) {
        Ok(dwarf) => dwarf,
        Err(_) => return Vec::new(),
    };

    let mut out: Vec<SymbolInfo> = Vec::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let low = match entry.attr_value(gimli::DW_AT_low_pc) {
                Some(gimli::AttributeValue::Addr(low)) => low,
                _ => continue,
            };
            let size = match entry.attr_value(gimli::DW_AT_high_pc) {
                Some(gimli::AttributeValue::Addr(high)) => high.saturating_sub(low),
                Some(gimli::AttributeValue::Udata(offset)) => offset,
                _ => 0,
            };
            let name = entry
                .attr_value(gimli::DW_AT_name)
                .and_then(|value| dwarf.attr_string(&unit, value).ok())
                .map(|reader| reader.to_string_lossy().into_owned())
                .unwrap_or_default();
            if low != 0 && size > 0 {
                out.push(SymbolInfo {
                    rva: low.saturating_sub(base),
                    size,
                    name,
                });
            }
        }
    }
    out.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    out.dedup_by(|a, b| a.sort_key() == b.sort_key());
    out
}

/// Every named entry in a PE export directory with its address, read directly.
///
/// `object::File::exports` drops exports whose address is not in an executable
/// section. That is wrong for system libraries: current Windows exports a large
/// share of `kernel32` — the heap APIs among them — through stubs that live in
/// read-only data, and the filter silently discards them (211 of kernel32's 1698
/// exports on the machine this was written on). An export's address is where a
/// caller jumps; whether the bytes there are code is the caller's question.
///
/// Forwarded exports are not returned: their directory slot holds a string, not
/// an address, and the forwarder chain is a loader concern. Neither are unnamed
/// (ordinal-only) entries: every returned pair has a non-empty name.
///
/// Returns `None` when the image is not a PE or has no export directory.
#[must_use]
pub fn pe_export_entries(data: &[u8]) -> Option<Vec<(String, u64)>> {
    let u16_at = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    if data.get(0..2)? != b"MZ" {
        return None;
    }
    let pe_offset = u32_at(0x3c)? as usize;
    if data.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let is_pe32 = u16_at(pe_offset + 24)? == 0x10b;
    let optional = pe_offset + 24;
    let directory = if is_pe32 {
        optional + 96
    } else {
        optional + 112
    };
    let export_rva = u32_at(directory)?;
    if export_rva == 0 {
        return None;
    }
    let section_count = u16_at(pe_offset + 6)? as usize;
    let sections = optional + u16_at(pe_offset + 20)? as usize;
    let rva_to_offset = |rva: u32| -> Option<usize> {
        (0..section_count).find_map(|index| {
            let header = sections + index * 40;
            let virtual_size = u32_at(header + 8)?;
            let virtual_address = u32_at(header + 12)?;
            let raw_size = u32_at(header + 16)?;
            let raw_pointer = u32_at(header + 20)?;
            (virtual_address <= rva && rva < virtual_address + virtual_size.max(raw_size))
                .then(|| raw_pointer as usize + (rva - virtual_address) as usize)
        })
    };
    let export_dir = rva_to_offset(export_rva)?;
    let function_count = u32_at(export_dir + 20)? as usize;
    let name_count = u32_at(export_dir + 24)? as usize;
    let functions = rva_to_offset(u32_at(export_dir + 28)?)?;
    let names = rva_to_offset(u32_at(export_dir + 32)?)?;
    let ordinals = rva_to_offset(u32_at(export_dir + 36)?)?;
    // The forwarder range: a function slot inside it is a string, not an address.
    let forward_base = u32_at(export_dir + 16)?;
    let forward_end = forward_base + u32_at(export_dir + 20 - 4)?;
    let mut out = Vec::with_capacity(name_count);
    for index in 0..name_count {
        let name_offset = rva_to_offset(u32_at(names + index * 4)?)?;
        let end = data[name_offset..].iter().position(|&b| b == 0)? + name_offset;
        let name = String::from_utf8_lossy(&data[name_offset..end]).into_owned();
        if name.is_empty() {
            continue;
        }
        let ordinal = u16_at(ordinals + index * 2)? as usize;
        if ordinal >= function_count {
            continue;
        }
        let rva = u32_at(functions + ordinal * 4)?;
        if rva == 0 || (forward_base..forward_end).contains(&rva) {
            continue;
        }
        out.push((name, u64::from(rva)));
    }
    Some(out)
}

impl LoadedModule {
    /// 载入伴生 PDB，把子程序（名字 + RVA + 精确长度）并入 [`Self::debug_functions`]。
    ///
    /// 这是 PE 精确边界的通道：mingw/MSVC 的 `-g` 把调试信息放伴生 `.pdb`（zig 在
    /// windows-gnu 目标产出 `<stem>.pdb`），EXE 本体没有 symtab 可用。ELF 调用无害
    /// （PDB 对 ELF 没意义，一般不会存在伴生文件）。
    /// 返回并入的新条目数；幂等（重复载入同名同 RVA 不重复计）。
    ///
    /// # Errors
    /// 打不开 / 解析不动 PDB 时返回 [`PdbError`]；调用方可以选择降级（没有 PDB 就
    /// 继续用 `.pdata` / call 证据）。
    pub fn load_pdb(&mut self, path: &std::path::Path) -> Result<usize, PdbError> {
        use pdb::FallibleIterator as _;

        let expected = self.pdb_identity.ok_or(PdbError::IdentityUnavailable)?;
        let file = std::fs::File::open(path)
            .map_err(|e| PdbError::Open(format!("{}: {e}", path.display())))?;
        let mut pdb =
            pdb::PDB::open(file).map_err(|e| PdbError::Open(format!("{}: {e}", path.display())))?;
        let pdb_info = pdb
            .pdb_information()
            .map_err(|e| PdbError::Parse(e.to_string()))?;
        let guid = *pdb_info.guid.as_bytes();
        let pdbi_age = pdb_info.age;
        let debug_info = pdb
            .debug_information()
            .map_err(|e| PdbError::Parse(e.to_string()))?;
        authenticate_pdb(expected, guid, pdbi_age, debug_info.age())?;
        let address_map = pdb
            .address_map()
            .map_err(|e| PdbError::Parse(e.to_string()))?;

        let mut found: Vec<SymbolInfo> = Vec::new();
        let mut modules = debug_info
            .modules()
            .map_err(|e| PdbError::Parse(e.to_string()))?;
        while let Ok(Some(module)) = modules.next() {
            let Ok(Some(info)) = pdb.module_info(&module) else {
                continue;
            };
            let Ok(mut symbols) = info.symbols() else {
                continue;
            };
            while let Ok(Some(symbol)) = symbols.next() {
                let Ok(pdb::SymbolData::Procedure(procedure)) = symbol.parse() else {
                    continue;
                };
                let Some(rva) = procedure.offset.to_rva(&address_map) else {
                    continue;
                };
                if procedure.len == 0 {
                    continue;
                }
                found.push(SymbolInfo {
                    rva: u64::from(rva.0),
                    size: u64::from(procedure.len),
                    name: procedure.name.to_string().into_owned(),
                });
            }
        }

        found.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        found.dedup_by(|a, b| a.sort_key() == b.sort_key());
        let before = self.debug_functions.len();
        self.debug_functions.extend(found);
        self.debug_functions
            .sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        self.debug_functions
            .dedup_by(|a, b| a.sort_key() == b.sort_key());
        Ok(self.debug_functions.len() - before)
    }

    /// 解析一个 ELF / PE 可执行文件。
    ///
    /// # Errors
    /// 非支持容器或结构损坏时返回 [`ImageError`]。
    pub fn parse(data: &[u8]) -> Result<Self, ImageError> {
        // 先做格式门（object::File::parse 对"不是二进制"给的是笼统错误）。
        let container =
            match FileKind::parse(data as &[u8]).map_err(|_| ImageError::UnsupportedFormat)? {
                FileKind::Elf64 => Container::Elf64,
                FileKind::Elf32 => Container::Elf32,
                FileKind::Pe64 => Container::Pe64,
                FileKind::Pe32 => Container::Pe32,
                FileKind::MachO64 => Container::MachO64,
                FileKind::MachO32 => Container::MachO32,
                FileKind::MachOFat64 => Container::MachOFat64,
                FileKind::MachOFat32 => Container::MachOFat32,
                FileKind::DyldCache => Container::DyldCache,
                FileKind::Wasm => Container::Wasm,
                FileKind::Xcoff64 => Container::Xcoff64,
                FileKind::Xcoff32 => Container::Xcoff32,
                FileKind::Coff => Container::Coff,
                FileKind::CoffBig => Container::CoffBig,
                FileKind::CoffImport => Container::CoffImport,
                FileKind::Archive => Container::Archive,
                _ => return Err(ImageError::UnsupportedFormat),
            };
        if !container.is_loadable() {
            // Recognised, but there is no loadable image behind it. Report the
            // format so callers can say what they saw instead of "unsupported".
            return Err(ImageError::NotLoadable(container.short()));
        }
        let file = object::File::parse(data).map_err(|e| ImageError::Parse(e.to_string()))?;
        Self::from_object(&file, data, container)
    }

    /// 地址空间视图。
    #[must_use]
    pub fn address_space(&self) -> FileAddressSpace<'_> {
        FileAddressSpace {
            backing: &self.backing,
            data: &self.data,
            segments: &self.segments,
        }
    }

    /// 覆盖某 RVA 的节。
    #[must_use]
    pub fn section_at(&self, rva: u64) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|s| s.rva > 0 && rva >= s.rva && rva < s.rva.saturating_add(s.size))
    }

    /// 内容寻址模块指纹：sha256 over（规范化头 + 可执行节按 RVA 升序拼接）。
    ///
    /// 归一化配方（identity v1）：
    /// `"kotama-id-v1"` + 每个执行节 `name|rva|len\n` 头 + 节字节。
    /// 重新编译 → 指纹变；同字节不同文件名 / 不同非执行节 → 仍变（含全部节会太脆，
    /// 只锚定执行节：重排 debug 节不影响身份）。
    #[must_use]
    pub fn module_id(&self) -> ModuleId {
        // 静态侧的口径：执行节按**虚拟尺寸**零填充——与活体（内存映像天然满尺寸）
        // 对齐，identity 才能跨静态/活体成立。
        let sections: Vec<(String, u64, u64, Vec<u8>)> = self
            .backing
            .iter()
            .filter_map(|range| {
                let section = self.section_at(range.rva)?;
                if !section.executable {
                    return None;
                }
                let start = range.offset;
                let end = start + usize::try_from(range.size).unwrap_or(usize::MAX);
                let bytes = self.data.get(start..end).unwrap_or(&[]).to_vec();
                Some((section.name.clone(), range.rva, section.size, bytes))
            })
            .collect();
        module_id_from_sections(&sections)
    }

    fn from_object(
        file: &object::File<'_>,
        data: &[u8],
        container: Container,
    ) -> Result<Self, ImageError> {
        let arch = match file.architecture() {
            object::Architecture::X86_64 => Arch::X86_64,
            object::Architecture::I386 => Arch::X86,
            other => Arch::Other(arch_name(other)),
        };

        // 归一基址：一切 RVA = 绝对地址 - base（ELF = 最小 LOAD 段 vaddr；PE = ImageBase）。
        // 不归一会出两种病：ELF 带着链接基址（与 Ghidra 口径差 0x100000，差分全 0）；
        // PE 更糟——`.pdata` 是相对的而节地址是绝对的，一张函数表里混两套地址空间
        // （2026-11-23 oracle 首跑实抓）。归一后与 Ghidra 的 image-base 减法同口径。
        let base = image_base(file, data, container);
        let to_rva = |address: u64| address.saturating_sub(base);

        let mut sections = Vec::new();
        let mut backing = Vec::new();
        let mut segments = Vec::new();
        for section in file.sections() {
            let size = section.size();
            if size == 0 {
                continue;
            }
            let name = section.name().unwrap_or("").to_string();
            let rva = to_rva(section.address());
            let kind = section.kind();
            let executable = kind == object::SectionKind::Text;
            sections.push(SectionInfo {
                rva,
                size,
                name: name.clone(),
                executable,
            });
            // 无字节背书（NOBITS / 仅元数据）、0 地址节（.debug_* 一类文件级元数据，
            // 不参与装载映像；挤在 rva 0 会遮蔽整个低地址空间——2026-11-23 vtable
            // 扫描实抓：read(0x29cb0) 读到的是 .debug_info 的 ASCII 垃圾）与过界节
            // 不进地址空间。
            if rva == 0 {
                continue;
            }
            let Some((offset, file_size)) = section.file_range() else {
                continue;
            };
            if file_size == 0 {
                continue;
            }
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            if offset >= data.len() {
                continue;
            }
            let cap = (data.len() - offset)
                .min(usize::try_from(file_size).unwrap_or(usize::MAX))
                .min(usize::try_from(size).unwrap_or(usize::MAX));
            let Ok(cap) = u64::try_from(cap) else {
                continue;
            };
            backing.push(BackingRange {
                rva,
                size: cap,
                offset,
            });
            segments.push(Segment {
                rva,
                size: cap,
                perms: Perms {
                    read: true,
                    write: kind == object::SectionKind::Data,
                    execute: executable,
                },
            });
        }
        sections.sort_by_key(|s| (s.rva, s.name.clone()));
        backing.sort_by_key(|r| (r.rva, r.size));
        segments.sort_by_key(|s| (s.rva, s.size));

        let mut symbols = Vec::new();
        for symbol in file.symbols() {
            if symbol.kind() != object::SymbolKind::Text || !symbol.is_definition() {
                continue;
            }
            // A zero-size Text symbol at the image base is the container's own
            // header marker (the Mach-O execute header, an ELF header alias),
            // not a function. Dropping it keeps the function table honest.
            if symbol.size() == 0 && to_rva(symbol.address()) == 0 {
                continue;
            }
            symbols.push(SymbolInfo {
                rva: to_rva(symbol.address()),
                size: symbol.size(),
                name: symbol.name().unwrap_or("").to_string(),
            });
        }
        symbols.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        symbols.dedup_by(|a, b| a.sort_key() == b.sort_key());

        let mut dynamic_symbols = Vec::new();
        for symbol in file.dynamic_symbols() {
            if symbol.kind() != object::SymbolKind::Text || !symbol.is_definition() {
                continue;
            }
            dynamic_symbols.push(SymbolInfo {
                rva: to_rva(symbol.address()),
                size: symbol.size(),
                name: symbol.name().unwrap_or("").to_string(),
            });
        }
        // PE: read the export directory directly. `object::File::exports` drops
        // exports whose address is not in an executable section, which discards
        // every stub-exported call in the system libraries (211 of kernel32's 1698
        // here); see `pe_export_entries`.
        if matches!(container, Container::Pe64 | Container::Pe32) {
            if let Some(entries) = pe_export_entries(data) {
                for (name, rva) in entries {
                    dynamic_symbols.push(SymbolInfo { rva, size: 0, name });
                }
            }
        }
        dynamic_symbols.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        dynamic_symbols.dedup_by(|a, b| a.sort_key() == b.sort_key());

        let mut imports = Vec::new();
        if let Ok(iterator) = file.imports() {
            for imported in iterator.flatten() {
                let library = std::str::from_utf8(imported.library())
                    .unwrap_or("")
                    .to_string();
                let name = match imported.name() {
                    NameOrOrdinal::Name(bytes) => {
                        std::str::from_utf8(bytes).unwrap_or("").to_string()
                    }
                    NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                imports.push(ImportInfo { library, name });
            }
        }
        imports.sort_by(|a, b| (&a.library, &a.name).cmp(&(&b.library, &b.name)));
        imports.dedup_by(|a, b| a.library == b.library && a.name == b.name);

        // Mach-O's LC_MAIN entry offset is already image-relative, unlike ELF
        // and PE where the entry is an absolute/virtual address. Subtracting the
        // base again would underflow to 0 and fabricate a function at RVA 0.
        let raw_entry = file.entry();
        let entry_rva = (raw_entry != 0).then_some(match container {
            Container::MachO64 | Container::MachO32 => raw_entry,
            _ => to_rva(raw_entry),
        });

        // 自相对重定位（ELF PIE 的 vtable/GOT 真值所在）。
        let mut relative_relocations = Vec::new();
        if let Some(iterator) = file.dynamic_relocations() {
            for (offset, relocation) in iterator {
                if relocation.kind() == object::RelocationKind::Relative {
                    relative_relocations.push((to_rva(offset), to_rva(relocation.addend() as u64)));
                }
            }
        }
        relative_relocations.sort_unstable();
        let debug_functions = dwarf_functions(file, base);
        let eh_frame_functions = frame_functions(file, base);
        let exception_directory = pe_data_directory(data, container, 3);
        let pdb_identity = pe_pdb_identity(data, &backing, container);
        let resources = pe_resources(data, &backing, container);
        let version_info = pe_version_info(data, &backing, &resources);

        Ok(Self {
            container,
            arch,
            entry_rva,
            segments,
            sections,
            symbols,
            dynamic_symbols,
            imports,
            debug_functions,
            eh_frame_functions,
            exception_directory,
            resources,
            version_info,
            pdb_identity,
            image_base: base,
            relative_relocations,
            data: data.to_vec(),
            backing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 夹具目录存在才跑（车道测试：容器车道挂载了工作树，`fixtures/generated` 在）。
    fn fixture(rel: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated")
            .join(rel);
        if path.exists() {
            Some(path)
        } else if std::env::var("KOTAMA_REQUIRE_FIXTURES").as_deref() == Ok("1") {
            panic!(
                "required fixture missing: {}; run tools/build_fixtures.py",
                path.display()
            );
        } else {
            None
        }
    }

    #[test]
    fn parses_x86_64_elf_fixture() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let module = LoadedModule::parse(&data).unwrap();
        assert_eq!(module.container, Container::Elf64);
        assert_eq!(module.arch, Arch::X86_64);
        assert!(module.entry_rva.is_some());
        assert!(module.symbols.iter().any(|s| s.name == "main"));
        assert!(!module.segments.is_empty());
    }

    #[test]
    fn pe_resource_tree_is_flattened_and_sorted() {
        let mut data = vec![0u8; 96];
        data[12..14].copy_from_slice(&0u16.to_le_bytes());
        data[14..16].copy_from_slice(&1u16.to_le_bytes());
        data[16..20].copy_from_slice(&3u32.to_le_bytes());
        data[20..24].copy_from_slice(&(0x8000_0000u32 | 24).to_le_bytes());
        data[24 + 12..24 + 14].copy_from_slice(&0u16.to_le_bytes());
        data[24 + 14..24 + 16].copy_from_slice(&1u16.to_le_bytes());
        data[40..44].copy_from_slice(&1u32.to_le_bytes());
        data[44..48].copy_from_slice(&(0x8000_0000u32 | 48).to_le_bytes());
        data[48 + 12..48 + 14].copy_from_slice(&0u16.to_le_bytes());
        data[48 + 14..48 + 16].copy_from_slice(&1u16.to_le_bytes());
        data[64..68].copy_from_slice(&1033u32.to_le_bytes());
        data[68..72].copy_from_slice(&80u32.to_le_bytes());
        data[80..84].copy_from_slice(&0x2000u32.to_le_bytes());
        data[84..88].copy_from_slice(&4u32.to_le_bytes());
        data[88..92].copy_from_slice(&1252u32.to_le_bytes());
        let backing = [BackingRange {
            rva: 0x1000,
            size: 96,
            offset: 0,
        }];
        let directory = DataDirectory {
            rva: 0x1000,
            size: 96,
        };
        let resources = parse_resource_tree(&data, &backing, directory);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].type_id, 3);
        assert_eq!(resources[0].id, 1);
        assert_eq!(resources[0].language, 1033);
        assert_eq!(resources[0].code_page, 1252);
        assert_eq!(resources[0].rva, 0x2000);
        assert_eq!(resources[0].size, 4);
    }

    fn version_block(key: &str, value: &[u8], value_type: u16, children: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 0]);
        let value_length = if value_type == 1 {
            value.len() / 2
        } else {
            value.len()
        };
        bytes.extend_from_slice(&(value_length as u16).to_le_bytes());
        bytes.extend_from_slice(&value_type.to_le_bytes());
        for unit in key.encode_utf16().chain(Some(0)) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(value);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(children);
        let length = bytes.len() as u16;
        bytes[0..2].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn pe_version_info_is_parsed_from_synthetic_resource() {
        let mut fixed = vec![0u8; 52];
        fixed[0..4].copy_from_slice(&0xfeef_04bdu32.to_le_bytes());
        fixed[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        fixed[8..12].copy_from_slice(&1u32.to_le_bytes());
        fixed[12..16].copy_from_slice(&2u32.to_le_bytes());
        fixed[16..20].copy_from_slice(&3u32.to_le_bytes());
        fixed[20..24].copy_from_slice(&4u32.to_le_bytes());
        let value: Vec<u8> = "Kotama\0"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let string = version_block("CompanyName", &value, 1, &[]);
        let table = version_block("040904b0", &[], 1, &string);
        let string_file = version_block("StringFileInfo", &[], 1, &table);
        let root = version_block("VS_VERSION_INFO", &fixed, 0, &string_file);
        let info = parse_vs_version_info(&root).unwrap();
        assert_eq!(info.file_version, Some((1, 2)));
        assert_eq!(info.product_version, Some((3, 4)));
        assert_eq!(
            info.strings.get("CompanyName").map(String::as_str),
            Some("Kotama")
        );
    }

    #[test]
    fn parses_x86_pe_fixture() {
        let Some(path) = fixture("x86-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let module = LoadedModule::parse(&data).unwrap();
        assert_eq!(module.container, Container::Pe32);
        assert_eq!(module.arch, Arch::X86);
        assert!(module.imports.iter().any(|i| i.name.contains("printf")));
    }

    #[test]
    fn pe_exports_are_loaded_as_dynamic_symbols() {
        let Some(path) = fixture("x86-windows-gnu/-O2/exports.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let module = LoadedModule::parse(&data).unwrap();
        assert_eq!(module.container, Container::Pe32);
        assert!(
            module
                .dynamic_symbols
                .iter()
                .any(|symbol| symbol.name == "fixture_exported"),
            "exports missing: {:?}",
            module.dynamic_symbols
        );
    }

    #[test]
    fn pe64_exports_are_loaded_as_dynamic_symbols() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/exports.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let module = LoadedModule::parse(&data).unwrap();
        assert_eq!(module.container, Container::Pe64);
        assert_eq!(module.arch, Arch::X86_64);
        assert!(
            module
                .dynamic_symbols
                .iter()
                .any(|symbol| symbol.name == "fixture_exported"),
            "exports missing: {:?}",
            module.dynamic_symbols
        );
    }

    #[test]
    fn module_id_is_stable_and_content_addressed() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/switch") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let first = LoadedModule::parse(&data).unwrap().module_id();
        let second = LoadedModule::parse(&data).unwrap().module_id();
        assert_eq!(first, second);
        // 同源不同优化档 → 代码节字节不同 → 指纹必须不同。
        let other = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/generated/x86_64-linux-gnu/-O0/switch"),
        )
        .unwrap();
        let other_id = LoadedModule::parse(&other).unwrap().module_id();
        assert_ne!(first, other_id);
    }

    #[test]
    fn loads_companion_pdb_for_pe() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let Some(pdb) = fixture("x86_64-windows-gnu/-O2/loops.pdb") else {
            eprintln!("skip: companion pdb not built");
            return;
        };
        let mut module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(module.pdb_identity.is_some(), "PE must carry RSDS identity");
        assert!(
            module.debug_functions.is_empty(),
            "no debug info before pdb"
        );
        let added = module.load_pdb(&pdb).unwrap();
        assert!(
            added > 10,
            "mingw pdb should carry many procedures, got {added}"
        );
        assert!(module
            .debug_functions
            .iter()
            .any(|s| s.name == "main" && s.size > 0));
        // 幂等：重复载入不重复计。
        let again = module.load_pdb(&pdb).unwrap();
        assert_eq!(again, 0);
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_rsds() -> (Vec<u8>, Vec<BackingRange>, PdbIdentity) {
        let mut data = vec![0u8; 0x400];
        write_u32(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let optional = 0x98;
        data[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        write_u32(&mut data, optional + 108, 16);
        let debug_directory = optional + 112 + 6 * 8;
        write_u32(&mut data, debug_directory, 0x2000);
        write_u32(&mut data, debug_directory + 4, 28);

        let entry = 0x200;
        write_u32(&mut data, entry + 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
        write_u32(&mut data, entry + 16, 24);
        write_u32(&mut data, entry + 20, 0x2100);
        write_u32(&mut data, entry + 24, 0x300);
        data[0x300..0x304].copy_from_slice(b"RSDS");
        let raw_guid: [u8; 16] = std::array::from_fn(|index| index as u8);
        data[0x304..0x314].copy_from_slice(&raw_guid);
        write_u32(&mut data, 0x314, 7);

        let expected = PdbIdentity {
            guid: [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15],
            age: 7,
        };
        let backing = vec![BackingRange {
            rva: 0x2000,
            size: 0x100,
            offset: 0x200,
        }];
        (data, backing, expected)
    }

    #[test]
    fn rsds_identity_normalizes_guid_and_reads_age() {
        let (data, backing, expected) = synthetic_rsds();
        assert_eq!(
            pe_data_directory(&data, Container::Pe64, 6),
            Some(DataDirectory {
                rva: 0x2000,
                size: 28,
            })
        );
        assert_eq!(
            pe_pdb_identity(&data, &backing, Container::Pe64),
            Some(expected)
        );
    }

    #[test]
    fn pdb_authentication_rejects_guid_and_age_mismatch() {
        let (_, _, expected) = synthetic_rsds();
        authenticate_pdb(expected, expected.guid, 99, Some(expected.age)).unwrap();

        let mut wrong_guid = expected.guid;
        wrong_guid[0] ^= 0xff;
        assert!(matches!(
            authenticate_pdb(expected, wrong_guid, expected.age, Some(expected.age)),
            Err(PdbError::IdentityMismatch { .. })
        ));
        assert!(matches!(
            authenticate_pdb(
                expected,
                expected.guid,
                expected.age + 1,
                Some(expected.age + 1)
            ),
            Err(PdbError::IdentityMismatch { .. })
        ));
        // 没有 DBI age 的老 PDB 按 pdb crate 文档接受更新过的 PDBI age。
        authenticate_pdb(expected, expected.guid, expected.age + 1, None).unwrap();
        assert!(authenticate_pdb(expected, expected.guid, expected.age - 1, None).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn authenticates_real_msvc_companion_pdb() {
        let Some(path) = fixture("x86_64-windows-msvc/-O0/loops.exe") else {
            eprintln!("skip: MSVC fixtures not built");
            return;
        };
        let Some(pdb) = fixture("x86_64-windows-msvc/-O0/loops.pdb") else {
            eprintln!("skip: MSVC companion pdb not built");
            return;
        };
        let mut module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(module.pdb_identity.is_some());
        let added = module.load_pdb(&pdb).unwrap();
        assert!(added > 0);
        assert!(module
            .debug_functions
            .iter()
            .any(|symbol| symbol.name == "main" && symbol.size > 0));
    }

    #[test]
    fn rejects_pdb_from_a_different_pe_identity() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let Some(wrong_pdb) = fixture("x86_64-windows-gnu/-O2/switch.pdb") else {
            eprintln!("skip: companion pdb not built");
            return;
        };
        let mut module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(matches!(
            module.load_pdb(&wrong_pdb),
            Err(PdbError::IdentityMismatch { .. })
        ));
        assert!(module.debug_functions.is_empty());
    }

    #[test]
    fn rejects_non_binary_input() {
        assert!(matches!(
            LoadedModule::parse(b"not a binary at all"),
            Err(ImageError::UnsupportedFormat)
        ));
    }

    #[test]
    fn recognises_object_files_as_not_loadable() {
        // A Unix ar archive is a real, well-formed container that carries no
        // loadable image. It must be reported by name, not as "unsupported".
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend_from_slice(b"member/         0           0     0     644     4         `");
        archive.extend_from_slice(b"data");
        assert!(matches!(
            LoadedModule::parse(&archive),
            Err(ImageError::NotLoadable("archive"))
        ));
    }

    /// Build a minimal but well-formed 64-bit Mach-O with a __PAGEZERO
    /// segment at 0 and a __TEXT segment at the given base, plus one Text symbol.
    fn minimal_macho64(base: u64, symbol_rva: u64, symbol_name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        let push64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        let push32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        // mach_header_64
        push32(&mut b, 0xfeed_facf); // MH_MAGIC_64
        push32(&mut b, 0x0100_0007); // CPU_TYPE_X86_64
        push32(&mut b, 3); // cpusubtype
        push32(&mut b, 2); // MH_EXECUTE
        push32(&mut b, 3); // ncmds
        let sizeofcmds_pos = b.len();
        push32(&mut b, 0); // sizeofcmds, patched below
        push32(&mut b, 0); // flags
        push32(&mut b, 0); // reserved
        let cmds_start = b.len();
        // LC_SEGMENT_64 __PAGEZERO
        push32(&mut b, 0x19);
        push32(&mut b, 72);
        b.extend_from_slice(b"__PAGEZERO\0\0\0\0\0\0");
        push64(&mut b, 0);
        push64(&mut b, 0x1_0000_0000);
        push64(&mut b, 0);
        push64(&mut b, 0);
        push32(&mut b, 0);
        push32(&mut b, 0);
        push32(&mut b, 0);
        push32(&mut b, 0);
        // LC_SEGMENT_64 __TEXT with one section_64 (__text).
        push32(&mut b, 0x19);
        push32(&mut b, 72 + 80);
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        push64(&mut b, base);
        push64(&mut b, 0x1000);
        push64(&mut b, 0);
        push64(&mut b, 0x1000);
        push32(&mut b, 5);
        push32(&mut b, 5);
        push32(&mut b, 1); // nsects
        push32(&mut b, 0);
        // section_64 __text: sectname[16], segname[16], addr, size, offset,
        // align, reloff, nreloc, flags, reserved1, reserved2, reserved3
        b.extend_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        push64(&mut b, base);
        push64(&mut b, 0x100);
        push32(&mut b, 0); // offset
        push32(&mut b, 4); // align
        push32(&mut b, 0); // reloff
        push32(&mut b, 0); // nreloc
        push32(&mut b, 0x80000400); // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        push32(&mut b, 0);
        push32(&mut b, 0);
        push32(&mut b, 0);
        // LC_SYMTAB
        push32(&mut b, 0x2);
        push32(&mut b, 24);
        let symoff_pos = b.len();
        push32(&mut b, 0);
        push32(&mut b, 1); // nsyms
        let stroff_pos = b.len();
        push32(&mut b, 0);
        let strsize_pos = b.len();
        push32(&mut b, 0);
        let sizeofcmds = (b.len() - cmds_start) as u32;
        b[sizeofcmds_pos..sizeofcmds_pos + 4].copy_from_slice(&sizeofcmds.to_le_bytes());
        while b.len() % 8 != 0 {
            b.push(0);
        }
        // nlist_64: strx, type, sect, desc, value
        let symoff = b.len() as u32;
        push32(&mut b, 1);
        b.push(0x0f); // N_SECT | N_EXT
        b.push(1);
        b.extend_from_slice(&0u16.to_le_bytes()); // desc is u16
        push64(&mut b, base + symbol_rva);
        let stroff = b.len() as u32;
        b.push(0);
        b.extend_from_slice(symbol_name.as_bytes());
        b.push(0);
        let strsize = b.len() as u32 - stroff;
        b[symoff_pos..symoff_pos + 4].copy_from_slice(&symoff.to_le_bytes());
        b[stroff_pos..stroff_pos + 4].copy_from_slice(&stroff.to_le_bytes());
        b[strsize_pos..strsize_pos + 4].copy_from_slice(&strsize.to_le_bytes());
        b.resize(0x2000, 0);
        b
    }

    #[test]
    fn macho64_base_skips_pagezero_and_normalises_rvas() {
        let bytes = minimal_macho64(0x1_0000_0000, 0x1488, "_main");
        let module = LoadedModule::parse(&bytes).unwrap();
        assert_eq!(module.container, Container::MachO64);
        assert_eq!(module.arch, Arch::X86_64);
        assert_eq!(module.image_base, 0x1_0000_0000);
        assert_eq!(module.symbols.len(), 1);
        assert_eq!(module.symbols[0].rva, 0x1488);
        assert_eq!(module.symbols[0].name, "_main");
    }

    #[test]
    fn macho_header_marker_symbol_is_not_a_function() {
        let bytes = minimal_macho64(0x1_0000_0000, 0, "__mh_execute_header");
        let module = LoadedModule::parse(&bytes).unwrap();
        assert!(module.symbols.is_empty());
    }

    #[test]
    fn wasm_is_recognised_as_not_loadable() {
        // A wasm module: magic + version + one custom section (id 0, size,
        // name length, name). The format gate needs a well-formed module,
        // not just the magic.
        let mut bytes = b"\0asm".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        // Custom section: id 0, payload size 5, name length 4, "name".
        bytes.extend_from_slice(&[0, 5, 4]);
        bytes.extend_from_slice(b"name");
        // Type section: one () -> () function type.
        bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        let got = LoadedModule::parse(&bytes);
        assert!(
            matches!(&got, Err(ImageError::NotLoadable("wasm"))),
            "actual: {got:?}"
        );
    }

    #[test]
    fn lifter_architectures_are_disassemblable_with_zero_x86_bitness() {
        // A64, RISC-V and ARM have lifters, so they are disassemblable — but not
        // through the x86 decoder, which is what `bitness` describes. Keeping the
        // two facts apart is the point of this test.
        for arch in [
            Arch::Other("aarch64"),
            Arch::Other("riscv64"),
            Arch::Other("arm"),
        ] {
            assert!(arch.is_disassemblable(), "{arch:?}");
            assert_eq!(arch.bitness(), 0, "{arch:?}");
        }
        assert_eq!(Arch::Other("aarch64").short(), "aarch64");
        assert!(Arch::X86_64.is_disassemblable());
        assert!(Arch::X86.is_disassemblable());
    }

    #[test]
    fn an_architecture_without_a_lifter_is_recognised_but_not_disassemblable() {
        let arch = Arch::Other("mips");
        assert!(!arch.is_disassemblable());
        assert_eq!(arch.bitness(), 0);
        assert_eq!(arch.short(), "mips");
    }

    #[test]
    fn container_short_names_are_stable() {
        assert_eq!(Container::MachO64.short(), "macho64");
        assert_eq!(Container::MachOFat64.short(), "macho-fat64");
        assert_eq!(Container::DyldCache.short(), "dyld-cache");
        assert_eq!(Container::Wasm.short(), "wasm");
        assert_eq!(Container::Xcoff64.short(), "xcoff64");
        assert_eq!(Container::CoffBig.short(), "coff-big");
        assert!(Container::MachO32.is_loadable());
        assert!(!Container::Coff.is_loadable());
    }

    #[test]
    fn a_real_elf_exposes_frame_ranges_inside_its_code_section() {
        // The fixture is a real linked ELF, so this covers the whole path from the
        // section lookup through the pcrel decode to the image-base subtraction.
        // Getting the base wrong shifts every range out of `.text`, so the assertion
        // is that they land inside it.
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            !module.eh_frame_functions.is_empty(),
            "a linked ELF with debug-friendly code always carries .eh_frame"
        );
        let text = module
            .sections
            .iter()
            .find(|section| section.executable && section.name.contains("text"))
            .expect("an executable section");
        let (start, end) = (text.rva, text.rva.saturating_add(text.size));
        let outside: Vec<u64> = module
            .eh_frame_functions
            .iter()
            .map(|function| function.rva)
            .filter(|rva| *rva < start || *rva >= end)
            .collect();
        assert!(
            outside.is_empty(),
            "frame ranges outside .text[{start:#x}..{end:#x}]: {outside:x?}"
        );
        // Every range has a length, because an FDE states one.
        assert!(module.eh_frame_functions.iter().all(|f| f.size > 0));
        // A frame entry carries no name: the section describes ranges, not symbols.
        assert!(module.eh_frame_functions.iter().all(|f| f.name.is_empty()));
        // Cross-check against an independent source: the same binary's DWARF
        // subprograms state a length for the same functions. Where both describe a
        // function they must agree, which pins the FDE length decode against
        // something other than itself.
        let dwarf: std::collections::BTreeMap<u64, u64> = module
            .debug_functions
            .iter()
            .map(|function| (function.rva, function.size))
            .collect();
        assert!(!dwarf.is_empty(), "fixture must carry DWARF subprograms");
        let compared: Vec<(u64, u64, u64)> = module
            .eh_frame_functions
            .iter()
            .filter_map(|function| {
                dwarf
                    .get(&function.rva)
                    .map(|size| (function.rva, function.size, *size))
            })
            .collect();
        assert!(
            !compared.is_empty(),
            "no function is described by both tables"
        );
        for (rva, frame_size, dwarf_size) in &compared {
            assert_eq!(
                frame_size, dwarf_size,
                "frame and DWARF disagree on the length of {rva:#x}"
            );
        }
    }

    /// Cross-compiled fixtures under `fixtures/generated/cross/<lane>/<stem>`.
    fn cross(lane: &str, stem: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/cross")
            .join(lane)
            .join(stem);
        if path.exists() {
            Some(path)
        } else if std::env::var("KOTAMA_REQUIRE_FIXTURES").as_deref() == Ok("1") {
            panic!(
                "required cross fixture missing: {}; run tools/build_fixtures.py",
                path.display()
            );
        } else {
            None
        }
    }

    fn load(lane: &str, stem: &str) -> Option<LoadedModule> {
        cross(lane, stem).map(|path| {
            LoadedModule::parse(&std::fs::read(path).unwrap()).expect("cross fixture must parse")
        })
    }

    #[test]
    fn every_cross_fixture_parses_with_its_container_and_architecture() {
        // (lane, stem, container, arch name, has an entry point)
        let expected = [
            ("riscv64-norvc", "norvc", Container::Elf64, "riscv64", true),
            ("riscv64-rvc", "rvc", Container::Elf64, "riscv64", true),
            (
                "riscv64-strings",
                "strings",
                Container::Elf64,
                "riscv64",
                true,
            ),
            ("arm-a32", "a32", Container::Elf32, "arm", true),
            ("arm-thumb", "thumb", Container::Elf32, "arm", true),
            ("arm-strings", "a32", Container::Elf32, "arm", true),
            ("arm-strings-thumb", "thumb", Container::Elf32, "arm", true),
            ("aarch64-elf", "elf", Container::Elf64, "aarch64", true),
            (
                "aarch64-macho",
                "macho",
                Container::MachO64,
                "aarch64",
                true,
            ),
        ];
        let mut checked = 0;
        for (lane, stem, container, arch, entry) in expected {
            let Some(module) = load(lane, stem) else {
                continue;
            };
            assert_eq!(module.container, container, "{lane}");
            assert_eq!(module.arch, Arch::Other(arch), "{lane}");
            assert_eq!(module.entry_rva.is_some(), entry, "{lane}");
            assert!(
                module.sections.iter().any(|section| section.executable),
                "{lane}: no executable section"
            );
            checked += 1;
        }
        if checked == 0 {
            eprintln!("skip: cross fixtures not built");
        }
    }

    #[test]
    fn the_cross_fixtures_are_stripped_as_the_lanes_intend() {
        // Every cross lane links with -s. A symbol table surviving would mean the
        // discovery tests are passing on symbols rather than on the lifters.
        for (lane, stem) in [
            ("riscv64-norvc", "norvc"),
            ("arm-a32", "a32"),
            ("aarch64-elf", "elf"),
        ] {
            let Some(module) = load(lane, stem) else {
                continue;
            };
            assert!(
                module.symbols.is_empty(),
                "{lane}: {lane} must be stripped, found {} symbols",
                module.symbols.len()
            );
        }
    }

    #[test]
    fn the_frame_section_follows_the_architecture_not_the_container() {
        // A64 and RISC-V link .eh_frame; ARM release builds do not. Both are ELF64 or
        // ELF32 containers, so the container alone does not predict the frame section.
        let Some(riscv) = load("riscv64-norvc", "norvc") else {
            eprintln!("skip: cross fixtures not built");
            return;
        };
        assert_eq!(riscv.eh_frame_functions.len(), 4, "riscv64");
        let arm = load("arm-a32", "a32").unwrap();
        assert!(
            arm.eh_frame_functions.is_empty(),
            "ARM release builds carry no .eh_frame; got {}",
            arm.eh_frame_functions.len()
        );
        let a64 = load("aarch64-elf", "elf").unwrap();
        assert_eq!(a64.eh_frame_functions.len(), 20, "aarch64");
    }

    #[test]
    fn the_macho_cross_fixture_has_both_unwind_sources_and_they_disagree() {
        // The two Mach-O sources cover different sets, and this fixture shows it:
        // the symbol table names 4, __unwind_info indexes 2 (the ones with a frame) and
        // __eh_frame carries 1 FDE (_main alone — the three callees were inlined and have
        // no frame of their own). Each source answers a different question, and none
        // implies another; a reader that assumed otherwise would be wrong on this file.
        let Some(module) = load("aarch64-macho", "macho") else {
            eprintln!("skip: cross fixtures not built");
            return;
        };
        let has = |name: &str| module.sections.iter().any(|section| section.name == name);
        assert!(has("__unwind_info"), "Mach-O must carry compact unwind");
        assert!(has("__eh_frame"), "Mach-O must carry a frame section");
        assert_eq!(module.eh_frame_functions.len(), 1);
        assert_eq!(module.eh_frame_functions[0].rva, 0x1550, "_main");
        let offsets = crate::macho_unwind::function_offsets(
            module
                .address_space()
                .read(
                    module
                        .sections
                        .iter()
                        .find(|s| s.name == "__unwind_info")
                        .unwrap()
                        .rva,
                    0x50,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            offsets.len(),
            2,
            "compact unwind: functions with a frame, leaves excluded"
        );
    }

    #[test]
    fn the_thumb_fixture_keeps_its_entry_in_thumb_mode() {
        // The ELF entry of a Thumb build has bit 0 set; the image must report it as-is
        // so the lifter can read the mode off it.
        let Some(module) = load("arm-thumb", "thumb") else {
            eprintln!("skip: cross fixtures not built");
            return;
        };
        let entry = module.entry_rva.expect("entry");
        assert_eq!(entry & 1, 1, "a Thumb entry address is odd");
        let a32 = load("arm-a32", "a32").unwrap();
        assert_eq!(
            a32.entry_rva.unwrap() & 1,
            0,
            "an A32 entry address is even"
        );
    }

    #[test]
    fn the_string_fixtures_keep_their_literals_in_a_data_section() {
        for (lane, stem, literal) in [
            ("riscv64-strings", "strings", "hello_from_riscv"),
            ("arm-strings", "a32", "hello_from_arm"),
            ("arm-strings-thumb", "thumb", "hello_from_arm"),
        ] {
            let Some(module) = load(lane, stem) else {
                continue;
            };
            use kotama::AddressSpace as _;
            let space = module.address_space();
            let data: Vec<u8> = module
                .sections
                .iter()
                .filter(|section| !section.executable && section.size > 0)
                .filter_map(|section| space.read(section.rva, section.size as usize))
                .flatten()
                .copied()
                .collect();
            assert!(
                data.windows(literal.len()).any(|w| w == literal.as_bytes()),
                "{lane}: literal {literal:?} not found in data sections"
            );
        }
    }

    /// A regression that was silent: `object::File::exports` drops exports whose
    /// address is outside an executable section, and current Windows exports the
    /// heap APIs through stubs in read-only data. `HeapAlloc` therefore vanished
    /// from `dynamic_symbols` while sitting in the export directory. The direct
    /// reader keeps it. Skips where the system library is not present.
    #[test]
    fn pe_exports_outside_executable_sections_are_kept() {
        let Ok(bytes) = std::fs::read("C:/Windows/System32/kernel32.dll") else {
            eprintln!("skip: kernel32.dll not on this machine");
            return;
        };
        let module = LoadedModule::parse(&bytes).unwrap();
        for name in ["HeapAlloc", "HeapReAlloc", "HeapSize", "HeapFree"] {
            assert!(
                module
                    .dynamic_symbols
                    .iter()
                    .any(|symbol| symbol.name == name),
                "{name} is in kernel32's export directory and must survive"
            );
        }
        let direct = pe_export_entries(&bytes).unwrap();
        let object_count = module
            .dynamic_symbols
            .iter()
            .filter(|symbol| !symbol.name.is_empty() && symbol.size == 0)
            .count();
        assert!(
            direct.len() >= object_count,
            "direct read {} must not be smaller than the symbol list {}",
            direct.len(),
            object_count
        );
    }

    /// The direct reader agrees with the raw directory on a fixture it can be
    /// checked against byte for byte: the shared-library fixture from #154.
    #[test]
    fn the_direct_reader_sees_the_shared_library_fixtures_exports() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/libexports.dll");
        let Ok(bytes) = std::fs::read(&path) else {
            if std::env::var("KOTAMA_REQUIRE_FIXTURES").as_deref() == Ok("1") {
                panic!("required fixture missing: {}", path.display());
            }
            eprintln!("skip: fixture not built");
            return;
        };
        let names: Vec<String> = pe_export_entries(&bytes)
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for wanted in ["exported_add", "exported_mul", "exported_void"] {
            assert!(names.iter().any(|n| n == wanted), "{wanted} missing");
        }
        assert!(
            !names.iter().any(|n| n == "hidden_helper"),
            "a static must not be exported"
        );
    }

    /// A forwarded export's directory slot holds a string ("KERNELBASE.HeapAlloc"),
    /// not an address. The reader must return the name — a caller links against
    /// `kernel32` — but must not hand out the string's RVA as if it were code.
    /// This is exactly the case `object::File::exports` got wrong by dropping
    /// them: on this machine kernel32 forwards 211 names, HeapAlloc among them.
    #[test]
    fn forwarded_exports_are_kept_by_name_without_a_bogus_address() {
        let Ok(bytes) = std::fs::read("C:/Windows/System32/kernel32.dll") else {
            eprintln!("skip: kernel32.dll not on this machine");
            return;
        };
        let module = LoadedModule::parse(&bytes).unwrap();
        let heap = module
            .dynamic_symbols
            .iter()
            .find(|symbol| symbol.name == "HeapAlloc")
            .expect("a forwarded export is still an export of this library");
        assert_ne!(heap.rva, 0);
        assert!(
            module
                .sections
                .iter()
                .any(|section| heap.rva >= section.rva && heap.rva < section.rva + section.size),
            "the RVA must land inside some section, not in the export directory"
        );
    }

    /// Not a PE: `None`, not a panic.
    #[test]
    fn the_direct_reader_declines_non_pe_input() {
        assert!(pe_export_entries(b"not a binary at all").is_none());
        assert!(pe_export_entries(&[]).is_none());
    }
}
