//! 映像装载：把 ELF / PE 文件变成 [`kotama::AddressSpace`] 加一份模块事实。
//!
//! P0 范围（x86 / x64 的 ELF 与 PE）：段表、节表、符号（ELF symtab / ELF dynsym）、
//! 导入表、入口点、以及**内容寻址的模块指纹**。PE 导出表与 PDB / DWARF 调试信息在
//! 后续阶段接入。
//!
//! 地址约定：一切地址是「映像相对地址」（RVA）。ELF 用节/符号的 vaddr 直接当 RVA
//! （PIE 与 ET_EXEC 都成立：我们从不声称真实加载基址）；PE 的 object 表示本来就是
//! 映像相对的。运行期基址属于会话，不属于这里。
//!
//! 确定性：同一字节序列两次装载得到逐字段相同的 [`LoadedModule`]（所有集合按地址
//! 排序，无时间戳）——差分与知识库复用的前提。

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
    /// 输入不是 kotama 支持的容器（当前：ELF / PE 可执行）。
    UnsupportedFormat,
    /// 容器结构损坏，object 无法解析。
    Parse(String),
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => f.write_str("unsupported container (want ELF or PE)"),
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
}

impl fmt::Display for PdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(msg) => write!(f, "pdb open: {msg}"),
            Self::Parse(msg) => write!(f, "pdb parse: {msg}"),
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
        }
    }
}

/// 指令集架构。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    /// x86-64。
    X86_64,
    /// x86（32 位）。
    X86,
}

impl Arch {
    /// iced 反汇编器要求的位宽（32 / 64）。
    #[must_use]
    pub const fn bitness(self) -> u32 {
        match self {
            Self::X86_64 => 64,
            Self::X86 => 32,
        }
    }

    /// 短名（进 JSON 报告）。
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
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

/// 从 `.debug_*` 节提取 `DW_TAG_subprogram`（名字 + low_pc/high_pc 精确边界）。
///
/// 这是「strip 了 symtab 但留着调试信息」的二进制拿精确边界的通道；对未 strip 的
/// ELF 它与 symtab 互为印证（差分口径见 oracle）。没有 `.debug_info` 就返回空。
/// 只处理 x86/x64 的小端（[`Arch`] 门已保证），压缩节（SHF_COMPRESSED）暂不支持——
/// 读不出来就当没有，不报错。
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

        let file = std::fs::File::open(path)
            .map_err(|e| PdbError::Open(format!("{}: {e}", path.display())))?;
        let mut pdb =
            pdb::PDB::open(file).map_err(|e| PdbError::Open(format!("{}: {e}", path.display())))?;
        let address_map = pdb
            .address_map()
            .map_err(|e| PdbError::Parse(e.to_string()))?;

        let mut found: Vec<SymbolInfo> = Vec::new();
        let debug_info = pdb
            .debug_information()
            .map_err(|e| PdbError::Parse(e.to_string()))?;
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
                _ => return Err(ImageError::UnsupportedFormat),
            };
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
            other => {
                return Err(ImageError::Parse(format!(
                    "arch {other:?} not supported in P0 (x86/x64 only)"
                )))
            }
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

        let entry_rva = (file.entry() != 0).then_some(to_rva(file.entry()));

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
        path.exists().then_some(path)
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
        let pdb = path.with_extension("pdb");
        if !pdb.exists() {
            eprintln!("skip: companion pdb not built");
            return;
        }
        let mut module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
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

    #[test]
    fn rejects_non_binary_input() {
        assert!(matches!(
            LoadedModule::parse(b"not a binary at all"),
            Err(ImageError::UnsupportedFormat)
        ));
    }
}
