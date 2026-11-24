//! MSVC C++ RTTI / 虚表事实。
//!
//! 通用 [`crate::vtables`] 只认「连续已知函数槽」：槽位必须逐个落在函数发现表里。
//! MSVC 虚表常夹纯虚调用 thunk、编译器生成的小跳板等**未知目标**，按槽判断会把
//! 一张真表拆成多张。本模块换一个锚点：**虚表 address point 前一指针是 MSVC 的
//! CompleteObjectLocator（COL）指针**，从 address point 起向前收槽，遇到不可执行
//! 目标才停——未知/纯虚/thunk 槽照收，真表不碎。通用 vtables 保持原样，两条通道
//! 并存：宽口径（本模块，带类名与继承事实）与窄口径（泛用，只要函数指针表）。
//!
//! 地址规则（2026-11-23 在 x64/x86 的真实 MSVC 夹具上实测钉死）：
//!
//! - 虚表里的 COL 指针，以及 TypeDescriptor 头两个指针，都是**已重定位的完整指针**
//!   （文件里存首选 VA；本模块用 `image_base` 换回 RVA）；
//! - PE64：COL 24 字节（signature=1，第 6 个 u32 是 self RVA、必须等于 COL 自身 RVA），
//!   COL / CHD / BCA / BCD 的内部字段是 **RVA**；
//! - PE32：COL 20 字节（signature=0，无 self），同名字段是 **首选 VA**，减 `image_base`
//!   回 RVA；BCD 与 CHD 的尺寸两档相同（BCD 24 字节、CHD 16 字节、BCA 是 u32 数组）。
//!
//! 阴性约束：Itanium ABI（windows-gnu / linux-gnu）的虚表前是 typeinfo 指针，读出来
//! 的 signature / self / TypeDescriptor 名字前缀（`.?A`）都不成立，因此不会被误判；
//! ELF 等非 PE 容器直接返回空事实。
//!
//! 确定性：候选指针与事实都过 `BTreeMap` / `BTreeSet`，输出按 address point、RVA
//! 升序；同一输入两次扫描逐字段相同。
//!
//! 已知边界：MSVC 虚表没有显式终止符，槽行走的停点是「0 或不可执行目标」。若某张
//! 虚表后面紧跟着一段恰好也是可执行指针的无关数据（表本身没被 RTTI 锚定、又没被
//! 别的数据隔开），会被并入前一张表——这是留宽口径换「真表不碎」的代价。

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use kotama::AddressSpace;
use kotama_image::Container;
use kotama_image::LoadedModule;
use kotama_image::SectionInfo;

/// PE64 CompleteObjectLocator 的 signature。
const COL_SIGNATURE_PE64: u32 = 1;
/// PE32 CompleteObjectLocator 的 signature。
const COL_SIGNATURE_PE32: u32 = 0;
/// PE64 COL 长度：20 字节公共字段 + self RVA。
const COL_SIZE_PE64: usize = 24;
/// PE32 COL 长度：无 self RVA。
const COL_SIZE_PE32: usize = 20;
/// BaseClassDescriptor 长度（两档同为 24 字节；PE64 的 pTypeDescriptor 是 u32 RVA）。
const BASE_CLASS_SIZE: usize = 24;
/// ClassHierarchyDescriptor 长度。
const HIERARCHY_SIZE: usize = 16;
/// 单张虚表的槽位上限（坏数据兜底）。
const MAX_SLOTS: usize = 4096;
/// 基类数量上限（坏数据兜底）。
const MAX_BASE_CLASSES: u32 = 4096;
/// TypeDescriptor 名字的读取上限。
const MAX_NAME_BYTES: u64 = 4096;

/// 一个 MSVC `TypeDescriptor`（类型名记录）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeDescriptor {
    /// 记录的 RVA。
    pub rva: u64,
    /// 原始 MSVC 修饰名，例如 `.?AVDerived@rtti_fixture@@`。
    pub mangled: String,
    /// 解出的可读类名，例如 `rtti_fixture::Derived`；模板与无法还原的名字保留修饰形态。
    pub class_name: String,
}

/// 一个 `BaseClassDescriptor`：继承图里的一条基类事实。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BaseClass {
    /// 描述符 RVA。
    pub rva: u64,
    /// 该基类的 `TypeDescriptor`。
    pub type_descriptor: TypeDescriptor,
    /// 该基类子对象里还包含的基类数量。
    pub num_contained_bases: u32,
    /// 基类子对象在完整对象里的成员位移（`_PMD::mdisp`）。
    pub member_disp: i32,
    /// 虚基类表位移（`_PMD::pdisp`）；`-1` 表示不是虚基类。
    pub vbtable_disp: i32,
    /// 虚基类在 vbtable 里的位移（`_PMD::vdisp`）。
    pub vbase_disp: i32,
    /// 原始 BCD 属性位（不做解释，保持可追溯）。
    pub attributes: u32,
}

/// `ClassHierarchyDescriptor`：一张完整对象的类层次事实。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClassHierarchy {
    /// 描述符 RVA。
    pub rva: u64,
    /// 原始类层次属性位。
    pub attributes: u32,
    /// `BaseClassArray` 的 RVA。
    pub base_class_array_rva: u64,
    /// 按 `BaseClassArray` 顺序的基类；第一条通常是类自身。
    pub bases: Vec<BaseClass>,
}

/// MSVC `CompleteObjectLocator`：一张 vftable 的 RTTI 锚点。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompleteObjectLocator {
    /// COL 自身 RVA。
    pub rva: u64,
    /// 原始 signature（PE64 为 1、PE32 为 0；与架构不符的候选一律拒绝）。
    pub signature: u32,
    /// 该 vfptr 在完整对象里的偏移（非主基类子对象的 vftable 非 0）。
    pub offset: u32,
    /// 构造 / 析构位移（`cdOffset`）。
    pub constructor_disp: u32,
    /// PE64 的 self RVA（已校验等于 [`Self::rva`]）；PE32 无此字段，为 `None`。
    pub self_rva: Option<u64>,
    /// 完整对象的 `TypeDescriptor`。
    pub type_descriptor: TypeDescriptor,
    /// 类层次（`BaseClassArray` 展开后的继承/位移事实）。
    pub hierarchy: ClassHierarchy,
}

/// 一张锚定到 RTTI 的 MSVC 虚表。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MsvcVtable {
    /// 虚表前 COL 指针所在的 RVA（槽数据的前一指针格）。
    pub locator_ptr_rva: u64,
    /// address point：对象 vfptr 指向的 RVA（PE64 = COL 指针 + 8，PE32 = COL 指针 + 4）。
    pub address_point: u64,
    /// 对应的 COL 事实。
    pub locator: CompleteObjectLocator,
    /// 槽位目标 RVA，按槽位顺序；允许未知函数入口（纯虚/thunk）的目标。
    pub slots: Vec<u64>,
}

/// 一次 MSVC RTTI 扫描的全部事实。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MsvcRttiFacts {
    /// 按 address point 升序的虚表事实（地址不重复）。
    pub vtables: Vec<MsvcVtable>,
    /// 被引用到的全部 `TypeDescriptor`（按 RVA 升序、去重）。
    pub type_descriptors: Vec<TypeDescriptor>,
}

/// 扫描视图：静态文件与将来的活体视图共用同一条管线。
///
/// `container` 决定指针宽度与字段编码（PE64 = RVA、PE32 = VA）；非 PE 容器返回空事实。
pub struct MsvcRttiView<'a> {
    /// 容器格式。
    pub container: Container,
    /// 归一基址（PE = ImageBase）；PE32 的 VA 字段与完整指针都靠它换回 RVA。
    pub image_base: u64,
    /// 节表（exec 判定与数据节候选范围都靠它）。
    pub sections: &'a [SectionInfo],
}

/// 对一个装载好的模块提取 MSVC RTTI / 虚表事实。
///
/// 只认可 PE32 / PE64；其他容器返回空事实。确定性：同一 [`LoadedModule`] 两次调用
/// 返回逐字段相同的结果。
#[must_use]
pub fn scan(module: &LoadedModule) -> MsvcRttiFacts {
    let view = MsvcRttiView {
        container: module.container,
        image_base: module.image_base,
        sections: &module.sections,
    };
    scan_with(view, &module.address_space())
}

/// 同一条扫描管线，吃任意 [`MsvcRttiView`] + 地址空间（活体进程走这里）。
#[must_use]
pub fn scan_with(view: MsvcRttiView<'_>, space: &dyn AddressSpace) -> MsvcRttiFacts {
    let Some(pointer_size) = pointer_size(view.container) else {
        return MsvcRttiFacts::default();
    };
    let mut parser = Parser::new(Reader {
        container: view.container,
        image_base: view.image_base,
        pointer_size,
        sections: view.sections,
        space,
    });

    let mut vtables: BTreeMap<u64, MsvcVtable> = BTreeMap::new();
    for cell in parser.reader.locator_pointers() {
        let Some(locator_rva) = parser.reader.read_pointer(cell) else {
            continue;
        };
        let Some(locator) = parser.locator(locator_rva) else {
            continue;
        };
        let Some(address_point) = cell.checked_add(pointer_size) else {
            continue;
        };
        let slots = parser.reader.read_slots(address_point);
        if slots.is_empty() {
            continue;
        }
        vtables.insert(
            address_point,
            MsvcVtable {
                locator_ptr_rva: cell,
                address_point,
                locator,
                slots,
            },
        );
    }

    // 只暴露「真正关联到存活虚表」的 TypeDescriptor：解析中途失败的候选即使
    // 缓存过 TD，也不该出现在事实里（事实必须能反查回某张虚表）。
    let mut type_descriptors: BTreeMap<u64, TypeDescriptor> = BTreeMap::new();
    for table in vtables.values() {
        let locator = &table.locator.type_descriptor;
        type_descriptors.insert(locator.rva, locator.clone());
        for base in &table.locator.hierarchy.bases {
            let descriptor = &base.type_descriptor;
            type_descriptors.insert(descriptor.rva, descriptor.clone());
        }
    }

    MsvcRttiFacts {
        vtables: vtables.into_values().collect(),
        type_descriptors: type_descriptors.into_values().collect(),
    }
}

/// 指针宽度：只有 PE 才参与 MSVC RTTI 扫描。
const fn pointer_size(container: Container) -> Option<u64> {
    match container {
        Container::Pe64 => Some(8),
        Container::Pe32 => Some(4),
        Container::Elf64 | Container::Elf32 => None,
    }
}

/// 只读地址空间访问器（所有解析共用一套地址口径）。
struct Reader<'a> {
    container: Container,
    image_base: u64,
    pointer_size: u64,
    sections: &'a [SectionInfo],
    space: &'a dyn AddressSpace,
}

impl Reader<'_> {
    const fn is_pe64(&self) -> bool {
        matches!(self.container, Container::Pe64)
    }

    /// 读一个完整指针并换成 RVA：文件里存的是首选 VA（PE32 为 32 位、PE64 为 64 位），
    /// 减 `image_base`；0 或小于基址的值不算有效指针。
    fn read_pointer(&self, rva: u64) -> Option<u64> {
        let length = usize::try_from(self.pointer_size).ok()?;
        let bytes = self.space.read(rva, length)?;
        let mut raw = [0u8; 8];
        raw.get_mut(..length)?.copy_from_slice(bytes);
        let value = if self.pointer_size == 8 {
            u64::from_le_bytes(raw)
        } else {
            u64::from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
        };
        let rva = value.checked_sub(self.image_base)?;
        (rva != 0).then_some(rva)
    }

    /// 解 COL / CHD / BCA / BCD 里的 32 位字段：PE64 是 RVA、PE32 是首选 VA。
    fn resolve_field(&self, field: u32) -> Option<u64> {
        let value = u64::from(field);
        if self.is_pe64() {
            return (value != 0).then_some(value);
        }
        let rva = value.checked_sub(self.image_base)?;
        (rva != 0).then_some(rva)
    }

    /// 该 RVA 是否落在非执行节里（RTTI 数据与候选指针格的合法落点）。
    fn is_data(&self, rva: u64) -> bool {
        self.sections.iter().any(|section| {
            !section.executable
                && section.rva != 0
                && rva >= section.rva
                && rva < section.rva.saturating_add(section.size)
        })
    }

    /// 该 RVA 是否落在可执行段里（虚表槽目标的合法落点）。
    fn is_exec(&self, rva: u64) -> bool {
        self.space
            .segments()
            .iter()
            .any(|segment| segment.perms.execute && rva >= segment.rva && rva < segment.end())
    }

    /// 数据节里所有「值能减基址得到非零 RVA」的指针对齐格；COL 指针必然是其子集。
    fn locator_pointers(&self) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for section in self.sections {
            if section.executable || section.size == 0 || section.rva == 0 {
                continue;
            }
            let start = section.rva.div_ceil(self.pointer_size) * self.pointer_size;
            let end = section.rva.saturating_add(section.size);
            let count = end.saturating_sub(start) / self.pointer_size;
            for index in 0..count {
                let cell = start + index * self.pointer_size;
                if self.read_pointer(cell).is_some() {
                    out.insert(cell);
                }
            }
        }
        out
    }

    /// 从 address point 向后收槽：目标必须落在可执行段，遇到 0 / 数据目标即停。
    fn read_slots(&self, address_point: u64) -> Vec<u64> {
        let mut slots = Vec::new();
        let mut cursor = address_point;
        while slots.len() < MAX_SLOTS {
            let Some(target) = self.read_pointer(cursor) else {
                break;
            };
            if !self.is_exec(target) {
                break;
            }
            slots.push(target);
            let Some(next) = cursor.checked_add(self.pointer_size) else {
                break;
            };
            cursor = next;
        }
        slots
    }
}

/// 带缓存的解析器：同一 COL / CHD / TypeDescriptor 只解析一次，且天然按 RVA 去重。
struct Parser<'a> {
    reader: Reader<'a>,
    locators: BTreeMap<u64, CompleteObjectLocator>,
    hierarchies: BTreeMap<u64, ClassHierarchy>,
    type_descriptors: BTreeMap<u64, TypeDescriptor>,
}

impl<'a> Parser<'a> {
    const fn new(reader: Reader<'a>) -> Self {
        Self {
            reader,
            locators: BTreeMap::new(),
            hierarchies: BTreeMap::new(),
            type_descriptors: BTreeMap::new(),
        }
    }

    fn locator(&mut self, rva: u64) -> Option<CompleteObjectLocator> {
        if let Some(found) = self.locators.get(&rva) {
            return Some(found.clone());
        }
        let parsed = self.parse_locator(rva)?;
        self.locators.insert(rva, parsed.clone());
        Some(parsed)
    }

    fn type_descriptor(&mut self, rva: u64) -> Option<TypeDescriptor> {
        if let Some(found) = self.type_descriptors.get(&rva) {
            return Some(found.clone());
        }
        let parsed = self.parse_type_descriptor(rva)?;
        self.type_descriptors.insert(rva, parsed.clone());
        Some(parsed)
    }

    fn hierarchy(&mut self, rva: u64) -> Option<ClassHierarchy> {
        if let Some(found) = self.hierarchies.get(&rva) {
            return Some(found.clone());
        }
        let parsed = self.parse_hierarchy(rva)?;
        self.hierarchies.insert(rva, parsed.clone());
        Some(parsed)
    }

    fn parse_locator(&mut self, rva: u64) -> Option<CompleteObjectLocator> {
        if !self.reader.is_data(rva) {
            return None;
        }
        let expected = if self.reader.is_pe64() {
            COL_SIGNATURE_PE64
        } else {
            COL_SIGNATURE_PE32
        };
        let size = if self.reader.is_pe64() {
            COL_SIZE_PE64
        } else {
            COL_SIZE_PE32
        };
        let bytes = self.reader.space.read(rva, size)?;
        let signature = read_u32_at(bytes, 0)?;
        if signature != expected {
            return None;
        }
        let offset = read_u32_at(bytes, 4)?;
        let constructor_disp = read_u32_at(bytes, 8)?;
        let type_descriptor_field = read_u32_at(bytes, 12)?;
        let hierarchy_field = read_u32_at(bytes, 16)?;
        // PE64 独有的 self RVA 自校验：指向自己才可能是真的 COL。
        let self_rva = if self.reader.is_pe64() {
            if u64::from(read_u32_at(bytes, 20)?) != rva {
                return None;
            }
            Some(rva)
        } else {
            None
        };
        let type_descriptor_rva = self.reader.resolve_field(type_descriptor_field)?;
        let hierarchy_rva = self.reader.resolve_field(hierarchy_field)?;
        let type_descriptor = self.type_descriptor(type_descriptor_rva)?;
        let hierarchy = self.hierarchy(hierarchy_rva)?;
        Some(CompleteObjectLocator {
            rva,
            signature,
            offset,
            constructor_disp,
            self_rva,
            type_descriptor,
            hierarchy,
        })
    }

    fn parse_type_descriptor(&self, rva: u64) -> Option<TypeDescriptor> {
        if !self.reader.is_data(rva) {
            return None;
        }
        // 两个指针头（pVFTable / spare）之后才是名字。pVFTable 指向 .rdata 里的
        // type_info vftable（不可执行），实测不能拿它做校验，故跳过不读。
        let name_rva = rva.checked_add(self.reader.pointer_size.checked_mul(2)?)?;
        let segment = self.reader.space.segment_at(name_rva)?;
        let available = segment.end().saturating_sub(name_rva).min(MAX_NAME_BYTES);
        let length = usize::try_from(available).ok()?;
        if length == 0 {
            return None;
        }
        let bytes = self.reader.space.read(name_rva, length)?;
        let end = bytes.iter().position(|byte| *byte == 0)?;
        let text = &bytes[..end];
        // 修饰类名至少是 ".?AVX" 这一量级；纯 ASCII 可打印是硬约束。
        if text.len() < 5 || !text.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return None;
        }
        let mangled = std::str::from_utf8(text).ok()?;
        if !mangled.starts_with(".?A") {
            return None;
        }
        Some(TypeDescriptor {
            rva,
            mangled: mangled.to_string(),
            class_name: decode_class_name(mangled),
        })
    }

    fn parse_hierarchy(&mut self, rva: u64) -> Option<ClassHierarchy> {
        if !self.reader.is_data(rva) {
            return None;
        }
        let header = self.reader.space.read(rva, HIERARCHY_SIZE)?;
        if read_u32_at(header, 0)? != 0 {
            return None;
        }
        let attributes = read_u32_at(header, 4)?;
        let count = read_u32_at(header, 8)?;
        if count == 0 || count > MAX_BASE_CLASSES {
            return None;
        }
        let base_class_array_rva = self.reader.resolve_field(read_u32_at(header, 12)?)?;
        if !self.reader.is_data(base_class_array_rva) {
            return None;
        }
        let count = usize::try_from(count).ok()?;
        let entry_bytes = self
            .reader
            .space
            .read(base_class_array_rva, count.checked_mul(4)?)?;
        // 先拷成 u32 再逐个解析，避免「持有数据借用 + 可变借解析器」冲突。
        let entries: Vec<u32> = entry_bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|entry| u32::from_le_bytes(*entry))
            .collect();
        let mut bases = Vec::with_capacity(entries.len());
        for entry in entries {
            let base_rva = self.reader.resolve_field(entry)?;
            bases.push(self.parse_base_class(base_rva)?);
        }
        Some(ClassHierarchy {
            rva,
            attributes,
            base_class_array_rva,
            bases,
        })
    }

    fn parse_base_class(&mut self, rva: u64) -> Option<BaseClass> {
        if !self.reader.is_data(rva) {
            return None;
        }
        let bytes = self.reader.space.read(rva, BASE_CLASS_SIZE)?;
        let type_descriptor_rva = self.reader.resolve_field(read_u32_at(bytes, 0)?)?;
        let type_descriptor = self.type_descriptor(type_descriptor_rva)?;
        Some(BaseClass {
            rva,
            type_descriptor,
            num_contained_bases: read_u32_at(bytes, 4)?,
            member_disp: read_i32_at(bytes, 8)?,
            vbtable_disp: read_i32_at(bytes, 12)?,
            vbase_disp: read_i32_at(bytes, 16)?,
            attributes: read_u32_at(bytes, 20)?,
        })
    }
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// 把 MSVC 修饰类名解成可读路径。
///
/// 规则：去掉 `.?A` 与类/结构/联合标记（`V`/`U`/`T`/`W`），去掉结尾 `@@`，
/// 再按 `@` 分段反序拼成 `::` 路径（MSVC 是内层在前）。含 `?` 的模板/特殊名
/// 不强行还原——返回原始修饰名，避免给出错误路径。
fn decode_class_name(mangled: &str) -> String {
    let Some(rest) = mangled.strip_prefix(".?A") else {
        return mangled.to_string();
    };
    let rest = rest
        .strip_prefix('V')
        .or_else(|| rest.strip_prefix('U'))
        .or_else(|| rest.strip_prefix('T'))
        .or_else(|| rest.strip_prefix('W'));
    let Some(rest) = rest else {
        return mangled.to_string();
    };
    let body = rest.strip_suffix("@@").unwrap_or(rest);
    if body.contains('?') {
        return mangled.to_string();
    }
    let parts: Vec<&str> = body.split('@').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return mangled.to_string();
    }
    let mut name = String::new();
    for (index, part) in parts.iter().rev().enumerate() {
        if index > 0 {
            name.push_str("::");
        }
        name.push_str(part);
    }
    name
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use kotama::Perms;
    use kotama::Segment;
    use kotama_image::LoadedModule;

    use super::*;

    /// 夹具目录存在才跑（与 crate 其余车道测试同口径）。
    fn fixture(relative: &str) -> Option<PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated")
            .join(relative);
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

    struct FakeSpace {
        base: u64,
        bytes: Vec<u8>,
        segments: Vec<Segment>,
    }

    impl FakeSpace {
        fn new(base: u64, size: usize, segments: Vec<Segment>) -> Self {
            Self {
                base,
                bytes: vec![0u8; size],
                segments,
            }
        }

        fn write(&mut self, rva: u64, bytes: &[u8]) {
            let start = usize::try_from(rva - self.base).expect("synthetic rva inside range");
            self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        }

        fn write_u32(&mut self, rva: u64, value: u32) {
            self.write(rva, &value.to_le_bytes());
        }

        fn write_i32(&mut self, rva: u64, value: i32) {
            self.write(rva, &value.to_le_bytes());
        }

        fn write_u64(&mut self, rva: u64, value: u64) {
            self.write(rva, &value.to_le_bytes());
        }

        fn write_pointer(&mut self, rva: u64, value: u64, pointer_size: u64) {
            if pointer_size == 8 {
                self.write_u64(rva, value);
            } else {
                self.write_u32(rva, u32::try_from(value).expect("32-bit synthetic pointer"));
            }
        }
    }

    impl AddressSpace for FakeSpace {
        fn segments(&self) -> &[Segment] {
            &self.segments
        }

        fn read(&self, rva: u64, len: usize) -> Option<&[u8]> {
            if !self
                .segments
                .iter()
                .any(|segment| segment.contains(rva, len))
            {
                return None;
            }
            let start = usize::try_from(rva.checked_sub(self.base)?).ok()?;
            self.bytes.get(start..start.checked_add(len)?)
        }
    }

    const TEXT_RVA: u64 = 0x1000;
    const LOCATOR_PTR_RVA: u64 = 0x2000;
    const LOCATOR_RVA: u64 = 0x2100;
    const TYPE_DESCRIPTOR_RVA: u64 = 0x2200;
    const HIERARCHY_RVA: u64 = 0x2300;
    const BASE_CLASS_ARRAY_RVA: u64 = 0x2400;
    const BASE_SELF_RVA: u64 = 0x2500;
    const BASE_PARENT_RVA: u64 = 0x2540;
    const PARENT_TYPE_DESCRIPTOR_RVA: u64 = 0x2600;

    /// 合成数据里 32 位 RTTI 字段的编码方式（用来钉 PE64=RVA / PE32=VA）。
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum FieldEncoding {
        Rva,
        Va,
    }

    /// 一张最小但完整的 MSVC RTTI 虚表：COL -> TD + CHD -> BCA -> 两条 BCD。
    ///
    /// 虚表三个槽，中间那个故意指向 .text 内部任意偏移（模拟纯虚/thunk 的未知槽）；
    /// 第四个槽保持 0 作为终止。返回的节表与地址空间可直接喂 scan_with。
    fn synthetic(
        container: Container,
        image_base: u64,
        encoding: FieldEncoding,
    ) -> (FakeSpace, Vec<SectionInfo>) {
        let pointer_size = pointer_size(container).expect("synthetic 只造 PE");
        let mut space = FakeSpace::new(
            0x1000,
            0x3000,
            vec![
                Segment {
                    rva: TEXT_RVA,
                    size: 0x1000,
                    perms: Perms {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                Segment {
                    rva: 0x2000,
                    size: 0x1000,
                    perms: Perms {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
        );
        let sections = vec![
            SectionInfo {
                rva: TEXT_RVA,
                size: 0x1000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x2000,
                size: 0x1000,
                name: ".rdata".into(),
                executable: false,
            },
        ];
        let field = |rva: u64| -> u32 {
            let value = match encoding {
                FieldEncoding::Rva => rva,
                FieldEncoding::Va => image_base + rva,
            };
            u32::try_from(value).expect("synthetic 32-bit field")
        };
        let pointer = |rva: u64| -> u64 { image_base + rva };

        // 虚表：COL 指针 + 三个槽 + 0 终止。
        space.write_pointer(LOCATOR_PTR_RVA, pointer(LOCATOR_RVA), pointer_size);
        let address_point = LOCATOR_PTR_RVA + pointer_size;
        space.write_pointer(address_point, pointer(TEXT_RVA), pointer_size);
        space.write_pointer(
            address_point + pointer_size,
            pointer(TEXT_RVA + 0x10),
            pointer_size,
        );
        space.write_pointer(
            address_point + pointer_size * 2,
            pointer(TEXT_RVA + 0x15),
            pointer_size,
        );

        // COL：PE64 24 字节（含 self RVA）；PE32 20 字节（无 self）。
        space.write_u32(
            LOCATOR_RVA,
            if container == Container::Pe64 {
                COL_SIGNATURE_PE64
            } else {
                COL_SIGNATURE_PE32
            },
        );
        space.write_u32(LOCATOR_RVA + 4, 0x10);
        space.write_u32(LOCATOR_RVA + 8, 0x8);
        space.write_u32(LOCATOR_RVA + 12, field(TYPE_DESCRIPTOR_RVA));
        space.write_u32(LOCATOR_RVA + 16, field(HIERARCHY_RVA));
        if container == Container::Pe64 {
            space.write_u32(
                LOCATOR_RVA + 20,
                u32::try_from(LOCATOR_RVA).expect("COL rva fits u32"),
            );
        }

        // TypeDescriptor：两个指针头 + 修饰名。pVFTable 在真实映像里指向 .rdata 的
        // type_info vftable（不可执行），实现不拿它做校验。
        space.write_pointer(TYPE_DESCRIPTOR_RVA, pointer(0x2f00), pointer_size);
        space.write_pointer(TYPE_DESCRIPTOR_RVA + pointer_size, 0, pointer_size);
        let terminator: [u8; 1] = [0];
        space.write(
            TYPE_DESCRIPTOR_RVA + pointer_size * 2,
            b".?AVDerived@fixture@@",
        );
        space.write(TYPE_DESCRIPTOR_RVA + pointer_size * 2 + 21, &terminator);

        // CHD + BCA + 两条 BCD。
        space.write_u32(HIERARCHY_RVA, 0);
        space.write_u32(HIERARCHY_RVA + 4, 0);
        space.write_u32(HIERARCHY_RVA + 8, 2);
        space.write_u32(HIERARCHY_RVA + 12, field(BASE_CLASS_ARRAY_RVA));
        space.write_u32(BASE_CLASS_ARRAY_RVA, field(BASE_SELF_RVA));
        space.write_u32(BASE_CLASS_ARRAY_RVA + 4, field(BASE_PARENT_RVA));

        space.write_u32(BASE_SELF_RVA, field(TYPE_DESCRIPTOR_RVA));
        space.write_u32(BASE_SELF_RVA + 4, 0);
        space.write_i32(BASE_SELF_RVA + 8, 0);
        space.write_i32(BASE_SELF_RVA + 12, -1);
        space.write_i32(BASE_SELF_RVA + 16, 0);
        space.write_u32(BASE_SELF_RVA + 20, 0x40);

        space.write_u32(BASE_PARENT_RVA, field(PARENT_TYPE_DESCRIPTOR_RVA));
        space.write_u32(BASE_PARENT_RVA + 4, 0);
        space.write_i32(BASE_PARENT_RVA + 8, 8);
        space.write_i32(BASE_PARENT_RVA + 12, -1);
        space.write_i32(BASE_PARENT_RVA + 16, 0);
        space.write_u32(BASE_PARENT_RVA + 20, 0x40);

        space.write_pointer(PARENT_TYPE_DESCRIPTOR_RVA, pointer(0x2f00), pointer_size);
        space.write_pointer(PARENT_TYPE_DESCRIPTOR_RVA + pointer_size, 0, pointer_size);
        space.write(
            PARENT_TYPE_DESCRIPTOR_RVA + pointer_size * 2,
            b".?AVBase@fixture@@",
        );
        space.write(
            PARENT_TYPE_DESCRIPTOR_RVA + pointer_size * 2 + 18,
            &terminator,
        );

        (space, sections)
    }

    fn scan_fake(
        space: &FakeSpace,
        sections: &[SectionInfo],
        container: Container,
        image_base: u64,
    ) -> MsvcRttiFacts {
        scan_with(
            MsvcRttiView {
                container,
                image_base,
                sections,
            },
            space,
        )
    }

    #[test]
    fn synthetic_pe64_uses_rva_fields_and_keeps_unknown_slots() {
        let image_base = 0x1_4000_0000;
        let (space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        let facts = scan_fake(&space, &sections, Container::Pe64, image_base);
        assert_eq!(
            facts,
            scan_fake(&space, &sections, Container::Pe64, image_base),
            "同一输入两次扫描必须逐字段相同"
        );
        assert_eq!(facts.vtables.len(), 1, "vtables: {:?}", facts.vtables);
        let table = &facts.vtables[0];
        assert_eq!(table.locator_ptr_rva, LOCATOR_PTR_RVA);
        assert_eq!(table.address_point, LOCATOR_PTR_RVA + 8);
        assert_eq!(
            table.slots,
            vec![TEXT_RVA, TEXT_RVA + 0x10, TEXT_RVA + 0x15],
            "未知/thunk 槽不得截断虚表"
        );
        assert_eq!(table.locator.rva, LOCATOR_RVA);
        assert_eq!(table.locator.signature, COL_SIGNATURE_PE64);
        assert_eq!(table.locator.offset, 0x10);
        assert_eq!(table.locator.constructor_disp, 0x8);
        assert_eq!(table.locator.self_rva, Some(LOCATOR_RVA));
        assert_eq!(table.locator.type_descriptor.rva, TYPE_DESCRIPTOR_RVA);
        assert_eq!(table.locator.type_descriptor.class_name, "fixture::Derived");
        assert_eq!(
            table.locator.hierarchy.base_class_array_rva,
            BASE_CLASS_ARRAY_RVA
        );
        let bases = &table.locator.hierarchy.bases;
        assert_eq!(bases.len(), 2);
        assert_eq!(bases[0].type_descriptor.class_name, "fixture::Derived");
        assert_eq!(bases[0].member_disp, 0);
        assert_eq!(bases[0].vbtable_disp, -1);
        assert_eq!(bases[0].attributes, 0x40);
        assert_eq!(bases[1].type_descriptor.class_name, "fixture::Base");
        assert_eq!(bases[1].member_disp, 8);
        assert_eq!(bases[1].num_contained_bases, 0);
        let descriptor_rvas: Vec<u64> = facts.type_descriptors.iter().map(|td| td.rva).collect();
        assert_eq!(
            descriptor_rvas,
            vec![TYPE_DESCRIPTOR_RVA, PARENT_TYPE_DESCRIPTOR_RVA]
        );
    }

    #[test]
    fn synthetic_pe32_uses_va_fields_and_four_byte_address_point() {
        let image_base = 0x40_0000;
        let (space, sections) = synthetic(Container::Pe32, image_base, FieldEncoding::Va);
        let facts = scan_fake(&space, &sections, Container::Pe32, image_base);
        assert_eq!(facts.vtables.len(), 1, "vtables: {:?}", facts.vtables);
        let table = &facts.vtables[0];
        assert_eq!(table.locator_ptr_rva, LOCATOR_PTR_RVA);
        assert_eq!(table.address_point, LOCATOR_PTR_RVA + 4);
        assert_eq!(table.slots.len(), 3);
        assert_eq!(table.locator.signature, COL_SIGNATURE_PE32);
        assert_eq!(table.locator.self_rva, None);
        assert_eq!(table.locator.type_descriptor.class_name, "fixture::Derived");
        assert_eq!(
            table.locator.hierarchy.bases[1].type_descriptor.class_name,
            "fixture::Base"
        );
    }

    #[test]
    fn pe64_fields_must_be_rvas_and_pe32_fields_must_be_vas() {
        // PE64 映像按 PE32 的 VA 规则写 COL/BCD 字段：不能当 RVA 接受。
        let image_base = 0x1000_0000;
        let (space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Va);
        assert!(
            scan_fake(&space, &sections, Container::Pe64, image_base)
                .vtables
                .is_empty(),
            "PE64 的 COL/BCD 字段必须是 RVA"
        );

        // PE32 映像按 PE64 的 RVA 规则写字段：VA 小于 ImageBase，必须拒绝。
        let image_base = 0x40_0000;
        let (space, sections) = synthetic(Container::Pe32, image_base, FieldEncoding::Rva);
        assert!(
            scan_fake(&space, &sections, Container::Pe32, image_base)
                .vtables
                .is_empty(),
            "PE32 的 COL/BCD 字段必须是首选 VA"
        );
    }

    #[test]
    fn clearing_locator_pointer_drops_the_association() {
        let image_base = 0x1_4000_0000;
        let (mut space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        space.write_u64(LOCATOR_PTR_RVA, 0);
        let facts = scan_fake(&space, &sections, Container::Pe64, image_base);
        assert!(facts.vtables.is_empty(), "锚点清零后不应再关联虚表");
        assert!(facts.type_descriptors.is_empty());
    }

    #[test]
    fn rewriting_type_descriptor_changes_the_class_name() {
        let image_base = 0x1_4000_0000;
        let (mut space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        let terminator: [u8; 1] = [0];
        space.write(TYPE_DESCRIPTOR_RVA + 16, b".?AVRotated@fixture@@");
        space.write(TYPE_DESCRIPTOR_RVA + 16 + 21, &terminator);
        let facts = scan_fake(&space, &sections, Container::Pe64, image_base);
        assert_eq!(facts.vtables.len(), 1);
        let table = &facts.vtables[0];
        assert_eq!(table.address_point, LOCATOR_PTR_RVA + 8);
        assert_eq!(
            table.locator.type_descriptor.mangled,
            ".?AVRotated@fixture@@"
        );
        assert_eq!(table.locator.type_descriptor.class_name, "fixture::Rotated");
        assert_eq!(
            table.locator.hierarchy.bases[0].type_descriptor.class_name,
            "fixture::Rotated"
        );
        assert_eq!(
            table.locator.hierarchy.bases[1].type_descriptor.class_name,
            "fixture::Base"
        );
    }

    #[test]
    fn breaking_locator_signature_is_rejected() {
        let image_base = 0x1_4000_0000;
        let (mut space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        space.write_u32(LOCATOR_RVA, COL_SIGNATURE_PE64 + 1);
        assert!(scan_fake(&space, &sections, Container::Pe64, image_base)
            .vtables
            .is_empty());

        let image_base = 0x40_0000;
        let (mut space, sections) = synthetic(Container::Pe32, image_base, FieldEncoding::Va);
        space.write_u32(LOCATOR_RVA, COL_SIGNATURE_PE32 + 1);
        assert!(scan_fake(&space, &sections, Container::Pe32, image_base)
            .vtables
            .is_empty());
    }

    #[test]
    fn breaking_locator_self_rva_is_rejected() {
        let image_base = 0x1_4000_0000;
        let (mut space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        space.write_u32(
            LOCATOR_RVA + 20,
            u32::try_from(LOCATOR_RVA + 4).expect("rva fits"),
        );
        assert!(scan_fake(&space, &sections, Container::Pe64, image_base)
            .vtables
            .is_empty());
    }

    #[test]
    fn breaking_type_descriptor_prefix_is_rejected() {
        let image_base = 0x1_4000_0000;
        let (mut space, sections) = synthetic(Container::Pe64, image_base, FieldEncoding::Rva);
        let terminator: [u8; 1] = [0];
        space.write(TYPE_DESCRIPTOR_RVA + 16, b"X?AVDerived@fixture@@");
        space.write(TYPE_DESCRIPTOR_RVA + 16 + 21, &terminator);
        assert!(scan_fake(&space, &sections, Container::Pe64, image_base)
            .vtables
            .is_empty());
    }

    /// 真实 MSVC PE 的事实断言：类名、address point、继承/位移、纯虚槽。
    ///
    /// MSVC 夹具只能由原生 Windows 车道产出（tools/build_fixtures.py 对非 Windows
    /// 宿主直接拒绝），所以整组测试按平台门控；Linux CI 不缺夹具也不误报。
    #[cfg(target_os = "windows")]
    fn assert_real_msvc(relative: &str, pointer_size: u64) {
        let Some(path) = fixture(relative) else {
            eprintln!("skip: fixture {relative} not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let facts = scan(&module);
        assert!(!facts.vtables.is_empty(), "{relative} 未扫出任何 RTTI 虚表");
        assert!(
            facts.vtables.len() >= 10,
            "{relative}: 只扫出 {} 张虚表，覆盖不足",
            facts.vtables.len()
        );
        assert_eq!(facts, scan(&module), "{relative} 两次扫描必须逐字段相同");
        assert!(
            facts
                .vtables
                .windows(2)
                .all(|pair| pair[0].address_point < pair[1].address_point),
            "{relative} 的 vtables 未按 address point 升序"
        );
        for table in &facts.vtables {
            assert_eq!(table.address_point, table.locator_ptr_rva + pointer_size);
            assert!(!table.slots.is_empty());
            for slot in &table.slots {
                let section = module.section_at(*slot).expect("槽目标必须落在节里");
                assert!(section.executable, "{relative}: 槽目标不在执行节 {slot:#x}");
            }
        }
        let names: BTreeSet<&str> = facts
            .type_descriptors
            .iter()
            .map(|descriptor| descriptor.class_name.as_str())
            .collect();
        for expected in [
            "rtti_fixture::Device",
            "rtti_fixture::Left",
            "rtti_fixture::Right",
            "rtti_fixture::Fan",
        ] {
            assert!(
                names.contains(expected),
                "{relative} 缺类名 {expected}: {names:?}"
            );
        }
        let fan: Vec<&MsvcVtable> = facts
            .vtables
            .iter()
            .filter(|table| table.locator.type_descriptor.class_name == "rtti_fixture::Fan")
            .collect();
        assert!(
            fan.len() >= 2,
            "{relative}: Fan 只有 {} 张 vftable",
            fan.len()
        );
        assert!(
            fan.iter().any(|table| table.locator.offset > 0),
            "{relative}: Fan 的非主基类 vtable offset 全为 0"
        );
        let primary = fan
            .iter()
            .find(|table| table.locator.offset == 0)
            .expect("Fan 主 vtable 必须存在");
        let bases = &primary.locator.hierarchy.bases;
        let base_names: BTreeSet<&str> = bases
            .iter()
            .map(|base| base.type_descriptor.class_name.as_str())
            .collect();
        for expected in [
            "rtti_fixture::Fan",
            "rtti_fixture::Left",
            "rtti_fixture::Right",
            "rtti_fixture::Device",
        ] {
            assert!(
                base_names.contains(expected),
                "{relative}: Fan 层次缺 {expected}: {base_names:?}"
            );
        }
        let device = bases
            .iter()
            .find(|base| base.type_descriptor.class_name == "rtti_fixture::Device")
            .expect("Fan 层次里必须有 Device 虚基类");
        assert!(
            device.vbtable_disp >= 0,
            "{relative}: Device 是虚继承，pdisp 应指向 vbtable"
        );
        let right = bases
            .iter()
            .find(|base| base.type_descriptor.class_name == "rtti_fixture::Right")
            .expect("Fan 层次里必须有 Right");
        assert!(
            right.member_disp > 0,
            "{relative}: Right 是非主基类，mdisp 应非 0"
        );
        assert_eq!(right.vbtable_disp, -1);
        // 抽象基类 Device 的 vftable 是纯虚调用槽：收槽必须越过未知目标。
        let device_table = facts
            .vtables
            .iter()
            .find(|table| table.locator.type_descriptor.class_name == "rtti_fixture::Device")
            .expect("Device vftable 必须存在");
        assert!(
            device_table.slots.len() >= 3,
            "{relative}: 纯虚/thunk 槽被截断: {:?}",
            device_table.slots
        );
        // 通用 vtables 通道保持不变：函数发现照常可用。
        assert!(!crate::discover(&module).is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn real_msvc_pe64_rtti_reports_class_names_and_address_points() {
        for relative in [
            "x86_64-windows-msvc/-O2/msvc_rtti.exe",
            "x86_64-windows-msvc/-O0/msvc_rtti.exe",
        ] {
            assert_real_msvc(relative, 8);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn real_msvc_pe32_rtti_reports_class_names_and_address_points() {
        for relative in [
            "x86-windows-msvc/-O2/msvc_rtti.exe",
            "x86-windows-msvc/-O0/msvc_rtti.exe",
        ] {
            assert_real_msvc(relative, 4);
        }
    }

    #[test]
    fn gnu_itanium_tables_are_not_mistaken_for_msvc_rtti() {
        let mut checked = 0usize;
        for relative in [
            "x86_64-windows-gnu/-O2/msvc_rtti.exe",
            "x86-windows-gnu/-O2/msvc_rtti.exe",
            "x86_64-linux-gnu/-O2/msvc_rtti",
            "x86_64-linux-gnu/-O2/vtable",
        ] {
            let Some(path) = fixture(relative) else {
                continue;
            };
            let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
            let facts = scan(&module);
            assert!(
                facts.vtables.is_empty(),
                "{relative} 的 Itanium 虚表被误判成 MSVC RTTI: {:?}",
                facts
                    .vtables
                    .iter()
                    .map(|table| table.locator.type_descriptor.class_name.as_str())
                    .collect::<Vec<_>>()
            );
            checked += 1;
        }
        if checked == 0 {
            eprintln!("skip: 没有可用的 gnu C++ 夹具；先跑 tools/build_fixtures.py");
        }
    }
}
