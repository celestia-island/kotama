//! 函数发现：多路证据种子合并成一张带来源的函数表。
//!
//! P0 证据（设计案 §4.2 的子集；provenance 是硬要求——每条结论都记它信谁）：
//!
//! - `sym`：ELF symtab 的已定义函数符号（名字 + 精确长度，非 strip 二进制覆盖近全量）
//! - `dynsym`：ELF dynsym 导出的函数
//! - `pdata`：PE64 `.pdata` 的 `RUNTIME_FUNCTION`（编译器自记的精确边界）
//! - `entry`：映像入口点
//! - `call`：可执行节的直接 `call` 目标（线性反汇编收集；strip 二进制的主要信号）
//! - `pointer`：非执行节里的函数指针（回调表 / vtable / 手工分派表）
//! - `immediate`：代码里的绝对地址立即数（`push offset` / `mov reg, offset`）
//! - `prologue`：16 字节对齐、前面有填充的 `sub esp, imm` 序言
//!
//! 长度推断：没有边界的条目按「到下一个函数条目的距离」补（`size_inferred = true`）。
//! 确定性：所有输出按 RVA 升序、证据集合排序稳定；同一输入两次发现逐字段相同。

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::FlowControl;
use iced_x86::Instruction;
use iced_x86::OpKind;
use kotama::AddressSpace;
use kotama_image::Arch;
use kotama_image::Container;
use kotama_image::DataDirectory;
use kotama_image::ExceptionFunction;
use kotama_image::LoadedModule;
use kotama_image::RuntimeFunction;
use kotama_image::SectionInfo;
use kotama_image::SymbolInfo;
use kotama_image::UnwindInfo;

pub mod msvc_rtti;

pub use kotama::Evidence;
pub use kotama::FunctionEntry;

/// 合并中的条目（内部态）。
#[derive(Default)]
struct Builder {
    size: Option<u64>,
    name: Option<String>,
    evidence: BTreeSet<Evidence>,
}

/// 对装载好的模块做函数发现。
///
/// 确定性：同一 [`LoadedModule`] 两次调用返回逐字段相同的结果。
// 适配器：让既有发现主体把「视图 + 地址空间」当模块用（字段同名 + address_space()）。
// 泛型字段经 Deref 不行（生命周期），所以直接平铺字段。
struct ViewAdapter<'a> {
    container: Container,
    arch: Arch,
    image_base: u64,
    entry_rva: Option<u64>,
    sections: &'a [SectionInfo],
    symbols: &'a [SymbolInfo],
    dynamic_symbols: &'a [SymbolInfo],
    debug_functions: &'a [SymbolInfo],
    space: &'a dyn AddressSpace,
}
impl ViewAdapter<'_> {
    #[must_use]
    const fn address_space(&self) -> &dyn AddressSpace {
        self.space
    }
}

/// 发现管线的输入视图：静态文件与活体进程各构造一份，跑同一条管线
/// （设计案地基一——「文件 / 活体 / 快照不是三套代码」的类型化落地）。
pub struct ScanView<'a> {
    /// 容器格式（决定 `.pdata` 证据是否启用等）。
    pub container: Container,
    /// 指令集架构。
    pub arch: Arch,
    /// 入口 RVA（无则 `None`）。
    pub entry_rva: Option<u64>,
    /// PE 的首选映像基址；0 表示从地址空间的 PE 头读取（活体缓存）。
    pub image_base: u64,
    /// 节表（执行节判定 / `.pdata` 定位都靠它）。
    pub sections: &'a [SectionInfo],
    /// ELF symtab 函数符号（活体一般为空）。
    pub symbols: &'a [SymbolInfo],
    /// ELF dynsym（活体一般为空）。
    pub dynamic_symbols: &'a [SymbolInfo],
    /// 调试信息子程序（DWARF / PDB；活体一般为空）。
    pub debug_functions: &'a [SymbolInfo],
}

/// 对一个装载好的模块做函数发现（静态侧便捷入口）。
///
/// 确定性：同一 [`LoadedModule`] 两次调用返回逐字段相同的结果。
#[must_use]
pub fn discover(module: &LoadedModule) -> Vec<FunctionEntry> {
    let view = ScanView {
        container: module.container,
        arch: module.arch,
        image_base: module.image_base,
        entry_rva: module.entry_rva,
        sections: &module.sections,
        symbols: &module.symbols,
        dynamic_symbols: &module.dynamic_symbols,
        debug_functions: &module.debug_functions,
    };
    discover_impl(view, &module.address_space(), module.exception_directory)
}

/// 提取静态 PE64 的完整异常目录与 `.xdata` 事实，供反编译 sidecar 使用。
///
/// 结果按完整 RUNTIME_FUNCTION 排序去重；同一份坏输入不会依赖节遍历顺序。
#[must_use]
pub fn exception_functions(module: &LoadedModule) -> Vec<ExceptionFunction> {
    let exception_directory = module.exception_directory;
    let space = module.address_space();
    let view = ViewAdapter {
        container: module.container,
        arch: module.arch,
        image_base: module.image_base,
        entry_rva: module.entry_rva,
        sections: &module.sections,
        symbols: &module.symbols,
        dynamic_symbols: &module.dynamic_symbols,
        debug_functions: &module.debug_functions,
        space: &space,
    };
    exception_functions_impl(&view, exception_directory)
}

/// 同一条发现管线，吃任意 [`ScanView`] + 地址空间（活体进程走这里）。
///
/// 活体视图尚未携带数据目录时，保留 `.pdata` 节回退；静态 [`discover`] 优先使用
/// PE exception directory。
pub fn discover_with(view: ScanView<'_>, space: &dyn AddressSpace) -> Vec<FunctionEntry> {
    discover_impl(view, space, None)
}

fn discover_impl(
    view: ScanView<'_>,
    space: &dyn AddressSpace,
    exception_directory: Option<DataDirectory>,
) -> Vec<FunctionEntry> {
    let module = ViewAdapter {
        container: view.container,
        arch: view.arch,
        image_base: view.image_base,
        entry_rva: view.entry_rva,
        sections: view.sections,
        symbols: view.symbols,
        dynamic_symbols: view.dynamic_symbols,
        debug_functions: view.debug_functions,
        space,
    };
    let mut table: BTreeMap<u64, Builder> = BTreeMap::new();

    // 1) ELF symtab：名字 + 长度，优先级最高（先插，名字不被后续覆盖）。
    for symbol in module.symbols {
        let entry = table.entry(symbol.rva).or_default();
        if symbol.size > 0 && entry.size.is_none() {
            entry.size = Some(symbol.size);
        }
        if entry.name.is_none() && !symbol.name.is_empty() {
            entry.name = Some(symbol.name.clone());
        }
        entry.evidence.insert(Evidence::Symtab);
    }

    // 2) 调试信息的子程序：ELF = DWARF、PE = 伴生 PDB（`load_pdb` 已并入）；strip 了
    //    symtab 但留调试信息的通道；与 symtab 互为印证。
    let debug_evidence = match module.container {
        Container::Elf64 | Container::Elf32 => Evidence::Dwarf,
        Container::Pe64 | Container::Pe32 => Evidence::Pdb,
    };
    for symbol in module.debug_functions {
        let entry = table.entry(symbol.rva).or_default();
        if entry.size.is_none() && symbol.size > 0 {
            entry.size = Some(symbol.size);
        }
        if entry.name.is_none() && !symbol.name.is_empty() {
            entry.name = Some(symbol.name.clone());
        }
        entry.evidence.insert(debug_evidence);
    }

    // 3) ELF dynsym：导出面（strip 但保留动态符号的库 / PIE）。
    for symbol in module.dynamic_symbols {
        let entry = table.entry(symbol.rva).or_default();
        if entry.size.is_none() && symbol.size > 0 {
            entry.size = Some(symbol.size);
        }
        if entry.name.is_none() && !symbol.name.is_empty() {
            entry.name = Some(symbol.name.clone());
        }
        entry.evidence.insert(Evidence::Dynsym);
    }

    // 3) PE64 exception directory：编译器自记的函数边界；节名仅是活体兼容回退。
    for exception in exception_functions_impl(&module, exception_directory) {
        let runtime = exception.runtime;
        let entry = table.entry(u64::from(runtime.begin_rva)).or_default();
        if entry.size.is_none() {
            entry.size = Some(u64::from(runtime.end_rva.saturating_sub(runtime.begin_rva)));
        }
        entry.evidence.insert(Evidence::Pdata);
    }

    // 4) 入口点。
    if let Some(entry_rva) = module.entry_rva {
        table
            .entry(entry_rva)
            .or_default()
            .evidence
            .insert(Evidence::Entry);
    }

    // 5) 直接 call 目标 + 非执行节里的函数指针。条件/无条件跳转目标不进入种子：
    //    函数内跳转占绝大多数，直接当函数起点会级联出大量假函数。
    let exec_ranges: Vec<(u64, u64)> = module
        .sections
        .iter()
        .filter(|s| s.executable && s.size > 0)
        .map(|s| (s.rva, s.size))
        .collect();
    for target in direct_call_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::CallTarget);
    }
    for target in data_pointer_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PointerTarget);
    }
    for target in immediate_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::ImmediateTarget);
    }
    for target in prologue_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PrologueTarget);
    }

    // 6) 线性扫描精化：按解码出的终结符重算边界，并合并「其实落在前一个函数体内」的候选。
    let rvas: Vec<u64> = table.keys().copied().collect();
    if std::env::var_os("KOTAMA_DEBUG_DISCOVER").is_some() {
        eprintln!(
            "# discover: table={} keys[:8]={:?} … keys[3..6]={:?}",
            table.len(),
            &rvas[..rvas.len().min(8)],
            &rvas[3..rvas.len().min(6)]
        );
    }
    let mut out = refine_bodies(&module, &exec_ranges, rvas, &table);
    out.sort_by_key(|entry| entry.rva);
    out
}

/// 线性扫描精化。
///
/// 为什么需要：`call` 目标会命中**函数中间的共享尾块**（编译器把多个返回路径合并到
/// 一段公共代码），把那里当成新函数入口就会把真函数从中间切断——伪 C 里的分支会被
/// 误判成「函数外」，CFG 直接断。判据很直接：从入口顺序解码，如果还没遇到终结
/// （`ret` / 无条件跳转 / 间接跳转 / 非法指令）就先撞上了下一个候选入口，那这个
/// 候选根本不是新函数，合并进当前函数继续解码。
///
/// 精确边界（symtab 长度 / `.pdata`）一律信任，只精化推断出来的那些。
fn refine_bodies(
    module: &ViewAdapter<'_>,
    exec_ranges: &[(u64, u64)],
    rvas: Vec<u64>,
    table: &BTreeMap<u64, Builder>,
) -> Vec<FunctionEntry> {
    let space = module.address_space();
    let bitness = module.arch.bitness();
    let mut out: Vec<FunctionEntry> = Vec::with_capacity(rvas.len());
    let mut index = 0usize;

    while index < rvas.len() {
        let start = rvas[index];
        let builder = &table[&start];

        // 落在上一个已出函数体内的候选 = 共享尾块残余：证据并入上一个，不再单出
        //（否则中途起跳的垃圾解码会级联吸收后面所有候选——vtable 夹具实抓：
        // 一次吞掉八千个表项只剩 6 个「函数」）。
        if let Some(last) = out.last() {
            let last_end = last.rva.saturating_add(last.size.max(1));
            if start < last_end {
                if let Some(last_entry) = out.last_mut() {
                    last_entry.evidence.extend(builder.evidence.iter().copied());
                }
                index += 1;
                continue;
            }
        }

        // 精确边界：直接采信，不做扫描。
        if let Some(size) = builder.size {
            out.push(FunctionEntry {
                rva: start,
                size,
                size_inferred: false,
                name: builder.name.clone(),
                evidence: builder.evidence.clone(),
            });
            index += 1;
            continue;
        }

        let section_limit = exec_limit(exec_ranges, start);
        let mut end = start;
        let mut merged: BTreeSet<Evidence> = builder.evidence.clone();
        let mut consumed = 0usize;
        'sweep: loop {
            let next_candidate = rvas.get(index + 1 + consumed).copied();
            let stop_at = next_candidate.map_or(section_limit, |n| n.min(section_limit));
            let len = usize::try_from(stop_at.saturating_sub(end)).unwrap_or(0);
            if len == 0 {
                break;
            }
            let Some(bytes) = space.read(end, len) else {
                break;
            };
            let mut decoder = Decoder::with_ip(bitness, bytes, end, DecoderOptions::NONE);
            let mut stopped = false;
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    // 非法指令 = 解码失步，停在这里别硬扫（更别级联吸收）。
                    stopped = true;
                    break;
                }
                end = instruction.next_ip();
                if is_terminator(&instruction) {
                    stopped = true;
                    break;
                }
            }
            if stopped {
                break 'sweep;
            }
            // 没终结就撞到下一个候选：只有**无精确边界**的候选（call 噪声）可被吸收；
            // 有 symtab/DWARF/pdata 边界的是真函数，吸收它等于吃掉一个函数。
            let Some(next) = next_candidate else {
                break;
            };
            if next >= section_limit {
                break;
            }
            match table.get(&next) {
                Some(absorbed) if absorbed.size.is_none() => {
                    merged.extend(absorbed.evidence.iter().copied());
                    consumed += 1;
                }
                _ => break,
            }
        }

        let size = end.saturating_sub(start);
        out.push(FunctionEntry {
            rva: start,
            size,
            size_inferred: true,
            name: builder.name.clone(),
            evidence: merged,
        });
        index += 1 + consumed;
    }
    out
}

/// 是否终止一个函数体（顺序执行不再往下走）。
fn is_terminator(instruction: &Instruction) -> bool {
    matches!(
        instruction.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Interrupt
            | FlowControl::Exception
    )
}

/// RVA 所在执行节的末端（不含）；不在任何执行节时返回 RVA 自身（长度 0）。
fn exec_limit(exec_ranges: &[(u64, u64)], rva: u64) -> u64 {
    exec_ranges
        .iter()
        .find(|(start, size)| rva >= *start && rva < start + size)
        .map_or(rva, |(start, size)| start + size)
}

/// 一条函数级调用边：`from` 的函数体内直接 `call` 到 `to` 的函数。
///
/// 目标按「包含它的函数条目」归并（共享尾块已被 [`discover`] 的精化合并，
/// 所以落在函数中段的 call 目标也归到该函数）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CallEdge {
    /// 调用方入口 RVA。
    pub from: u64,
    /// 被调方入口 RVA。
    pub to: u64,
}

/// 计算函数级调用图（xref 的调用方向）。
///
/// 只收**直接** call（rel32 / rel8）；间接调用（`call rax` / GOT / PLT 尾跳）记不进来——
/// 这是 P0 口径，PLT 展开与间接目标解析随 P1 的 xref 深化补。
/// 确定性：按 `(from, to)` 排序去重。
#[must_use]
pub fn call_graph(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<CallEdge> {
    use std::collections::BTreeSet;

    let space = module.address_space();
    let bitness = module.arch.bitness();
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();

    for function in functions {
        if function.size == 0 {
            continue;
        }
        let Some(bytes) = space.read(
            function.rva,
            usize::try_from(function.size).unwrap_or(usize::MAX),
        ) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(bitness, bytes, function.rva, DecoderOptions::NONE);
        let mut buffer = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut buffer);
            if buffer.flow_control() != FlowControl::Call {
                continue;
            }
            let Some(target) = direct_near_target(&buffer) else {
                continue;
            };
            if let Some(callee) = entry_containing(functions, target) {
                if callee != function.rva {
                    edges.insert((function.rva, callee));
                }
            }
        }
    }
    edges
        .into_iter()
        .map(|(from, to)| CallEdge { from, to })
        .collect()
}

/// 找包含某地址的函数条目入口（条目按 RVA 升序）。
fn entry_containing(functions: &[FunctionEntry], address: u64) -> Option<u64> {
    let index = functions.partition_point(|entry| entry.rva <= address);
    let entry = index.checked_sub(1).map(|i| &functions[i])?;
    let end = entry.rva.saturating_add(entry.size.max(1));
    (address < end).then_some(entry.rva)
}

/// 一条字符串引用：某函数体里引用了某地址处的字符串字面量。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StringXref {
    /// 引用方函数入口 RVA。
    pub func_rva: u64,
    /// 字符串所在 RVA。
    pub string_rva: u64,
    /// 字符串内容（ASCII 可打印段，最长 64）。
    pub text: String,
}

/// 扫函数体里对字符串字面量的引用（`lea reg,[rip+X]` / 立即数落到只读数据节）。
///
/// 用途（设计案 §4.2）：① 给函数起"它操作什么数据"的语义线索；② 字符串 xref 聚类的
/// 输入。判据保守：目标必须落在**非执行**节、解出来 ≥4 个可打印字符、以 NUL 收尾。
/// 确定性：按 `(func_rva, string_rva)` 排序去重。
#[must_use]
pub fn string_xrefs(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<StringXref> {
    use std::collections::BTreeSet;

    let space = module.address_space();
    let bitness = module.arch.bitness();
    let data_sections: Vec<(u64, u64)> = module
        .sections
        .iter()
        // 地址为 0 的节（.comment / .symtab 一类）不参与装载映像，是文件级元数据。
        .filter(|s| !s.executable && s.size > 0 && s.rva > 0)
        .map(|s| (s.rva, s.size))
        .collect();
    let in_data = |address: u64| {
        data_sections
            .iter()
            .any(|(start, size)| address >= *start && address < start + size)
    };

    let mut out: BTreeSet<(u64, u64, String)> = BTreeSet::new();
    for function in functions {
        if function.size == 0 {
            continue;
        }
        let Some(bytes) = space.read(
            function.rva,
            usize::try_from(function.size).unwrap_or(usize::MAX),
        ) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(bitness, bytes, function.rva, DecoderOptions::NONE);
        let mut buffer = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut buffer);
            // 只取 RIP 相对内存操作数：字符串引用的常态形态（`lea reg,[rip+X]`）。
            // 立即数形态只出现在非 PIE 的 `mov esi,imm32`，P1 先不碰（误判面大）。
            if buffer.is_ip_rel_memory_operand() {
                let target = buffer.ip_rel_memory_address();
                if in_data(target) {
                    if let Some(text) = read_cstring(&space, target) {
                        out.insert((function.rva, target, text));
                    }
                }
            }
        }
    }
    out.into_iter()
        .map(|(func_rva, string_rva, text)| StringXref {
            func_rva,
            string_rva,
            text,
        })
        .collect()
}

/// 读一段以 NUL 收尾的可打印 ASCII（≥4 字符，≤64），否则 `None`。
///
/// 读取按所在段尾截断——`AddressSpace::read` 的契约是「完整落在单个背书范围」，
/// 一次要满 65 字节会在字符串贴节尾时整体失败（jump_table 同型坑）。
fn read_cstring(space: &dyn AddressSpace, rva: u64) -> Option<String> {
    const MAX: usize = 64;
    let limit = space
        .segment_at(rva)?
        .end()
        .saturating_sub(rva)
        .min(u64::try_from(MAX + 1).ok()?);
    let len = usize::try_from(limit).ok()?;
    if len < 5 {
        return None;
    }
    let bytes = space.read(rva, len)?;
    let end = bytes.iter().position(|b| *b == 0)?;
    if end < 4 {
        return None;
    }
    let text = &bytes[..end];
    if text.iter().all(|b| (0x20..=0x7e).contains(b)) {
        Some(String::from_utf8_lossy(text).into_owned())
    } else {
        None
    }
}

/// 一个识别出的 vtable（或纯函数指针表）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vtable {
    /// 表起始 RVA。
    pub rva: u64,
    /// 槽位目标（函数入口 RVA，按槽位顺序）。
    pub targets: Vec<u64>,
}

/// 扫描 vtable / 纯函数指针表。
///
/// 判据：非执行节里**指针宽度对齐**的连续 ≥2 个槽位，每个槽位都解析到**已知函数入口**。
/// 槽位解析两条路：
/// 1. PIE ELF：vtable 槽在文件里是 0，真值在 `R_*_RELATIVE` 重定位的 addend——
///    用 [`LoadedModule::relative_relocations`]（这也是为什么它必须由 image 提供）。
/// 2. 非 PIE / PE：槽里是原始绝对地址，减 `image_base` 回 RVA。
///
/// 「每个目标都是已知函数」这一条杀掉 GOT / 字符串指针表 / C 结构体混排的噪声；
/// 代价是 C++ 夹具外的覆盖依赖函数表质量——这是有意的保守。
/// 确定性：按表 RVA 升序；目标列表保持槽位顺序。
#[must_use]
pub fn vtables(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<Vtable> {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    let space = module.address_space();
    let pointer_size: u64 = if module.arch == Arch::X86_64 { 8 } else { 4 };
    let entries: BTreeSet<u64> = functions.iter().map(|f| f.rva).collect();
    let relocs: BTreeMap<u64, u64> = module.relative_relocations.iter().copied().collect();

    // 候选节：非执行、有地址（rva>0）、非 0 地址元数据。
    let candidates: Vec<(u64, u64)> = module
        .sections
        .iter()
        .filter(|s| !s.executable && s.size > 0 && s.rva > 0)
        .map(|s| (s.rva, s.size))
        .collect();

    let mut out: Vec<Vtable> = Vec::new();
    for (start, size) in candidates {
        // 按指针对齐读槽。
        let aligned_start = start.div_ceil(pointer_size) * pointer_size;
        let count = size.saturating_sub(aligned_start - start) / pointer_size;
        let mut run_start: Option<u64> = None;
        let mut run: Vec<u64> = Vec::new();
        for index in 0..count {
            let slot = aligned_start + index * pointer_size;
            let resolved = relocs.get(&slot).copied().or_else(|| {
                let len = usize::try_from(pointer_size).ok()?;
                let bytes = space.read(slot, len)?;
                let value = match pointer_size {
                    8 => {
                        let mut raw = [0u8; 8];
                        raw.copy_from_slice(bytes);
                        u64::from_le_bytes(raw)
                    }
                    _ => {
                        let mut raw = [0u8; 4];
                        raw.copy_from_slice(bytes);
                        u64::from(u32::from_le_bytes(raw))
                    }
                };
                (value > module.image_base).then(|| value - module.image_base)
            });
            let is_function = resolved.is_some_and(|rva| entries.contains(&rva));
            if is_function {
                if run_start.is_none() {
                    run_start = Some(slot);
                }
                run.push(resolved.expect("checked above"));
            } else if run.len() >= 2 {
                out.push(Vtable {
                    rva: run_start.expect("run nonempty implies start"),
                    targets: std::mem::take(&mut run),
                });
                run_start = None;
            } else {
                run.clear();
                run_start = None;
            }
        }
        if run.len() >= 2 {
            out.push(Vtable {
                rva: run_start.unwrap_or_default(),
                targets: run,
            });
        }
    }
    out.sort_by_key(|v| v.rva);
    out.dedup_by(|a, b| a.rva == b.rva);
    out
}

const RUNTIME_FUNCTION_SIZE: u64 = 12;
const UNW_FLAG_EHANDLER: u8 = 1;
const UNW_FLAG_UHANDLER: u8 = 2;
const UNW_FLAG_CHAININFO: u8 = 4;

/// 读取 PE64 exception directory；没有目录时才按 `.pdata` 节名回退。
fn runtime_functions(
    module: &ViewAdapter<'_>,
    directory: Option<DataDirectory>,
) -> Vec<RuntimeFunction> {
    if module.container != Container::Pe64 {
        return Vec::new();
    }
    let directory = directory.or_else(|| {
        module
            .sections
            .iter()
            .find(|section| section.name == ".pdata")
            .map(|section| DataDirectory {
                rva: section.rva,
                size: section.size,
            })
    });
    let Some(directory) = directory else {
        return Vec::new();
    };
    let space = module.address_space();
    // 数据目录的声明尺寸可能含尾部填充；截到可读段尾，避免一条坏尾记录抹掉整表。
    let available = space
        .segment_at(directory.rva)
        .map_or(directory.size, |segment| {
            segment.end().saturating_sub(directory.rva)
        });
    let count = directory.size.min(available) / RUNTIME_FUNCTION_SIZE;
    let Ok(length) = usize::try_from(count * RUNTIME_FUNCTION_SIZE) else {
        return Vec::new();
    };
    let Some(bytes) = space.read(directory.rva, length) else {
        return Vec::new();
    };
    let mut out: Vec<RuntimeFunction> = bytes
        .as_chunks::<12>()
        .0
        .iter()
        .filter_map(|entry| {
            let begin_rva = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let end_rva = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let unwind_info_rva = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            (begin_rva != 0 && end_rva > begin_rva).then_some(RuntimeFunction {
                begin_rva,
                end_rva,
                unwind_info_rva,
            })
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn read_u32(space: &dyn AddressSpace, rva: u32) -> Option<u32> {
    let bytes = space.read(u64::from(rva), 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// 解析 UNWIND_INFO 头与对齐后的 handler/chained 尾随记录。
fn unwind_info(space: &dyn AddressSpace, rva: u32) -> Option<UnwindInfo> {
    if rva == 0 {
        return None;
    }
    let header = space.read(u64::from(rva), 4)?;
    let version = header[0] & 0x07;
    let flags = header[0] >> 3;
    let unwind_code_count = header[2];
    // UNWIND_CODE 是 u16；尾随 handler/RUNTIME_FUNCTION 按 4 字节对齐。
    let trailing_offset = (4usize + usize::from(unwind_code_count) * 2 + 3) & !3;
    let trailing_rva = rva.checked_add(u32::try_from(trailing_offset).ok()?)?;
    let mut handler_rva = None;
    let mut chained = None;
    if flags & UNW_FLAG_CHAININFO != 0 {
        let begin_rva = read_u32(space, trailing_rva)?;
        let end_rva = read_u32(space, trailing_rva.checked_add(4)?)?;
        let unwind_info_rva = read_u32(space, trailing_rva.checked_add(8)?)?;
        chained = (begin_rva != 0 && end_rva > begin_rva).then_some(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva,
        });
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let handler = read_u32(space, trailing_rva)?;
        handler_rva = (handler != 0).then_some(handler);
    }
    Some(UnwindInfo {
        version,
        flags,
        prolog_size: header[1],
        unwind_code_count,
        frame_register: header[3] & 0x0f,
        frame_offset: header[3] >> 4,
        handler_rva,
        chained,
    })
}

fn exception_functions_impl(
    module: &ViewAdapter<'_>,
    directory: Option<DataDirectory>,
) -> Vec<ExceptionFunction> {
    let space = module.address_space();
    runtime_functions(module, directory)
        .into_iter()
        .map(|runtime| ExceptionFunction {
            runtime,
            unwind: unwind_info(space, runtime.unwind_info_rva),
        })
        .collect()
}

/// 从 PE 可选头读取映像基址（指针可能是绝对 VA，需要它归一成 RVA）。
fn pe_image_base(space: &dyn AddressSpace, container: Container) -> Option<u64> {
    if !matches!(container, Container::Pe32 | Container::Pe64) {
        return None;
    }
    let header = space.read(0, 0x1000).or_else(|| space.read(0, 0x400))?;
    if header.len() < 0x40 {
        return None;
    }
    let pe = u32::from_le_bytes(header.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if pe.checked_add(24 + 32)? > header.len() {
        return None;
    }
    let optional = pe + 24;
    let magic = u16::from_le_bytes(header.get(optional..optional + 2)?.try_into().ok()?);
    match (container, magic) {
        (Container::Pe32, 0x10B) => Some(u64::from(u32::from_le_bytes(
            header.get(optional + 28..optional + 32)?.try_into().ok()?,
        ))),
        (Container::Pe64, 0x20B) => Some(u64::from_le_bytes(
            header.get(optional + 24..optional + 32)?.try_into().ok()?,
        )),
        _ => None,
    }
}

/// 函数起点前应有代码边界：填充、ret 或跳转；避免从指令中间开始。
fn has_code_boundary_before(space: &dyn AddressSpace, rva: u64) -> bool {
    let Some(bytes) = space.read(rva.saturating_sub(1), 1) else {
        return true;
    };
    matches!(
        bytes[0],
        0xCC | 0x90 | 0x00 | 0xC3 | 0xC2 | 0xE9 | 0xEB | 0xFF
    )
}

/// `mov/lea reg, [ebp+disp]` is a frame-relative access, never a function entry.
fn is_frame_relative_start(space: &dyn AddressSpace, rva: u64) -> bool {
    let Some(bytes) = space.read(rva, 2) else {
        return false;
    };
    matches!(bytes[0], 0x8B | 0x8D)
        && matches!(
            bytes[1],
            0x45 | 0x4D
                | 0x55
                | 0x5D
                | 0x65
                | 0x6D
                | 0x75
                | 0x7D
                | 0x85
                | 0x8D
                | 0x95
                | 0x9D
                | 0xA5
                | 0xAD
                | 0xB5
                | 0xBD
        )
}

/// 明显不是函数起点的字节：ret、int3、null、常见的 padding 噪声形状
/// `sub ecx, [ecx+disp]`（`2B 49`），以及 frame-relative 访问。
fn is_degenerate_start(space: &dyn AddressSpace, rva: u64) -> bool {
    let Some(bytes) = space.read(rva, 2) else {
        return false;
    };
    matches!(bytes[0], 0xCC | 0xC3 | 0x00)
        || (bytes[0] == 0x2B && bytes[1] == 0x49)
        || is_frame_relative_start(space, rva)
}

/// 较宽的起点判定：在强序言之外，接受 getter / 常量返回 / 导入 thunk 的常见开头。
fn looks_like_function_start_weak(space: &dyn AddressSpace, rva: u64) -> bool {
    if is_degenerate_start(space, rva) {
        return false;
    }
    if looks_like_function_start(space, rva) {
        return true;
    }
    let start = rva.saturating_sub(2);
    let Some(bytes) = space.read(start, 10) else {
        return false;
    };
    let Ok(offset) = usize::try_from(rva - start) else {
        return false;
    };
    let Some(window) = bytes.get(offset..offset + 5) else {
        return false;
    };
    if window[0] == 0x8B
        && matches!(
            window[1],
            0x01 | 0x41 | 0x44 | 0x49 | 0x4C | 0x51 | 0x54 | 0x59 | 0x5C
        )
    {
        return true;
    }
    (window[0] == 0x33 && window[1] == 0xC0)
        || window[0] == 0xB8
        || (window[0] == 0x0F
            && window[1] == 0xB6
            && matches!(window[2], 0x41 | 0x44 | 0x49 | 0x4C))
        || (window[0] == 0xFF && window[1] == 0x25)
}

/// 目标是否像函数起点：前面有对齐填充，或开头是常见 x86 序言。
fn looks_like_function_start(space: &dyn AddressSpace, rva: u64) -> bool {
    if is_degenerate_start(space, rva) {
        return false;
    }
    let start = rva.saturating_sub(2);
    let (window, padded) = if let Some(bytes) = space.read(start, 8) {
        let offset = usize::try_from(rva - start).unwrap_or(0);
        let padded = offset >= 2
            && matches!(bytes[offset - 1], 0xCC | 0x90 | 0x00)
            && matches!(bytes[offset - 2], 0xCC | 0x90 | 0x00);
        (bytes.get(offset..offset + 5), padded)
    } else {
        (space.read(rva, 5), false)
    };
    let Some(window) = window else {
        return false;
    };
    if window.len() < 3 {
        return false;
    }
    let prologue = (window[0] == 0x55 && window[1] == 0x8B && window[2] == 0xEC)
        || (window[0] == 0x83 && matches!(window[1], 0xEC | 0xE4))
        || (window[0] == 0x81 && matches!(window[1], 0xEC | 0xE4))
        || matches!(window[0], 0x53 | 0x56 | 0x57);
    padded || prologue
}

/// 扫描非执行节里的函数指针（回调表 / vtable / 手写分派表）。
///
/// 指针可能是绝对 VA 或已经归一过的 RVA；两者都接受。目标必须在执行节内、
/// 按指针宽度对齐，且看起来像函数起点，避免把普通整数误认成函数入口。
fn data_pointer_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let image_base = if module.image_base != 0 {
        module.image_base
    } else if let Some(base) = pe_image_base(space, module.container) {
        base
    } else {
        return BTreeSet::new();
    };
    let pointer_size = usize::try_from(module.arch.bitness() / 8).unwrap_or(0);
    if pointer_size != 4 && pointer_size != 8 {
        return BTreeSet::new();
    }
    let in_exec = |rva: u64| {
        exec_ranges
            .iter()
            .any(|(start, size)| rva >= *start && rva < start.saturating_add(*size))
    };
    let mut targets = BTreeSet::new();
    for section in module
        .sections
        .iter()
        .filter(|section| !section.executable && section.size > 0)
    {
        let Ok(size) = usize::try_from(section.size) else {
            continue;
        };
        let Some(bytes) = space.read(section.rva, size) else {
            continue;
        };
        for chunk in bytes.chunks_exact(pointer_size) {
            let value = if pointer_size == 4 {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(chunk);
                u64::from(u32::from_le_bytes(bytes))
            } else {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                u64::from_le_bytes(bytes)
            };
            let rva_target = in_exec(value).then_some(value);
            let va_target = value.checked_sub(image_base).filter(|rva| in_exec(*rva));
            let (target, prefer_rva) = match (rva_target, va_target) {
                (Some(rva), Some(va))
                    if looks_like_function_start_weak(space, rva)
                        && !looks_like_function_start(space, va) =>
                {
                    (rva, true)
                }
                (_, Some(va)) => (va, false),
                (Some(rva), None) => (rva, true),
                (None, None) => continue,
            };
            let plausible = looks_like_function_start(space, target)
                || (prefer_rva && looks_like_function_start_weak(space, target));
            let aligned = target % pointer_size as u64 == 0
                && (!matches!(module.arch, Arch::X86) || target % 16 == 0);
            if aligned && plausible && has_code_boundary_before(space, target) {
                targets.insert(target);
            }
        }
        // 连续 RVA 表：编译器生成的 vtable/分派表通常是一串 4 字节 RVA。
        // 只要连续 8 项都能按 RVA 解释且像函数起点，就整段收下；这能
        // 纠正“错误 VA 目标恰好也像起点”时的逐个值误判。
        let mut run = Vec::new();
        for chunk in bytes.as_chunks::<4>().0 {
            let value = u64::from(u32::from_le_bytes(*chunk));
            if in_exec(value) && looks_like_function_start_weak(space, value) {
                run.push(value);
            } else {
                if run.len() >= 8 {
                    for value in run.drain(..) {
                        let aligned = value % 4 == 0
                            && (!matches!(module.arch, Arch::X86) || value % 16 == 0);
                        if aligned && has_code_boundary_before(space, value) {
                            targets.insert(value);
                        }
                    }
                } else {
                    run.clear();
                }
            }
        }
        if run.len() >= 8 {
            for value in run {
                let aligned =
                    value % 4 == 0 && (!matches!(module.arch, Arch::X86) || value % 16 == 0);
                if aligned && has_code_boundary_before(space, value) {
                    targets.insert(value);
                }
            }
        }
    }
    targets
}

/// 扫描代码里的绝对地址立即数（静态回调注册 / 函数指针赋值）。
///
/// 只接受落在执行节内、按 4 字节对齐的值；绝对 VA 与已经归一过的 RVA 都接受。
fn immediate_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let image_base = if module.image_base != 0 {
        module.image_base
    } else if let Some(base) = pe_image_base(space, module.container) {
        base
    } else {
        return BTreeSet::new();
    };
    let in_exec = |rva: u64| {
        exec_ranges
            .iter()
            .any(|(start, size)| rva >= *start && rva < start.saturating_add(*size))
    };
    let mut targets = BTreeSet::new();
    let bitness = module.arch.bitness();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(bitness, bytes, *start, DecoderOptions::NONE);
        let mut buffer = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut buffer);
            for index in 0..buffer.op_count() {
                let value = match buffer.op_kind(index) {
                    OpKind::Immediate32 => u64::from(buffer.immediate32()),
                    OpKind::Immediate64 => buffer.immediate64(),
                    _ => continue,
                };
                let rva = if value >= image_base {
                    match value.checked_sub(image_base) {
                        Some(rva) if in_exec(rva) => rva,
                        _ => continue,
                    }
                } else if in_exec(value) {
                    value
                } else {
                    continue;
                };
                let aligned = rva % 4 == 0 && (!matches!(module.arch, Arch::X86) || rva % 16 == 0);
                if aligned
                    && looks_like_function_start(space, rva)
                    && has_code_boundary_before(space, rva)
                {
                    targets.insert(rva);
                }
            }
        }
    }
    targets
}

/// 扫描 16 字节对齐、前面有对齐填充的 sub esp, imm 序言。
///
/// 这是没有符号/没有引用的叶函数最常见的入口形态；限定 16 字节对齐和
/// 两字节填充，避免把普通指令序列误认成函数起点。
fn prologue_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let mut targets = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        let mut offset = usize::try_from((16 - (*start % 16)) % 16).unwrap_or(0);
        while offset + 8 <= bytes.len() {
            let rva = *start + u64::try_from(offset).unwrap_or(0);
            let window = &bytes[offset..offset + 8];
            let padded = offset >= 2
                && matches!(bytes[offset - 1], 0xCC | 0x90 | 0x00)
                && matches!(bytes[offset - 2], 0xCC | 0x90 | 0x00);
            let prologue = (window[0] == 0x83 && matches!(window[1], 0xEC | 0xE4))
                || (window[0] == 0x81 && matches!(window[1], 0xEC | 0xE4))
                || (window[0] == 0xB8 && window[5] == 0xC3)
                || (window[0] == 0x8B && window[1] == 0x41 && window[3] == 0xC3)
                || (window[0] == 0x8B
                    && window[1] == 0x44
                    && window[2] == 0x24
                    && window[4] == 0xC3)
                || (window[0] == 0x8B && window[1] == 0x01 && window[2] == 0xC3)
                || (window[0] == 0x55 && window[1] == 0x8B && window[2] == 0xEC)
                || (window[0] == 0xE8 && window[5] == 0xFF && window[6] == 0x25);
            if padded && prologue {
                targets.insert(rva);
            }
            offset += 16;
        }
    }
    targets
}

/// 线性反汇编全部执行节，收集直接（rel）call 的目标，只留落在执行节内的。
fn direct_call_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    let bitness = module.arch.bitness();
    let space = module.address_space();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(bitness, bytes, *start, DecoderOptions::NONE);
        let mut buffer = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut buffer);

            let direct_target = match buffer.flow_control() {
                FlowControl::Call => direct_near_target(&buffer),
                _ => None,
            };
            if let Some(target) = direct_target {
                if exec_ranges
                    .iter()
                    .any(|(s, sz)| target >= *s && target < s + sz)
                    && !is_frame_relative_start(space, target)
                {
                    targets.insert(target);
                }
            }
        }
    }
    targets
}

/// 取直接 rel 转移的目标地址（近转移操作数）；间接转移返回 `None`。
fn direct_near_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotama_image::LoadedModule;

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
    fn elf_fixture_main_has_symbol_evidence_and_exact_size() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        let main = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        assert!(main.evidence.contains(&Evidence::Symtab));
        assert!(!main.size_inferred);
        assert!(main.size > 0);
    }

    #[test]
    fn pe64_fixture_uses_pdata() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/switch.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        assert!(functions
            .iter()
            .any(|f| f.evidence.contains(&Evidence::Pdata) && !f.size_inferred));
        assert!(module.entry_rva.is_some());
    }

    #[test]
    fn real_pe64_exception_facts_include_xdata() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert!(module.exception_directory.is_some());
        let facts = exception_functions(&module);
        assert!(!facts.is_empty());
        assert!(facts.iter().any(|fact| fact.unwind.is_some()));
        assert!(facts
            .iter()
            .all(|fact| fact.runtime.end_rva > fact.runtime.begin_rva));
        assert_eq!(facts, exception_functions(&module));
    }

    #[test]
    fn stripped_elf_still_finds_entry_and_call_targets() {
        let host_sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/host-samples/true");
        if cfg!(target_os = "windows") && !host_sample.exists() {
            // /bin/true 是 Linux 宿主样本，Windows 夹具车道不伪造它；这是平台 lane-skip，
            // 不影响 KOTAMA_REQUIRE_FIXTURES 对可生成矩阵的强制要求。Linux CI 缺它仍失败。
            eprintln!("lane-skip: Linux host-samples/true is unavailable on native Windows");
            return;
        }
        let Some(path) = fixture("host-samples/true") else {
            eprintln!("skip: host samples not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        assert!(functions
            .iter()
            .any(|f| f.evidence.contains(&Evidence::Entry)));
        assert!(functions
            .iter()
            .any(|f| f.evidence.contains(&Evidence::CallTarget)));
    }

    #[test]
    fn elf_fixture_carries_dwarf_evidence() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        let main = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        assert!(main.evidence.contains(&Evidence::Dwarf));
        assert!(!main.size_inferred);
    }

    #[test]
    fn pe_rvas_are_image_relative() {
        // 归一回归：PE 的所有路径必须同一地址空间（`.pdata` 相对，其余曾带 ImageBase）。
        let Some(path) = fixture("x86_64-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        // mingw PE64 的 .text 从 RVA 0x1000 起；任何函数入口都该 < 0x100000。
        assert!(functions.iter().all(|f| f.rva < 0x100_0000),);
        assert!(functions
            .iter()
            .any(|f| f.evidence.contains(&Evidence::Pdata) && f.rva >= 0x1000));
    }

    #[test]
    fn elf_rvas_are_base_normalized() {
        // 归一回归：zig PIE 的 ELF 曾带 0x100000 链接基址（oracle 差分全 0 抓出来的）。
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        assert!(functions.iter().all(|f| f.rva < 0x100_0000),);
    }

    #[test]
    fn string_xrefs_find_literal_references() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/strings") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        let xrefs = string_xrefs(&module, &functions);
        // choose() 的三个分支串必须至少抓到两个；全部挂在同一个函数下。
        let texts: Vec<&str> = xrefs.iter().map(|x| x.text.as_str()).collect();
        let hits = ["large", "medium", "small"]
            .iter()
            .filter(|word| texts.contains(word))
            .count();
        assert!(hits >= 2, "expected literal references, got {xrefs:?}");
        assert!(xrefs.iter().all(|x| x.text.len() >= 4));
    }

    #[test]
    fn vtable_scan_finds_cpp_vtables_via_relocations() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/vtable") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        // 修级联吸收的回归：整表八千个候选不许塌缩成个位数（修复前实测只剩 6）。
        assert!(functions.len() > 300, "got {}", functions.len());
        let names = functions.iter().filter_map(|f| f.name.as_deref());
        assert!(
            names.clone().any(|n| n.contains("3Fan4step")),
            "mangled Fan::step missing"
        );
        let tables = vtables(&module, &functions);
        // Fan / Pump 两个 vtable，每个至少 step/mode/两个 dtor 共 3+ 槽。
        assert!(tables.len() >= 2, "vtables: {tables:?}");
        assert!(
            tables.iter().all(|t| t.targets.len() >= 3),
            "vtables too small: {tables:?}"
        );
        let entries: std::collections::BTreeSet<u64> = functions.iter().map(|f| f.rva).collect();
        assert!(tables
            .iter()
            .all(|t| t.targets.iter().all(|target| entries.contains(target))));
    }

    struct SyntheticSpace {
        base: u64,
        bytes: Vec<u8>,
        segments: Vec<kotama::Segment>,
    }

    impl SyntheticSpace {
        fn write(&mut self, rva: u64, bytes: &[u8]) {
            let offset = usize::try_from(rva - self.base).unwrap();
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    impl AddressSpace for SyntheticSpace {
        fn segments(&self) -> &[kotama::Segment] {
            &self.segments
        }

        fn read(&self, rva: u64, len: usize) -> Option<&[u8]> {
            self.segments
                .iter()
                .find(|segment| segment.contains(rva, len))?;
            let start = usize::try_from(rva.checked_sub(self.base)?).ok()?;
            self.bytes.get(start..start.checked_add(len)?)
        }
    }

    fn synthetic_exception_input(flags: u8) -> (SyntheticSpace, Vec<SectionInfo>, DataDirectory) {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x3000],
            segments: vec![
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
                segment(0x3000, 0x1000, false),
            ],
        };
        space.write(0x2000, &0x1000u32.to_le_bytes());
        space.write(0x2004, &0x1040u32.to_le_bytes());
        space.write(0x2008, &0x3000u32.to_le_bytes());
        // Version=1，一个 unwind code，frame register=5 / offset=1。
        space.write(0x3000, &[(flags << 3) | 1, 4, 1, 0x15, 0, 0]);
        if flags & UNW_FLAG_CHAININFO != 0 {
            space.write(0x3008, &0x1040u32.to_le_bytes());
            space.write(0x300c, &0x1060u32.to_le_bytes());
            space.write(0x3010, &0u32.to_le_bytes());
        } else {
            space.write(0x3008, &0x1040u32.to_le_bytes());
        }
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x1000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x2000,
                size: 12,
                // 故意不用 .pdata：只有 exception directory 能找到它。
                name: ".exception".into(),
                executable: false,
            },
            SectionInfo {
                rva: 0x3000,
                size: 0x1000,
                name: ".xdata".into(),
                executable: false,
            },
        ];
        (
            space,
            sections,
            DataDirectory {
                rva: 0x2000,
                size: 12,
            },
        )
    }

    fn synthetic_adapter<'a>(
        sections: &'a [SectionInfo],
        space: &'a dyn AddressSpace,
    ) -> ViewAdapter<'a> {
        ViewAdapter {
            container: Container::Pe64,
            arch: Arch::X86_64,
            image_base: 0,
            entry_rva: None,
            sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
            space,
        }
    }

    #[test]
    fn exception_facts_preserve_runtime_and_aligned_handler() {
        let (space, sections, directory) = synthetic_exception_input(UNW_FLAG_EHANDLER);
        let adapter = synthetic_adapter(&sections, &space);
        let facts = exception_functions_impl(&adapter, Some(directory));
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].runtime,
            RuntimeFunction {
                begin_rva: 0x1000,
                end_rva: 0x1040,
                unwind_info_rva: 0x3000,
            }
        );
        let unwind = facts[0].unwind.unwrap();
        assert_eq!(unwind.version, 1);
        assert_eq!(unwind.flags, UNW_FLAG_EHANDLER);
        assert_eq!(unwind.prolog_size, 4);
        assert_eq!(unwind.unwind_code_count, 1);
        assert_eq!(unwind.frame_register, 5);
        assert_eq!(unwind.frame_offset, 1);
        assert_eq!(unwind.handler_rva, Some(0x1040));
        assert_eq!(unwind.chained, None);
        assert_eq!(facts, exception_functions_impl(&adapter, Some(directory)));
    }

    #[test]
    fn exception_facts_decode_chained_runtime_function() {
        let (space, sections, directory) = synthetic_exception_input(UNW_FLAG_CHAININFO);
        let adapter = synthetic_adapter(&sections, &space);
        let facts = exception_functions_impl(&adapter, Some(directory));
        let unwind = facts[0].unwind.unwrap();
        assert_eq!(unwind.handler_rva, None);
        assert_eq!(
            unwind.chained,
            Some(RuntimeFunction {
                begin_rva: 0x1040,
                end_rva: 0x1060,
                unwind_info_rva: 0,
            })
        );
    }

    #[test]
    fn discovery_uses_exception_directory_not_pdata_section_name() {
        let (space, sections, directory) = synthetic_exception_input(UNW_FLAG_EHANDLER);
        let view = ScanView {
            container: Container::Pe64,
            arch: Arch::X86_64,
            image_base: 0,
            entry_rva: None,
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_impl(view, &space, Some(directory));
        let function = functions
            .iter()
            .find(|function| function.rva == 0x1000)
            .unwrap();
        assert_eq!(function.size, 0x40);
        assert!(!function.size_inferred);
        assert!(function.evidence.contains(&Evidence::Pdata));
    }

    #[test]
    fn pe_data_pointer_seeds_are_discovered() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x2000],
            segments: vec![
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
            ],
        };
        space.write(0x1000, &[0xC3]);
        space.write(0x1010, &[0x55, 0x8B, 0xEC, 0xC3]);
        // Absolute VA of 0x1010 under the PE preferred base 0x400000.
        space.write(0x2000, &0x40_1010u32.to_le_bytes());
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x1000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x2000,
                size: 0x1000,
                name: ".data".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x400000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            functions.iter().any(|function| function.rva == 0x1010
                && function.evidence.contains(&Evidence::PointerTarget)),
            "pointer target not discovered: {functions:?}"
        );
    }

    #[test]
    fn ambiguous_rva_pointer_prefers_getter_start() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x2100],
            segments: vec![segment(0x1000, 0x2000, true), segment(0x3000, 0x100, false)],
        };
        space.write(0x1000, &[0xC3]);
        space.write(0x100E, &[0x11, 0x22]);
        // The VA interpretation (0x1010) is not a plausible start; the RVA
        // interpretation (0x2010) is a getter.
        space.write(0x1010, &[0x00, 0x00, 0x00, 0x00]);
        space.write(0x2010, &[0x8B, 0x41, 0x04, 0xC3]);
        space.write(0x3000, &0x2010u32.to_le_bytes());
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x2000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x3000,
                size: 0x100,
                name: ".data".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x1000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            functions.iter().any(|function| function.rva == 0x2010
                && function.evidence.contains(&Evidence::PointerTarget)),
            "RVA getter target not discovered: {functions:?}"
        );
    }

    #[test]
    fn contiguous_rva_table_seeds_getters() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x2100],
            segments: vec![segment(0x1000, 0x2000, true), segment(0x3000, 0x100, false)],
        };
        space.write(0x1000, &[0xC3]);
        for index in 0..8u64 {
            let va_target = 0x1010 + index * 0x10;
            let rva_target = 0x2010 + index * 0x10;
            space.write(va_target, &[0x55, 0x8B, 0xEC, 0xC3]);
            space.write(rva_target, &[0x8B, 0x41, 0x04, 0xC3]);
            let value = u32::try_from(rva_target).unwrap();
            space.write(0x3000 + index * 4, &value.to_le_bytes());
        }
        // A 4-byte-aligned table entry must not become a function start.
        space.write(0x2014, &[0x8B, 0x41, 0x04, 0xC3]);
        space.write(0x3020, &0x2014u32.to_le_bytes());
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x2000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x3000,
                size: 0x100,
                name: ".rdata".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x1000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            functions.iter().any(|function| function.rva == 0x2010
                && function.evidence.contains(&Evidence::PointerTarget)),
            "RVA table target not discovered: {functions:?}"
        );
        assert!(
            !functions.iter().any(|function| function.rva == 0x2014
                && function.evidence.contains(&Evidence::PointerTarget)),
            "4-byte-aligned table entry was accepted: {functions:?}"
        );
    }

    #[test]
    fn padded_sub_esp_prologue_is_discovered() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x1000],
            segments: vec![segment(0x1000, 0x1000, true)],
        };
        space.write(0x1000, &[0xC3]);
        space.write(0x100E, &[0xCC, 0xCC]);
        space.write(0x1010, &[0x83, 0xEC, 0x10, 0xC3]);
        space.write(0x102E, &[0xCC, 0xCC]);
        space.write(0x1030, &[0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3]);
        space.write(0x104E, &[0xCC, 0xCC]);
        space.write(0x1050, &[0x8B, 0x41, 0x04, 0xC3]);
        space.write(0x106E, &[0xCC, 0xCC]);
        space.write(0x1070, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x107E, &[0xCC, 0xCC]);
        space.write(
            0x1080,
            &[
                0xE8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xC3,
            ],
        );
        let sections = vec![SectionInfo {
            rva: 0x1000,
            size: 0x1000,
            name: ".text".into(),
            executable: true,
        }];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x400000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        let prologue_targets: Vec<u64> = functions
            .iter()
            .filter(|function| function.evidence.contains(&Evidence::PrologueTarget))
            .map(|function| function.rva)
            .collect();
        assert!(
            prologue_targets.contains(&0x1010)
                && prologue_targets.contains(&0x1030)
                && prologue_targets.contains(&0x1050)
                && prologue_targets.contains(&0x1070)
                && prologue_targets.contains(&0x1080),
            "prologue targets not discovered: {functions:?}"
        );
    }

    #[test]
    fn degenerate_pointer_targets_are_rejected() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x2000],
            segments: vec![
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
            ],
        };
        space.write(0x1000, &[0xC3]);
        space.write(0x1010, &[0xCC, 0xCC, 0xCC, 0xCC]);
        space.write(0x1020, &[0x8D, 0x4D, 0x08, 0xC3]);
        space.write(0x2000, &0x40_1010u32.to_le_bytes());
        space.write(0x2004, &0x40_1020u32.to_le_bytes());
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x1000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x2000,
                size: 0x1000,
                name: ".data".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x400000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            !functions
                .iter()
                .any(|function| matches!(function.rva, 0x1010 | 0x1020)
                    && function.evidence.contains(&Evidence::PointerTarget)),
            "degenerate target was accepted: {functions:?}"
        );
    }

    #[test]
    fn pointer_target_without_code_boundary_is_rejected() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x2000],
            segments: vec![
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
            ],
        };
        space.write(0x1000, &[0xC3]);
        space.write(0x100E, &[0x8B, 0x8B]);
        space.write(0x1010, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x2000, &0x40_1010u32.to_le_bytes());
        let sections = vec![
            SectionInfo {
                rva: 0x1000,
                size: 0x1000,
                name: ".text".into(),
                executable: true,
            },
            SectionInfo {
                rva: 0x2000,
                size: 0x1000,
                name: ".data".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x400000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            !functions.iter().any(|function| function.rva == 0x1010
                && function.evidence.contains(&Evidence::PointerTarget)),
            "non-boundary target was accepted: {functions:?}"
        );
    }

    #[test]
    fn code_immediate_seeds_are_discovered() {
        let segment = |rva, size, execute| kotama::Segment {
            rva,
            size,
            perms: kotama::Perms {
                read: true,
                write: false,
                execute,
            },
        };
        let mut space = SyntheticSpace {
            base: 0x1000,
            bytes: vec![0u8; 0x1100],
            segments: vec![segment(0x1000, 0x1000, true)],
        };
        // push 0x401010; ret
        space.write(0x1000, &[0x68, 0x10, 0x10, 0x40, 0x00, 0xC3]);
        space.write(0x1010, &[0x55, 0x8B, 0xEC, 0xC3]);
        let sections = vec![SectionInfo {
            rva: 0x1000,
            size: 0x1000,
            name: ".text".into(),
            executable: true,
        }];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x400000,
            entry_rva: Some(0x1000),
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        assert!(
            functions.iter().any(|function| function.rva == 0x1010
                && function.evidence.contains(&Evidence::ImmediateTarget)),
            "immediate target not discovered: {functions:?}"
        );
    }

    #[test]
    fn discovery_is_deterministic() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/switch") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(discover(&module), discover(&module));
    }
}
