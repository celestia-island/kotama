//! 函数发现：多路证据种子合并成一张带来源的函数表。
//!
//! P0 证据（设计案 §4.2 的子集；provenance 是硬要求——每条结论都记它信谁）：
//!
//! - `sym`：ELF symtab 的已定义函数符号（名字 + 精确长度，非 strip 二进制覆盖近全量）
//! - `dynsym`：ELF dynsym 导出的函数
//! - `pdata`：PE64 `.pdata` 的 `RUNTIME_FUNCTION`（编译器自记的精确边界）
//! - `entry`：映像入口点
//! - `call`：可执行节的直接 `call`/`jmp` 目标（线性反汇编收集；strip 二进制的主要信号）
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
use kotama_image::LoadedModule;
use kotama_image::SectionInfo;
use kotama_image::SymbolInfo;

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
    discover_with(
        ScanView {
            container: module.container,
            arch: module.arch,
            entry_rva: module.entry_rva,
            sections: &module.sections,
            symbols: &module.symbols,
            dynamic_symbols: &module.dynamic_symbols,
            debug_functions: &module.debug_functions,
        },
        &module.address_space(),
    )
}

/// 同一条发现管线，吃任意 [`ScanView`] + 地址空间（活体进程走这里）。
pub fn discover_with(view: ScanView<'_>, space: &dyn AddressSpace) -> Vec<FunctionEntry> {
    let module = ViewAdapter {
        container: view.container,
        arch: view.arch,
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

    // 3) PE64 .pdata：编译器自记的函数边界。
    if module.container == Container::Pe64 {
        for (begin, end) in pdata_entries(&module) {
            let entry = table.entry(u64::from(begin)).or_default();
            if entry.size.is_none() {
                entry.size = Some(u64::from(end.saturating_sub(begin)));
            }
            entry.evidence.insert(Evidence::Pdata);
        }
    }

    // 4) 入口点。
    if let Some(entry_rva) = module.entry_rva {
        table
            .entry(entry_rva)
            .or_default()
            .evidence
            .insert(Evidence::Entry);
    }

    // 5) 直接 call/jmp 目标（strip 二进制的主力信号；数据岛会造成少量噪声条目，
    //    证据标 `call` 供下游按置信度取舍）。
    let exec_ranges: Vec<(u64, u64)> = module
        .sections
        .iter()
        .filter(|s| s.executable && s.size > 0)
        .map(|s| (s.rva, s.size))
        .collect();
    for target in direct_branch_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::CallTarget);
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

/// 解析 PE64 `.pdata` 的 `(BeginAddress, EndAddress)` 列表（EndAddress 不含）。
fn pdata_entries(module: &ViewAdapter<'_>) -> Vec<(u32, u32)> {
    let Some(section) = module.sections.iter().find(|s| s.name == ".pdata") else {
        return Vec::new();
    };
    let space = module.address_space();
    let count = (section.size / 12).min(u64::from(u32::MAX));
    let Some(bytes) = space.read(section.rva, usize::try_from(count * 12).unwrap_or(0)) else {
        return Vec::new();
    };
    bytes
        .as_chunks::<12>()
        .0
        .iter()
        .filter_map(|entry| {
            let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let end = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            (begin != 0 && end > begin).then_some((begin, end))
        })
        .collect()
}

/// 线性反汇编全部执行节，收集直接（rel）call/jmp 的目标，只留落在执行节内的。
fn direct_branch_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
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
                FlowControl::Call
                | FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch => direct_near_target(&buffer),
                _ => None,
            };
            if let Some(target) = direct_target {
                if exec_ranges
                    .iter()
                    .any(|(s, sz)| target >= *s && target < s + sz)
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
        path.exists().then_some(path)
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
    fn stripped_elf_still_finds_entry_and_call_targets() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/host-samples/true");
        if !path.exists() {
            eprintln!("skip: host samples not built");
            return;
        }
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
