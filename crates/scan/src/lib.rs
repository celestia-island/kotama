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

#[cfg(test)]
mod field_xref_tests {
    use super::field_accesses;

    #[test]
    fn decodes_base_disp_accesses() {
        // 89 87 b4 55 00 00   mov [edi+0x55b4], eax
        // ff 8f b4 55 00 00   dec dword [edi+0x55b4]
        // 8b 8f b4 55 00 00   mov ecx, [edi+0x55b4]
        let bytes = [
            0x89, 0x87, 0xb4, 0x55, 0x00, 0x00, 0xff, 0x8f, 0xb4, 0x55, 0x00, 0x00, 0x8b, 0x8f,
            0xb4, 0x55, 0x00, 0x00,
        ];
        let accesses = field_accesses(&bytes, 0x1000, 32);
        assert_eq!(accesses.len(), 3);
        assert!(accesses.iter().all(|access| access.disp == 0x55b4));
        assert!(accesses.iter().all(|access| access.width == 4));
        assert!(accesses[0].write);
        assert!(accesses[1].write);
        assert_eq!(accesses[0].insn_rva, 0x1000);
        assert_eq!(accesses[2].insn_rva, 0x100C);
    }

    #[test]
    fn skips_indexed_and_rip_relative() {
        // 8b 04 8f            mov eax, [edi+ecx*4]   (index -> skip)
        // 8b 87 b4 55 00 00   mov eax, [edi+0x55b4] (base+disp -> keep)
        // 8b 47 fc            mov eax, [edi-4]       (negative disp)
        let bytes = [
            0x8b, 0x04, 0x8f, 0x8b, 0x87, 0xb4, 0x55, 0x00, 0x00, 0x8b, 0x47, 0xfc,
        ];
        let accesses = field_accesses(&bytes, 0x2000, 32);
        assert_eq!(accesses.len(), 2);
        assert_eq!(accesses[0].disp, 0x55b4);
        assert_eq!(accesses[1].disp, -4);
    }

    #[test]
    fn skips_stack_frame_bases() {
        // 89 45 fc            mov [ebp-4], eax   (stack slot -> skip)
        // 89 87 b4 55 00 00   mov [edi+0x55b4], eax (field -> keep)
        let bytes = [0x89, 0x45, 0xfc, 0x89, 0x87, 0xb4, 0x55, 0x00, 0x00];
        let accesses = field_accesses(&bytes, 0x3000, 32);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].disp, 0x55b4);
    }
}

pub mod msvc_rtti;

pub mod a64;
pub mod a64_xrefs;

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
    // Aarch64 has its own decoder and its own evidence set; keep it off the
    // iced-x86 path entirely.
    if module.arch.is_aarch64() {
        return a64::discover_a64(module);
    }
    // Instruction-level discovery needs an x86 decoder. A recognised but
    // non-disassemblable architecture yields no functions rather than a panic.
    if !module.arch.is_disassemblable() {
        return Vec::new();
    }
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
///
/// 已量測并否決的起点规则（不要再试；数据来自带 PDB 的 MSVC 样本 sqlite3 / zstd / FLTK，
/// 以及若干真实 PE32 样本）：
///
/// - 「紧跟在 `ret` 之后、且没有任何直接引用」：1,485 个候选里只有 8 个是真过程
///   （三份真值合计），真实样本上会新增数千个函数体内块。
/// - 「直接 `jmp` 的目标（尾部调用）」：按字节扫描 6,803 个候选只有 129 个真过程；
///   在已发现函数体里解码则一个候选都出不来——回归吸收早把可达目标纳进函数体了。
///
/// 结论：剩余漏召回是「无引用、无填充的叶子函数」，只有符号信息能分辨，静态侧不再猜。
pub fn discover_with(view: ScanView<'_>, space: &dyn AddressSpace) -> Vec<FunctionEntry> {
    // Same gate as `discover`: never hand a non-x86 architecture to the decoder.
    if !view.arch.is_disassemblable() {
        return Vec::new();
    }
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
        // Mach-O carries DWARF too; the PDB channel is PE-only.
        Container::MachO64 | Container::MachO32 => Evidence::Dwarf,
        Container::Pe64 | Container::Pe32 => Evidence::Pdb,
        // No debug channel is wired for these; only container membership.
        _ => Evidence::Pdb,
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
    //    UNW_FLAG_CHAININFO 条目是父函数的延续块（PDB 也把它归入父过程），不是起点：
    //    紧邻父函数末尾的块并入父函数尺寸，分开的冷代码块只留在异常事实里。
    let exceptions = exception_functions_impl(&module, exception_directory);
    let mut chains: BTreeMap<u64, Vec<(u32, u32)>> = BTreeMap::new();
    for exception in &exceptions {
        if let Some(parent) = exception
            .unwind
            .as_ref()
            .and_then(|unwind| unwind.chained.as_ref())
        {
            chains
                .entry(u64::from(parent.begin_rva))
                .or_default()
                .push((exception.runtime.begin_rva, exception.runtime.end_rva));
        }
    }
    for exception in exceptions {
        let runtime = exception.runtime;
        if exception
            .unwind
            .as_ref()
            .is_some_and(|unwind| unwind.chained.is_some())
        {
            continue;
        }
        let begin = u64::from(runtime.begin_rva);
        let mut end = runtime.end_rva;
        if let Some(chunks) = chains.get(&begin) {
            while let Some(next) = chunks.iter().find(|(chunk_begin, _)| *chunk_begin == end) {
                end = next.1;
            }
        }
        let entry = table.entry(begin).or_default();
        if entry.size.is_none() {
            entry.size = Some(u64::from(end.saturating_sub(runtime.begin_rva)));
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
    for target in frame_prologue_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PrologueTarget);
    }
    for target in aligned_pattern_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PrologueTarget);
    }
    for target in byte_pattern_targets(&module, &exec_ranges) {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PrologueTarget);
    }
    // 调整器 thunk / 对齐跳转 stub 的起点是函数，它们 `jmp` 到的目标也是函数。
    let (thunk_starts, thunk_jumps) = thunk_targets(&module, &exec_ranges);
    for target in thunk_starts {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::PrologueTarget);
    }
    for target in thunk_jumps {
        table
            .entry(target)
            .or_default()
            .evidence
            .insert(Evidence::CallTarget);
    }
    for target in padded_code_targets(&module, &exec_ranges) {
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
    let known_starts: BTreeSet<u64> = rvas.iter().copied().collect();
    let call_sites = direct_call_sites(&module, &exec_ranges);
    let mut out = refine_bodies(&module, &exec_ranges, rvas, &table, &call_sites);
    expand_inferred_sizes(&module, &exec_ranges, &known_starts, &mut out);
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
    call_sites: &BTreeMap<u64, BTreeSet<u64>>,
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
            // 被别的函数直接 call 的候选即使能 fall-through 到达，也是独立函数（IDA 同样切分）；
            // 只有函数内部的 call 才允许吸收。
            let called_from_outside = call_sites
                .get(&next)
                .is_some_and(|sites| sites.iter().any(|site| !(start..next).contains(site)));
            match table.get(&next) {
                Some(absorbed) if absorbed.size.is_none() && !called_from_outside => {
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

/// 用直接條件分支目標擴大「推斷」函數的 size。
///
/// 只改輸出 size，不改入口集合，也不吸收候選；上界是下一個函數起點或執行節末。
/// 分支目標若本身就是已知函數起點，則視為共享尾塊/其他函數，不跟隨。
fn expand_inferred_sizes(
    module: &ViewAdapter<'_>,
    exec_ranges: &[(u64, u64)],
    known_starts: &BTreeSet<u64>,
    functions: &mut [FunctionEntry],
) {
    let space = module.address_space();
    let bitness = module.arch.bitness();
    for index in 0..functions.len() {
        if !functions[index].size_inferred {
            continue;
        }
        let start = functions[index].rva;
        let limit = functions
            .get(index + 1)
            .map_or_else(|| exec_limit(exec_ranges, start), |next| next.rva)
            .min(exec_limit(exec_ranges, start));
        if limit <= start {
            continue;
        }
        let mut end = start;
        let mut visited = BTreeSet::new();
        let mut work = vec![start];
        while let Some(address) = work.pop() {
            if address < start || address >= limit || !visited.insert(address) {
                continue;
            }
            let Some(bytes) = space.read(
                address,
                usize::try_from(limit - address).unwrap_or(usize::MAX),
            ) else {
                continue;
            };
            let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
            let mut instruction = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                if instruction.is_invalid() {
                    break;
                }
                end = end.max(instruction.next_ip());
                match instruction.flow_control() {
                    FlowControl::ConditionalBranch => {
                        if let Some(target) = direct_near_target(&instruction) {
                            if (start..limit).contains(&target) && !known_starts.contains(&target) {
                                work.push(target);
                            }
                        }
                    }
                    FlowControl::Return
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::Interrupt
                    | FlowControl::Exception => break,
                    _ => {}
                }
            }
        }
        let expanded = end.saturating_sub(start);
        if expanded >= functions[index].size.saturating_add(2) {
            functions[index].size = expanded;
        }
    }
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
    if module.arch.is_aarch64() {
        return a64_xrefs::call_graph_a64(module, functions);
    }
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
    if module.arch.is_aarch64() {
        return a64_xrefs::string_xrefs_a64(module, functions);
    }
    use std::collections::BTreeSet;

    // x86 非 PIE 用绝对地址立即数引用字符串（`push offset str` / `mov reg, imm32`）。
    let image_base = module.image_base;

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
            // RIP 相对内存操作数（x64 `lea reg,[rip+X]`）是字符串引用的常态形态。
            if buffer.is_ip_rel_memory_operand() {
                let target = buffer.ip_rel_memory_address();
                if in_data(target) {
                    if let Some(text) = read_cstring(&space, target) {
                        out.insert((function.rva, target, text));
                    }
                }
            }
            // x86 非 PIE 的绝对地址立即数（`push offset` / `mov reg, imm32`）：目标落在
            // 数据节且能解出 NUL 结尾的可打印字符串才算，普通数值立即数过不了这一关。
            for index in 0..buffer.op_count() {
                if buffer.op_kind(index) != OpKind::Immediate32 {
                    continue;
                }
                let Some(target) = u64::from(buffer.immediate32()).checked_sub(image_base) else {
                    continue;
                };
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
pub(crate) fn read_cstring(space: &dyn AddressSpace, rva: u64) -> Option<String> {
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

/// 一条结构体字段访问（`[base + disp]`）事实。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FieldAccess {
    /// 所在函数入口 RVA。
    pub func_rva: u64,
    /// 指令 RVA。
    pub insn_rva: u64,
    /// 结构体成员偏移。
    pub disp: i64,
    /// 访问宽度（字节）。
    pub width: u32,
    /// 是否为写访问。
    pub write: bool,
}

/// 一条字段偏移的聚合视图。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldXref {
    /// 结构体成员偏移。
    pub disp: i64,
    /// 命中该偏移的访问点（按 `(func_rva, insn_rva)` 升序）。
    pub accesses: Vec<FieldAccess>,
}

/// 从一段机器码里解出所有 `[base + disp]` 形态的访存（不含 index / RIP 相对）。
#[must_use]
pub fn field_accesses(bytes: &[u8], ip: u64, bitness: u32) -> Vec<FieldAccess> {
    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let Some(disp) = base_disp(&instruction) else {
            continue;
        };
        let width = instruction.memory_size().size() as u32;
        if width == 0 {
            continue;
        }
        out.push(FieldAccess {
            func_rva: 0,
            insn_rva: instruction.ip(),
            disp,
            width,
            write: writes_memory(&instruction),
        });
    }
    out
}

fn base_disp(instruction: &Instruction) -> Option<i64> {
    use iced_x86::Register as R;
    let base = instruction.memory_base();
    // 栈帧基址（ESP/EBP/RSP/RBP）后面跟的是局部变量，不是结构体成员；收进来只会把
    // 「字段偏移」变成「栈槽统计」，与用途相反。
    if base == R::None
        || matches!(base, R::ESP | R::EBP | R::RSP | R::RBP)
        || instruction.memory_index() != R::None
        || instruction.is_ip_rel_memory_operand()
        || instruction.memory_displ_size() == 0
    {
        return None;
    }
    let _ = base;
    // 32 位模式里负偏移是 32 位补码；直接取 u64 会得到 0xFFFF_FFFC 这种巨值。
    let disp = instruction.memory_displacement64();
    let disp = match instruction.memory_displ_size() {
        1 => i64::from(disp as u8 as i8),
        2 => i64::from(disp as u16 as i16),
        4 => i64::from(disp as u32 as i32),
        _ => disp as i64,
    };
    Some(disp)
}

fn writes_memory(instruction: &Instruction) -> bool {
    use iced_x86::Mnemonic as M;
    if matches!(
        instruction.mnemonic(),
        M::Cmp | M::Test | M::Lea | M::Push | M::Pop | M::Fld | M::Fild
    ) {
        return false;
    }
    // 目标操作数是内存或寄存器-内存（`add [mem], reg` / `dec [mem]`）即写。
    matches!(
        instruction.op0_kind(),
        OpKind::Memory | OpKind::MemorySegSI | OpKind::MemorySegDI | OpKind::MemoryESDI
    )
}

/// 扫全部函数体，按成员偏移聚合 `[base + disp]` 访问。
#[must_use]
pub fn field_xrefs(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<FieldXref> {
    let space = module.address_space();
    let bitness = module.arch.bitness();
    let mut grouped: BTreeMap<i64, Vec<FieldAccess>> = BTreeMap::new();
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
        for mut access in field_accesses(bytes, function.rva, bitness) {
            if access.disp == 0 {
                continue;
            }
            access.func_rva = function.rva;
            grouped.entry(access.disp).or_default().push(access);
        }
    }
    grouped
        .into_iter()
        .map(|(disp, mut accesses)| {
            accesses.sort_by_key(|access| (access.func_rva, access.insn_rva));
            FieldXref { disp, accesses }
        })
        .collect()
}

/// 一张表的来源：通用指针表扫描，还是 MSVC RTTI 锚定的精确 vtable。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VtableKind {
    /// 通用扫描：非执行节里连续解析到函数入口的指针表（可能是 vtable，也可能是回调表）。
    PointerTable,
    /// RTTI 锚定：由 `CompleteObjectLocator` 指回的 vftable，槽位内容可信。
    RttiAnchored,
}

/// 一个识别出的 vtable（或纯函数指针表）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Vtable {
    /// 表起始 RVA。
    pub rva: u64,
    /// 槽位目标（函数入口 RVA，按槽位顺序）。
    pub targets: Vec<u64>,
    /// 这张表是怎么来的。
    pub kind: VtableKind,
}

/// 扫描 vtable / 纯函数指针表。
///
/// 判据：非执行节里**指针宽度对齐**的连续 ≥2 个槽位，每个槽位都解析到**已知函数入口**。
/// 槽位解析两条路：
/// 1. PIE ELF：vtable 槽在文件里是 0，真值在 `R_*_RELATIVE` 重定位的 addend——
///    用 [`LoadedModule::relative_relocations`]（这也是为什么它必须由 image 提供）。
/// 2. 非 PIE / PE：槽里是原始绝对地址，减 `image_base` 回 RVA。
///
/// 「每个目标都是已知函数（或其跳转 thunk）」这一条杀掉 GOT / 字符串指针表 / C 结构体
/// 混排的噪声；代价是 C++ 夹具外的覆盖依赖函数表质量——这是有意的保守。
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

    // 槽位可能指向链接器 thunk（`/INCREMENTAL` 的 ILT thunk、跳转 stub），真身是 thunk
    // 的跳转目标：`jmp rel32` / `jmp rel8` 落在已知函数上时，槽位同样算函数槽。
    let thunk_destination = |rva: u64| -> Option<u64> {
        let bytes = space.read(rva, 6)?;
        let (length, rel) = match bytes[0] {
            0xE9 => (
                5i64,
                i64::from(i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])),
            ),
            0xEB => (2i64, i64::from(i8::from_le_bytes([bytes[1]]))),
            _ => return None,
        };
        let target = u64::try_from(i64::try_from(rva).ok()? + length + rel).ok()?;
        entries.contains(&target).then_some(target)
    };

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
            let is_function = resolved
                .is_some_and(|rva| entries.contains(&rva) || thunk_destination(rva).is_some());
            if is_function {
                if run_start.is_none() {
                    run_start = Some(slot);
                }
                run.push(resolved.expect("checked above"));
            } else if run.len() >= 2 {
                out.push(Vtable {
                    rva: run_start.expect("run nonempty implies start"),
                    targets: std::mem::take(&mut run),
                    kind: VtableKind::PointerTable,
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
                kind: VtableKind::PointerTable,
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
    matches!(bytes[0], 0x8B | 0x8D | 0xFF) && is_ebp_disp_modrm(bytes[1])
}

fn is_ebp_disp_modrm(byte: u8) -> bool {
    matches!(
        byte,
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
/// `sub ecx, [ecx+disp]`（`2B 49`，但虚基类调整器 thunk `2B 49 FC E9` 除外），
/// 以及 frame-relative 访问。
fn is_degenerate_start(space: &dyn AddressSpace, rva: u64) -> bool {
    is_padding_noise(space, rva) || is_frame_relative_start(space, rva)
}

/// padding 噪声形状（与 frame-relative 无关的那一半）。
fn is_padding_noise(space: &dyn AddressSpace, rva: u64) -> bool {
    let Some(bytes) = space.read(rva, 4) else {
        return false;
    };
    matches!(bytes[0], 0xCC | 0xC3 | 0x00)
        || (bytes[0] == 0x90 && bytes[1] == 0x90)
        // 2B 49 FC（sub ecx,[ecx-4]）是 vbtable 调整 thunk 的固定开头，不是噪声。
        || (bytes[0] == 0x2B && bytes[1] == 0x49 && bytes[2] != 0xFC)
        || (bytes[0] == 0x6A
            && bytes.len() >= 4
            && matches!(bytes[2], 0x8B | 0x8D)
            && is_ebp_disp_modrm(bytes[3]))
}

/// 前面有两字节对齐填充、自身不是 padding 噪声的起点；**不**排除 frame-relative 开头。
///
/// MSVC x86 `/O2` 常把 EBP 当通用寄存器（省略帧指针），这类函数天生以
/// `lea/mov reg,[ebp±disp]` 开头。单独的 frame-relative 访问确实不是入口，但
/// 「vtable 指向 + 16 对齐 + 对齐填充」已是足够强的入口证据，不应再被它否决。
fn looks_like_padded_start(space: &dyn AddressSpace, rva: u64) -> bool {
    if is_padding_noise(space, rva) {
        return false;
    }
    // 只认 int3 / nop 对齐填充：`00 00` 往往是前一条指令 imm32/disp32 的高位字节。
    space
        .read(rva.saturating_sub(2), 2)
        .is_some_and(|bytes| matches!(bytes[0], 0xCC | 0x90) && matches!(bytes[1], 0xCC | 0x90))
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
    // 活体映像里 .eh_frame / DWARF 的地址引用不会被加载器重定位，仍按 PE 头里的首选
    // 基址书写；解引用时在（活体）实际基址之后回退到它。静态分析两者相同。
    let preferred_base = pe_image_base(space, module.container).unwrap_or(image_base);
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
            // 活体映像里 .eh_frame / DWARF 的地址引用不会被加载器重定位，仍按文件首选
            // 基址书写；先按（活体）实际基址解释，再回退到 PE 头里的首选基址。
            let va_target = value
                .checked_sub(image_base)
                .filter(|rva| in_exec(*rva))
                .or_else(|| {
                    value
                        .checked_sub(preferred_base)
                        .filter(|rva| in_exec(*rva))
                });
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
                || (prefer_rva && looks_like_function_start_weak(space, target))
                // 16 对齐 + 对齐填充的 frame-relative 开头（EBP 作通用寄存器的函数）。
                || (target % 16 == 0 && looks_like_padded_start(space, target));
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
            if in_exec(value)
                && (looks_like_function_start_weak(space, value)
                    || looks_like_padded_start(space, value))
            {
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
    let preferred_base = pe_image_base(space, module.container).unwrap_or(image_base);
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
                // 依次尝试：（活体）实际基址 VA、裸 RVA、PE 头首选基址 VA（未重定位的
                // .eh_frame / DWARF 引用）。
                let Some(rva) = value
                    .checked_sub(image_base)
                    .filter(|rva| in_exec(*rva))
                    .or_else(|| in_exec(value).then_some(value))
                    .or_else(|| {
                        value
                            .checked_sub(preferred_base)
                            .filter(|rva| in_exec(*rva))
                    })
                else {
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
                || (window[0] == 0xE8 && window[5] == 0xFF && window[6] == 0x25)
                || (window[0] == 0x8B
                    && window[1] == 0x44
                    && window[2] == 0x24
                    && window[3] == 0x08)
                || (window[0] == 0x51
                    && window[1] == 0x56
                    && window[2] == 0x8B
                    && window[3] == 0xF1)
                || (window[0] == 0x56
                    && window[1] == 0x8D
                    && window[2] == 0x71
                    && window[3] == 0xF0)
                || (window[0] == 0x51
                    && window[1] == 0x8B
                    && window[2] == 0x44
                    && window[3] == 0x24)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0xE8)
                || (window[0] == 0x56
                    && window[1] == 0x57
                    && window[2] == 0x8B
                    && window[3] == 0xF9
                    && window[4] == 0x8D
                    && window[5] == 0x77)
                || (window[0] == 0x53
                    && window[1] == 0x56
                    && window[2] == 0x57
                    && window[3] == 0x8B
                    && window[4] == 0xF9
                    && window[5] == 0x8B)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0x74
                    && window[3] == 0x24
                    && window[4] == 0x08
                    && window[5] == 0x85)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0x8B
                    && window[4] == 0x46
                    && window[5] == 0x08)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0x71
                    && window[3] == 0xF8)
                || (window[0] == 0x51
                    && window[1] == 0x53
                    && window[2] == 0x8B
                    && window[3] == 0x5C)
                || (window[0] == 0x53
                    && window[1] == 0x56
                    && window[2] == 0x8B
                    && window[3] == 0xF1)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0x57)
                || (window[0] == 0x56
                    && window[1] == 0x57
                    && window[2] == 0x8B
                    && window[3] == 0x7C
                    && window[4] == 0x24
                    && window[5] == 0x0C)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0x8B
                    && window[4] == 0x4C
                    && window[5] == 0x24)
                || (window[0] == 0x8B
                    && window[1] == 0x41
                    && window[2] == 0x04
                    && window[3] == 0x80)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0x74
                    && window[3] == 0x24
                    && window[4] == 0x08
                    && window[5] == 0x83)
                || (window[0] == 0x53
                    && window[1] == 0x57
                    && window[2] == 0x8B
                    && window[3] == 0x7C
                    && window[4] == 0x24
                    && window[5] == 0x0C)
                || (window[0] == 0x55
                    && window[1] == 0x56
                    && window[2] == 0x57
                    && window[3] == 0x8B
                    && window[4] == 0xF9
                    && window[5] == 0x8B)
                || (window[0] == 0x56
                    && window[1] == 0x57
                    && window[2] == 0x8B
                    && window[3] == 0xF1)
                || (window[0] == 0x51
                    && window[1] == 0x53
                    && window[2] == 0x56
                    && window[3] == 0x8B)
                || (window[0] == 0x55
                    && window[1] == 0x57
                    && window[2] == 0x8B
                    && window[3] == 0x7C
                    && window[4] == 0x24
                    && window[5] == 0x0C)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0x8B
                    && window[4] == 0x46
                    && window[5] == 0xF0)
                || (window[0] == 0x56
                    && window[1] == 0x8B
                    && window[2] == 0xF1
                    && window[3] == 0x8B
                    && window[4] == 0x4C
                    && window[5] == 0x24)
                || (window[0] == 0x80
                    && window[1] == 0x79
                    && window[2] == 0x38
                    && window[3] == 0x00)
                || (window[0] == 0x53
                    && window[1] == 0x56
                    && window[2] == 0x8B
                    && window[3] == 0xD9);
            if padded && prologue {
                targets.insert(rva);
            }
            offset += 16;
        }
    }
    targets
}

/// 4 字节对齐的 `55 8B EC` 帧指针序言。
///
/// 16 字节对齐 pass 会漏掉一些紧凑布局的函数；这里额外按 4 字节步长扫描，
/// 只接受标准 `push ebp; mov ebp, esp` 形态和前置填充，避免把普通指令中间当起点。
fn frame_prologue_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let mut targets = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        let mut offset = usize::try_from((4 - (*start % 4)) % 4).unwrap_or(0);
        while offset + 4 <= bytes.len() {
            let padded = offset >= 2
                && matches!(bytes[offset - 1], 0xCC | 0x90 | 0x00)
                && matches!(bytes[offset - 2], 0xCC | 0x90 | 0x00);
            let boundary = offset >= 1
                && matches!(
                    bytes[offset - 1],
                    0xC3 | 0xC2 | 0xE9 | 0xEB | 0xFF | 0xCC | 0x90 | 0x00
                );
            if (padded || boundary)
                && bytes[offset] == 0x55
                && bytes[offset + 1] == 0x8B
                && bytes[offset + 2] == 0xEC
            {
                targets.insert(*start + u64::try_from(offset).unwrap_or(0));
            }
            offset += 4;
        }
    }
    targets
}

/// 4 字节对齐、前置代码边界的热补丁 / thunk 形态。
///
/// 这些起点不满足 16 对齐的两字节填充前提，但形态本身很窄：
/// 热补丁 `8B FF 55 8B EC`、尾调用 `83 E9 imm8; E9`、以及常见 thunk 序言。
fn aligned_pattern_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let mut targets = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        let mut offset = usize::try_from((4 - (*start % 4)) % 4).unwrap_or(0);
        while offset + 8 <= bytes.len() {
            let boundary = offset >= 1
                && matches!(
                    bytes[offset - 1],
                    0xC3 | 0xC2 | 0xE9 | 0xEB | 0xFF | 0xCC | 0x90 | 0x00
                );
            if boundary {
                let window = &bytes[offset..offset + 5];
                let thunk = window[0] == 0x83 && window[1] == 0xE9 && window[3] == 0xE9;
                let hotpatch = (window[0] == 0x8B
                    && window[1] == 0xFF
                    && window[2] == 0x55
                    && window[3] == 0x8B
                    && window[4] == 0xEC)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x56
                        && window[3] == 0x8B)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x56
                        && window[3] == 0x57)
                    || (window[0] == 0x8B && window[1] == 0x01 && window[2] == 0xC3)
                    || (window[0] == 0x6A
                        && window[1] == 0x03
                        && window[2] == 0x58
                        && window[3] == 0xC3);
                let common = (window[0] == 0x51
                    && window[1] == 0x56
                    && window[2] == 0x8B
                    && window[3] == 0x74)
                    || (window[0] == 0x8D
                        && window[1] == 0x41
                        && window[2] == 0xF4
                        && window[3] == 0x85)
                    || (window[0] == 0xF6
                        && window[1] == 0x44
                        && window[2] == 0x24
                        && window[3] == 0x04)
                    || (window[0] == 0x8D
                        && window[1] == 0x41
                        && window[2] == 0x04
                        && window[3] == 0x50)
                    || (window[0] == 0x51
                        && window[1] == 0x53
                        && window[2] == 0x56
                        && window[3] == 0x8B)
                    || (window[0] == 0x8A
                        && window[1] == 0x44
                        && window[2] == 0x24
                        && window[3] == 0x04)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x56
                        && window[3] == 0x8B)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x53
                        && window[3] == 0x56)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x56
                        && window[3] == 0x57)
                    || (window[0] == 0x8B && window[1] == 0x01 && window[2] == 0xC3)
                    || (window[0] == 0x8B && window[1] == 0xC1 && window[2] == 0xC3)
                    || (window[0] == 0x33
                        && window[1] == 0xC0
                        && window[2] == 0x40
                        && window[3] == 0xC3)
                    || (window[0] == 0x6A
                        && window[1] == 0x03
                        && window[2] == 0x58
                        && window[3] == 0xC3);
                if thunk || hotpatch || common {
                    targets.insert(*start + u64::try_from(offset).unwrap_or(0));
                }
            }
            offset += 4;
        }
    }
    targets
}

/// 任意字节偏移的极窄热补丁 / tiny thunk / lea 形态。
///
/// 接受可无边界的 `8B FF 55 8B EC`，以及前置代码边界后的
/// `8B FF 56 8B`、`8B FF 56 57`、`8B 01 C3`、`6A 03 58 C3`、`8D 41 04 50`；
/// 这些形态在紧凑 DLL/MSVC 无 PDB 样本中常出现在非 4 对齐位置。
fn byte_pattern_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    let space = module.address_space();
    let mut targets = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        for offset in 1..bytes.len().saturating_sub(4) {
            let window = &bytes[offset..offset + 5];
            let hotpatch = window[0] == 0x8B
                && window[1] == 0xFF
                && window[2] == 0x55
                && window[3] == 0x8B
                && window[4] == 0xEC;
            let boundary = matches!(
                bytes[offset - 1],
                0xC3 | 0xC2 | 0xE9 | 0xEB | 0xFF | 0xCC | 0x90 | 0x00
            );
            let boundary_tiny = boundary
                && ((window[0] == 0x8B
                    && window[1] == 0xFF
                    && window[2] == 0x56
                    && window[3] == 0x8B)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x56
                        && window[3] == 0x57)
                    || (window[0] == 0x8B
                        && window[1] == 0xFF
                        && window[2] == 0x53
                        && window[3] == 0x56)
                    || (window[0] == 0x8B && window[1] == 0x01 && window[2] == 0xC3)
                    || (window[0] == 0x6A
                        && window[1] == 0x03
                        && window[2] == 0x58
                        && window[3] == 0xC3));
            // 上一条指令是 `jmp rel8`（尾调用）同样是边界：它的最后一个字节是任意位移。
            let rva = *start + u64::try_from(offset).unwrap_or(0);
            let short_jump_target = rva as i64 + i64::from(i8::from_le_bytes([bytes[offset - 1]]));
            let after_short_jump = offset >= 2
                && bytes[offset - 2] == 0xEB
                && short_jump_target >= 0
                && in_exec_range(exec_ranges, short_jump_target as u64);
            if !boundary && !hotpatch && !after_short_jump {
                continue;
            }
            // 只有帧序言接受「短跳转之后」这种边界；其余形态仍要求单字节边界。
            let lea_push = boundary
                && window[0] == 0x8D
                && window[1] == 0x41
                && window[2] == 0x04
                && window[3] == 0x50;
            let safe_frame = matches!(bytes[offset - 1], 0xC3 | 0xE9 | 0xEB | 0xCC | 0x90 | 0x00);
            let frame = (safe_frame || after_short_jump)
                && window[0] == 0x55
                && window[1] == 0x8B
                && window[2] == 0xEC;
            let tail_thunk =
                boundary && window[0] == 0x83 && window[1] == 0xE9 && window[3] == 0xE9;
            if hotpatch || boundary_tiny || lea_push || frame || tail_thunk {
                targets.insert(*start + u64::try_from(offset).unwrap_or(0));
            }
        }
    }
    targets
}

/// RVA 是否落在任一执行节内。
fn in_exec_range(exec_ranges: &[(u64, u64)], rva: u64) -> bool {
    exec_ranges
        .iter()
        .any(|(start, size)| rva >= *start && rva < start.saturating_add(*size))
}

/// MSVC 调整器 thunk：先修正 `ecx`（this 指针）再 `jmp rel32` 跳到真函数。
/// 返回 (thunk 长度, rel32 所在偏移)；x64 多一个 `48` REX.W 前缀。
fn adjustor_thunk_shape(window: &[u8]) -> Option<(usize, usize)> {
    match window {
        [0x2B, 0x49, 0xFC, 0xE9, ..] => Some((8, 3)),
        [0x83, 0xC1 | 0xE9, _, 0xE9, ..] => Some((8, 3)),
        [0x81, 0xC1 | 0xE9, _, _, _, _, 0xE9, ..] => Some((11, 6)),
        [0x48, 0x2B, 0x49, 0xFC, 0xE9, ..] => Some((9, 4)),
        [0x48, 0x83, 0xC1 | 0xE9, _, 0xE9, ..] => Some((9, 4)),
        [0x48, 0x81, 0xC1 | 0xE9, _, _, _, _, 0xE9, ..] => Some((12, 7)),
        _ => None,
    }
}

/// 窗口 `at` 处（`E9` 之后）的 rel32。
fn rel32_at(window: &[u8], at: usize) -> Option<i32> {
    let bytes = window.get(at + 1..at + 5)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

/// thunk 之前的结构性代码边界：`int3` / `nop` 对齐填充、`ret`、
/// `jmp rel8`、`jmp rel32`（目标在节内）或节首。
///
/// 只看前一字节不够：`90` / `FF` / `00` 也常是前一条指令的位移字节
/// （`mov ecx,[ebp-0x70]` 以 `90` 结尾），函数内的 adjustor 尾调用会借此混进来。
fn has_structural_boundary(
    bytes: &[u8],
    offset: usize,
    rva: u64,
    exec_ranges: &[(u64, u64)],
) -> bool {
    if offset == 0 {
        return true;
    }
    let back = |distance: usize| {
        offset
            .checked_sub(distance)
            .and_then(|index| bytes.get(index))
            .copied()
    };
    let padding = back(1) == Some(0xCC) || (back(1) == Some(0x90) && back(2) == Some(0x90));
    let terminator = back(1) == Some(0xC3) || back(3) == Some(0xC2) || back(2) == Some(0xEB);
    let jump = if back(5) == Some(0xE9) {
        rel32_at(&bytes[offset - 5..], 0).is_some_and(|rel| {
            i64::try_from(rva)
                .ok()
                .and_then(|rva| u64::try_from(rva + i64::from(rel)).ok())
                .is_some_and(|target| in_exec_range(exec_ranges, target))
        })
    } else {
        back(6) == Some(0xFF) && back(5) == Some(0x25)
    };
    padding || terminator || jump
}

/// 真 thunk 成表排列：后面紧跟对齐填充或下一个 thunk。函数里的 adjustor 尾调用
/// （`mov ecx,[ebp-0x34]; add ecx,N; jmp`）后面则是普通代码，借此排除。
fn is_packed_thunk_tail(bytes: &[u8], tail: usize) -> bool {
    let Some(after) = bytes.get(tail..) else {
        return true;
    };
    let padding = after.first() == Some(&0xCC)
        || (after.first() == Some(&0x90) && after.get(1) == Some(&0x90));
    if padding || adjustor_thunk_shape(after).is_some() {
        return true;
    }
    // 同表混排的其它 thunk：导入跳转 / 导入调用 / this 调整后调用 / tiny getter /
    // 热补丁序言 / 跳转 stub。
    after.starts_with(&[0xFF, 0x25])
        || after.starts_with(&[0xFF, 0x15])
        || after.starts_with(&[0x8D, 0x41, 0x04, 0x50])
        || (after.starts_with(&[0x8B, 0x41]) && after.get(3) == Some(&0xC3))
        || after.starts_with(&[0x8B, 0xFF])
        || after.first() == Some(&0xE9)
}

/// 调整器 thunk 与 16 对齐跳转 stub：返回 (起点集合, 它们的 `jmp` 目标集合)。
///
/// - 调整器 thunk（`sub/add ecx, …; jmp rel32`）是 vtable 项，布局紧凑、常不在
///   16 字节边界上；它前面几乎总是另一个 thunk 的 `jmp rel32` 或 `int3` 填充，
///   所以要求前面是结构性代码边界（见 `has_structural_boundary`），且跳转目标落在执行节内。
/// - 跳转 stub：16 对齐、前置对齐填充的单条 `jmp rel32`——编译器把函数体放到下一个
///   16 字节边界时留下的入口，IDA 也把它列为 5 字节函数。
/// - 导入跳转 stub：`jmp [IAT]`（`FF 25`），槽位在非执行节，前面是 ret / int3 或另一个 stub。
///
/// thunk 存在的意义就是跳到目标，所以目标也是函数起点。
fn thunk_targets(
    module: &ViewAdapter<'_>,
    exec_ranges: &[(u64, u64)],
) -> (BTreeSet<u64>, BTreeSet<u64>) {
    let space = module.address_space();
    let image_base = if module.image_base != 0 {
        module.image_base
    } else {
        pe_image_base(space, module.container).unwrap_or(0)
    };
    let mut starts = BTreeSet::new();
    let mut jumps = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        for offset in 0..bytes.len() {
            let Some(window) = bytes.get(offset..offset + 11) else {
                break;
            };
            let rva = *start + u64::try_from(offset).unwrap_or(0);
            let adjustor = if has_structural_boundary(bytes, offset, rva, exec_ranges) {
                adjustor_thunk_shape(window)
                    .and_then(|(len, at)| rel32_at(window, at).map(|rel| (len, rel)))
                    .filter(|(len, _)| is_packed_thunk_tail(bytes, offset + len))
            } else {
                None
            };
            let stub = if window[0] == 0xE9
                && offset >= 2
                && rva % 16 == 0
                && matches!(bytes[offset - 1], 0xCC | 0x90)
                && matches!(bytes[offset - 2], 0xCC | 0x90)
            {
                rel32_at(window, 0).map(|rel| (5usize, rel))
            } else {
                None
            };
            // 导入跳转 stub：jmp [IAT 槽]（x64 rip 相对，x86 绝对 VA），槽位落在非执行节；
            // 前面是 ret / int3 填充或另一个 stub（导入表按 6 字节连排）。IDA 把它们列为函数。
            if window[0] == 0xFF && window[1] == 0x25 {
                let slot = rel32_at(window, 1).and_then(|disp| {
                    if module.arch.bitness() == 64 {
                        Some(i64::try_from(rva + 6).ok()? + i64::from(disp))
                    } else {
                        Some(i64::from(disp as u32) - i64::try_from(image_base).ok()?)
                    }
                });
                let in_data = slot
                    .and_then(|slot| u64::try_from(slot).ok())
                    .is_some_and(|slot| !in_exec_range(exec_ranges, slot));
                let after_stub =
                    offset >= 6 && bytes[offset - 6] == 0xFF && bytes[offset - 5] == 0x25;
                if in_data && (matches!(bytes[offset - 1], 0xC3 | 0xCC) || after_stub) {
                    starts.insert(rva);
                }
                continue;
            }
            let Some((len, rel)) = adjustor.or(stub) else {
                continue;
            };
            let next = rva.saturating_add(u64::try_from(len).unwrap_or(0));
            let jump = i64::try_from(next)
                .ok()
                .and_then(|next| u64::try_from(next + i64::from(rel)).ok())
                .filter(|jump| in_exec_range(exec_ranges, *jump));
            let Some(jump) = jump else {
                continue;
            };
            starts.insert(rva);
            if !is_frame_relative_start(space, jump) || looks_like_padded_start(space, jump) {
                jumps.insert(jump);
            }
        }
    }
    (starts, jumps)
}

/// 按 4 字节对齐、前置 `int3` 填充（≥2 字节，或 `ret` 后跟 1 字节）、且能顺序解码到终结符的代码起点。
///
/// [`prologue_targets`] 形状表的泛化：MSVC 把每个函数（包括没有任何引用的 leaf、模板
/// 实例化、调整 thunk）对齐到 16 字节，COMDAT 折叠后的小函数落在 4 字节边界上，并用
/// `int3` 填充，而起点的指令形态无穷无尽。
/// 只认 `int3`（`90 90` 常是 `mov edx,[eax+1]` 这类指令的 ModRM/disp 字节，
/// 不是填充），且必须在 8 KiB 内、不遇非法指令地解码到 ret / 无条件跳转 / 间接跳转
/// （`ret; int3` 之后的单字节填充同样成立：`ret` 已是完整指令，其后的 `int3` 只能是填充）
/// （或 fastfail 的 `int3; ret`）。
fn padded_code_targets(module: &ViewAdapter<'_>, exec_ranges: &[(u64, u64)]) -> BTreeSet<u64> {
    const MAX_BODY: usize = 8192;
    let space = module.address_space();
    let bitness = module.arch.bitness();
    let image_base = if module.image_base != 0 {
        module.image_base
    } else {
        pe_image_base(space, module.container).unwrap_or(0)
    };
    let mut targets = BTreeSet::new();
    for (start, size) in exec_ranges {
        let Some(bytes) = space.read(*start, usize::try_from(*size).unwrap_or(usize::MAX)) else {
            continue;
        };
        // 结束于 offset 的 6 字节 jmp [槽] 是否真是导入 stub：槽位要落在非执行节
        //（`FF 25` 两个字节也常出现在普通指令的立即数里）。
        let import_stub_ends_here = |stub_at: usize, rva: u64| {
            rel32_at(&bytes[stub_at..], 1)
                .map(i64::from)
                .and_then(|disp| {
                    if bitness == 64 {
                        i64::try_from(rva).ok().map(|next| next + disp)
                    } else {
                        Some(disp - i64::try_from(image_base).unwrap_or(0))
                    }
                })
                .and_then(|slot| u64::try_from(slot).ok())
                .is_some_and(|slot| {
                    module.sections.iter().any(|section| {
                        !section.executable
                            && section.rva > 0
                            && slot >= section.rva
                            && slot < section.rva.saturating_add(section.size)
                    })
                })
        };
        // COMDAT 折叠后的小函数按 4 字节粒度落位，与位宽无关。
        let alignment = 4u64;
        let mut offset =
            usize::try_from((alignment - (*start % alignment)) % alignment).unwrap_or(0);
        while offset < bytes.len() {
            let rva = *start + u64::try_from(offset).unwrap_or(0);
            let body = bytes.get(offset..offset + MAX_BODY.min(bytes.len() - offset));
            let cc_padded = offset >= 2
                && bytes[offset - 1] == 0xCC
                && matches!(bytes[offset - 2], 0xCC | 0xC3);
            // 导入跳转 stub（jmp [iat]）之后直接是下一个函数，没有填充。
            let after_import_stub = (offset >= 6
                && bytes[offset - 6] == 0xFF
                && bytes[offset - 5] == 0x25
                && import_stub_ends_here(offset - 6, rva))
                || (offset >= 7
                    && bytes[offset - 1] == 0xCC
                    && bytes[offset - 7] == 0xFF
                    && bytes[offset - 6] == 0x25
                    && import_stub_ends_here(offset - 7, rva - 1));
            if (cc_padded || after_import_stub)
                && !matches!(bytes[offset], 0xCC | 0xC3 | 0x90 | 0x00)
                && !is_padding_noise(space, rva)
                && body.is_some_and(|body| decodes_to_terminator(bitness, body, rva))
            {
                targets.insert(rva);
            }
            offset += usize::try_from(alignment).unwrap_or(4);
        }
    }
    targets
}

/// 顺序解码是否到达终结符。
///
/// `int3` 既可能是函数体里的 fastfail（`cmp; ja; int3; ret`），也可能是跟在数据后面的填充：
/// 只有它后面不是 `int3` 时才算终结符，填充串则拒绝；`call` 之后的 `int3` 填充是
/// noreturn 调用（exit / abort）的函数结尾，也算终结符。非法指令一律拒绝。
fn decodes_to_terminator(bitness: u32, body: &[u8], ip: u64) -> bool {
    let mut decoder = Decoder::with_ip(bitness, body, ip, DecoderOptions::NONE);
    let mut instructions = 0usize;
    // 距上一条 call 的指令数；开头即视为「很久没调用」。
    let mut since_call = 1usize;
    // call 之后到目前为止是否全是尾聲形態指令（不可达的收尾）。
    let mut epilogue_tail = true;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return false;
        }
        instructions += 1;
        if instruction.flow_control() == FlowControl::Interrupt {
            let next = instruction.next_ip();
            // call（直接或间接）紧跟填充：被调方不返回（exit / abort 一类），函数到此为止。
            // 放宽到「call 后两三条指令内」会在真实样本上接进几十个无人认可的数据块，不放宽。
            if since_call == 0 {
                return true;
            }
            // call 之后最多两条尾聲形態指令（pop / leave / add esp,imm / mov esp,ebp）再跟填充：
            // 同样是 noreturn 结尾，多出来的是编译器留下的不可达收尾指令。
            // 只放行尾聲形態——单纯按条数放宽会在真实样本上接进几十个无人认可的数据块。
            if since_call <= 2 && epilogue_tail {
                return true;
            }
            // 两字节的 int imm8（如 fastfail 的 int 29h）本身就是终结符；只有单字节
            // int3 可能是数据后面的填充串，才要求它后面不是又一个 int3。
            let two_byte_int = instruction.len() == 2;
            return two_byte_int
                || (instructions >= 2
                    && body
                        .get(usize::try_from(next - ip).unwrap_or(usize::MAX)..)
                        .and_then(|rest| rest.first())
                        .is_some_and(|byte| *byte != 0xCC));
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            since_call = 0;
            epilogue_tail = true;
        } else {
            let start = usize::try_from(instruction.ip().saturating_sub(ip)).unwrap_or(0);
            let raw = body
                .get(start..start.saturating_add(instruction.len()))
                .unwrap_or_default();
            if since_call <= 2 && !is_epilogue_tail(raw) {
                epilogue_tail = false;
            }
            since_call = since_call.saturating_add(1);
        }
        if is_terminator(&instruction) {
            return true;
        }
    }
    false
}
/// call 之后不可达的收尾指令形态：`pop r32`、`leave`、`add esp, imm`、`mov esp, ebp`。
fn is_epilogue_tail(raw: &[u8]) -> bool {
    matches!(
        raw,
        [0x58..=0x5F, ..]
            | [0xC9, ..]
            | [0x8B, 0xE5, ..]
            | [0x83, 0xC4, _]
            | [0x81, 0xC4, _, _, _, _]
    )
}

/// 扫描 vtable：通用指针表扫描 ∪ RTTI 锚定的虚表。
///
/// RTTI 锚定的表是精确事实（`CompleteObjectLocator` 指回的 vftable）。通用扫描要求
/// 连续 ≥2 个槽位都解析到函数入口，因此会漏掉「只有析构槽」「槽位是 NULL」或槽位指向
/// 未发现函数的表；两者合并后按 RVA 升序、去重。
#[must_use]
pub fn vtables_with_rtti(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<Vtable> {
    use std::collections::BTreeSet;

    let mut tables = vtables(module, functions);
    let mut known: BTreeSet<u64> = tables.iter().map(|table| table.rva).collect();
    for fact in msvc_rtti::scan(module).vtables {
        if known.insert(fact.address_point) {
            tables.push(Vtable {
                rva: fact.address_point,
                targets: fact.slots,
                kind: VtableKind::RttiAnchored,
            });
        } else if let Some(existing) = tables.iter_mut().find(|t| t.rva == fact.address_point) {
            // 通用扫描也认出来的表：RTTI 锚点把它升级成精确事实。
            existing.kind = VtableKind::RttiAnchored;
        }
    }
    tables.sort_by_key(|table| table.rva);
    tables
}

/// 直接（rel）call 的位置 → 目标，按目标归组（用于判断候选是否被外部函数调用）。
fn direct_call_sites(
    module: &ViewAdapter<'_>,
    exec_ranges: &[(u64, u64)],
) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut sites: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
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
            if buffer.flow_control() != FlowControl::Call {
                continue;
            }
            if let Some(target) = direct_near_target(&buffer) {
                if in_exec_range(exec_ranges, target) && !is_frame_relative_start(space, target) {
                    sites.entry(target).or_default().insert(buffer.ip());
                }
            }
        }
    }
    sites
}

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

    /// x86 非 PIE（旧版原生程序多属此类）：`push offset str` / `mov reg, imm32` 的
    /// 绝对地址立即数也要归到引用它的函数——此前只认 x64 的 RIP 相对形态，x86 永远为空。
    #[test]
    fn string_xrefs_find_absolute_immediate_references() {
        for rel in [
            "x86-windows-gnu/-O2/strings.exe",
            "x86-windows-msvc/-O2/strings.exe",
        ] {
            let Some(path) = fixture(rel) else {
                eprintln!("skip: fixtures not built");
                continue;
            };
            let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
            let functions = discover(&module);
            let xrefs = string_xrefs(&module, &functions);
            let texts: Vec<&str> = xrefs.iter().map(|x| x.text.as_str()).collect();
            let hits = ["large", "medium", "small"]
                .iter()
                .filter(|word| texts.contains(word))
                .count();
            assert!(
                hits >= 2,
                "{rel}: expected absolute literal references, got {xrefs:?}"
            );
            assert!(xrefs.iter().all(|x| x.text.len() >= 4));
            // 每条引用的字符串都落在数据节，引用方函数确实存在。
            assert!(xrefs
                .iter()
                .all(|x| functions.iter().any(|f| f.rva == x.func_rva)));
        }
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

    /// `--vtables` 合并 RTTI 锚定的虚表：RTTI 给出的是精确事实，通用扫描漏掉的
    /// （只有析构槽、槽位为 NULL、槽位指向未发现函数）都由它补齐。
    #[test]
    fn vtables_include_rtti_anchored_tables() {
        let Some(path) = fixture("x86-windows-msvc/-O2/msvc_rtti.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        let facts = msvc_rtti::scan(&module);
        assert!(!facts.vtables.is_empty(), "fixture should expose MSVC RTTI");
        let merged = vtables_with_rtti(&module, &functions);
        let rvas: std::collections::BTreeSet<u64> = merged.iter().map(|table| table.rva).collect();
        for table in &facts.vtables {
            assert!(
                rvas.contains(&table.address_point),
                "RTTI-anchored vtable {:#x} missing from --vtables",
                table.address_point
            );
        }
        // 合并结果的每个表都至少有一个槽位目标，且 RVA 不重复；RTTI 锚定的表要带头衔。
        assert!(merged.iter().all(|table| !table.targets.is_empty()));
        let anchored: std::collections::BTreeSet<u64> = merged
            .iter()
            .filter(|table| table.kind == VtableKind::RttiAnchored)
            .map(|table| table.rva)
            .collect();
        for table in &facts.vtables {
            assert!(anchored.contains(&table.address_point));
        }
        let unique: std::collections::BTreeSet<u64> = merged.iter().map(|t| t.rva).collect();
        assert_eq!(unique.len(), merged.len());
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
        // 「每个表都 ≥3 槽」是夹具布局相关的期望：链接器把只有两个虚函数的类也排进
        // 同一段 .rodata 时，合法的表就是 2 槽（重建夹具后实测出现），所以只要求
        // 至少两个 3 槽以上的表，保留原来 Fan / Pump 每个都够大的本意。
        assert!(
            tables.iter().filter(|t| t.targets.len() >= 3).count() >= 2,
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

    /// 链式 .pdata：延续块不是起点，紧邻的并入父函数尺寸，分开的冷代码块只留在事实里。
    #[test]
    fn chained_unwind_chunks_are_not_function_starts() {
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
            bytes: vec![0u8; 0x4000],
            segments: vec![
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
                segment(0x3000, 0x1000, false),
            ],
        };
        // .pdata：父函数 1000-1040、紧邻延续块 1040-1060、分开的冷块 1200-1220。
        let entries: [(u32, u32, u32); 3] = [
            (0x1000, 0x1040, 0x3000),
            (0x1040, 0x1060, 0x3020),
            (0x1200, 0x1220, 0x3040),
        ];
        for (index, (begin, end, unwind)) in entries.iter().enumerate() {
            let at = 0x2000u64 + index as u64 * 12;
            space.write(at, &begin.to_le_bytes());
            space.write(at + 4, &end.to_le_bytes());
            space.write(at + 8, &unwind.to_le_bytes());
        }
        // 父函数的 UNWIND_INFO：version 1、无标志、一个 unwind code。
        space.write(0x3000, &[1, 4, 1, 0x05, 0, 0]);
        // 两个延续块的 UNWIND_INFO：CHAININFO，尾随父记录 1000-1040 @ 3000。
        for unwind in [0x3020u64, 0x3040] {
            space.write(unwind, &[(UNW_FLAG_CHAININFO << 3) | 1, 4, 1, 0x05, 0, 0]);
            space.write(unwind + 8, &0x1000u32.to_le_bytes());
            space.write(unwind + 12, &0x1040u32.to_le_bytes());
            space.write(unwind + 16, &0x3000u32.to_le_bytes());
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
                size: 36,
                name: ".pdata".into(),
                executable: false,
            },
            SectionInfo {
                rva: 0x3000,
                size: 0x1000,
                name: ".xdata".into(),
                executable: false,
            },
        ];
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
        let directory = DataDirectory {
            rva: 0x2000,
            size: 36,
        };
        let adapter = ViewAdapter {
            container: Container::Pe64,
            arch: Arch::X86_64,
            image_base: 0,
            entry_rva: None,
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
            space: &space,
        };
        let facts = exception_functions_impl(&adapter, Some(directory));
        assert_eq!(facts.len(), 3, "exception facts keep every chunk");
        let functions = discover_impl(view, &space, Some(directory));
        let parent = functions
            .iter()
            .find(|function| function.rva == 0x1000)
            .expect("parent function");
        assert_eq!(parent.size, 0x60, "contiguous chunk extends the parent");
        assert!(!parent.size_inferred);
        for rva in [0x1040u64, 0x1200] {
            assert!(
                !functions.iter().any(|function| function.rva == rva),
                "chained chunk {rva:#x} must not be a start: {functions:?}"
            );
        }
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
        space.write(0x1090, &[0x8B, 0x44, 0x24, 0x08, 0xC3]);
        space.write(0x10A0, &[0x51, 0x56, 0x8B, 0xF1, 0xC3]);
        space.write(0x10B0, &[0x56, 0x8D, 0x71, 0xF0, 0xC3]);
        space.write(0x10C0, &[0x51, 0x8B, 0x44, 0x24, 0xC3]);
        space.write(
            0x10D0,
            &[0x56, 0x8B, 0xF1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3],
        );
        space.write(0x10E4, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x10E8, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x10F0, &[0x56, 0x57, 0x8B, 0xF9, 0x8D, 0x77, 0x00, 0xC3]);
        space.write(0x1100, &[0x53, 0x56, 0x57, 0x8B, 0xF9, 0x8B, 0x00, 0xC3]);
        space.write(0x1110, &[0x56, 0x57, 0x8B, 0x7C, 0x24, 0x0C, 0xC3]);
        space.write(0x1120, &[0x8B, 0x41, 0x04, 0x80, 0xC3, 0x00, 0xC3]);
        space.write(0x1130, &[0x51, 0x56, 0x8B, 0x74, 0x24, 0x08, 0xC3]);
        space.write(
            0x1140,
            &[0x83, 0xE9, 0x28, 0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3],
        );
        space.write(0x1150, &[0x8D, 0x41, 0xF4, 0x85, 0xC0, 0xC3]);
        space.write(0x1160, &[0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x1170, &[0xF6, 0x44, 0x24, 0x04, 0x01, 0xC3]);
        space.write(0x1180, &[0x8D, 0x41, 0x04, 0x50, 0xC3]);
        space.write(0x1191, &[0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x11A1, &[0x8D, 0x41, 0x04, 0x50, 0xC3]);
        space.write(0x11B0, &[0xC3]);
        space.write(0x11B1, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(
            0x11C1,
            &[0x83, 0xE9, 0x28, 0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3],
        );
        space.write(0x11D0, &[0x55]);
        space.write(0x11D1, &[0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x11E0, &[0x51, 0x53, 0x56, 0x8B, 0x74, 0x24, 0x08, 0xC3]);
        space.write(0x11F0, &[0x8A, 0x44, 0x24, 0x04, 0xC3]);
        space.write(0x1200, &[0x56, 0x8B, 0xF1, 0x8B, 0x46, 0xF0, 0xC3]);
        space.write(0x1210, &[0x56, 0x8B, 0xF1, 0x8B, 0x4C, 0x24, 0x08, 0xC3]);
        space.write(0x1220, &[0x80, 0x79, 0x38, 0x00, 0x74, 0x1B, 0xC3]);
        space.write(0x1230, &[0x53, 0x56, 0x8B, 0xD9, 0xC3]);
        space.write(0x1240, &[0x8B, 0xFF, 0x56, 0x8B, 0xF1, 0xC3]);
        space.write(0x1250, &[0x8B, 0xFF, 0x53, 0x56, 0x8B, 0xC1, 0xC3]);
        space.write(0x1260, &[0x8B, 0xFF, 0x56, 0x57, 0x8B, 0xC1, 0xC3]);
        space.write(0x12A0, &[0xC3]);
        space.write(0x12A1, &[0x8B, 0xFF, 0x56, 0x8B, 0xF1, 0xC3]);
        space.write(0x1270, &[0x8B, 0x01, 0xC3]);
        space.write(0x1280, &[0x8B, 0xC1, 0xC3]);
        space.write(0x1290, &[0x33, 0xC0, 0x40, 0xC3]);
        space.write(0x12B0, &[0x6A, 0x03, 0x58, 0xC3]);
        space.write(0x1300, &[0xC3]);
        space.write(0x1301, &[0x8B, 0xFF, 0x56, 0x57, 0x8B, 0xC1, 0xC3]);
        space.write(0x1310, &[0xC3]);
        space.write(0x1311, &[0x8B, 0x01, 0xC3]);
        space.write(0x1320, &[0xC3]);
        space.write(0x1321, &[0x6A, 0x03, 0x58, 0xC3]);
        space.write(0x1330, &[0xC3]);
        space.write(0x1331, &[0x8B, 0xFF, 0x53, 0x56, 0x8B, 0xC1, 0xC3]);
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
                && prologue_targets.contains(&0x1080)
                && prologue_targets.contains(&0x1090)
                && prologue_targets.contains(&0x10A0)
                && prologue_targets.contains(&0x10B0)
                && prologue_targets.contains(&0x10C0)
                && prologue_targets.contains(&0x10D0)
                && prologue_targets.contains(&0x10E4)
                && prologue_targets.contains(&0x10E8)
                && prologue_targets.contains(&0x10F0)
                && prologue_targets.contains(&0x1100)
                && prologue_targets.contains(&0x1110)
                && prologue_targets.contains(&0x1120)
                && prologue_targets.contains(&0x1130)
                && prologue_targets.contains(&0x1140)
                && prologue_targets.contains(&0x1150)
                && prologue_targets.contains(&0x1160)
                && prologue_targets.contains(&0x1170)
                && prologue_targets.contains(&0x1180)
                && prologue_targets.contains(&0x1191)
                && prologue_targets.contains(&0x11A1)
                && prologue_targets.contains(&0x11B1)
                && prologue_targets.contains(&0x11C1)
                && prologue_targets.contains(&0x11D1)
                && prologue_targets.contains(&0x11E0)
                && prologue_targets.contains(&0x11F0)
                && prologue_targets.contains(&0x1200)
                && prologue_targets.contains(&0x1210)
                && prologue_targets.contains(&0x1220)
                && prologue_targets.contains(&0x1230)
                && prologue_targets.contains(&0x1240)
                && prologue_targets.contains(&0x1250)
                && prologue_targets.contains(&0x1260)
                && prologue_targets.contains(&0x1270)
                && prologue_targets.contains(&0x1280)
                && prologue_targets.contains(&0x1290)
                && prologue_targets.contains(&0x12A1)
                && prologue_targets.contains(&0x12B0)
                && prologue_targets.contains(&0x1301)
                && prologue_targets.contains(&0x1311)
                && prologue_targets.contains(&0x1321)
                && prologue_targets.contains(&0x1331),
            "prologue targets not discovered: {functions:?}"
        );
    }

    #[test]
    fn cfg_size_includes_conditional_branch_block() {
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
            segments: vec![segment(0x1000, 0x1000, true)],
        };
        space.write(0x1000, &[0x74, 0x1E]);
        space.write(0x1002, &[0xC3]);
        space.write(0x1020, &[0xC3]);
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
        let entry = functions
            .iter()
            .find(|function| function.rva == 0x1000)
            .expect("entry function");
        assert_eq!(entry.size, 0x21);
        assert!(entry.size_inferred);
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
        space.write(0x1030, &[0x90, 0x90, 0x8B, 0x44, 0x24, 0x04, 0xC3]);
        space.write(0x1050, &[0x6A, 0x18, 0x8B, 0x45, 0x08, 0xC3]);
        space.write(0x2000, &0x40_1010u32.to_le_bytes());
        space.write(0x2004, &0x40_1030u32.to_le_bytes());
        space.write(0x2008, &0x40_1050u32.to_le_bytes());
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
                .any(|function| matches!(function.rva, 0x1010 | 0x1030 | 0x1050)
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
    fn adjustor_thunks_alignment_stubs_and_short_jump_frames_are_discovered() {
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
        // 16 对齐、int3 填充的虚基类调整器 thunk：sub ecx,[ecx-4]; jmp 0x1100
        space.write(0x101E, &[0xCC, 0xCC]);
        space.write(0x1020, &[0x2B, 0x49, 0xFC, 0xE9]);
        space.write(0x1024, &(0x1100i32 - 0x1028i32).to_le_bytes());
        // 紧随其后的非 4 对齐 thunk：前一条是上一个 thunk 的 jmp rel32
        space.write(0x1028, &[0x83, 0xC1, 0x04, 0xE9]);
        space.write(0x102C, &(0x1110i32 - 0x1030i32).to_le_bytes());
        // sub ecx, imm32; jmp 0x1120（同样紧跟上一个 thunk）
        space.write(0x1030, &[0x81, 0xE9, 0x10, 0x00, 0x00, 0x00, 0xE9]);
        space.write(0x1037, &(0x1120i32 - 0x103Bi32).to_le_bytes());
        space.write(0x103B, &[0xCC]);
        // 16 对齐、前置填充的跳转 stub：jmp 0x1080，其后 11 字节 int3
        space.write(0x106E, &[0xCC, 0xCC]);
        space.write(0x1070, &[0xE9, 0x0B, 0x00, 0x00, 0x00]);
        space.write(0x1075, &[0xCC; 11]);
        space.write(0x1080, &[0x56, 0x8B, 0xF1, 0xC3]);
        // 上一条是 jmp rel8 尾调用的帧序言
        space.write(0x1150, &[0xEB, 0x0E]);
        space.write(0x1152, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x1160, &[0xC3]);
        // thunk / stub 的目标函数体
        space.write(0x1100, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x1110, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x1120, &[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]);
        // 反例：目标不在执行节内的 thunk；无边界的调整器 thunk；非 16 对齐的 stub
        space.write(0x11A0, &[0xCC]);
        space.write(0x11A1, &[0x2B, 0x49, 0xFC, 0xE9, 0x00, 0x00, 0x10, 0x00]);
        // `mov ecx,[ebp-0x70]` 以 0x90 结尾不是边界：这是函数内的 adjustor 尾调用
        space.write(0x11A8, &[0x8B, 0x4D, 0x90]);
        space.write(0x11AB, &[0x83, 0xC1, 0x08, 0xE9]);
        space.write(0x11AF, &(0x1100i32 - 0x11B3i32).to_le_bytes());
        // ret 之后、后面接普通代码的尾调用同样不是 thunk
        space.write(0x11C0, &[0xC3]);
        space.write(0x11C1, &[0x83, 0xC1, 0x04, 0xE9]);
        space.write(0x11C5, &(0x1100i32 - 0x11CAi32).to_le_bytes());
        space.write(0x11C9, &[0x8B, 0x45, 0xF0]);
        space.write(0x11B0, &[0x8B, 0xC1]);
        space.write(0x11B2, &[0x83, 0xE9, 0x04, 0xE9]);
        space.write(0x11B6, &(0x1100i32 - 0x11BAi32).to_le_bytes());
        space.write(0x11D1, &[0xCC, 0xCC]);
        space.write(0x11D3, &[0xE9, 0x0B, 0x00, 0x00, 0x00]);
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
        let has = |rva: u64, evidence: Evidence| {
            functions
                .iter()
                .any(|function| function.rva == rva && function.evidence.contains(&evidence))
        };
        for rva in [0x1020u64, 0x1028, 0x1030, 0x1070, 0x1152] {
            assert!(
                has(rva, Evidence::PrologueTarget),
                "thunk/stub/frame at {rva:#x} not discovered: {functions:?}"
            );
        }
        for rva in [0x1080u64, 0x1100, 0x1110, 0x1120] {
            assert!(
                has(rva, Evidence::CallTarget),
                "thunk target {rva:#x} not discovered: {functions:?}"
            );
        }
        for rva in [0x11A1u64, 0x11AB, 0x11B2, 0x11C1, 0x11D3] {
            assert!(
                !functions.iter().any(|function| function.rva == rva),
                "invalid thunk at {rva:#x} was accepted: {functions:?}"
            );
        }
    }

    #[test]
    fn vtable_pointing_at_adjustor_thunk_is_accepted() {
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
        space.write(0x100E, &[0xCC, 0xCC]);
        space.write(0x1010, &[0x2B, 0x49, 0xFC, 0xE9]);
        space.write(0x1014, &(0x1100i32 - 0x1018i32).to_le_bytes());
        space.write(0x1100, &[0x55, 0x8B, 0xEC, 0xC3]);
        // vtable 指向一个 `sub ecx,[ecx+8]` 开头、后接 ret 的普通函数：仍是噪声形状
        space.write(0x1020, &[0x2B, 0x49, 0x08, 0xC3]);
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
                name: ".rdata".into(),
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
            "vtable adjustor thunk was rejected: {functions:?}"
        );
        assert!(
            !functions.iter().any(|function| function.rva == 0x1020
                && function.evidence.contains(&Evidence::PointerTarget)),
            "sub ecx,[ecx+8] noise was accepted: {functions:?}"
        );
    }

    #[test]
    fn vtable_pointing_at_padded_frame_relative_start_is_accepted() {
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
        // 16 对齐、int3 填充、以 lea ecx,[ebp-0x2c] 开头（EBP 作通用寄存器）的函数
        space.write(0x100E, &[0xCC, 0xCC]);
        space.write(
            0x1010,
            &[0x8D, 0x4D, 0xD4, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3],
        );
        // 同样开头但没有对齐填充：仍是函数中段的栈访问
        space.write(0x1020, &[0x8B, 0x8B]);
        space.write(0x1022, &[0x8B, 0x45, 0x08, 0xC3]);
        // int3 填充 + push [ebp+8]; call; ret：同样是 EBP 作通用寄存器的小函数
        space.write(0x102E, &[0xCC, 0xCC]);
        // ret 后只跟一个 int3：同样是填充
        space.write(0x11FE, &[0xC3, 0xCC]);
        space.write(0x1200, &[0x8B, 0x44, 0x24, 0x04, 0xC3]);
        // 零字节「填充」（其实是前一条指令的 imm32 高位）不算证据
        space.write(0x1040, &[0xC7, 0x45, 0xFC, 0x08, 0x00, 0x00, 0x00]);
        space.write(0x1047, &[0xFF, 0x75, 0xDC, 0xC3]);
        space.write(0x1028, &[0xC3]);
        space.write(
            0x1030,
            &[0xFF, 0x75, 0x08, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3],
        );
        space.write(0x2000, &0x40_1010u32.to_le_bytes());
        space.write(0x2004, &0x40_1022u32.to_le_bytes());
        space.write(0x2008, &0x40_1030u32.to_le_bytes());
        space.write(0x200C, &0x40_1047u32.to_le_bytes());
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
                name: ".rdata".into(),
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
            "padded frame-relative start was rejected: {functions:?}"
        );
        assert!(
            functions.iter().any(|function| function.rva == 0x1030
                && function.evidence.contains(&Evidence::PointerTarget)),
            "padded push-[ebp+8] start was rejected: {functions:?}"
        );
        for rva in [0x1022u64, 0x1047] {
            assert!(
                !functions.iter().any(|function| function.rva == rva
                    && function.evidence.contains(&Evidence::PointerTarget)),
                "frame-relative access without int3/nop padding was accepted: {functions:?}"
            );
        }
    }

    /// 活体场景：加载器把头里的 ImageBase 改成实际基址（0x600000），而 .eh_frame / DWARF
    /// 里的函数地址仍按链接期基址（0x400000）书写、不会被重定位。
    #[test]
    fn unrelocated_references_fall_back_to_the_link_time_base() {
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
            base: 0,
            bytes: vec![0u8; 0x3000],
            segments: vec![
                segment(0, 0x1000, false),
                segment(0x1000, 0x1000, true),
                segment(0x2000, 0x1000, false),
            ],
        };
        // 最小 PE32 头：MZ、e_lfanew=0x80、PE\0\0、可选头魔数 0x10B、ImageBase=0x400000。
        space.write(0, b"MZ");
        space.write(0x3C, &0x80u32.to_le_bytes());
        space.write(0x80, b"PE\0\0");
        space.write(0x84, &0x014cu16.to_le_bytes());
        space.write(0x98, &0x10Bu16.to_le_bytes());
        space.write(0x98 + 28, &0x40_0000u32.to_le_bytes());
        // 实际基址 0x600000 的重定位指针 + 链接期基址 0x400000 的未重定位引用。
        space.write(0x2000, &0x60_1030u32.to_le_bytes());
        space.write(0x2004, &0x40_1050u32.to_le_bytes());
        space.write(0x1030, &[0x55, 0x8B, 0xEC, 0xC3]);
        space.write(0x1050, &[0x55, 0x8B, 0xEC, 0xC3]);
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
                name: ".rdata".into(),
                executable: false,
            },
        ];
        let view = ScanView {
            container: Container::Pe32,
            arch: Arch::X86,
            image_base: 0x600_000,
            entry_rva: None,
            sections: &sections,
            symbols: &[],
            dynamic_symbols: &[],
            debug_functions: &[],
        };
        let functions = discover_with(view, &space);
        for rva in [0x1030u64, 0x1050] {
            assert!(
                functions.iter().any(|function| function.rva == rva
                    && function.evidence.contains(&Evidence::PointerTarget)),
                "pointer target {rva:#x} not discovered: {functions:?}"
            );
        }
    }

    /// 指针对齐 + `int3` 填充 + 可顺序解码到终结符：无引用 leaf 函数的通用形态。
    #[test]
    fn padded_code_starts_are_discovered_but_tables_and_fake_padding_are_not() {
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
            bytes: vec![0u8; 0x1800],
            segments: vec![segment(0x1000, 0x1800, true)],
        };
        space.write(0x1000, &[0xC3]);
        // 无引用的 leaf：xor eax,eax; ret
        space.write(0x100E, &[0xCC, 0xCC]);
        space.write(0x1010, &[0x33, 0xC0, 0xC3]);
        // 调整 thunk：sub ecx,[ecx-4]; sub ecx,0x38; jmp 0x1100
        space.write(0x102E, &[0xCC, 0xCC]);
        space.write(0x1030, &[0x2B, 0x49, 0xFC, 0x83, 0xE9, 0x38, 0xE9]);
        space.write(0x1037, &(0x1100i32 - 0x103Ci32).to_le_bytes());
        // 16 对齐、int3 填充的跳转表：解码会撞上填充 int3，不是代码
        space.write(0x104E, &[0xCC, 0xCC]);
        space.write(
            0x1050,
            &[
                0x10, 0x10, 0x40, 0x00, 0x20, 0x10, 0x40, 0x00, 0xCC, 0xCC, 0xCC, 0xCC,
            ],
        );
        // 90 90 不是填充：它们是 mov edx,[eax+1] 的 ModRM/disp
        space.write(0x1068, &[0x8B, 0x90, 0x01, 0x00, 0x00]);
        space.write(0x1070, &[0x33, 0xC0, 0xC3]);
        // 窗口内到不了终结符
        space.write(0x108E, &[0xCC, 0xCC]);
        space.write(0x1090, &[0x40; 300]);
        // 超过 256 字节才到达 ret 的大函数：窗口足够宽
        space.write(0x152E, &[0xCC, 0xCC]);
        space.write(0x1530, &[0x40; 300]);
        space.write(0x165C, &[0xC3]);
        // fastfail：mov ecx,2; int 29h，后面是填充——两字节 int 本身就是终结符
        space.write(0x172E, &[0xCC, 0xCC]);
        space.write(0x1730, &[0xB9, 0x02, 0x00, 0x00, 0x00, 0xCD, 0x29]);
        space.write(0x1737, &[0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
        // 函数体内的 fastfail：cmp; ja; int3; ret（int3 后面不是填充）
        space.write(0x11EE, &[0xCC, 0xCC]);
        space.write(0x11F0, &[0x48, 0x39, 0xC8, 0x77, 0x02, 0xCC, 0xC3]);
        // ret 后只跟一个 int3：同样是填充
        space.write(0x11FE, &[0xC3, 0xCC]);
        space.write(0x1200, &[0x8B, 0x44, 0x24, 0x04, 0xC3]);
        // 非 16 对齐
        space.write(0x11C0, &[0xCC, 0xCC]);
        space.write(0x11C2, &[0x33, 0xC0, 0xC3]);
        // 帧序言作为对照
        space.write(0x11DE, &[0xCC, 0xCC]);
        space.write(0x11E0, &[0x55, 0x8B, 0xEC, 0xC3]);
        let sections = vec![SectionInfo {
            rva: 0x1000,
            size: 0x1800,
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
        let has = |rva: u64| {
            functions.iter().any(|function| {
                function.rva == rva && function.evidence.contains(&Evidence::PrologueTarget)
            })
        };
        for rva in [0x1010u64, 0x1030, 0x11E0, 0x11F0, 0x1200, 0x1530, 0x1730] {
            assert!(
                has(rva),
                "padded code start {rva:#x} not discovered: {functions:?}"
            );
        }
        for rva in [0x1050u64, 0x1070, 0x1090, 0x11C2] {
            assert!(
                !functions.iter().any(|function| function.rva == rva),
                "non-code or fake padding at {rva:#x} was accepted: {functions:?}"
            );
        }
    }

    /// 被别的函数直接 call 的候选，即使前一函数无终结符地 fall-through 到它，也是独立函数；
    /// 只被本函数内部 call 的共享尾块仍被吸收。
    #[test]
    fn externally_called_fallthrough_candidates_are_split() {
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
            bytes: vec![0xCC; 0x1000],
            segments: vec![segment(0x1000, 0x1000, true)],
        };
        // A：push ecx; push edx; 无终结符直接落到 B
        space.write(0x1000, &[0x51, 0x52]);
        // B：xor eax,eax; pop edx; pop ecx; ret（被 C 外部 call）
        space.write(0x1002, &[0x33, 0xC0, 0x5A, 0x59, 0xC3]);
        // C：call B; ret
        space.write(0x1010, &[0xE8]);
        space.write(0x1011, &((0x1002i32 - 0x1015i32).to_le_bytes()));
        space.write(0x1015, &[0xC3]);
        // D：call 内部尾块 E; push; pop —— 无终结符直接落到 E，E 只被 D 自己调用
        space.write(0x1020, &[0xE8]);
        space.write(0x1021, &((0x1027i32 - 0x1025i32).to_le_bytes()));
        space.write(0x1025, &[0x50, 0x58]);
        space.write(0x1027, &[0x33, 0xC0, 0x40, 0xC3]);
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
        let by_rva = |rva: u64| functions.iter().find(|function| function.rva == rva);
        let a = by_rva(0x1000).expect("A");
        assert_eq!(
            a.size, 2,
            "A must stop where the externally called B begins"
        );
        assert!(
            by_rva(0x1002)
                .is_some_and(|function| function.evidence.contains(&Evidence::CallTarget)),
            "externally called B must be its own function: {functions:?}"
        );
        let d = by_rva(0x1020).expect("D");
        assert!(
            d.size == 0xB,
            "internally called tail E stays absorbed into D (size {:x})",
            d.size
        );
        assert!(
            by_rva(0x1027).is_none(),
            "shared tail E must not be a function"
        );
    }

    /// 导入跳转 stub：jmp [IAT 槽]，槽位在数据节；槽位落在代码里的同名形态不算。
    #[test]
    fn import_jump_stubs_are_discovered() {
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
        // ret 之后：两个连排的导入 stub（x86 绝对 VA 指向 .data 里的 IAT 槽）
        space.write(0x100F, &[0xC3]);
        space.write(0x1010, &[0xFF, 0x25]);
        space.write(0x1012, &0x40_2000u32.to_le_bytes());
        space.write(0x1016, &[0xFF, 0x25]);
        space.write(0x1018, &0x40_2004u32.to_le_bytes());
        // 导入 stub 之后直接是下一个函数（没有填充）；再后面是 noreturn 调用 + 填充的小函数
        // （函数 4 字节对齐，stub 落在 2 mod 4）
        space.write(0x1042, &[0xFF, 0x25]);
        space.write(0x1044, &0x40_2008u32.to_le_bytes());
        space.write(0x1048, &[0xB0, 0x01, 0xC3]);
        space.write(0x104E, &[0xCC, 0xCC]);
        space.write(0x1050, &[0x6A, 0x01, 0xFF, 0x15]);
        space.write(0x1054, &0x40_200Cu32.to_le_bytes());
        space.write(0x1058, &[0xCC, 0xCC, 0xCC, 0xCC]);
        // 槽位落在代码里：不是导入 stub
        space.write(0x102F, &[0xC3]);
        space.write(0x1030, &[0xFF, 0x25]);
        space.write(0x1032, &0x40_1010u32.to_le_bytes());
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
                name: ".idata".into(),
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
        for (rva, size) in [(0x1010u64, 6u64), (0x1016, 6), (0x1048, 3), (0x1050, 9)] {
            assert!(
                functions
                    .iter()
                    .any(|function| function.rva == rva && function.size == size),
                "import stub {rva:#x} not discovered: {functions:?}"
            );
        }
        assert!(
            !functions.iter().any(|function| function.rva == 0x1030),
            "jmp into code is not an import stub: {functions:?}"
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
