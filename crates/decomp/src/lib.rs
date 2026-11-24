//! P0 基本块级反编译：把一个函数发射成「CFG 骨架 + 地址锚注释」的伪 C。
//!
//! 形态（设计案 §4.4 的能力档位③起步，档位①②随 IR / 类型推断在 P1 落地）：
//!
//! ```text
//! /* kotama://<模块指纹>/<rva> name=main evidence=[sym] */
//! void main(void)
//! {
//! L_1040:
//!     /* 1040: push rbp */ ;
//!     /* 1046: jne 0x1060 */ goto L_1060;
//! L_1050:
//!     /* 1050: ret */ return;
//! }
//! ```
//!
//! 契约：每条指令带 `ip` 注释（GUI 高亮与智能体引用的锚）；块按地址排序；
//! `goto` 只对**函数内**直接转移发射；间接跳转先经 [`jump_table`] 恢复成多路后继，
//! 恢复出来就为每个目标建块并标注置信度，恢复不出来就诚实留注释。
//! 确定性：同一输入两次发射逐字节相同。
//!
//! 已知边界：函数体上界依赖 `FunctionEntry` 的边界质量——精确边界（symtab / `.pdata`）
//! 时完全可靠；推断边界时调用方应传 `body_limit`（[`decompile_function_bounded`]），
//! 否则分支目标可能被判成「函数外」。PE 的精确边界要等 PDB 接入。

pub mod jump_table;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::FlowControl;
use iced_x86::Formatter as _;
use iced_x86::Instruction;
use iced_x86::Mnemonic;
use iced_x86::NasmFormatter;
use kotama::AddressSpace;
use kotama::FuncKey;
use kotama::FunctionEntry;
use kotama::ModuleId;
use kotama_image::Arch;
use kotama_image::ExceptionFunction;

/// 单个函数的发射结果。
pub struct FunctionText {
    /// 函数身份的 URI 形式（`kotama://<模块指纹>/<rva>`）。
    pub uri: String,
    /// 伪 C 文本。
    pub text: String,
}

/// 发射一个函数的基本块级伪 C。
///
/// `size` 由 [`FunctionEntry::size`] 给出；越界 / 不可读 / 非法指令会诚实截断
/// 并在文本里注明，不假装成功。
#[must_use]
pub fn decompile_function(
    space: &dyn AddressSpace,
    module_id: ModuleId,
    arch: Arch,
    function: &FunctionEntry,
) -> FunctionText {
    decompile_function_bounded(space, module_id, arch, function, None)
}

/// 带函数体上界的发射。
///
/// `body_limit` = 函数体的绝对上界（不含），通常是「下一个已知函数的起点」或所在节尾。
/// 只在 `function.size_inferred` 为真时生效：推断出的长度常常偏小（相邻条目可能是
/// 被误认成函数的数据），按它切会把函数自己的分支判成「函数外」，CFG 直接断掉。
/// 有精确边界（symtab / `.pdata`）时一律尊重精确边界。
#[must_use]
pub fn decompile_function_bounded(
    space: &dyn AddressSpace,
    module_id: ModuleId,
    arch: Arch,
    function: &FunctionEntry,
    body_limit: Option<u64>,
) -> FunctionText {
    decompile_impl(space, module_id, arch, function, body_limit, &[])
}

/// 带 PE64 SEH sidecar 的函数发射。
///
/// `exceptions` 通常来自 `kotama_scan::exception_functions`；只取 BeginAddress 与当前
/// 函数入口相同的记录，不改变既有调用方，也不把 handler 假装成普通直接分支。
#[must_use]
pub fn decompile_function_bounded_with_exceptions(
    space: &dyn AddressSpace,
    module_id: ModuleId,
    arch: Arch,
    function: &FunctionEntry,
    body_limit: Option<u64>,
    exceptions: &[ExceptionFunction],
) -> FunctionText {
    decompile_impl(space, module_id, arch, function, body_limit, exceptions)
}

fn decompile_impl(
    space: &dyn AddressSpace,
    module_id: ModuleId,
    arch: Arch,
    function: &FunctionEntry,
    body_limit: Option<u64>,
    exceptions: &[ExceptionFunction],
) -> FunctionText {
    let exception = exceptions
        .iter()
        .find(|exception| u64::from(exception.runtime.begin_rva) == function.rva);
    let key = FuncKey::new(module_id, function.rva);
    let uri = key.to_string();
    let fallback_name = format!("sub_{:x}", function.rva);
    let name = function.name.as_deref().unwrap_or(&fallback_name);
    let mut out = String::with_capacity(1024);

    let bytes = match read_body(space, function, body_limit) {
        Some(bytes) => bytes,
        None => {
            let _ = writeln!(
                out,
                "/* kotama://{module_id}/{:x} name={name} */",
                function.rva
            );
            let _ = writeln!(out, "void {name}(void)");
            let _ = writeln!(out, "{{");
            write_seh(&mut out, exception);
            let _ = writeln!(
                out,
                "    /* ERROR: unreadable body at {:x} */",
                function.rva
            );
            let _ = writeln!(out, "}}");
            return FunctionText { uri, text: out };
        }
    };

    // 解码并停在第一条非法指令（诚实截断）。
    let mut decoder = Decoder::with_ip(arch.bitness(), bytes, function.rva, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    let mut truncated = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            truncated = true;
            break;
        }
        instructions.push(instruction);
    }

    let end_rva = function.rva + u64::try_from(bytes.len()).unwrap_or(0);
    let body_hint = if truncated {
        "  /* truncated at invalid instruction */"
    } else {
        ""
    };
    let evidence: Vec<&str> = function.evidence.iter().map(|e| e.short()).collect();
    let _ = writeln!(
        out,
        "/* kotama://{module_id}/{:x} name={name} evidence=[{}] */",
        function.rva,
        evidence.join(",")
    );
    let _ = writeln!(out, "void {name}(void){body_hint}");
    let _ = writeln!(out, "{{");
    write_seh(&mut out, exception);

    // 间接跳转先恢复成跳转表：稠密 switch 的后继全靠它，不恢复 CFG 就断在这里。
    let tables = jump_table::recover(space, &instructions, function.rva, end_rva);
    let table_at = |ip: u64| tables.iter().find(|table| table.at == ip);

    // 领头集合：函数入口 + 转移目标 + 跳转表目标 + 终结者的 fallthrough。
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(function.rva);
    for instruction in &instructions {
        let next = instruction.next_ip();
        match instruction.flow_control() {
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::Call => {
                if let Some(target) = direct_target(instruction) {
                    if target >= function.rva && target < end_rva {
                        leaders.insert(target);
                    }
                }
                if next < end_rva {
                    leaders.insert(next);
                }
            }
            FlowControl::IndirectBranch => {
                if let Some(table) = table_at(instruction.ip()) {
                    leaders.extend(table.targets.iter().copied());
                }
            }
            FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception
                if next < end_rva =>
            {
                leaders.insert(next);
            }
            _ => {}
        }
    }

    let mut formatter = NasmFormatter::new();
    let mut asm = String::new();
    let mut current: Option<u64> = None;
    for instruction in &instructions {
        let ip = instruction.ip();
        if leaders.contains(&ip) {
            if current.is_some() {
                out.push('\n');
            }
            let _ = writeln!(out, "L_{ip:x}:");
            current = Some(ip);
        }
        asm.clear();
        formatter.format(instruction, &mut asm);
        let _ = writeln!(out, "    /* {ip:x}: {asm} */ ;");
        // 块终结语句。
        match instruction.flow_control() {
            FlowControl::Return => {
                let _ = writeln!(out, "    return;");
            }
            FlowControl::ConditionalBranch => {
                if let Some(target) = direct_target(instruction) {
                    if target >= function.rva && target < end_rva {
                        let _ = writeln!(out, "    goto L_{target:x};");
                    } else {
                        let _ = writeln!(out, "    /* branch outside function -> {target:x} */");
                    }
                }
            }
            FlowControl::UnconditionalBranch => {
                if let Some(target) = direct_target(instruction) {
                    if target >= function.rva && target < end_rva {
                        let _ = writeln!(out, "    goto L_{target:x};");
                    } else {
                        let _ = writeln!(out, "    /* tail jump -> {target:x} */");
                    }
                } else {
                    let _ = writeln!(out, "    /* indirect jump */");
                }
            }
            FlowControl::IndirectBranch => {
                if let Some(table) = table_at(ip) {
                    // 多路后继：C 里一行 goto 表达不了，逐行列出并标注置信度。
                    let _ = writeln!(
                        out,
                        "    /* switch via jump table {:x} (confidence {}%, {} targets) */",
                        table.base,
                        table.confidence,
                        table.targets.len()
                    );
                    for target in &table.targets {
                        let _ = writeln!(out, "    goto L_{target:x}; /* switch arm */");
                    }
                } else {
                    let _ = writeln!(out, "    /* indirect jump: table not recovered */");
                }
            }
            _ => {}
        }
    }
    // 稀疏尾：块没终结就到头了。
    if instructions.last().is_some_and(|last| {
        !matches!(
            last.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::Interrupt
                | FlowControl::Exception
        )
    }) {
        let _ = writeln!(out, "    /* falls through end of discovered body */");
    }
    let _ = writeln!(out, "}}");
    FunctionText { uri, text: out }
}

/// 发射确定性的 SEH sidecar；handler 仍是 RVA，不伪造函数内 goto。
fn write_seh(out: &mut String, exception: Option<&ExceptionFunction>) {
    let Some(exception) = exception else { return };
    let runtime = exception.runtime;
    let _ = writeln!(
        out,
        "    /* seh: runtime=[0x{:x},0x{:x}) unwind=0x{:x} */",
        runtime.begin_rva, runtime.end_rva, runtime.unwind_info_rva
    );
    if let Some(unwind) = exception.unwind {
        let _ = writeln!(
            out,
            "    /* seh: unwind version={} flags=0x{:02x} prolog={} codes={} frame={}:{} */",
            unwind.version,
            unwind.flags,
            unwind.prolog_size,
            unwind.unwind_code_count,
            unwind.frame_register,
            unwind.frame_offset
        );
        if let Some(handler) = unwind.handler_rva {
            let _ = writeln!(out, "    /* seh: handler=0x{handler:x} (external RVA) */");
        }
        if let Some(chained) = unwind.chained {
            let _ = writeln!(
                out,
                "    /* seh: chained runtime=[0x{:x},0x{:x}) unwind=0x{:x} */",
                chained.begin_rva, chained.end_rva, chained.unwind_info_rva
            );
        }
    } else if runtime.unwind_info_rva != 0 {
        let _ = writeln!(out, "    /* seh: unwind metadata unavailable */");
    }
}

/// 读取函数体：优先整段；跨节时截到所在节尾，且永不越过声明/推断上界。
fn read_body<'a>(
    space: &'a dyn AddressSpace,
    function: &FunctionEntry,
    body_limit: Option<u64>,
) -> Option<&'a [u8]> {
    // 精确边界优先；推断边界才看调用方给的上界。
    let size = match (function.size_inferred, body_limit) {
        (true, Some(limit)) if limit > function.rva => limit - function.rva,
        _ => function.size,
    };
    let whole = usize::try_from(size).unwrap_or(usize::MAX);
    if let Some(bytes) = space.read(function.rva, whole) {
        return Some(bytes);
    }
    let limit = space
        .segment_at(function.rva)?
        .end()
        .saturating_sub(function.rva);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    if whole <= limit {
        return None;
    }
    // 精确边界和 body_limit 都是硬上界；段更长也绝不能多读。
    space.read(function.rva, whole.min(limit))
}

/// 直接 rel 转移目标；间接返回 `None`。
fn direct_target(instruction: &Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

/// 便捷断言用：mnemonic 是否为 call（测试里核对 goto/return 计数）。
#[allow(dead_code)]
fn is_call(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Call
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
    fn emits_blocks_gotos_and_returns_with_anchors() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/switch") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = kotama_scan::discover(&module);
        // 注意：`dense`/`sparse` 是 static，-O2 下会被内联进 main——所以锚定 main，
        // 跳转表结构会以内联形态出现在 main 的 CFG 里。
        let dense = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        let space = module.address_space();
        let id = module.module_id();
        let text = decompile_function(&space, id, module.arch, dense).text;
        // 稠密 switch 应该有多个基本块标签与跳转。
        assert!(text.contains("L_"));
        assert!(text.contains("goto L_"));
        assert!(text.contains("return;"));
        // 地址锚：注释里至少出现函数首地址。
        assert!(text.contains(&format!("{:x}:", dense.rva)));
    }

    #[test]
    fn emits_switch_arms_for_a_recovered_jump_table() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/switch") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = kotama_scan::discover(&module);
        let main = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        let space = module.address_space();
        let text = decompile_function(&space, module.module_id(), module.arch, main).text;
        // 稠密 switch 的 10 个分支必须都出现在伪 C 里。
        assert!(
            text.contains("switch via jump table"),
            "expected a recovered jump table in:\n{text}"
        );
        let arms = text.matches("switch arm").count();
        assert_eq!(arms, 10, "fixture has 10 cases, got {arms} arms");
        // 每个 arm 目标都得有对应标签，否则 CFG 是断的。
        for line in text.lines().filter(|l| l.contains("switch arm")) {
            let label = line
                .split("goto L_")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
                .expect("arm line carries a label");
            assert!(
                text.contains(&format!("L_{label}:")),
                "arm target L_{label} has no block"
            );
        }
    }

    struct StaticSpace {
        segment: kotama::Segment,
        bytes: Vec<u8>,
    }

    impl AddressSpace for StaticSpace {
        fn segments(&self) -> &[kotama::Segment] {
            std::slice::from_ref(&self.segment)
        }

        fn read(&self, rva: u64, len: usize) -> Option<&[u8]> {
            if !self.segment.contains(rva, len) {
                return None;
            }
            let offset = usize::try_from(rva.checked_sub(self.segment.rva)?).ok()?;
            self.bytes.get(offset..offset.checked_add(len)?)
        }
    }

    #[test]
    fn seh_sidecar_emits_runtime_unwind_handler_and_chain() {
        use kotama_image::{RuntimeFunction, UnwindInfo};

        let space = StaticSpace {
            segment: kotama::Segment {
                rva: 0x1000,
                size: 1,
                perms: kotama::Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            bytes: vec![0xc3],
        };
        let function = FunctionEntry {
            rva: 0x1000,
            size: 1,
            size_inferred: false,
            name: Some("seh_main".into()),
            evidence: std::collections::BTreeSet::from([kotama::Evidence::Pdata]),
        };
        let exception = ExceptionFunction {
            runtime: RuntimeFunction {
                begin_rva: 0x1000,
                end_rva: 0x1001,
                unwind_info_rva: 0x2000,
            },
            unwind: Some(UnwindInfo {
                version: 1,
                flags: 1,
                prolog_size: 4,
                unwind_code_count: 1,
                frame_register: 5,
                frame_offset: 1,
                handler_rva: Some(0x1040),
                chained: Some(RuntimeFunction {
                    begin_rva: 0x1040,
                    end_rva: 0x1060,
                    unwind_info_rva: 0,
                }),
            }),
        };
        let id = ModuleId::from_bytes([0; 32]);
        let exceptions = [exception];
        let first = decompile_function_bounded_with_exceptions(
            &space,
            id,
            Arch::X86_64,
            &function,
            None,
            &exceptions,
        )
        .text;
        assert!(first.contains("seh: runtime=[0x1000,0x1001) unwind=0x2000"));
        assert!(first.contains("prolog=4 codes=1 frame=5:1"));
        assert!(first.contains("handler=0x1040 (external RVA)"));
        assert!(first.contains("chained runtime=[0x1040,0x1060) unwind=0x0"));
        assert!(!first.contains("goto L_1040"));
        let second = decompile_function_bounded_with_exceptions(
            &space,
            id,
            Arch::X86_64,
            &function,
            None,
            &exceptions,
        )
        .text;
        assert_eq!(first, second);
    }

    #[test]
    fn exact_body_never_requests_beyond_declared_end() {
        struct SpySpace {
            segment: kotama::Segment,
            max_requested: std::cell::Cell<usize>,
        }
        impl AddressSpace for SpySpace {
            fn segments(&self) -> &[kotama::Segment] {
                std::slice::from_ref(&self.segment)
            }

            fn read(&self, _rva: u64, len: usize) -> Option<&[u8]> {
                self.max_requested.set(self.max_requested.get().max(len));
                None
            }
        }

        let space = SpySpace {
            segment: kotama::Segment {
                rva: 0x1000,
                size: 0x100,
                perms: kotama::Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            max_requested: std::cell::Cell::new(0),
        };
        let function = FunctionEntry {
            rva: 0x1000,
            size: 8,
            size_inferred: false,
            name: None,
            evidence: std::collections::BTreeSet::new(),
        };
        let text = decompile_function_bounded(
            &space,
            ModuleId::from_bytes([0; 32]),
            Arch::X86_64,
            &function,
            None,
        )
        .text;
        assert!(text.contains("unreadable body"));
        assert_eq!(space.max_requested.get(), 8);
    }

    #[test]
    fn real_pe64_seh_facts_reach_decompiler_sidecar() {
        let Some(path) = fixture("x86_64-windows-gnu/-O2/loops.exe") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = kotama_scan::discover(&module);
        let exceptions = kotama_scan::exception_functions(&module);
        let function = functions
            .iter()
            .find(|function| {
                exceptions.iter().any(|exception| {
                    u64::from(exception.runtime.begin_rva) == function.rva
                        && exception.unwind.is_some()
                })
            })
            .expect("a pdata function with xdata");
        let text = decompile_function_bounded_with_exceptions(
            &module.address_space(),
            module.module_id(),
            module.arch,
            function,
            None,
            &exceptions,
        )
        .text;
        assert!(text.contains("seh: runtime=["));
        assert!(text.contains("seh: unwind version="));
    }

    #[test]
    fn emission_is_deterministic() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/loops") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = kotama_scan::discover(&module);
        let target = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        let space = module.address_space();
        let id = module.module_id();
        let first = decompile_function(&space, id, module.arch, target).text;
        let second = decompile_function(&space, id, module.arch, target).text;
        assert_eq!(first, second);
    }
}
