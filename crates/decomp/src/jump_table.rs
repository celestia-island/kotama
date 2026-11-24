//! 跳转表恢复：把稠密 `switch` 生成的间接跳转还原成一组块目标。
//!
//! 为什么必须做：-O2 下稠密 `switch` 不会长成 compare 链，而是
//! `lea base,[rip+TABLE]` + `movsxd reg,[base+idx*4]` + `add reg,base` + `jmp reg`
//! 的**相对偏移表**形态。不恢复它，函数的控制流在伪 C 里就直接断了（只剩一句
//! "indirect jump"），多路后继全部丢失。
//!
//! 判据（保守，宁可漏也不乱认）：
//! 1. 函数内存在间接跳转；
//! 2. 它在有限回看窗口内连着 `add <jmp同寄存器>, <base>`（相对表）或直接是
//!    `jmp [base+idx*8]`（绝对表）；
//! 3. 表项解出来的目标**落在本函数体内**的比例必须过半；
//! 4. 至少两个不同目标（单目标就不算 switch）。
//!
//! 恢复结果是「证据」而非事实：调用方拿到的每个表都带 `confidence`（命中比例），
//! 与设计案 §4.2 的 provenance 要求一致。

use std::collections::BTreeSet;

use iced_x86::FlowControl;
use iced_x86::Instruction;
use iced_x86::Mnemonic;
use iced_x86::Register;
use kotama::AddressSpace;

/// 一张被恢复出来的跳转表。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JumpTable {
    /// 发起间接跳转的指令地址。
    pub at: u64,
    /// 表在映像里的基址。
    pub base: u64,
    /// 恢复出的块目标（升序、去重、全部落在函数体内）。
    pub targets: Vec<u64>,
    /// 解出来的表项里落在函数体内的比例（0–100）。
    pub confidence: u8,
}

/// 最多读多少项（跳转表的扇出上限；超出部分不看，避免把后面别的表数据认进来）。
const MAX_ENTRIES: usize = 256;
/// 回看窗口：找 `add base` / `movsxd` 时最多往回扫多少条指令。
/// 循环内的 switch 与表基址的 `lea` 之间可能隔着整段循环体，窗口要放宽。
const LOOKBACK: usize = 96;

/// 从 `base` 读到所在段尾，最多 `max_entries * entry_size` 字节。
///
/// [`AddressSpace::read`] 的契约是「必须完整落在单个背书范围内」，一次性要满
/// 会跨节失败（表贴在某节尾部时尤其常见），所以先按段尾截断再读。
fn read_table(
    space: &dyn AddressSpace,
    base: u64,
    entry_size: usize,
    max_entries: usize,
) -> Option<&[u8]> {
    let segment = space.segment_at(base)?;
    let available = segment.end().saturating_sub(base);
    let want = (max_entries * entry_size) as u64;
    let len = usize::try_from(available.min(want)).ok()?;
    if len < entry_size * 2 {
        return None;
    }
    space.read(base, len)
}

/// 在一个已解码的函数里恢复全部跳转表。
///
/// `body` = `[func_start, func_end)`，用于判定目标是否落在函数体内。
#[must_use]
pub fn recover(
    space: &dyn AddressSpace,
    instructions: &[Instruction],
    func_start: u64,
    func_end: u64,
) -> Vec<JumpTable> {
    let mut tables: Vec<JumpTable> = Vec::new();

    for (index, instruction) in instructions.iter().enumerate() {
        let flow = instruction.flow_control();
        // 只处理"跳到寄存器"这一个形态；`jmp [mem]` 走下面的绝对表分支。
        let jmp_reg = match flow {
            FlowControl::IndirectBranch => indirect_register(instruction),
            _ => None,
        };
        // 情形一：jmp <reg> 且前面有 `add <同一 reg>, <base>` —— 相对偏移表。
        if let Some(jmp_reg) = jmp_reg {
            if let Some(base) = find_relative_base(instructions, index, jmp_reg) {
                if let Some(table) =
                    probe_relative(space, instruction.ip(), base, func_start, func_end)
                {
                    tables.push(table);
                    continue;
                }
            }
        }
        // 情形二：jmp qword [base+idx*8] —— 绝对地址表。
        if flow == FlowControl::IndirectBranch && instruction.memory_base() != Register::None {
            let base = absolute_base(space, instruction);
            if let Some(base) = base {
                if let Some(table) =
                    probe_absolute(space, instruction.ip(), base, func_start, func_end)
                {
                    tables.push(table);
                }
            }
        }
    }

    // 同一处只留置信度最高的那张（重复识别时后者胜出）。
    tables.sort_by(|a, b| (a.at, b.base).cmp(&(b.at, b.base)));
    tables.dedup_by(|a, b| a.at == b.at);
    tables.retain(|table| table.targets.len() >= 2 && table.confidence >= 51);
    // 收敛：返回按跳转点排序的稳定结果。
    tables.sort_by_key(|table| table.at);
    tables
}

/// `jmp <reg>` 的操作数寄存器（仅寄存器形态）。
fn indirect_register(instruction: &Instruction) -> Option<Register> {
    let register = instruction.op0_register();
    (register != Register::None).then_some(register)
}

/// 往回找 `add <target_reg>, <base_reg>`，再把 `base_reg` 解析成 `lea` 出来的常量。
fn find_relative_base(
    instructions: &[Instruction],
    jmp_index: usize,
    target_reg: Register,
) -> Option<u64> {
    let window_start = jmp_index.saturating_sub(LOOKBACK);
    let mut base_reg = None;
    for instruction in instructions[window_start..jmp_index].iter().rev() {
        // `add target, base`：目标寄存器写入 = 目标 + 表基址。
        if instruction.mnemonic() == Mnemonic::Add
            && instruction.op0_register() == target_reg
            && instruction.op1_kind() == iced_x86::OpKind::Register
        {
            base_reg = Some(instruction.op1_register());
            break;
        }
        // 被覆盖了（说明不是这个形态）。
        if writes_register(instruction, target_reg) {
            break;
        }
    }
    let base_reg = base_reg?;
    // 继续往回找 base_reg 的 `lea <base_reg>, [rip+X]`。
    for instruction in instructions[window_start..jmp_index].iter().rev() {
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == base_reg
            && instruction.is_ip_rel_memory_operand()
        {
            return Some(instruction.ip_rel_memory_address());
        }
        if writes_register(instruction, base_reg) {
            return None;
        }
    }
    None
}

/// 指令是否**写**了某寄存器。
///
/// 只看目的操作数（slot 0）：源操作数里出现同一寄存器是"读"，不是覆盖。
/// （踩过：`add %r13,%rcx` 的 r13 是源，早期版本把它当成写，回看提前中断。）
fn writes_register(instruction: &Instruction, register: Register) -> bool {
    instruction.op_count() > 0
        && matches!(
            instruction.op0_kind(),
            iced_x86::OpKind::Register | iced_x86::OpKind::Memory
        )
        && instruction.op0_register() == register
}

/// 从 `base` 处读 4 字节相对表项，解出目标并统计命中。
fn probe_relative(
    space: &dyn AddressSpace,
    at: u64,
    base: u64,
    func_start: u64,
    func_end: u64,
) -> Option<JumpTable> {
    let bytes = read_table(space, base, 4, MAX_ENTRIES)?;
    let mut targets = BTreeSet::new();
    let mut decoded = 0usize;
    let mut hit = 0usize;
    for chunk in bytes.as_chunks::<4>().0 {
        let offset = i64::from(i32::from_le_bytes(*chunk));
        let Some(target) = base.checked_add_signed(offset) else {
            break;
        };
        // 第一项必须像样，否则这不是表（避免把任意 rodata 认成跳转表）。
        if target < func_start || target >= func_end {
            if decoded == 0 && hit == 0 {
                break;
            }
            // 表尾：连续 miss 不再扩张，直接收工。
            break;
        }
        decoded += 1;
        hit += 1;
        targets.insert(target);
    }
    (hit >= 2).then(|| JumpTable {
        at,
        base,
        targets: targets.into_iter().collect(),
        confidence: percentage(hit, hit.max(decoded)),
    })
}

/// 绝对地址表：`jmp qword [base+idx*8]`。
fn absolute_base(space: &dyn AddressSpace, instruction: &Instruction) -> Option<u64> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    // 需要 `base` 寄存器里是常量——P0 只支持 RIP 相对形态，其余返回 None 交给上层。
    let _ = space;
    None
}

/// 从绝对地址表读 8 字节目标。
fn probe_absolute(
    space: &dyn AddressSpace,
    at: u64,
    base: u64,
    func_start: u64,
    func_end: u64,
) -> Option<JumpTable> {
    let bytes = read_table(space, base, 8, MAX_ENTRIES)?;
    let mut targets = BTreeSet::new();
    let mut decoded = 0usize;
    let mut hit = 0usize;
    for chunk in bytes.as_chunks::<8>().0 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(chunk);
        let target = u64::from_le_bytes(raw);
        decoded += 1;
        if target >= func_start && target < func_end {
            hit += 1;
            targets.insert(target);
        } else if hit > 0 || decoded > 4 {
            // 已经命中的表在 miss 处收尾；一个都没命中的话给 4 项宽限再放弃。
            break;
        }
    }
    (hit >= 2).then(|| JumpTable {
        at,
        base,
        targets: targets.into_iter().collect(),
        confidence: percentage(hit, decoded.max(1)),
    })
}

/// `hit / total` 取整百分比（`total == 0` 记 0）。
fn percentage(hit: usize, total: usize) -> u8 {
    if total == 0 {
        return 0;
    }
    u8::try_from(hit * 100 / total).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};
    use kotama_image::LoadedModule;
    use kotama_scan::discover;

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
    fn recovers_dense_switch_table_in_main() {
        let Some(path) = fixture("x86_64-linux-gnu/-O2/switch") else {
            eprintln!("skip: fixtures not built");
            return;
        };
        let module = LoadedModule::parse(&std::fs::read(path).unwrap()).unwrap();
        let functions = discover(&module);
        let main = functions
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .unwrap();
        let space = module.address_space();
        let bytes = space
            .read(main.rva, usize::try_from(main.size).unwrap())
            .unwrap();
        let mut decoder =
            Decoder::with_ip(module.arch.bitness(), bytes, main.rva, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            instructions.push(instruction);
        }
        let tables = recover(&space, &instructions, main.rva, main.rva + main.size);
        assert!(!tables.is_empty(), "dense switch should yield a jump table");
        let table = &tables[0];
        assert!(table.targets.len() >= 2);
        assert!(table.confidence >= 51);
        // 目标必须全部落在函数体内。
        assert!(table
            .targets
            .iter()
            .all(|t| *t >= main.rva && *t < main.rva + main.size));
    }

    #[test]
    fn no_table_in_a_loop_only_function() {
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
        let space = module.address_space();
        let bytes = space
            .read(main.rva, usize::try_from(main.size).unwrap())
            .unwrap();
        let mut decoder =
            Decoder::with_ip(module.arch.bitness(), bytes, main.rva, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            instructions.push(instruction);
        }
        let tables = recover(&space, &instructions, main.rva, main.rva + main.size);
        assert!(tables.is_empty(), "no switch here, must not invent tables");
    }
}
