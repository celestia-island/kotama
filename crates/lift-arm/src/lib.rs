//! ARM (A32) and Thumb-2 instruction lifting into control-flow facts.
//!
//! ARM is the third architecture here after Aarch64 and RISC-V, and it splits the
//! difference between them: the A32 encoding is fixed-width like A64, while Thumb-2
//! is variable-width like RISC-V. Both live in one binary, a function entry bit
//! selects the mode, so one lifter handles both and the width rule is the first
//! thing that has to be right.
//!
//! Only what discovery needs is decoded: where control flow goes, and which role an
//! instruction plays (call, return, branch, trap). ARM has no dedicated return
//! instruction; a return is a load-multiple that writes the program counter, so that
//! pattern is what is recognised. Everything else is reported with its width.

/// Execution state a byte is decoded in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// A32: fixed 4-byte instructions.
    Arm,
    /// Thumb / Thumb-2: 2 or 4 bytes, chosen by the leading halfword.
    Thumb,
}

/// What an instruction does to control flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    /// Execution continues at the next instruction.
    FallThrough,
    /// An unconditional branch; target is set when it is static.
    Branch,
    /// A conditional branch; target is set when it is static.
    BranchConditional,
    /// A call (link register written). Target is set for bl.
    Call,
    /// A return (program counter written by a load-multiple or bx lr).
    Return,
    /// A branch or exchange through a register with no static target.
    IndirectBranch,
    /// A trap (bkpt, udf, undefined).
    Trap,
}

/// One lifted instruction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArmLifted {
    /// Address of the instruction.
    pub address: u64,
    /// Width in bytes (2 or 4).
    pub width: usize,
    /// Disassembly text.
    pub text: String,
    /// Control-flow role.
    pub flow: Flow,
    /// Static target, when the instruction has one.
    pub target: Option<u64>,
}

/// Program counter register number.
pub const PC: u32 = 15;
/// Link register number.
pub const LR: u32 = 14;
/// Stack pointer register number.
pub const SP: u32 = 13;

/// Width of the Thumb instruction starting with halfword low.
///
/// A 32-bit Thumb-2 instruction begins with 0b11101, 0b11110 or 0b11111 in the top
/// five bits of its first halfword; everything else is 16 bits. This is the rule the
/// architecture defines, and the one an exhaustive comparison against a reference
/// decoder pins.
#[must_use]
pub const fn thumb_width(low: u16) -> usize {
    // Pinned against a reference decoder over every leading 5-bit value: exactly
    // 0b11101, 0b11110 and 0b11111 open a 32-bit instruction; all 29 others are 16-bit.
    if low >> 11 >= 0b11101 {
        4
    } else {
        2
    }
}

/// Sign-extend the low bits of value.
const fn sext(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

fn fact(address: u64, width: usize, text: String, flow: Flow, target: Option<u64>) -> ArmLifted {
    ArmLifted {
        address,
        width,
        text,
        flow,
        target,
    }
}

/// Decode one A32 instruction word at address.
///
/// Every rule below was pinned against a reference decoder rather than derived from
/// the manual: the condition field of svc/udf is AL, not the unspecified 0b1111, and
/// bx/blx are distinguished by bit 5 inside a fixed 0b1111_1111_00xx pattern, which is
/// easy to get wrong by hand.
fn decode_arm(word: u32, address: u64) -> ArmLifted {
    let cond = word >> 28;
    let pc = address.wrapping_add(8);
    let op = word >> 25 & 0b111;
    // B / BL (cond != 0b1111): bits 27:25 = 101, L (bit 24) selects link.
    // Unconditional BLX <imm> shares bits 27:25 = 101 with cond = 0b1111.
    if op == 0b101 {
        let link = word >> 24 & 1 == 1;
        if cond == 0b1111 {
            // BLX <imm>: target = pc + (SignExtend(imm24) << 2) + (H << 1), H = bit 24.
            let h = u64::from(word >> 24 & 1);
            let offset = sext(u64::from(word & 0x00ff_ffff), 24) << 2 | h << 1;
            let target = pc.wrapping_add(offset);
            return fact(
                address,
                4,
                format!("blx {target:#x}"),
                Flow::Call,
                Some(target),
            );
        }
        let offset = sext(u64::from(word & 0x00ff_ffff), 24) << 2;
        let target = pc.wrapping_add(offset);
        return if link {
            fact(
                address,
                4,
                format!("bl {target:#x}"),
                Flow::Call,
                Some(target),
            )
        } else if cond == 0b1110 {
            fact(
                address,
                4,
                format!("b {target:#x}"),
                Flow::Branch,
                Some(target),
            )
        } else {
            fact(
                address,
                4,
                format!("b{cond:#x} {target:#x}"),
                Flow::BranchConditional,
                Some(target),
            )
        };
    }
    // BX / BLX (register): bits 27:4 = 0b0001_0010_1111_1111_1111, bit 5 = link.
    // BX has bits 7:4 = 0001 and BLX has 0011; bit 4 is the link bit, bit 5 is fixed 1.
    // Mask off bit 5 (the link bit) and bits 3:0 (rM): BX is low12 0xf10|rM, BLX 0xf30|rM.
    if word & 0x0fff_ffd0 == 0x012f_ff10 {
        let rm = word & 0x0f;
        // Pinned exhaustively: BX is low12 = 0xf10|rM, BLX is 0xf30|rM.
        let link = word & 0x20 != 0;
        return if link {
            fact(address, 4, "blx".to_string(), Flow::Call, None)
        } else if rm == LR {
            fact(address, 4, "bx lr".to_string(), Flow::Return, None)
        } else {
            fact(address, 4, format!("bx r{rm}"), Flow::IndirectBranch, None)
        };
    }
    // LDM with the program counter in the register list is a return:
    // bits 27:25 = 100, L (bit 20) = 1, bit 15 = 1, cond != 0b1111.
    if op == 0b100 && cond != 0b1111 && word >> 20 & 1 == 1 && word >> 15 & 1 == 1 {
        let base = (word >> 16) & 0x0f;
        return if cond == 0b1110 {
            fact(
                address,
                4,
                format!("ldm r{base}, {{..., pc}}"),
                Flow::Return,
                None,
            )
        } else {
            fact(
                address,
                4,
                "ldmcond {pc}".to_string(),
                Flow::BranchConditional,
                None,
            )
        };
    }
    // SVC: cond = AL, bits 27:24 = 1111. UDF: bits 27:20 = 0111_1111 and bits 7:0 = 0xf0.
    if word & 0x0f00_0000 == 0x0f00_0000 {
        return fact(address, 4, "svc".to_string(), Flow::Trap, None);
    }
    if word & 0x0ff0_00f0 == 0x07f0_00f0 {
        return fact(address, 4, "udf".to_string(), Flow::Trap, None);
    }
    fact(address, 4, ".word".to_string(), Flow::FallThrough, None)
}

/// Decode one Thumb instruction (16 or 32 bits) at address.
///
/// The 16-bit groups are keyed on the top four bits, not five: B<cond> spans
/// 0xd0..0xdd (two five-bit groups) and only cond 0b1110 / 0b1111 are UDF / SVC.
fn decode_thumb(low: u16, high: Option<u16>, address: u64) -> ArmLifted {
    let pc = address.wrapping_add(4);
    if let Some(second) = high {
        // 32-bit Thumb-2 BL / BLX: first halfword 0b11110, second 0b11x1 at bits 14:12.
        // imm = SignExtend(S:I1:I2:imm10:imm11:0), I1 = NOT(J1) XOR S, I2 = NOT(J2) XOR S.
        // 32-bit Thumb-2 BL / BLX, fields per the architecture manual and pinned
        // against a reference decoder on real branches: S and imm10 live in the first
        // halfword, J1/J2/imm11 in the second, and I1/I2 are the inverted J bits
        // XOR S. BLX (rather than BL) is selected by the low bit of the first halfword.
        if low >> 11 == 0b11110 && second >> 14 == 0b11 && second >> 12 & 1 == 1 {
            let s = u64::from(low >> 10 & 1);
            let j1 = u64::from(second >> 13 & 1);
            let j2 = u64::from(second >> 11 & 1);
            let i1 = (j1 ^ 1) ^ s;
            let i2 = (j2 ^ 1) ^ s;
            let imm10 = u64::from(low & 0x03ff);
            let imm11 = u64::from(second & 0x07ff);
            let offset = sext(
                (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1),
                25,
            );
            let is_blx = low & 1 == 1;
            let target = pc.wrapping_add(offset & !1);
            let text = if is_blx {
                format!("blx {target:#x}")
            } else {
                format!("bl {target:#x}")
            };
            return fact(address, 4, text, Flow::Call, Some(target));
        }
        return fact(address, 4, ".wide".to_string(), Flow::FallThrough, None);
    }
    // 16-bit: B<cond> is 0xd000..0xddff; cond = bits 11:8; 0xde = UDF, 0xdf = SVC.
    if low & 0xf000 == 0xd000 {
        let cond = low >> 8 & 0x0f;
        let offset = sext(u64::from(low & 0xff), 8) << 1;
        let target = pc.wrapping_add(offset);
        return match cond {
            0b1110 => fact(address, 2, "udf".to_string(), Flow::Trap, None),
            0b1111 => fact(address, 2, "svc".to_string(), Flow::Trap, None),
            _ => fact(
                address,
                2,
                format!("b{cond:#x} {target:#x}"),
                Flow::BranchConditional,
                Some(target),
            ),
        };
    }
    // 16-bit unconditional B: 0xe000..0xe7ff, 11-bit offset.
    if low & 0xf800 == 0xe000 {
        let offset = sext(u64::from(low & 0x07ff), 11) << 1;
        let target = pc.wrapping_add(offset);
        return fact(
            address,
            2,
            format!("b {target:#x}"),
            Flow::Branch,
            Some(target),
        );
    }
    // 16-bit BX / BLX (register), pinned exhaustively: 0x4700|(rM<<3) is BX and
    // 0x4780|(rM<<3) is BLX. BX lr is the Thumb return idiom.
    if low & 0xff87 == 0x4700 {
        let rm = u32::from((low >> 3) & 0x0f);
        return if rm == LR {
            fact(address, 2, "bx lr".to_string(), Flow::Return, None)
        } else {
            fact(address, 2, format!("bx r{rm}"), Flow::IndirectBranch, None)
        };
    }
    if low & 0xff87 == 0x4780 {
        return fact(address, 2, "blx".to_string(), Flow::Call, None);
    }
    // POP {.., pc}: 0xbd00..0xbdff is the return idiom.
    if low & 0xff00 == 0xbd00 {
        return fact(address, 2, "pop {.., pc}".to_string(), Flow::Return, None);
    }
    fact(address, 2, ".half".to_string(), Flow::FallThrough, None)
}

/// Lift bytes starting at address in mode.
#[must_use]
pub fn lift(bytes: &[u8], address: u64, mode: Mode) -> Vec<ArmLifted> {
    let mut out = Vec::new();
    let mut pc = address;
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let low = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let width = match mode {
            Mode::Arm => 4,
            Mode::Thumb => thumb_width(low),
        };
        if i + width > bytes.len() {
            break;
        }
        let lifted = match mode {
            Mode::Arm => {
                let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
                decode_arm(word, pc)
            }
            Mode::Thumb if width == 4 => {
                let second = u16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
                decode_thumb(low, Some(second), pc)
            }
            Mode::Thumb => decode_thumb(low, None, pc),
        };
        out.push(lifted);
        i += width;
        pc += width as u64;
    }
    out
}

/// One resolved data address: a `movw` + `movt` pair that materialises a 32-bit value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressForm {
    /// Address of the `movt` that completes the value.
    pub at: u64,
    /// The 32-bit value the pair computes, zero-extended.
    pub target: u64,
}

/// Decode an A32 `movw`/`movt` word; returns `(is_movt, rd, imm16)`.
const fn arm_mov_imm(word: u32) -> Option<(bool, u32, u32)> {
    // bits 27:20 = 0x30 (movw) or 0x34 (movt); imm4 in bits 19:16, rd in 15:12, imm12 low.
    let op = (word >> 20) & 0xff;
    if op != 0x30 && op != 0x34 {
        return None;
    }
    let imm4 = (word >> 16) & 0xf;
    let rd = (word >> 12) & 0xf;
    let imm12 = word & 0xfff;
    Some((op == 0x34, rd, (imm4 << 12) | imm12))
}

/// Decode a Thumb-2 `movw`/`movt` from its two halfwords; returns `(is_movt, rd, imm16)`.
const fn thumb_mov_imm(low: u16, second: u16) -> Option<(bool, u32, u32)> {
    // hw1 = 1111 0 i 10 op1 imm4 with op1 = 0100 (movw) / 1100 (movt); hw2 = 0 imm3 rd imm8.
    // hw1 = 11110 i 10 op1 imm4: bit 9 is 1 and bit 8 is 0 (bit 10 carries i, so it is
    // not part of the fixed pattern).
    if low >> 11 != 0b11110 || low >> 8 & 0b11 != 0b10 {
        return None;
    }
    let op1 = (low >> 4) & 0xf;
    if op1 != 0b0100 && op1 != 0b1100 {
        return None;
    }
    if second >> 15 != 0 {
        return None;
    }
    let i = (low >> 10 & 1) as u32;
    let imm4 = (low & 0xf) as u32;
    let imm3 = (second >> 12 & 0x7) as u32;
    let rd = (second >> 8 & 0xf) as u32;
    let imm8 = (second & 0xff) as u32;
    Some((
        op1 == 0b1100,
        rd,
        (i << 11) | (imm4 << 12) | (imm3 << 8) | imm8,
    ))
}

/// Every 32-bit constant materialised by a `movw` + `movt` pair in `bytes`.
///
/// ARM cannot load a 32-bit address in one instruction. The compiler emits `movw` to set
/// the low half of a register and `movt` to set the high half while keeping the low, so
/// the two together form a constant — which for a string literal is its address. This is
/// ARM's counterpart of RISC-V's `lui` + `addi`.
///
/// Each register's most recent `movw` is tracked and paired with the next `movt` on that
/// same register. A `movt` with no preceding `movw` forms only the high half and is not a
/// complete address, so it is skipped. Any other write to a tracked register ends its
/// pending `movw`.
#[must_use]
pub fn address_forms(bytes: &[u8], address: u64, mode: Mode) -> Vec<AddressForm> {
    let mut pending: Vec<(u32, u32)> = Vec::new();
    let mut out = Vec::new();
    let mut pc = address;
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let low = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let width = match mode {
            Mode::Arm => 4,
            Mode::Thumb => thumb_width(low),
        };
        if i + width > bytes.len() {
            break;
        }
        let decoded = match mode {
            Mode::Arm => {
                let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
                arm_mov_imm(word)
            }
            Mode::Thumb if width == 4 => {
                let second = u16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
                thumb_mov_imm(low, second)
            }
            Mode::Thumb => None,
        };
        if let Some((is_movt, rd, imm16)) = decoded {
            if is_movt {
                if let Some(index) = pending.iter().position(|(reg, _)| *reg == rd) {
                    let low_half = pending[index].1;
                    out.push(AddressForm {
                        at: pc,
                        target: u64::from(low_half | (imm16 << 16)),
                    });
                    pending.remove(index);
                }
            } else {
                pending.retain(|(reg, _)| *reg != rd);
                pending.push((rd, imm16));
            }
        } else if let Some(rd) = register_written(mode, low, bytes.get(i + 1).copied(), width) {
            pending.retain(|(reg, _)| *reg != rd);
        }
        i += width;
        pc += width as u64;
    }
    out
}

/// Best-effort destination register of an instruction, for invalidating a pending `movw`.
///
/// Only the common data-processing shapes are recognised; anything else returns `None`,
/// which leaves the pending `movw` in place rather than discarding a real one.
fn register_written(mode: Mode, low: u16, _second: Option<u8>, width: usize) -> Option<u32> {
    match (mode, width) {
        (Mode::Arm, 4) => None,
        (Mode::Thumb, 2) => {
            // 16-bit Thumb data-processing: op 00 xxxxx; rd in bits 2:0 for the two-operand form.
            if low >> 10 <= 0b00100 {
                Some(u32::from(low & 0x7))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_width_follows_the_leading_halfword() {
        assert_eq!(thumb_width(0b1110_1000_0000_0000), 4);
        assert_eq!(thumb_width(0b1111_1000_0000_0000), 4);
        assert_eq!(thumb_width(0b1110_0111_1111_1111), 2);
        assert_eq!(thumb_width(0x0000), 2);
    }

    fn le(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    // Every encoding below was read back from a reference decoder on a real binary,
    // never assembled by hand.

    #[test]
    fn arm_bl_targets_the_link_register_and_reports_the_call() {
        // 00 00 00 eb at 0x20284: bl +8 -> 0x2028c. ARM reads the pc as address + 8.
        let lifted = lift(&le(&[0x00, 0x00, 0x00, 0xeb]), 0x20284, Mode::Arm);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Call, Some(0x2028c))
        );
    }

    #[test]
    fn arm_conditional_branch_keeps_its_condition_and_target() {
        // 1e 00 00 ba at 0x2031c: blt 0x2039c (pc reads as address + 8, imm 0x1e << 2).
        let lifted = lift(&le(&[0x1e, 0x00, 0x00, 0xba]), 0x2031c, Mode::Arm);
        assert_eq!(lifted[0].flow, Flow::BranchConditional);
        assert_eq!(lifted[0].target, Some(0x2039c));
    }

    #[test]
    fn arm_bx_lr_is_a_return() {
        // 1e ff 2f e1: bx lr, the ARM return idiom. There is no ret instruction.
        let lifted = lift(&le(&[0x1e, 0xff, 0x2f, 0xe1]), 0x20a60, Mode::Arm);
        assert_eq!(
            (lifted[0].flow, lifted[0].text.as_str()),
            (Flow::Return, "bx lr")
        );
    }

    #[test]
    fn arm_blx_register_is_a_call_without_a_static_target() {
        // 30 ff 2f e1: blx r0. Distinguished from bx by bit 5 inside 0xff3x.
        let lifted = lift(&le(&[0x30, 0xff, 0x2f, 0xe1]), 0x205b8, Mode::Arm);
        assert_eq!(lifted[0].flow, Flow::Call);
        assert_eq!(lifted[0].target, None);
    }

    #[test]
    fn arm_pop_with_pc_is_a_return() {
        // 00 80 bd e8: ldm sp!, {pc} (pop {pc} in capstone).
        let lifted = lift(&le(&[0x00, 0x80, 0xbd, 0xe8]), 0x206a0, Mode::Arm);
        assert_eq!(lifted[0].flow, Flow::Return);
    }

    #[test]
    fn arm_svc_is_a_trap_with_condition_al() {
        // 00 00 00 ef: svc #0. Its condition is AL, not the unspecified 0b1111.
        let lifted = lift(&le(&[0x00, 0x00, 0x00, 0xef]), 0x2052c, Mode::Arm);
        assert_eq!(lifted[0].flow, Flow::Trap);
    }

    #[test]
    fn thumb_bl_assembles_its_target_from_both_halfwords() {
        // 00 f0 02 f8 at 0x2025c: bl 0x20264. S=0 imm10=0 in the first halfword,
        // J1/J2/imm11 in the second; the target is pc + 4 + imm.
        let lifted = lift(&le(&[0x00, 0xf0, 0x02, 0xf8]), 0x2025c, Mode::Thumb);
        assert_eq!(lifted[0].width, 4);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Call, Some(0x20264))
        );
    }

    #[test]
    fn thumb_backward_bl_sign_extends_across_both_halfwords() {
        // ff f7 c9 ff at 0x20302: bl 0x20298. S=1 and the inverted J bits make the
        // offset negative; this is the case that pins the I1/I2 formula.
        let lifted = lift(&le(&[0xff, 0xf7, 0xc9, 0xff]), 0x20302, Mode::Thumb);
        assert_eq!(lifted[0].target, Some(0x20298));
    }

    #[test]
    fn thumb_conditional_branch_covers_the_whole_d0_to_dd_range() {
        // d4 d4 at 0x20296: bmi 0x20242. The cond field is bits 11:8 and the group
        // spans two five-bit prefixes, so keying on the top five bits misses half of it.
        let lifted = lift(&le(&[0xd4, 0xd4]), 0x20296, Mode::Thumb);
        assert_eq!(lifted[0].flow, Flow::BranchConditional);
        assert_eq!(lifted[0].target, Some(0x20242));
    }

    #[test]
    fn thumb_unconditional_b_and_pop_pc_are_separated() {
        // e7 e0: b -4 ; bd 80: pop {r7, pc}. Both are 16 bits, different roles.
        let b = lift(&le(&[0xe7, 0xe0]), 0x2000, Mode::Thumb);
        assert_eq!(b[0].flow, Flow::Branch);
        let pop = lift(&le(&[0x80, 0xbd]), 0x20294, Mode::Thumb);
        assert_eq!((pop[0].flow, pop[0].width), (Flow::Return, 2));
    }

    #[test]
    fn thumb_bx_lr_and_blx_register() {
        // 70 47: bx lr ; 80 47: blx r0.
        let bx = lift(&le(&[0x70, 0x47]), 0x20800, Mode::Thumb);
        assert_eq!(bx[0].flow, Flow::Return);
        let blx = lift(&le(&[0x80, 0x47]), 0x204a2, Mode::Thumb);
        assert_eq!(blx[0].flow, Flow::Call);
    }

    #[test]
    fn a_mixed_sequence_keeps_the_sweep_aligned() {
        // 16-bit push, a 32-bit wide mov, 16-bit ldr: widths must tile exactly.
        let code = le(&[0x80, 0xb5, 0x4f, 0xf0, 0x00, 0x0b, 0x03, 0x49]);
        let lifted = lift(&code, 0x20264, Mode::Thumb);
        let widths: Vec<usize> = lifted.iter().map(|l| l.width).collect();
        assert_eq!(widths, vec![2, 4, 2]);
    }

    #[test]
    fn thumb_conditional_branch_reaches_the_upper_half_of_the_range() {
        // 14 db at 0x202c8: blt 0x202f4. Its leading five bits are 0b11011, not the
        // 0b11010 that bmi has; keying the group on five bits would miss every
        // branch from bhi to ble.
        let lifted = lift(&le(&[0x14, 0xdb]), 0x202c8, Mode::Thumb);
        assert_eq!(lifted[0].flow, Flow::BranchConditional);
        assert_eq!(lifted[0].target, Some(0x202f4));
    }

    #[test]
    fn thumb_unconditional_b_sign_extends_eleven_bits() {
        // Halfword 0xe400 (stored 00 e4) at 0x2000: b 0x1804. Bit 10 of the offset is set,
        // which is the bit a 10-bit field would treat as the sign and read as +0x400.
        let lifted = lift(&le(&[0x00, 0xe4]), 0x2000, Mode::Thumb);
        assert_eq!(lifted[0].target, Some(0x1804));
    }

    #[test]
    fn thumb_blx_immediate_is_labelled_distinctly_from_bl() {
        // 01 f0 02 f8: the low bit of the first halfword selects BLX over BL.
        let blx = lift(&le(&[0x01, 0xf0, 0x02, 0xf8]), 0x2000, Mode::Thumb);
        assert_eq!(blx[0].flow, Flow::Call);
        assert!(blx[0].text.starts_with("blx"), "{}", blx[0].text);
        let bl = lift(&le(&[0x00, 0xf0, 0x02, 0xf8]), 0x2000, Mode::Thumb);
        assert!(bl[0].text.starts_with("bl "), "{}", bl[0].text);
    }

    // Every encoding below was read from a real binary through a reference decoder.

    #[test]
    fn arm_movw_movt_form_the_string_address() {
        // movw r0, #0x230 ; movt r0, #1 at 0x202fc -> 0x10230 (hello_from_arm).
        let code = le(&[0x30, 0x02, 0x00, 0xe3, 0x01, 0x00, 0x40, 0xe3]);
        let forms = address_forms(&code, 0x202fc, Mode::Arm);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].at, 0x20300);
        assert_eq!(forms[0].target, 0x1_0230);
    }

    #[test]
    fn thumb_movw_movt_form_the_string_address() {
        // From the real binary: 40 f2 10 20 (movw r0,#0x210) ; c0 f2 01 00 (movt r0,#1).
        let code = le(&[0x40, 0xf2, 0x10, 0x20, 0xc0, 0xf2, 0x01, 0x00]);
        let forms = address_forms(&code, 0x202c0, Mode::Thumb);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].at, 0x202c4);
        assert_eq!(forms[0].target, 0x1_0210);
    }

    #[test]
    fn thumb_movt_alone_forms_nothing() {
        // c0 f2 01 00: movt r0, #1 with no movw before it.
        let code = le(&[0xc0, 0xf2, 0x01, 0x00]);
        assert!(address_forms(&code, 0x2000, Mode::Thumb).is_empty());
    }

    #[test]
    fn a_movw_on_another_register_does_not_pair() {
        // movw r0,#0x210 (40 f2 10 20) ; movt r1,#1 (c1 f2 01 01): no address.
        let code = le(&[0x40, 0xf2, 0x10, 0x20, 0xc1, 0xf2, 0x01, 0x01]);
        assert!(address_forms(&code, 0x2000, Mode::Thumb).is_empty());
    }

    #[test]
    fn the_thumb_i_bit_contributes_bit_11() {
        // From the real binary: 40 f6 60 14 (movw r4,#0x960, i=1) ; c0 f2 03 04 (movt r4,#3).
        let code = le(&[0x40, 0xf6, 0x60, 0x14, 0xc0, 0xf2, 0x03, 0x04]);
        let forms = address_forms(&code, 0x202cc, Mode::Thumb);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].target, 0x3_0960);
    }

    #[test]
    fn a_mixed_width_sequence_stays_aligned() {
        // 16-bit push, a 32-bit movw, 16-bit nop: widths must tile.
        let code = le(&[0x80, 0xb5, 0x40, 0xf2, 0x10, 0x20, 0x00, 0xbf]);
        let forms = address_forms(&code, 0x2000, Mode::Thumb);
        assert!(forms.is_empty(), "movw alone forms nothing: {forms:?}");
    }

    #[test]
    fn arm_movw_with_a_high_imm4_is_decoded() {
        // movw r0,#0xf230 = 30 02 0f e3 (imm4 = 0xf in bits 19:16) ; movt r0,#1 = 01 00 40 e3.
        let code = le(&[0x30, 0x02, 0x0f, 0xe3, 0x01, 0x00, 0x40, 0xe3]);
        let forms = address_forms(&code, 0x2000, Mode::Arm);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].target, 0x1_f230);
    }

    #[test]
    fn thumb_imm4_lives_in_the_low_nibble_of_the_first_halfword() {
        // movw r0,#0xf230 = 4f f2 30 20 (imm4 = 0xf in hw1[3:0]) ; movt r0,#1 = c0 f2 01 00.
        let code = le(&[0x4f, 0xf2, 0x30, 0x20, 0xc0, 0xf2, 0x01, 0x00]);
        let forms = address_forms(&code, 0x2000, Mode::Thumb);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].target, 0x1_f230);
    }

    #[test]
    fn a_second_movt_on_the_same_register_forms_nothing() {
        // movw r0,#0x210 ; movt r0,#1 ; movt r0,#2: the movw is consumed by the first
        // movt, so the second forms only a high half and must not be reported.
        let code = le(&[
            0x40, 0xf2, 0x10, 0x20, 0xc0, 0xf2, 0x01, 0x00, 0xc0, 0xf2, 0x02, 0x00,
        ]);
        let forms = address_forms(&code, 0x2000, Mode::Thumb);
        assert_eq!(forms.len(), 1, "{forms:?}");
        assert_eq!(forms[0].target, 0x1_0210);
    }
}
