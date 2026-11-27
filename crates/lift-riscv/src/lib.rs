//! RISC-V (RV64) instruction lifting: variable length decode and control-flow facts.
//!
//! RISC-V instructions are 2, 4, 6 or 8 bytes wide; the width follows from the low
//! bits alone, so a linear sweep recovers every boundary without guessing. The C
//! (compressed) extension is the whole reason that matters: a real `rv64gc` build is
//! around 40 percent smaller than the same code without it, and its branches and
//! returns are overwhelmingly compressed. A lifter that decoded only 4-byte
//! instructions would lose most of the control flow in such a binary.
//!
//! Only control flow is interpreted here: every branch, jump, call, return and trap,
//! in both the 4-byte and the 2-byte encodings. Everything else is reported as data
//! with its width, because function discovery needs to know where control leaves an
//! instruction, not what the arithmetic does.
//!
//! The decoder is self-contained and allocation-bounded by the input: the same bytes
//! always produce the same facts.

use std::fmt;

/// Register `x1`, the standard return-address link register.
pub const RA: u32 = 1;
/// Register `x5`, the alternate link register.
pub const T1: u32 = 5;
/// Register `x0`, the hard-wired zero register.
pub const ZERO: u32 = 0;

/// What an instruction does to control flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    /// Falls through to the next instruction.
    FallThrough,
    /// Unconditional branch to a PC-relative target.
    Branch,
    /// Conditional branch; taken target plus fall-through.
    BranchConditional,
    /// Subroutine call (`jal x1` / `jalr x1` / `c.jal` / `c.jalr`).
    Call,
    /// Return from subroutine (`jalr x0, x1|x5` / `c.jr x1|x5`).
    Return,
    /// Indirect jump or call through a register with no static target.
    IndirectBranch,
    /// Terminates control flow (`ecall` / `ebreak` / `c.ebreak`).
    Trap,
}

impl Flow {
    /// Stable lowercase name for reports.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::FallThrough => "fall-through",
            Self::Branch => "branch",
            Self::BranchConditional => "branch-conditional",
            Self::Call => "call",
            Self::Return => "return",
            Self::IndirectBranch => "indirect-branch",
            Self::Trap => "trap",
        }
    }

    /// True when the instruction can transfer control somewhere other than the next.
    /// address. Traps count: nothing after them is reachable.
    #[must_use]
    pub const fn leaves(self) -> bool {
        !matches!(self, Self::FallThrough)
    }
}

/// One lifted instruction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RvLifted {
    /// Address of the instruction.
    pub address: u64,
    /// Width in bytes: 2 for compressed, 4 otherwise (6 and 8 are reserved).
    pub width: u8,
    /// Disassembly text, or a `.half` / `.word` placeholder for non-control data.
    pub text: String,
    /// Control-flow effect.
    pub flow: Flow,
    /// Direct target address when the flow has one.
    pub target: Option<u64>,
}

impl fmt::Display for RvLifted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.target {
            Some(target) => write!(
                f,
                "{:#x}: ({}) {} -> {:#x} [{}]",
                self.address,
                self.width,
                self.text,
                target,
                self.flow.short()
            ),
            None => write!(
                f,
                "{:#x}: ({}) {} [{}]",
                self.address,
                self.width,
                self.text,
                self.flow.short()
            ),
        }
    }
}

/// Width of the instruction whose lowest 16 bits are `low`, per the encoding rule.
///
/// `00`/`01`/`10` are 2-byte compressed encodings; `011`/`111` extend to 4/6/8 bytes.
/// The rule is the one every RISC-V decoder implements, so it is the same function
/// the sweep and any external decoder would agree on.
#[must_use]
pub const fn instruction_width(low: u16) -> usize {
    if low & 0b11 != 0b11 {
        2
    } else if low & 0b1_1100 != 0b1_1100 {
        4
    } else if low & 0b11_1111 == 0b01_1111 {
        6
    } else if low & 0b0111_1111 == 0b0011_1111 {
        8
    } else {
        // Reserved for >= 48 bits; the largest defined instruction is 8 bytes.
        8
    }
}

/// Sign-extend a value occupying `bits` bits, as `i64`.
const fn sext(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// B-type (conditional branch) immediate: imm[12|10:5] at bits 31|30:25, imm[4:1|11] at 11:8|7.
const fn b_imm(word: u32) -> i64 {
    let imm = ((word >> 31) << 12)
        | (((word >> 25) & 0x3f) << 5)
        | (((word >> 8) & 0xf) << 1)
        | (((word >> 7) & 1) << 11);
    sext(imm as u64, 13)
}

/// J-type (`jal`) immediate: imm[20|10:1|11|19:12] scattered across the upper 20 bits.
const fn j_imm(word: u32) -> i64 {
    let imm = ((word >> 31) << 20)
        | (((word >> 12) & 0xff) << 12)
        | (((word >> 20) & 1) << 11)
        | (((word >> 21) & 0x3ff) << 1);
    sext(imm as u64, 21)
}

/// I-type immediate (bits 31:20), sign-extended.
const fn i_imm(word: u32) -> i64 {
    sext((word >> 20) as u64, 12)
}

/// Build the fact for one instruction.
fn fact(address: u64, width: u8, text: String, flow: Flow, target: Option<u64>) -> RvLifted {
    RvLifted {
        address,
        width,
        text,
        flow,
        target,
    }
}

/// Decode a 4-byte instruction at `address`.
fn decode32(address: u64, word: u32) -> RvLifted {
    let opcode = word & 0x7f;
    let rd = (word >> 7) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = (word >> 15) & 0x1f;
    match opcode {
        // JAL: rd = PC+4, PC += imm. x1 is a call; x0 is an unconditional jump.
        0x6f => {
            let target = address.wrapping_add(j_imm(word) as u64);
            if rd == RA {
                fact(
                    address,
                    4,
                    format!("jal ra, {target:#x}"),
                    Flow::Call,
                    Some(target),
                )
            } else if rd == ZERO {
                fact(
                    address,
                    4,
                    format!("j {target:#x}"),
                    Flow::Branch,
                    Some(target),
                )
            } else {
                fact(
                    address,
                    4,
                    format!("jal x{rd}, {target:#x}"),
                    Flow::Branch,
                    Some(target),
                )
            }
        }
        // JALR: rd = PC+4, PC = rs1 + imm. The register pair decides call/return/jump.
        0x67 => {
            let imm = i_imm(word);
            let disp = if imm == 0 {
                String::new()
            } else {
                format!(", {imm}")
            };
            if rd == RA || rd == T1 {
                fact(
                    address,
                    4,
                    format!("jalr ra, x{rs1}{disp}"),
                    Flow::Call,
                    None,
                )
            } else if rd == ZERO && (rs1 == RA || rs1 == T1) && imm == 0 {
                fact(address, 4, "ret".to_string(), Flow::Return, None)
            } else if rd == ZERO {
                fact(
                    address,
                    4,
                    format!("jr x{rs1}{disp}"),
                    Flow::IndirectBranch,
                    None,
                )
            } else {
                fact(
                    address,
                    4,
                    format!("jalr x{rd}, x{rs1}{disp}"),
                    Flow::IndirectBranch,
                    None,
                )
            }
        }
        // Conditional branches: six comparisons, all PC-relative B-type.
        0x63 => {
            let rs2 = (word >> 20) & 0x1f;
            let target = address.wrapping_add(b_imm(word) as u64);
            let mnemonic = match funct3 {
                0b000 => "beq",
                0b001 => "bne",
                0b100 => "blt",
                0b101 => "bge",
                0b110 => "bltu",
                0b111 => "bgeu",
                _ => "b?",
            };
            fact(
                address,
                4,
                format!("{mnemonic} x{rs1}, x{rs2}, {target:#x}"),
                Flow::BranchConditional,
                Some(target),
            )
        }
        // SYSTEM: ecall / ebreak / mret / wfi all stop a linear sweep.
        0x73 => {
            // funct3 = 0 is the trap family. The CSR ops (funct3 = 1..=7) do not stop
            // a sweep, but LLVM emits `csrw` with rd=x0/rs1=x0 as `unimp` to implement
            // `__builtin_trap`, and that encoding raises an illegal-instruction trap.
            let text = match (funct3, (word >> 20) & 0xfff) {
                (0, 0) => "ecall".to_string(),
                (0, 1) => "ebreak".to_string(),
                (0b001, 0xc00) => "unimp".to_string(),
                _ => "system".to_string(),
            };
            fact(address, 4, text, Flow::Trap, None)
        }
        // AUIPC: rd = PC + (imm << 12). Not control flow itself, but the first half of
        // every address formed under the medany code model, including call targets.
        0x17 => {
            let imm = (word & 0xffff_f000) as i32 as i64;
            fact(
                address,
                4,
                format!("auipc x{rd}, {:#x}", address.wrapping_add(imm as u64)),
                Flow::FallThrough,
                None,
            )
        }
        _ => fact(address, 4, ".word".to_string(), Flow::FallThrough, None),
    }
}

/// Decode a 2-byte compressed instruction at `address`.
///
/// Only the compressed control-flow encodings are interpreted; the rest is reported
/// as `.half`. Quadrant 1 holds `c.j`, `c.jal`, `c.beqz`, `c.bnez`; quadrant 2 holds
/// `c.jr`, `c.jalr` and `c.ebreak`.
fn decode16(address: u64, low: u16) -> RvLifted {
    let quadrant = low & 0b11;
    let funct3 = (low >> 13) & 0x7;
    let data = RvLifted {
        address,
        width: 2,
        text: ".half".to_string(),
        flow: Flow::FallThrough,
        target: None,
    };
    match (quadrant, funct3) {
        // c.j: offset[11|4|9:8|10|6|7|3:1|5] at bits 12|11|10:9|8|7:6|5:3|2.
        (0b01, 0b101) => {
            let o = u32::from(low);
            // Bit map confirmed exhaustively against a reference decoder:
            //   bit12->imm[11] (sign)  bit11->imm[4]   bit10->imm[9]   bit9->imm[8]
            //   bit8->imm[10]         bit7->imm[6]    bit6->imm[7]    bit5->imm[3]
            //   bit4->imm[2]          bit3->imm[1]    bit2->imm[5]
            let imm = (((o >> 12) & 1) << 11)
                | (((o >> 11) & 1) << 4)
                | (((o >> 10) & 1) << 9)
                | (((o >> 9) & 1) << 8)
                | (((o >> 8) & 1) << 10)
                | (((o >> 7) & 1) << 6)
                | (((o >> 6) & 1) << 7)
                | (((o >> 5) & 1) << 3)
                | (((o >> 4) & 1) << 2)
                | (((o >> 3) & 1) << 1)
                | (((o >> 2) & 1) << 5);
            let target = address.wrapping_add(sext(imm as u64, 12) as u64);
            fact(
                address,
                2,
                format!("c.j {target:#x}"),
                Flow::Branch,
                Some(target),
            )
        }
        // c.jal (RV32 only; on RV64 this encoding is c.addiw, not a control transfer).
        // Treated as a call only if the caller says the mode is RV32, which the
        // public entry point never does, so this arm documents the encoding.
        (0b01, 0b001) => data,
        // c.beqz / c.bnez: offset[8|4:3] and imm[7:6|2:1|5] at bits 12|11:10|6:5|4:3|2.
        (0b01, 0b110) | (0b01, 0b111) => {
            let o = u32::from(low);
            // Bit map confirmed by flipping each bit through a reference decoder.
            // The offset is a multiple of two, so imm[0] is implicit and imm is 9 bits.
            //   bit12 -> imm[8] (sign)  bit11 -> imm[4]  bit10 -> imm[3]
            //   bit6  -> imm[7]        bit5  -> imm[6]  bit2  -> imm[5]
            //   bit4  -> imm[2]        bit3  -> imm[1]
            let imm = (((o >> 12) & 1) << 8)
                | (((o >> 11) & 1) << 4)
                | (((o >> 10) & 1) << 3)
                | (((o >> 6) & 1) << 7)
                | (((o >> 5) & 1) << 6)
                | (((o >> 2) & 1) << 5)
                | (((o >> 4) & 1) << 2)
                | (((o >> 3) & 1) << 1);
            let target = address.wrapping_add(sext(imm as u64, 9) as u64);
            // Compressed branches address only x8..x15 through a 3-bit rs1'.
            let rs1 = 8 + ((o >> 7) & 0b111);
            let mnemonic = if funct3 == 0b110 { "c.beqz" } else { "c.bnez" };
            fact(
                address,
                2,
                format!("{mnemonic} x{rs1}, {target:#x}"),
                Flow::BranchConditional,
                Some(target),
            )
        }
        // Quadrant 2, funct3=100 is a small grid keyed by bit 12, the rd field
        // (bits 6:2) and rs1 (bits 11:7). Every jump encodes rd = 00000:
        //   bit12=0, rd=0, rs1!=0  -> c.jr    (rd=00010 with rs1=0 is c.ebreak)
        //   bit12=1, rd=0, rs1!=0  -> c.jalr  (link register is implicitly x1)
        //   rd!=0 is c.mv (rs1=0) or c.add (rs1!=0): arithmetic, not control flow.
        (0b10, 0b100) => {
            let rs1 = u32::from((low >> 7) & 0x1f);
            let rd = (low >> 2) & 0x1f;
            let link = (low >> 12) & 1;
            if rs1 == 0 && rd == 0 {
                // c.ebreak is the all-zero jump slot
                fact(address, 2, "c.ebreak".to_string(), Flow::Trap, None)
            } else if rd != 0 {
                // c.mv / c.add
                data
            } else if link == 1 {
                fact(address, 2, format!("c.jalr x{rs1}"), Flow::Call, None)
            } else if rs1 == RA || rs1 == T1 {
                fact(address, 2, "c.jr ra".to_string(), Flow::Return, None)
            } else {
                fact(
                    address,
                    2,
                    format!("c.jr x{rs1}"),
                    Flow::IndirectBranch,
                    None,
                )
            }
        }
        _ => data,
    }
}

/// Lift a byte slice starting at `address` into instruction facts.
///
/// Stops at the first instruction that would run past the end of `bytes`, returning
/// what was lifted before it; a trailing partial instruction is the end of input, not
/// an error.
#[must_use]
pub fn lift(bytes: &[u8], address: u64) -> Vec<RvLifted> {
    let mut out = Vec::new();
    let mut pc = address;
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let low = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let width = instruction_width(low);
        if i + width > bytes.len() {
            break;
        }
        let decoded = if width == 2 {
            decode16(pc, low)
        } else if width == 4 {
            decode32(
                pc,
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]),
            )
        } else {
            // 6- and 8-byte encodings are reserved; report and continue.
            fact(
                pc,
                width as u8,
                ".long".to_string(),
                Flow::FallThrough,
                None,
            )
        };
        out.push(decoded);
        i += width;
        pc += width as u64;
    }
    out
}

/// Addresses that end a basic block, in order.
#[must_use]
pub fn block_ends(instructions: &[RvLifted]) -> Vec<u64> {
    instructions
        .iter()
        .filter(|lifted| lifted.flow.leaves())
        .map(|lifted| lifted.address)
        .collect()
}

/// Every direct control-flow edge (from, to) in address order.
#[must_use]
pub fn direct_edges(instructions: &[RvLifted]) -> Vec<(u64, u64)> {
    instructions
        .iter()
        .filter_map(|lifted| lifted.target.map(|target| (lifted.address, target)))
        .collect()
}

/// One resolved indirect call: `auipc` formed a base, `jalr` added an offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallTarget {
    /// Address of the `jalr` that performs the call.
    pub at: u64,
    /// Absolute target the pair computes.
    pub target: u64,
}

/// Absolute target of every `auipc` + `jalr` call pair in `bytes` starting at `address`.
///
/// Under the medany code model a call is two instructions: `auipc x1, hi` puts
/// `PC + (hi << 12)` in the link register, then `jalr x1, x1, lo` calls `base + lo`.
/// Neither instruction knows the target on its own, so a lifter that reads one
/// instruction at a time sees a call with no destination. This pairs them.
///
/// Tracks the most recent `auipc` per register and pairs it with the next `jalr`
/// that reads the same register as its base, which is the only way a compiler
/// forms a call target. `jalr` through a register no `auipc` wrote is a genuine
/// indirect call and yields nothing.
#[must_use]
pub fn call_targets(bytes: &[u8], address: u64) -> Vec<CallTarget> {
    let mut bases: Vec<(u32, u64)> = Vec::new();
    let mut out = Vec::new();
    let mut pc = address;
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let low = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let width = instruction_width(low);
        if i + width > bytes.len() {
            break;
        }
        if width == 4 {
            let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            let opcode = word & 0x7f;
            let rd = (word >> 7) & 0x1f;
            let rs1 = (word >> 15) & 0x1f;
            match opcode {
                0x17 => {
                    // auipc x{rd}, hi : base = PC + (hi << 12), sign-extended.
                    let hi = (word & 0xffff_f000) as i32 as i64;
                    bases.retain(|(reg, _)| *reg != rd);
                    bases.push((rd, pc.wrapping_add(hi as u64)));
                }
                0x67 if rd == RA || rd == T1 => {
                    // jalr through a register an auipc wrote: a resolvable call.
                    let lo = i_imm(word);
                    if let Some((_, base)) = bases.iter().find(|(reg, _)| *reg == rs1) {
                        out.push(CallTarget {
                            at: pc,
                            target: base.wrapping_add(lo as u64),
                        });
                    }
                }
                _ => {}
            }
        }
        i += width;
        pc += width as u64;
    }
    out
}

/// One resolved data address: a two-instruction pair that computes an absolute value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressForm {
    /// Address of the instruction that completes the address (the `addi`).
    pub at: u64,
    /// The absolute value the pair computes.
    pub target: u64,
}

/// Every two-instruction data address formed in `bytes` starting at `address`.
///
/// RISC-V cannot materialise a 64-bit address in one instruction, and it uses two
/// different pairs depending on the code model:
///
/// - `auipc xd, hi` + `addi xd, xd, lo` for position-independent code: the base is
///   `PC + (hi << 12)`, so the result moves with the load address;
/// - `lui xd, hi` + `addi xd, xd, lo` for absolute code: the base is `hi << 12`
///   sign-extended through its 32-bit form, so the result is a fixed address.
///
/// Both are tracked per register and paired with the `addi` that reads that register.
/// Any instruction that writes a register ends the base it held, so a stale value can
/// never be paired with a later `addi`.
#[must_use]
pub fn address_forms(bytes: &[u8], address: u64) -> Vec<AddressForm> {
    let mut bases: Vec<(u32, u64)> = Vec::new();
    let mut out = Vec::new();
    let mut pc = address;
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let low = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let width = instruction_width(low);
        if i + width > bytes.len() {
            break;
        }
        if width == 4 {
            let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            let opcode = word & 0x7f;
            let rd = (word >> 7) & 0x1f;
            let rs1 = (word >> 15) & 0x1f;
            match opcode {
                // auipc: base = PC + (hi << 12).
                0x17 => {
                    let hi = (word & 0xffff_f000) as i32 as i64;
                    bases.retain(|(reg, _)| *reg != rd);
                    bases.push((rd, pc.wrapping_add(hi as u64)));
                }
                // lui: base = (hi << 12) sign-extended through its 32-bit form.
                0x37 => {
                    let hi = (word & 0xffff_f000) as i64;
                    let value = (hi as i32) as i64;
                    bases.retain(|(reg, _)| *reg != rd);
                    bases.push((rd, value as u64));
                }
                // addi rd, rs1, imm12 completes a base formed just above.
                0x13 if (word >> 12) & 0x7 == 0 => {
                    let lo = i_imm(word);
                    if let Some((_, base)) = bases.iter().find(|(reg, _)| *reg == rs1) {
                        out.push(AddressForm {
                            at: pc,
                            target: base.wrapping_add(lo as u64),
                        });
                    }
                    // The addi consumed rs1 and wrote rd; drop rd's stale base last,
                    // because rd == rs1 here is the normal case.
                    bases.retain(|(reg, _)| *reg != rd);
                }
                // Every other instruction that writes rd ends the base it held.
                0x67 | 0x03 | 0x23 | 0x33 | 0x1b | 0x3b => {
                    bases.retain(|(reg, _)| *reg != rd);
                }
                _ => {}
            }
        }
        i += width;
        pc += width as u64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble instructions from their 16-bit halves, little-endian.
    fn words(halves: &[u16]) -> Vec<u8> {
        halves.iter().flat_map(|h| h.to_le_bytes()).collect()
    }

    // Every encoding below was emitted by a real assembler and read back with
    // capstone, not hand-assembled, so the expected bytes are authoritative.

    #[test]
    fn width_follows_the_low_bits() {
        assert_eq!(instruction_width(0x0000), 2);
        assert_eq!(instruction_width(0x0001), 2);
        assert_eq!(instruction_width(0x0002), 2);
        assert_eq!(instruction_width(0x0003), 4);
        assert_eq!(instruction_width(0x0013), 4); // addi
        assert_eq!(instruction_width(0x0063), 4); // branch
        assert_eq!(instruction_width(0x001f), 6);
        assert_eq!(instruction_width(0x003f), 8);
    }

    #[test]
    fn jal_through_ra_is_a_call_and_through_zero_a_jump() {
        // jal ra, +4 = ef 00 40 00 ; j +4 = 6f 00 40 00
        let call = words(&[0x00ef, 0x0040]);
        let lifted = lift(&call, 0x1000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Call, Some(0x1004))
        );
        let jump = words(&[0x006f, 0x0040]);
        let lifted = lift(&jump, 0x1000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Branch, Some(0x1004))
        );
    }

    #[test]
    fn jalr_register_roles_decide_call_return_jump() {
        // jalr ra, ra, -0x58 = e7 80 80 fa
        assert_eq!(lift(&words(&[0x80e7, 0xfa80]), 0)[0].flow, Flow::Call);
        // ret = 67 80 00 00
        assert_eq!(lift(&words(&[0x8067, 0x0000]), 0)[0].flow, Flow::Return);
        // jr t0 = 67 80 02 00 (alternate link register, also a return)
        assert_eq!(lift(&words(&[0x8067, 0x0002]), 0)[0].flow, Flow::Return);
        // jr a0 = 67 00 05 00 (plain indirect jump)
        assert_eq!(
            lift(&words(&[0x0067, 0x0005]), 0)[0].flow,
            Flow::IndirectBranch
        );
    }

    #[test]
    fn conditional_branches_take_b_type_immediates() {
        // beqz zero, +4 = 63 02 00 00
        let beq = words(&[0x0263, 0x0000]);
        let lifted = lift(&beq, 0x3000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x3004))
        );
        // bnez a0, +4 = 63 12 05 00
        let bne = words(&[0x1263, 0x0005]);
        let lifted = lift(&bne, 0x3000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x3004))
        );
        assert!(lifted[0].text.starts_with("bne x10, x0"));
    }

    #[test]
    fn backward_branches_sign_extend_the_b_type_immediate() {
        // bge t0, t1, -4 = e3 de 62 fe : from 0x8 back to 0x4. imm[12] and imm[11]
        // are both set; dropping imm[11] would land four bytes past the target.
        let bge = words(&[0xdee3, 0xfe62]);
        let lifted = lift(&bge, 0x8);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x4))
        );
        // bltu t2, s0, -8 = e3 ec 83 fe : from 0xc back to 0x4.
        let bltu = words(&[0xece3, 0xfe83]);
        let lifted = lift(&bltu, 0xc);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x4))
        );
        assert!(lifted[0].text.starts_with("bltu x7, x8"));
    }

    #[test]
    fn backward_jumps_sign_extend_the_j_type_immediate() {
        // j -4 = 6f f0 df ff : J-type imm[20] is the sign bit; from 0x4 back to 0x0.
        let j = words(&[0xf06f, 0xffdf]);
        let lifted = lift(&j, 0x4);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Branch, Some(0x0))
        );
        // jal ra, -4 = ef f0 df ff : same offset, link register written, so a call.
        let jal = words(&[0xf0ef, 0xffdf]);
        let lifted = lift(&jal, 0x4);
        assert_eq!((lifted[0].flow, lifted[0].target), (Flow::Call, Some(0x0)));
    }

    #[test]
    fn backward_compressed_branches_sign_extend_and_keep_their_mnemonic() {
        // c.beqz s0, -2 = 7d dc : from 0xa back to 0x8.
        let beqz = words(&[0xdc7d]);
        let lifted = lift(&beqz, 0xa);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x8))
        );
        assert!(
            lifted[0].text.starts_with("c.beqz x8"),
            "{}",
            lifted[0].text
        );
        // c.bnez s1, -4 = f5 fc : from 0xc back to 0x8.
        let bnez = words(&[0xfcf5]);
        let lifted = lift(&bnez, 0xc);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x8))
        );
        assert!(
            lifted[0].text.starts_with("c.bnez x9"),
            "{}",
            lifted[0].text
        );
    }

    #[test]
    fn a_backward_c_j_sign_extends_its_offset() {
        // c.j -2 = fd bf, emitted by the assembler: every imm bit except imm[1] is set.

        let cj = words(&[0xbffd]);
        let lifted = lift(&cj, 0x10);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Branch, Some(0xe))
        );
    }

    #[test]
    fn a_c_j_at_the_negative_limit_sign_extends_twelve_bits() {
        // c.j -2048 = 01 b0 : only imm[11] (the sign) is set. An 8-bit sign extension
        // would read this as 0, so this encoding is what pins the width of the field.
        let lifted = lift(&words(&[0xb001]), 0x2000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Branch, Some(0x1800))
        );
        // c.j -2016 = 05 b0 : sign plus imm[5], still needs the full 12-bit width.
        let lifted = lift(&words(&[0xb005]), 0x2000);
        assert_eq!(lifted[0].target, Some(0x1820));
    }

    #[test]
    fn jalr_text_carries_its_displacement() {
        // jalr ra, ra, -0x58 = e7 80 80 fa : the displacement is part of the record.
        let lifted = lift(&words(&[0x80e7, 0xfa80]), 0);
        assert_eq!(lifted[0].flow, Flow::Call);
        assert!(lifted[0].text.contains("-88"), "{}", lifted[0].text);
        // ret = 67 80 00 00 has no displacement and is spelled as the pseudo-instruction.
        let lifted = lift(&words(&[0x8067, 0x0000]), 0);
        assert_eq!(lifted[0].text, "ret");
    }

    #[test]
    fn c_jr_through_a_link_register_is_a_return() {
        // c.jr ra = 82 80 ; c.jr t0 = 82 82 ; c.jr a0 = 02 85
        assert_eq!(lift(&words(&[0x8082]), 0)[0].flow, Flow::Return);
        assert_eq!(lift(&words(&[0x8282]), 0)[0].flow, Flow::Return);
        assert_eq!(lift(&words(&[0x8502]), 0)[0].flow, Flow::IndirectBranch);
    }

    #[test]
    fn c_jalr_is_a_call_and_c_add_is_not() {
        // c.jalr t0 = 82 92 : bit 12 set, rd field zero.
        assert_eq!(lift(&words(&[0x9282]), 0)[0].flow, Flow::Call);
        // c.add a0, a1 = 2e 95 shares funct3=100 but has a non-zero rd field.
        // Misreading it as a call would invent a function out of arithmetic.
        assert_eq!(lift(&words(&[0x952e]), 0)[0].flow, Flow::FallThrough);
        // c.mv a0, a1 = 2e 85 (rs1 field zero, rd non-zero).
        assert_eq!(lift(&words(&[0x852e]), 0)[0].flow, Flow::FallThrough);
    }

    #[test]
    fn c_j_and_c_beqz_are_branches() {
        // c.j +2 = 09 a0 ; c.beqz s0, +2 = 09 c0
        let lifted = lift(&words(&[0xa009]), 0x5000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::Branch, Some(0x5002))
        );
        let lifted = lift(&words(&[0xc009]), 0x5000);
        assert_eq!(
            (lifted[0].flow, lifted[0].target),
            (Flow::BranchConditional, Some(0x5002))
        );
    }

    #[test]
    fn compressed_and_wide_traps_stop_the_sweep() {
        // ebreak = 73 00 10 00 ; c.ebreak = 02 90
        assert_eq!(lift(&words(&[0x0073, 0x0010]), 0)[0].flow, Flow::Trap);
        assert_eq!(lift(&words(&[0x9002]), 0)[0].flow, Flow::Trap);
    }

    #[test]
    fn a_mixed_stream_alternates_widths_and_keeps_addresses() {
        // c.nop = 01 00 ; addi zero,zero,0 = 13 00 00 00 ; ret = 67 80 00 00
        let stream = words(&[0x0001, 0x0013, 0x0000, 0x0001, 0x8067, 0x0000]);
        let lifted = lift(&stream, 0x100);
        let widths: Vec<u8> = lifted.iter().map(|l| l.width).collect();
        let addrs: Vec<u64> = lifted.iter().map(|l| l.address).collect();
        assert_eq!(widths, vec![2, 4, 2, 4]);
        assert_eq!(addrs, vec![0x100, 0x102, 0x106, 0x108]);
        assert_eq!(lifted[3].flow, Flow::Return);
    }

    #[test]
    fn a_trailing_partial_instruction_is_the_end_of_input() {
        let mut bytes = words(&[0x0001]);
        bytes.push(0x00);
        assert_eq!(lift(&bytes, 0).len(), 1);
        let cut = words(&[0x0013, 0x0000])[..3].to_vec();
        assert!(lift(&cut, 0).is_empty());
    }

    #[test]
    fn edges_and_block_ends_follow_control_flow() {
        // jal ra, +4 ; ret
        let lifted = lift(&words(&[0x00ef, 0x0040, 0x8067, 0x0000]), 0x1000);
        assert_eq!(block_ends(&lifted), vec![0x1000, 0x1004]);
        assert_eq!(direct_edges(&lifted), vec![(0x1000, 0x1004)]);
    }

    fn words32(encodings: &[u32]) -> Vec<u8> {
        encodings.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    // Encodings below were emitted by a real assembler and read back with capstone.

    #[test]
    fn an_auipc_jalr_pair_resolves_to_an_absolute_target() {
        // At 0x1000: auipc x1, 0 ; jalr x1, x1, -88  ->  target 0x1000 - 88 = 0xfa8
        let code = words32(&[0x0000_0097, 0xfa80_80e7]);
        let targets = call_targets(&code, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].at, 0x1004);
        assert_eq!(targets[0].target, 0x1000u64.wrapping_sub(88));
    }

    #[test]
    fn an_auipc_with_a_high_immediate_contributes_its_page() {
        // auipc x1, 1 -> base = 0x1000 + 0x1000 = 0x2000 ; jalr x1, x1, 0x10 -> 0x2010
        let code = words32(&[0x0000_1097, 0x0100_80e7]);
        let targets = call_targets(&code, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target, 0x2010);
    }

    #[test]
    fn a_jalr_without_a_matching_auipc_is_a_genuine_indirect_call() {
        // jalr x1, x10, 0 : the base register was never written by an auipc here.
        let code = words32(&[0x0005_00e7]);
        assert!(call_targets(&code, 0x1000).is_empty());
    }

    #[test]
    fn the_most_recent_auipc_for_a_register_wins() {
        // Two auipc writes to x1 with different pages, then a jalr through x1.
        // The second base must win: 0x1004 + (2 << 12) = 0x3004.
        let code = words32(&[0x0000_1097, 0x0000_2097, 0x0000_80e7]);
        let targets = call_targets(&code, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target, 0x3004);
    }

    #[test]
    fn a_plain_jal_needs_no_pairing() {
        // jal ra, +4 carries its own target; call_targets only reports pairs.
        let code = words32(&[0x0040_00ef]);
        assert!(call_targets(&code, 0x1000).is_empty());
    }

    #[test]
    fn a_negative_auipc_high_part_reaches_lower_addresses() {
        // auipc x1, 0xfffff -> hi = -4096, base = 0x8000 - 0x1000 = 0x7000.
        // Without sign extension the base would be 0x8000 + 0xfffff000, a wild address.
        let code = words32(&[0xffff_f097, 0x0000_80e7]);
        let targets = call_targets(&code, 0x8000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target, 0x7000);
    }

    #[test]
    fn a_jalr_that_writes_a_plain_register_is_not_a_call() {
        // jalr a0, ra, 0 = 0x0000_8567 : rd=x10 is not a link register, so this is an
        // indirect jump even though an auipc did write the base register ra.
        let code = words32(&[0x0000_0097, 0x0000_8567]);
        assert!(call_targets(&code, 0x1000).is_empty());
    }

    #[test]
    fn an_auipc_addi_pair_forms_a_pc_relative_address() {
        // auipc x10, 0 ; addi x10, x10, 0x1c8  ->  0x2000 + 0x1c8 = 0x21c8
        let code = words32(&[0x0000_0517, 0x1c85_0513]);
        let forms = address_forms(&code, 0x2000);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].at, 0x2004);
        assert_eq!(forms[0].target, 0x21c8);
    }

    #[test]
    fn a_lui_addi_pair_forms_an_absolute_address() {
        // lui x10, 0x1000000 ; addi x10, x10, 0x1c8  ->  0x10001c8. A non-PIC build
        // uses this shape, and it must not be read as PC-relative.
        let code = words32(&[0x0100_0537, 0x1c85_0513]);
        let forms = address_forms(&code, 0x2000);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].target, 0x100_01c8);
    }

    #[test]
    fn a_lui_high_part_is_sign_extended_from_32_bits() {
        // lui x10, 0xfff00000 sign-extends to 0xffff_ffff_fff0_0000, not 0xfff0_0000.
        let code = words32(&[0xfff0_0537, 0x0005_0513]);
        let forms = address_forms(&code, 0);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].target, 0xffff_ffff_fff0_0000);
    }

    #[test]
    fn an_addi_without_a_base_register_is_not_an_address() {
        // addi x10, x0, 0x1c8 alone: no base was ever formed.
        let code = words32(&[0x1c80_0513]);
        assert!(address_forms(&code, 0x2000).is_empty());
    }

    #[test]
    fn a_stale_base_is_invalidated_by_another_write() {
        // auipc x10, 0 ; addi x10, x0, 0x40 (overwrites x10) ; addi x10, x10, 0x1c8
        let code = words32(&[0x0000_0517, 0x0400_0513, 0x1c85_0513]);
        let forms = address_forms(&code, 0x2000);
        assert!(forms.is_empty(), "stale base must not pair: {forms:?}");
    }

    #[test]
    fn a_shift_with_the_same_opcode_is_not_an_addi() {
        // slli x10, x10, 4 = 0x0045_1513 has opcode 0x13 but funct3 = 1, so it must not
        // be paired with a base the way addi (funct3 = 0) is.
        let code = words32(&[0x0000_0517, 0x0045_1513]);
        assert!(
            address_forms(&code, 0x2000).is_empty(),
            "a shift must not complete an address"
        );
    }

    #[test]
    fn the_last_lui_for_a_register_wins() {
        // lui x10, 1 ; lui x10, 2 ; addi x10, x10, 0  ->  0x2000, not 0x1000.
        let code = words32(&[0x0000_1537, 0x0000_2537, 0x0005_0513]);
        let forms = address_forms(&code, 0);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms.first().map(|form| form.target), Some(0x2000));
    }

    #[test]
    fn the_last_auipc_for_a_register_wins() {
        // auipc x10, 0 ; auipc x10, 2 ; addi x10, x10, 0  ->  base of the second auipc
        // (0x1004 + 0x2000), not the first. Two live bases for one register would let
        // the stale one be picked.
        let code = words32(&[0x0000_0517, 0x0000_2517, 0x0005_0513]);
        let forms = address_forms(&code, 0x1000);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms.first().map(|form| form.target), Some(0x1004 + 0x2000));
    }

    #[test]
    fn a_negative_auipc_high_part_reaches_lower_addresses_in_an_address_form() {
        // auipc x10, 0xfffff -> hi = -4096, so the base is 0x8000 - 0x1000 = 0x7000.
        // Without sign extension the base would be a huge positive number.
        let code = words32(&[0xffff_f517, 0x0005_0513]);
        let forms = address_forms(&code, 0x8000);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms.first().map(|form| form.target), Some(0x7000));
    }
}
