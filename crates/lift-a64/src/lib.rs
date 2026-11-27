//! Aarch64 instruction lifting: structured decode and control-flow facts.
//!
//! A64 is fixed-width (every instruction is 4 bytes) and its branch targets are
//! PC-relative immediates, so a linear sweep recovers every direct edge without
//! guessing. This crate turns decoded instructions into the small set of facts the
//! scan pipeline needs: an address, a length, a mnemonic, and what control flow (if
//! any) leaves the instruction.
//!
//! It is deterministic and I/O-free: the same bytes produce the same facts.

use std::fmt;
use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{ARMv8, InstDecoder, Instruction, Opcode, Operand};
/// Width of every A64 instruction, in bytes.
pub const INSTRUCTION_SIZE: u64 = 4;

/// What an instruction does to control flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    /// Falls through to the next instruction.
    FallThrough,
    /// Unconditional branch to a PC-relative target.
    Branch,
    /// Conditional branch; taken target plus fall-through.
    BranchConditional,
    /// Subroutine call (BL / BLR).
    Call,
    /// Return from subroutine.
    Return,
    /// Unconditional branch to a register (switch tables, tail calls).
    IndirectBranch,
    /// Terminates control flow (BRK / HLT / UDF).
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

    /// True when the instruction ends a basic block.
    #[must_use]
    pub const fn ends_block(self) -> bool {
        !matches!(self, Self::FallThrough)
    }
}

/// One lifted instruction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lifted {
    /// Address of the instruction.
    pub address: u64,
    /// Disassembly text.
    pub text: String,
    /// Control-flow effect.
    pub flow: Flow,
    /// Direct target address when the flow has one.
    pub target: Option<u64>,
}

impl fmt::Display for Lifted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.target {
            Some(target) => write!(
                f,
                "{:#x}: {} -> {:#x} [{}]",
                self.address,
                self.text,
                target,
                self.flow.short()
            ),
            None => write!(
                f,
                "{:#x}: {} [{}]",
                self.address,
                self.text,
                self.flow.short()
            ),
        }
    }
}

/// Decode error from the underlying decoder.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiftError(pub String);

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LiftError {}

/// Classify an opcode's control-flow effect and extract its direct target.
fn classify(instruction: &Instruction, address: u64) -> (Flow, Option<u64>) {
    // B, Bcc and BL all carry their PC-relative displacement as the last operand.
    let pc_target = |instruction: &Instruction| -> Option<u64> {
        instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::PCOffset(offset) => Some((address as i64 + *offset) as u64),
                _ => None,
            })
    };
    match instruction.opcode {
        Opcode::B => (Flow::Branch, pc_target(instruction)),
        Opcode::Bcc(_) => (Flow::BranchConditional, pc_target(instruction)),
        Opcode::BL => (Flow::Call, pc_target(instruction)),
        Opcode::BLR => (Flow::Call, None),
        Opcode::RET => (Flow::Return, None),
        Opcode::BR => (Flow::IndirectBranch, None),
        Opcode::BRK | Opcode::HLT | Opcode::UDF => (Flow::Trap, None),
        _ => (Flow::FallThrough, None),
    }
}

/// Lift a byte slice starting at `address` into instruction facts.
///
/// Stops at the first undecodable word, returning what was lifted before it
/// together with the error, so a caller can still use the prefix. A trailing
/// partial word is not an error: it is simply the end of input.
///
/// # Errors
/// Returns [LiftError] when the underlying decoder rejects a whole word.
pub fn lift(bytes: &[u8], address: u64) -> (Vec<Lifted>, Option<LiftError>) {
    let mut out = Vec::new();
    // The reader implements Reader<A, u8> for every address width, so naming
    // the decoder's concrete type is what pins the address to u64 here.
    let decoder: <ARMv8 as Arch>::Decoder = InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    let mut pc = address;
    loop {
        match decoder.decode(&mut reader) {
            Ok(decoded) => {
                let (flow, target) = classify(&decoded, pc);
                out.push(Lifted {
                    address: pc,
                    text: format!("{}", decoded),
                    flow,
                    target,
                });
                pc += INSTRUCTION_SIZE;
            }
            Err(error) => {
                // A clean end is "fewer than one instruction left", judged by
                // bytes consumed so far, not by a decode failure.
                let consumed = out.len() * (INSTRUCTION_SIZE as usize);
                if bytes.len() - consumed < (INSTRUCTION_SIZE as usize) {
                    // Clean end of input: the trailing word was simply absent.
                    return (out, None);
                }
                return (out, Some(LiftError(error.to_string())));
            }
        }
    }
}

/// Addresses that end a basic block, in order.
#[must_use]
pub fn block_ends(instructions: &[Lifted]) -> Vec<u64> {
    instructions
        .iter()
        .filter(|lifted| lifted.flow.ends_block())
        .map(|lifted| lifted.address)
        .collect()
}

/// Every direct control-flow edge (from, to) in address order.
#[must_use]
pub fn direct_edges(instructions: &[Lifted]) -> Vec<(u64, u64)> {
    instructions
        .iter()
        .filter_map(|lifted| lifted.target.map(|target| (lifted.address, target)))
        .collect()
}

/// One `ADRP` + `ADD` pair, which is how A64 forms a data address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressForm {
    /// Address of the `ADD` that completes the address.
    pub at: u64,
    /// The absolute (image-relative) address the pair computes.
    pub target: u64,
}

/// Page base computed by an `ADRP` at `pc` with the given offset.
const fn adrp_page(pc: u64, offset: i64) -> u64 {
    // ADRP rounds the PC down to 4 KiB, then adds the (already shifted) offset.
    (pc & !0xfff).wrapping_add(offset as u64)
}

/// The 12-bit immediate of an `ADD (immediate)` operand, if it is one.
fn add_immediate(operand: &Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(u64::from(*value)),
        Operand::ImmShift(value, shift) => Some(u64::from(*value) << *shift),
        _ => None,
    }
}

/// Every `ADRP` + `ADD` address formed in `bytes` starting at `address`.
///
/// Tracks the most recent `ADRP` per base register and pairs it with the next
/// `ADD` that reads that register. This is the A64 idiom for taking the address
/// of a static object, so the result is exactly the set of data addresses the
/// code materialises, without the caller knowing any opcode.
#[must_use]
pub fn address_forms(bytes: &[u8], address: u64) -> Vec<AddressForm> {
    use yaxpeax_arch::{Arch, Decoder, U8Reader};
    use yaxpeax_arm::armv8::a64::{ARMv8, Opcode};
    let decoder: <ARMv8 as Arch>::Decoder = InstDecoder::default();
    let mut reader = U8Reader::new(bytes);
    let mut pc = address;
    let mut pages: Vec<(u64, u64)> = Vec::new();
    let mut out = Vec::new();
    while let Ok(decoded) = decoder.decode(&mut reader) {
        match decoded.opcode {
            Opcode::ADRP => {
                if let (Operand::Register(_, rd), Operand::PCOffset(offset)) =
                    (decoded.operands[0], decoded.operands[1])
                {
                    pages.retain(|(reg, _)| *reg != u64::from(rd));
                    pages.push((u64::from(rd), adrp_page(pc, offset)));
                }
            }
            Opcode::ADD => {
                // `add xd, xn, #imm` materialises an address into a register.
                if let (Operand::RegisterOrSP(_, rn), Some(imm)) =
                    (decoded.operands[1], add_immediate(&decoded.operands[2]))
                {
                    if let Some((_, page)) = pages.iter().find(|(reg, _)| *reg == u64::from(rn)) {
                        out.push(AddressForm {
                            at: pc,
                            target: page.wrapping_add(imm),
                        });
                    }
                }
            }
            // `ldr/str xt, [xn, #imm]` is the commonest A64 memory shape: the
            // base is a paged register and the offset indexes into that page.
            Opcode::LDR
            | Opcode::LDRB
            | Opcode::LDRH
            | Opcode::LDRSW
            | Opcode::STR
            | Opcode::STRB
            | Opcode::STRH => {
                for operand in &decoded.operands[1..] {
                    if let Operand::RegPreIndex(rn, offset, false) = *operand {
                        if let Some((_, page)) = pages.iter().find(|(reg, _)| *reg == u64::from(rn))
                        {
                            out.push(AddressForm {
                                at: pc,
                                target: page.wrapping_add(offset as u64),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        pc += INSTRUCTION_SIZE;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encoding reference: A64 is little-endian, 4 bytes per instruction.
    //   ORR (immediate) w20, w20, #4   = 0x321e0294 -> 94 02 1e 32
    //   B   .+8 (offset +8 = 2 words)   = 0x14000002 -> 02 00 00 14
    //   BL  .+4 (offset +4 = 1 word)   = 0x94000001 -> 01 00 00 94
    //   RET                            = 0xd65f03c0 -> c0 03 5f d6
    //   NOP                            = 0xd503201f -> 1f 20 03 d5

    fn words(encodings: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        for encoding in encodings {
            out.extend_from_slice(&encoding.to_le_bytes());
        }
        out
    }

    #[test]
    fn decodes_the_documented_orr_immediate() {
        // The example from the decoder's own documentation.
        let bytes = [0x94, 0x02, 0x1e, 0x32];
        let (lifted, err) = lift(&bytes, 0x1000);
        assert!(err.is_none());
        assert_eq!(lifted.len(), 1);
        assert_eq!(lifted[0].text, "orr w20, w20, #0x4");
        assert_eq!(lifted[0].flow, Flow::FallThrough);
        assert_eq!(lifted[0].target, None);
    }

    #[test]
    fn unconditional_branch_targets_are_pc_relative() {
        // B .+8 : at 0x2000, offset +8 -> 0x2008.
        let bytes = words(&[0x1400_0002]);
        let (lifted, _) = lift(&bytes, 0x2000);
        assert_eq!(lifted[0].flow, Flow::Branch);
        assert_eq!(lifted[0].target, Some(0x2008));
    }

    #[test]
    fn backward_branch_targets_are_pc_relative() {
        // B .-4 : at 0x3000, offset -4 -> 0x2ffc.
        let bytes = words(&[0x17ff_ffff]);
        let (lifted, _) = lift(&bytes, 0x3000);
        assert_eq!(lifted[0].flow, Flow::Branch);
        assert_eq!(lifted[0].target, Some(0x2ffc));
    }

    #[test]
    fn call_and_return_are_classified() {
        // BL .+4 at 0x4000 -> 0x4004, then RET.
        let bytes = words(&[0x9400_0001, 0xd65f_03c0]);
        let (lifted, _) = lift(&bytes, 0x4000);
        assert_eq!(lifted[0].flow, Flow::Call);
        assert_eq!(lifted[0].target, Some(0x4004));
        assert_eq!(lifted[1].flow, Flow::Return);
        assert_eq!(lifted[1].target, None);
    }

    #[test]
    fn block_ends_and_edges_follow_control_flow() {
        // NOP ; B .+8 ; NOP  -- two blocks, one edge.
        let bytes = words(&[0xd503_201f, 0x1400_0002, 0xd503_201f]);
        let (lifted, _) = lift(&bytes, 0x5000);
        assert_eq!(lifted.len(), 3);
        assert_eq!(block_ends(&lifted), vec![0x5004]);
        assert_eq!(direct_edges(&lifted), vec![(0x5004, 0x500c)]);
    }

    #[test]
    fn truncated_input_stops_cleanly() {
        // One full instruction plus a stray byte: no error, one instruction.
        let mut bytes = words(&[0xd503_201f]);
        bytes.push(0x00);
        let (lifted, err) = lift(&bytes, 0);
        assert_eq!(lifted.len(), 1);
        assert!(err.is_none());
    }

    #[test]
    fn every_instruction_is_four_bytes() {
        let bytes = words(&[0xd503_201f, 0xd503_201f, 0xd503_201f]);
        let (lifted, _) = lift(&bytes, 0x100);
        assert_eq!(
            lifted.iter().map(|l| l.address).collect::<Vec<_>>(),
            vec![0x100, 0x104, 0x108]
        );
    }
}
