//! Turn a patchable prefix into the bytes that install a hook.
//!
//! `patchable` says whether a function's entry can take a jump; this says what
//! the jump **is**, and what the trampoline that re-executes the overwritten
//! instructions looks like. Both are pure functions over bytes. Neither touches
//! a process: the install step in `host` consumes an [`Install`] and writes it
//! under the `WriteMemory` capability, and this module cannot.
//!
//! # x64 only, and only prefixes without RIP-relative operands
//!
//! A five-byte `E9 rel32` covers the entry; the trampoline holds the displaced
//! instructions followed by a jump back to `entry + overwrite`. An instruction
//! that addresses memory relative to RIP — `mov rax, [rip+X]`, a call through
//! the GOT, any `lea` of a global — reads a different address once moved, so a
//! prefix containing one is `Unsupported`, not silently mis-executed. Most
//! function prologues are stack-relative and relocate fine; the ones that are
//! not are refused by name.

use crate::patchable::{x86_prefix, Prefix, PrefixError};
use iced_x86::Decoder;
use iced_x86::DecoderOptions;

/// The jump instruction's length on x64: `E9 rel32`.
pub const JUMP_SIZE: usize = 5;

/// Why an install plan could not be built.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InstallError {
    /// The prefix could not be evaluated; see [`PrefixError`].
    Prefix(PrefixError),
    /// An instruction in the overwritten range addresses memory relative to RIP
    /// and would read a different address from the trampoline.
    RipRelative {
        /// Offset of the instruction from the entry.
        at: u64,
    },
    /// The hook or trampoline is farther than rel32 reaches from the entry.
    OutOfRange,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prefix(e) => write!(f, "{e}"),
            Self::RipRelative { at } => write!(
                f,
                "RIP-relative instruction at +{at:#x} cannot be relocated"
            ),
            Self::OutOfRange => f.write_str("hook is farther than rel32 reaches"),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<PrefixError> for InstallError {
    fn from(e: PrefixError) -> Self {
        Self::Prefix(e)
    }
}

/// Encode `E9 rel32` from `from` to `to`.
///
/// # Errors
/// [`InstallError::OutOfRange`] when `to - (from + 5)` is outside i32.
pub fn jump_bytes(from: u64, to: u64) -> Result<[u8; JUMP_SIZE], InstallError> {
    // Signed arithmetic in i128 so a backwards jump (to < from) is a negative
    // displacement, not a checked_sub failure: the trampoline's return jump
    // always goes backwards.
    let displacement = i128::from(to) - i128::from(from) - JUMP_SIZE as i128;
    let displacement = i32::try_from(displacement).map_err(|_| InstallError::OutOfRange)?;
    let mut out = [0u8; JUMP_SIZE];
    out[0] = 0xE9;
    out[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(out)
}

/// One contiguous write the install step performs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstallWrite {
    /// Absolute address in the target.
    pub address: u64,
    /// Bytes to write.
    pub bytes: Vec<u8>,
}

/// Everything the install step writes, in order: trampoline first, then the
/// jump, so a thread that enters the function mid-install lands in a complete
/// trampoline rather than in a half-written jump.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Install {
    /// The displaced instructions, then a jump back to the entry's tail.
    pub trampoline: InstallWrite,
    /// The `E9 rel32` over the entry.
    pub jump: InstallWrite,
    /// What was overwritten, for an uninstall.
    pub original: Vec<u8>,
}

/// Plan the two writes for hooking `entry` with a jump to `hook`, the
/// trampoline living at `trampoline`.
///
/// `code` is the function from its entry, `entries` the other known entries
/// relative to it (as for [`x86_prefix`]).
///
/// # Errors
/// [`InstallError::Prefix`] if the entry cannot take the jump;
/// [`InstallError::RipRelative`] if a displaced instruction cannot be moved;
/// [`InstallError::OutOfRange`] if either jump does not fit in rel32.
pub fn plan(
    code: &[u8],
    entries: &[u64],
    entry: u64,
    hook: u64,
    trampoline: u64,
) -> Result<Install, InstallError> {
    let prefix: Prefix = x86_prefix(code, entries, 64, JUMP_SIZE)?;
    // A prefix that takes the jump but strands another entry is not installable:
    // the jump would land that entry inside its own immediate.
    if !prefix.is_patchable() {
        return Err(InstallError::Prefix(PrefixError::Stranded(prefix.stranded)));
    }
    let mut decoder = Decoder::with_ip(64, &code[..prefix.overwrite], entry, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.is_ip_rel_memory_operand() {
            return Err(InstallError::RipRelative {
                at: instruction.ip() - entry,
            });
        }
    }
    let back = jump_bytes(
        trampoline.wrapping_add(prefix.overwrite as u64),
        entry.wrapping_add(prefix.overwrite as u64),
    )?;
    let mut trampoline_bytes = code[..prefix.overwrite].to_vec();
    trampoline_bytes.extend_from_slice(&back);
    let jump = jump_bytes(entry, hook)?;
    Ok(Install {
        trampoline: InstallWrite {
            address: trampoline,
            bytes: trampoline_bytes,
        },
        jump: InstallWrite {
            address: entry,
            bytes: jump.to_vec(),
        },
        original: code[..prefix.overwrite].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The jump encodes E9 with a little-endian rel32 measured from the end
    /// of the instruction, and refuses a target rel32 cannot reach.
    ///
    /// mutate: rel-off-by-five (measuring from `from` instead of `from + 5`
    /// lands every jump five bytes past its target; the forward case asserts
    /// the exact bytes).
    #[test]
    fn a_jump_is_e9_plus_the_displacement_from_its_own_end() {
        // 0x2000 - (0x1000 + 5) = 0xFFB
        assert_eq!(
            jump_bytes(0x1000, 0x2000).unwrap(),
            [0xE9, 0xFB, 0x0F, 0x00, 0x00]
        );
        // 0x1000 - (0x2000 + 5) = -0x1005
        assert_eq!(
            jump_bytes(0x2000, 0x1000).unwrap(),
            [0xE9, 0xFB, 0xEF, 0xFF, 0xFF]
        );
        // Just in range, and just out.
        let far = 0x1000u64 + 0x7FFF_FFFFu64 + 5;
        assert!(jump_bytes(0x1000, far).is_ok());
        assert_eq!(jump_bytes(0x1000, far + 1), Err(InstallError::OutOfRange));
    }

    /// A stack-relative prologue plans: the trampoline holds the displaced
    /// bytes then a jump back to entry+overwrite, and the entry gets E9.
    ///
    /// mutate: no-return-jump (a trampoline without the trailing E9 re-executes
    /// the prologue and falls into the next function; the trampoline length
    /// never matches 8 + 5).
    #[test]
    fn a_stack_prologue_plans_two_writes() {
        // push rbp (1) ; mov rbp, rsp (3) ; sub rsp, 0x20 (4): overwrite 8.
        let code = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x90];
        let install = plan(
            &code,
            &[],
            0x7FF6_0000_1000,
            0x7FF6_0000_8000,
            0x7FF6_0000_9000,
        )
        .unwrap();
        assert_eq!(install.original, code[..8]);
        assert_eq!(install.trampoline.address, 0x7FF6_0000_9000);
        assert_eq!(install.trampoline.bytes.len(), 8 + JUMP_SIZE);
        assert_eq!(&install.trampoline.bytes[..8], &code[..8]);
        let back = jump_bytes(0x7FF6_0000_9008, 0x7FF6_0000_1008).unwrap();
        assert_eq!(&install.trampoline.bytes[8..], &back);
        assert_eq!(install.jump.address, 0x7FF6_0000_1000);
        assert_eq!(
            install.jump.bytes,
            jump_bytes(0x7FF6_0000_1000, 0x7FF6_0000_8000)
                .unwrap()
                .to_vec()
        );
    }

    /// A RIP-relative instruction in the prefix is refused by offset, not
    /// moved: `mov rax, [rip+0x10]` (48 8B 05 10 00 00 00) is 7 bytes and
    /// covers the jump on its own.
    ///
    /// mutate: rip-not-checked (skipping the check plans a trampoline that
    /// reads the wrong address; the refusal assertion never passes).
    #[test]
    fn a_rip_relative_prefix_is_refused_not_moved() {
        let code = [0x48u8, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0x90];
        assert_eq!(
            plan(&code, &[], 0x1000, 0x8000, 0x9000),
            Err(InstallError::RipRelative { at: 0 })
        );
    }

    /// The prefix's own verdicts pass through as `Prefix`: too short, stranded.
    #[test]
    fn prefix_failures_are_reported() {
        assert_eq!(
            plan(&[0xC3], &[], 0x1000, 0x8000, 0x9000),
            Err(InstallError::Prefix(PrefixError::TooShort))
        );
        // A call target at +3 inside a 5-byte overwrite strands.
        let code = [0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x90];
        assert!(matches!(
            plan(&code, &[3], 0x1000, 0x8000, 0x9000),
            Err(InstallError::Prefix(_))
        ));
    }

    /// Every function the real fixture discovers and that takes a jump plans
    /// or is refused by name — never a panic, never a plan with a RIP-relative
    /// instruction inside.
    #[test]
    fn every_discovered_function_plans_or_is_refused_by_name() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: fixture not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&data).unwrap();
        use kotama::AddressSpace as _;
        let space = module.address_space();
        let functions = crate::discover(&module);
        let (mut planned, mut refused) = (0, 0);
        for function in &functions {
            let end = function.rva.checked_add(function.size).unwrap();
            let Some(code) = space.read(function.rva, (end - function.rva) as usize) else {
                continue;
            };
            let entries: Vec<u64> = functions
                .iter()
                .filter(|o| o.rva > function.rva && o.rva < end)
                .map(|o| o.rva - function.rva)
                .collect();
            let entry = module.image_base + function.rva;
            match plan(code, &entries, entry, entry + 0x1000_0000, entry + 0x1000) {
                Ok(_) => planned += 1,
                Err(InstallError::Prefix(_)) | Err(InstallError::RipRelative { .. }) => {
                    refused += 1
                }
                Err(e) => panic!("{:?} @ {:#x}: {e}", function.name, function.rva),
            }
        }
        assert!(planned >= 3, "planned {planned}, refused {refused}");
    }
}
