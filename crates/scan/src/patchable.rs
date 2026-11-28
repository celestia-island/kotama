//! Is a function's entry safe to overwrite with a jump, and how many bytes.
//!
//! Installing a hook means writing a jump over the first bytes of a function.
//! On x86 that is `E9 rel32` — five bytes — and the bytes it replaces must be
//! whole instructions, because the trampoline will re-execute them. It also
//! requires that **no other entry point lands inside those bytes**: a jump
//! target or a symbol that points into the middle of what gets overwritten
//! would land in the middle of the jump, on garbage.
//!
//! This module computes both facts from bytes and a set of known entries. It
//! does not install anything. It is the read-only prerequisite the install step
//! (#190's missing fourth link) will consume, and it is useful on its own: a
//! plan that names a function whose entry cannot take a five-byte jump is a
//! plan that cannot be carried out, and knowing that before touching the
//! process is the whole point.
//!
//! Only x86 is handled — the only architecture with a decoder here. Other
//! architectures return `Err(Unsupported)`, not a guess.

use iced_x86::Decoder;
use iced_x86::DecoderOptions;

/// Why a prefix could not be evaluated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PrefixError {
    /// Not an x86 image.
    Unsupported,
    /// The decoder ran out of bytes before covering `wanted`.
    TooShort,
    /// An instruction the decoder refused; `at` is its offset from the entry.
    Undecodable {
        /// Offset from the function's entry, in bytes.
        at: u64,
    },
    /// Known entries that land inside the bytes a jump would overwrite. The
    /// prefix is evaluated but not installable; raised by consumers that need
    /// the verdict as an error rather than a field.
    Stranded(Vec<u64>),
}

impl std::fmt::Display for PrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("no decoder for this architecture"),
            Self::TooShort => f.write_str("function too short to hold the jump"),
            Self::Undecodable { at } => write!(f, "undecodable instruction at {at:#x}"),
            Self::Stranded(entries) => {
                write!(f, "entries at {entries:?} would land inside the jump")
            }
        }
    }
}

impl std::error::Error for PrefixError {}

/// What overwriting the entry would need.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Prefix {
    /// How many bytes a jump must overwrite: the smallest whole-instruction
    /// boundary that is at least the jump's size.
    pub overwrite: usize,
    /// Instructions in the overwritten range, as (offset from entry, length).
    pub instructions: Vec<(u64, u8)>,
    /// Known entries (call targets, symbols, pointer targets) that land inside
    /// the overwritten range but not at its start. Non-empty means a jump here
    /// would strand them.
    pub stranded: Vec<u64>,
}

impl Prefix {
    /// Whether the jump can go in: whole instructions, nothing stranded.
    #[must_use]
    pub fn is_patchable(&self) -> bool {
        self.stranded.is_empty()
    }
}

/// The bytes a five-byte `E9 rel32` must cover, evaluated for x86-64.
///
/// `code` is the function from its entry; `entries` are all known entry
/// addresses **relative to the function's entry** (0 is the function itself and
/// is not stranded). The function's own length is `code.len()`, so a jump that
/// needs more than the function has is `TooShort`, not an overwrite into the
/// next function.
///
/// # Errors
/// [`PrefixError::TooShort`] if the function is shorter than the jump;
/// [`PrefixError::Undecodable`] if the decoder stops before covering it.
pub fn x86_prefix(
    code: &[u8],
    entries: &[u64],
    bitness: u32,
    jump_size: usize,
) -> Result<Prefix, PrefixError> {
    if !matches!(bitness, 16 | 32 | 64) {
        return Err(PrefixError::Unsupported);
    }
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut covered = 0usize;
    while covered < jump_size {
        if !decoder.can_decode() {
            return Err(PrefixError::TooShort);
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(PrefixError::Undecodable { at: covered as u64 });
        }
        let length = u8::try_from(instruction.len()).unwrap_or(u8::MAX);
        instructions.push((covered as u64, length));
        covered += usize::from(length);
    }
    let stranded = entries
        .iter()
        .copied()
        .filter(|&e| e > 0 && (e as usize) < covered)
        .collect::<Vec<_>>();
    Ok(Prefix {
        overwrite: covered,
        instructions,
        stranded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotama::AddressSpace as _;

    const BITNESS: u32 = 64;

    /// `push rbp; mov rbp, rsp` is 1+3 bytes, so a 5-byte jump needs a third
    /// instruction. The classic prologue `48 89 5c 24 08` (`mov [rsp+8], rbx`)
    /// is exactly 5 and covers on its own.
    ///
    /// mutate: boundary-off-by-one (covering one byte less than the jump makes
    /// a 4-byte boundary "enough" and the overwrite lands mid-instruction).
    #[test]
    fn a_five_byte_jump_lands_on_a_whole_instruction_boundary() {
        // mov [rsp+8], rbx (5) ; push rbp (1) ; ...
        let code = [0x48u8, 0x89, 0x5c, 0x24, 0x08, 0x55, 0x48, 0x89, 0xe5];
        let p = x86_prefix(&code, &[], BITNESS, 5).unwrap();
        assert_eq!(p.overwrite, 5);
        assert_eq!(p.instructions, vec![(0, 5)]);
        assert!(p.is_patchable());
        // push rbp (1) ; mov rbp, rsp (3) ; needs the next instruction too.
        let code = [0x55u8, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20];
        let p = x86_prefix(&code, &[], BITNESS, 5).unwrap();
        assert_eq!(
            p.overwrite, 8,
            "1 + 3 does not reach 5; sub rsp,0x20 (4) does"
        );
        assert_eq!(p.instructions.len(), 3);
    }

    /// An entry inside the overwritten range strands: a call target at +3 would
    /// land inside the jump's immediate. The plan must refuse.
    ///
    /// mutate: stranded-not-seen (dropping the filter makes a +3 call target
    /// pass as patchable; the assertion on is_patchable fails).
    #[test]
    fn an_entry_inside_the_overwritten_range_is_stranded() {
        let code = [0x48u8, 0x89, 0x5c, 0x24, 0x08, 0x55, 0x48, 0x89, 0xe5];
        let p = x86_prefix(&code, &[3], BITNESS, 5).unwrap();
        assert_eq!(p.stranded, vec![3]);
        assert!(!p.is_patchable());
        // At +5 — the next instruction — is fine: it is outside the overwrite.
        let p = x86_prefix(&code, &[5], BITNESS, 5).unwrap();
        assert!(p.stranded.is_empty());
        // The function's own entry (0) is never stranded.
        let p = x86_prefix(&code, &[0], BITNESS, 5).unwrap();
        assert!(p.stranded.is_empty());
    }

    /// A function shorter than the jump is TooShort, never an overwrite into
    /// the next function's bytes.
    #[test]
    fn a_short_function_is_too_short_not_overwritten() {
        // ret (1)
        let code = [0xc3u8];
        assert_eq!(
            x86_prefix(&code, &[], BITNESS, 5),
            Err(PrefixError::TooShort)
        );
        // Exactly 5: a 5-byte instruction alone is enough.
        let code = [0x48u8, 0x89, 0x5c, 0x24, 0x08];
        assert_eq!(x86_prefix(&code, &[], BITNESS, 5).unwrap().overwrite, 5);
    }

    /// The real PE fixture: every discovered function with at least five bytes
    /// yields a whole-instruction boundary, and the boundary never exceeds the
    /// function. Computed over actual discovered functions, not a hand-picked
    /// prologue.
    #[test]
    fn every_discovered_function_in_the_fixture_yields_a_boundary() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/generated/x86_64-windows-gnu/-O2/spin.exe");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skip: fixture not built");
            return;
        };
        let module = kotama_image::LoadedModule::parse(&data).unwrap();
        let space = module.address_space();
        let functions = crate::discover(&module);
        assert!(functions.len() >= 5);
        let mut evaluated = 0;
        for function in &functions {
            let end = function.rva.checked_add(function.size).unwrap();
            let Some(code) = space.read(function.rva, (end - function.rva) as usize) else {
                continue;
            };
            let entries: Vec<u64> = functions
                .iter()
                .filter(|other| other.rva > function.rva && other.rva < end)
                .map(|other| other.rva - function.rva)
                .collect();
            match x86_prefix(code, &entries, BITNESS, 5) {
                Ok(prefix) => {
                    assert!(prefix.overwrite >= 5);
                    assert!(prefix.overwrite <= code.len());
                    evaluated += 1;
                }
                Err(PrefixError::TooShort) => {}
                Err(e) => panic!("{:?} @ {:#x}: {e}", function.name, function.rva),
            }
        }
        assert!(
            evaluated >= 3,
            "most functions should take a jump: {evaluated}"
        );
    }

    /// Non-x86 bitness is Unsupported, not a guess.
    #[test]
    fn other_bitnesses_are_unsupported() {
        assert_eq!(
            x86_prefix(&[0x90; 8], &[], 0, 5),
            Err(PrefixError::Unsupported)
        );
    }
}
