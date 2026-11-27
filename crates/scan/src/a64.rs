//! Aarch64 function discovery.
//!
//! A64 has no equivalent of the PE `.pdata` exception directory that the x86 path
//! relies on for exact bounds, but it has something nearly as good: every `BL`
//! instruction is a call with a PC-relative target, so a linear sweep over executable
//! sections recovers every direct callee without any heuristic. Symbols and the
//! image entry point seed the table; `BL` targets add functions the symbols missed;
//! sizes come from the symbol when it has one and are otherwise inferred as the
//! distance to the next entry. The compact unwind index adds every function that
//! has a stack frame, which is the only source that survives stripping.

use std::collections::BTreeMap;

use kotama::{AddressSpace, Evidence};
use kotama_image::{LoadedModule, SymbolInfo};
use kotama_lift_a64::{lift, Flow};

/// A function candidate under construction.
#[derive(Default)]
struct Candidate {
    size: Option<u64>,
    name: Option<String>,
    evidence: std::collections::BTreeSet<Evidence>,
}

/// Add a symbol to the table.
fn seed_symbol(table: &mut BTreeMap<u64, Candidate>, symbol: &SymbolInfo, evidence: Evidence) {
    let entry = table.entry(symbol.rva).or_default();
    entry.evidence.insert(evidence);
    if entry.size.is_none() && symbol.size > 0 {
        entry.size = Some(symbol.size);
    }
    if entry.name.is_none() && !symbol.name.is_empty() {
        entry.name = Some(symbol.name.clone());
    }
}

/// Discover functions in an Aarch64 module.
///
/// Determinism: the same module yields the same entries in the same order.
#[must_use]
pub fn discover_a64(module: &LoadedModule) -> Vec<kotama::FunctionEntry> {
    let mut table: BTreeMap<u64, Candidate> = BTreeMap::new();
    for symbol in module.symbols.iter().chain(&module.dynamic_symbols) {
        seed_symbol(&mut table, symbol, Evidence::Symtab);
    }
    for symbol in &module.debug_functions {
        seed_symbol(&mut table, symbol, Evidence::Dwarf);
    }
    if let Some(entry) = module.entry_rva {
        table
            .entry(entry)
            .or_default()
            .evidence
            .insert(Evidence::Entry);
    }

    // Every BL target is a function entry. Sweep each executable section once.
    let space = module.address_space();
    for section in module.sections.iter().filter(|section| section.executable) {
        let Some(bytes) = space.read(section.rva, section.size as usize) else {
            continue;
        };
        let (instructions, _) = lift(bytes, section.rva);
        for instruction in instructions {
            if instruction.flow == Flow::Call {
                if let Some(target) = instruction.target {
                    table
                        .entry(target)
                        .or_default()
                        .evidence
                        .insert(Evidence::CallTarget);
                }
            }
        }
    }

    // Compact unwind names every function that has a stack frame. It is the
    // Mach-O counterpart of the PE exception directory: exhaustive for non-leaf
    // functions and present in a stripped binary, where symbols are not.
    if let Some(section) = module
        .sections
        .iter()
        .find(|section| section.name == "__unwind_info")
    {
        if let Some(bytes) = space.read(section.rva, section.size as usize) {
            if let Ok(offsets) = kotama_image::macho_unwind::function_offsets(bytes) {
                for rva in offsets {
                    table
                        .entry(rva)
                        .or_default()
                        .evidence
                        .insert(Evidence::UnwindInfo);
                }
            }
        }
    }

    // Keep only entries that land inside an executable section.
    let is_code = |rva: u64| {
        module.sections.iter().any(|section| {
            section.executable
                && rva >= section.rva
                && rva < section.rva.saturating_add(section.size)
        })
    };
    let keys: Vec<u64> = table.keys().copied().filter(|rva| is_code(*rva)).collect();
    let mut out = Vec::with_capacity(keys.len());
    for (index, rva) in keys.iter().enumerate() {
        let candidate = &table[rva];
        let (size, inferred) = match candidate.size {
            Some(size) => (size, false),
            None => {
                // Distance to the next entry, capped at the end of this section.
                let next = keys.get(index + 1).copied().unwrap_or(u64::MAX);
                let section_end = module
                    .sections
                    .iter()
                    .filter(|section| section.executable)
                    .find(|section| {
                        *rva >= section.rva && *rva < section.rva.saturating_add(section.size)
                    })
                    .map_or(u64::MAX, |section| section.rva.saturating_add(section.size));
                let end = next.min(section_end);
                (end.saturating_sub(*rva), true)
            }
        };
        out.push(kotama::FunctionEntry {
            rva: *rva,
            size,
            size_inferred: inferred,
            name: candidate.name.clone(),
            evidence: candidate.evidence.clone(),
        });
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use kotama_image::Arch;

    /// Build a minimal Mach-O 64 carrying an A64 `__text` section, a symbol table
    /// with the given (name, rva, size) entries, and an entry point at the first symbol.
    ///
    /// Same layout the image crate's own Mach-O tests use; assembled here because
    /// `LoadedModule` can only be built by parsing bytes.
    fn module(code: &[u8], symbols: &[(&str, u64, u64)]) -> LoadedModule {
        const BASE: u64 = 0x1_0000_0000;
        let mut b = Vec::new();
        let p64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        let p32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        // mach_header_64, CPU_TYPE_ARM64 = 0x0100000c
        p32(&mut b, 0xfeed_facf);
        p32(&mut b, 0x0100_000c);
        p32(&mut b, 0);
        p32(&mut b, 2);
        p32(&mut b, 4);
        let sizeofcmds_pos = b.len();
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        let cmds_start = b.len();
        p32(&mut b, 0x19);
        p32(&mut b, 72);
        b.extend_from_slice(b"__PAGEZERO\0\0\0\0\0\0");
        p64(&mut b, 0);
        p64(&mut b, 0x1_0000_0000);
        p64(&mut b, 0);
        p64(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        let code_offset = 0x2000u32;
        let code_len = code.len() as u32;
        p32(&mut b, 0x19);
        p32(&mut b, 72 + 80);
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        p64(&mut b, BASE);
        p64(&mut b, 0x1000);
        p64(&mut b, 0);
        p64(&mut b, 0x1000);
        p32(&mut b, 5);
        p32(&mut b, 5);
        p32(&mut b, 1);
        p32(&mut b, 0);
        b.extend_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        p64(&mut b, BASE + 0x1000);
        p64(&mut b, code_len as u64);
        p32(&mut b, code_offset);
        p32(&mut b, 4);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0x80000400);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0x2);
        p32(&mut b, 24);
        let symoff_pos = b.len();
        p32(&mut b, 0);
        p32(&mut b, symbols.len() as u32);
        let stroff_pos = b.len();
        p32(&mut b, 0);
        let strsize_pos = b.len();
        p32(&mut b, 0);
        p32(&mut b, 0x80000028);
        p32(&mut b, 24);
        let entryoff_pos = b.len();
        p64(&mut b, 0);
        p64(&mut b, 0);
        let sizeofcmds = (b.len() - cmds_start) as u32;
        b[sizeofcmds_pos..sizeofcmds_pos + 4].copy_from_slice(&sizeofcmds.to_le_bytes());
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let symoff = b.len() as u32;
        let mut strtab = vec![0u8];
        let mut strx = Vec::new();
        for (name, _, _) in symbols {
            strx.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        for (index, (_, rva, _)) in symbols.iter().enumerate() {
            p32(&mut b, strx[index]);
            b.push(0x0f);
            b.push(1);
            b.extend_from_slice(&0u16.to_le_bytes());
            p64(&mut b, BASE + rva);
        }
        let stroff = b.len() as u32;
        b.extend_from_slice(&strtab);
        b[symoff_pos..symoff_pos + 4].copy_from_slice(&symoff.to_le_bytes());
        b[stroff_pos..stroff_pos + 4].copy_from_slice(&stroff.to_le_bytes());
        b[strsize_pos..strsize_pos + 4].copy_from_slice(&(strtab.len() as u32).to_le_bytes());
        if let Some((_, entry_rva, _)) = symbols.first() {
            b[entryoff_pos..entryoff_pos + 8].copy_from_slice(&(*entry_rva).to_le_bytes());
        }
        b.resize(code_offset as usize, 0);
        b.extend_from_slice(code);
        LoadedModule::parse(&b).expect("synthetic Mach-O must parse")
    }

    fn words(encodings: &[u32]) -> Vec<u8> {
        encodings.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    #[test]
    fn is_aarch64_is_name_based() {
        assert!(Arch::Other("aarch64").is_aarch64());
        assert!(Arch::Other("aarch64_ilp32").is_aarch64());
        assert!(!Arch::Other("arm").is_aarch64());
        assert!(!Arch::X86_64.is_aarch64());
    }

    #[test]
    fn bl_targets_become_call_target_evidence() {
        // main @0x1000: bl .+12 -> 0x100c ; bl .+8 -> 0x100c ; ret
        // callee @0x100c: ret
        let code = words(&[0x9400_0003, 0x9400_0002, 0xd65f_03c0, 0xd65f_03c0]);
        let module = module(&code, &[("_main", 0x1000, 0)]);
        let found = discover_a64(&module);
        // Two entries: main, and the single callee both calls reach.
        assert_eq!(found.len(), 2);
        let main = &found[0];
        assert_eq!(main.rva, 0x1000);
        // Mach-O symbols carry no size, so the bound is the distance to the
        // next entry, which the BL sweep discovered.
        assert_eq!((main.size, main.size_inferred), (12, true));
        assert!(main.evidence.contains(&Evidence::Entry));
        let callee = &found[1];
        assert_eq!(callee.rva, 0x100c);
        assert!(callee.evidence.contains(&Evidence::CallTarget));
        assert!(
            callee.name.is_none(),
            "a BL target has no name unless a symbol says so"
        );
    }

    #[test]
    fn a_symbol_without_size_is_bounded_by_the_next_entry() {
        // Mach-O symbols never carry a size, so every bound is inferred: the
        // first entry reaches the second, and the last reaches the section end.
        let code = words(&[0xd65f_03c0, 0xd65f_03c0, 0xd65f_03c0]);
        let module = module(&code, &[("_a", 0x1000, 0), ("_b", 0x1004, 0)]);
        let found = discover_a64(&module);
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].size, found[0].size_inferred), (4, true));
        // The last entry is bounded by the end of the executable section.
        assert_eq!((found[1].size, found[1].size_inferred), (8, true));
    }

    #[test]
    fn seeds_outside_executable_sections_are_dropped() {
        // A data symbol must not become a function.
        let code = words(&[0xd65f_03c0]);
        let module = module(&code, &[("_data", 0x5000, 8), ("_main", 0x1000, 4)]);
        let found = discover_a64(&module);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("_main"));
    }

    #[test]
    fn the_result_is_sorted_by_address() {
        // Symbols given out of order still come back sorted.
        let code = words(&[0xd65f_03c0, 0xd65f_03c0, 0xd65f_03c0]);
        let module = module(
            &code,
            &[("_c", 0x1008, 4), ("_a", 0x1000, 4), ("_b", 0x1004, 4)],
        );
        let found = discover_a64(&module);
        let rvas: Vec<u64> = found.iter().map(|f| f.rva).collect();
        assert_eq!(rvas, vec![0x1000, 0x1004, 0x1008]);
    }
}
