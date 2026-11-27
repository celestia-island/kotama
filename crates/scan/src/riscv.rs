//! RISC-V function discovery and cross-references.
//!
//! RV64 is a load-store architecture with PC-relative control flow, so the same
//! three sources that work on A64 work here, with one improvement: an ELF symbol
//! carries an exact size, so a function named in the symbol table gets a real
//! boundary rather than an inferred one.
//!
//! Calls are `jal` with the link register written. `jalr` and `c.jalr` go through a
//! register and have no static target, so they contribute no edge and no seed, but
//! they do end a basic block. The compressed forms of every branch and return are
//! decoded as well, which matters because a `+c` build is around 40 percent smaller
//! and its returns are overwhelmingly `c.jr ra`.

use std::collections::{BTreeMap, BTreeSet};

use kotama::{AddressSpace, Evidence, FunctionEntry};
use kotama_image::{LoadedModule, SymbolInfo};
use kotama_lift_riscv::{address_forms, call_targets, lift, Flow};

use crate::{CallEdge, StringXref};

/// A function candidate under construction.
#[derive(Default)]
struct Candidate {
    size: Option<u64>,
    name: Option<String>,
    evidence: BTreeSet<Evidence>,
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

/// Discover functions in a RISC-V module.
///
/// Determinism: the same module yields the same entries in the same order.
#[must_use]
pub fn discover_riscv(module: &LoadedModule) -> Vec<FunctionEntry> {
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

    // Every call seeds its target. Under the medany code model that is an
    // `auipc` + `jalr` pair, so the target only exists after pairing; a `jal ra`
    // carries it directly. Both shapes are collected here.
    let space = module.address_space();
    for section in module.sections.iter().filter(|section| section.executable) {
        let Some(bytes) = space.read(section.rva, section.size as usize) else {
            continue;
        };
        let mut targets: Vec<u64> = call_targets(bytes, section.rva)
            .into_iter()
            .map(|call| call.target)
            .collect();
        for instruction in lift(bytes, section.rva) {
            if instruction.flow == Flow::Call {
                if let Some(target) = instruction.target {
                    targets.push(target);
                }
            }
        }
        for target in targets {
            table
                .entry(target)
                .or_default()
                .evidence
                .insert(Evidence::CallTarget);
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
            // An ELF symbol states its own size; that is a real boundary.
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
        out.push(FunctionEntry {
            rva: *rva,
            size,
            size_inferred: inferred,
            name: candidate.name.clone(),
            evidence: candidate.evidence.clone(),
        });
    }
    out
}

/// Function-level call graph for a RISC-V module.
///
/// Every `jal` with a direct target that lands inside a known function is an edge.
/// Indirect calls (`jalr`, `c.jalr`) have no static target and are skipped, as are
/// self-edges and targets outside the table.
#[must_use]
pub fn call_graph_riscv(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<CallEdge> {
    let space = module.address_space();
    let mut edges = BTreeSet::new();
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
        // Two shapes carry a call. Under the medany code model a call is
        // `auipc x1, hi` + `jalr x1, x1, lo`, so the target is only visible after
        // pairing them; a `jal ra, target` carries it directly.
        let mut targets: Vec<u64> = call_targets(bytes, function.rva)
            .into_iter()
            .map(|call| call.target)
            .collect();
        let instructions = lift(bytes, function.rva);
        for instruction in instructions {
            if instruction.flow == Flow::Call {
                if let Some(target) = instruction.target {
                    targets.push(target);
                }
            }
        }
        for target in targets {
            if let Some(callee) = FunctionEntry::containing(functions, target) {
                if callee != function.rva {
                    edges.insert(CallEdge {
                        from: function.rva,
                        to: callee,
                    });
                }
            }
        }
    }
    edges.into_iter().collect()
}

/// String references for a RISC-V module.
///
/// RISC-V cannot load a 64-bit address in one instruction, so the compiler forms a data
/// address with a two-instruction pair: `auipc`/`lui` for the high part and `addi` for the
/// low part. The pairing lives in the architecture crate; this module consumes the
/// addresses and keeps the ones that point at a printable C string in a data section.
#[must_use]
pub fn string_xrefs_riscv(module: &LoadedModule, functions: &[FunctionEntry]) -> Vec<StringXref> {
    let space = module.address_space();
    let image_base = module.image_base;
    let data_sections: Vec<(u64, u64)> = module
        .sections
        .iter()
        // A section at address 0 is file-level metadata, not part of the loaded image.
        .filter(|section| !section.executable && section.size > 0 && section.rva > 0)
        .map(|section| (section.rva, section.size))
        .collect();
    let in_data = |rva: u64| {
        data_sections
            .iter()
            .any(|(start, size)| rva >= *start && rva < start.saturating_add(*size))
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
        for form in address_forms(bytes, function.rva) {
            // address_forms reports the value the code computes, which is a virtual
            // address; section ranges are relative to the image base.
            let Some(rva) = form.target.checked_sub(image_base) else {
                continue;
            };
            if !in_data(rva) {
                continue;
            }
            if let Some(text) = crate::read_cstring(&space, rva) {
                out.insert((function.rva, rva, text));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RISC-V ELF64 with a `.text` blob and a symbol table.
    ///
    /// `LoadedModule` can only be built by parsing bytes, so the fixture is assembled
    /// here. Section header order: null, `.text`, `.symtab`, `.strtab`, `.shstrtab`.
    fn module(code: &[u8], symbols: &[(&str, u64, u64)]) -> LoadedModule {
        module_with_rodata(code, symbols, &[])
    }

    /// Same layout plus a `.rodata` section at RVA 0x2000, for string-reference tests.
    fn module_with_rodata(
        code: &[u8],
        symbols: &[(&str, u64, u64)],
        rodata: &[u8],
    ) -> LoadedModule {
        module_at(0, code, symbols, rodata)
    }

    /// The builder behind the two helpers. `base` is the link-time address of RVA 0
    /// and is also emitted as a `PT_LOAD`, so `image_base` comes out as `base` —
    /// which is what lets the rebasing path be tested.
    fn module_at(
        base: u64,
        code: &[u8],
        symbols: &[(&str, u64, u64)],
        rodata: &[u8],
    ) -> LoadedModule {
        const TEXT_RVA: u64 = 0x1000;
        const RODATA_RVA: u64 = 0x2000;
        let mut b: Vec<u8> = Vec::new();
        let p64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        let p32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let p16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
        // ELF64 header (64 bytes). e_machine = 243 (RISC-V).
        b.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        b.extend_from_slice(&[0u8; 8]);
        p16(&mut b, 2); // e_type = ET_EXEC
        p16(&mut b, 243); // e_machine = EM_RISCV
        p32(&mut b, 1); // e_version
        p64(&mut b, base + TEXT_RVA); // e_entry
        p64(&mut b, 64); // e_phoff
        p64(&mut b, 0); // e_shoff (patched below)
        p32(&mut b, 0); // e_flags
        p16(&mut b, 64); // e_ehsize
        p16(&mut b, 56); // e_phentsize
        p16(&mut b, 1); // e_phnum
        p16(&mut b, 64); // e_shentsize
        p16(&mut b, 6); // e_shnum
        p16(&mut b, 5); // e_shstrndx
        assert_eq!(b.len(), 64);
        // PT_LOAD covering the whole image at `BASE`: this is what makes image_base
        // equal `base` instead of defaulting to zero.
        p32(&mut b, 1); // p_type = PT_LOAD
        p32(&mut b, 5); // p_flags = PF_R | PF_X
        p64(&mut b, 0); // p_offset
        p64(&mut b, base); // p_vaddr
        p64(&mut b, base); // p_paddr
        p64(&mut b, 0); // p_filesz (patched below)
        p64(&mut b, 0); // p_memsz (patched below)
        p64(&mut b, 0x1000); // p_align
        assert_eq!(b.len(), 120);
        // .text payload at 0x100 (so its vaddr 0x1000 maps to file offset 0x100).
        b.resize(0x100, 0);
        let text_off = b.len() as u64;
        b.extend_from_slice(code);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        let rodata_off = b.len() as u64;
        b.extend_from_slice(rodata);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        // .strtab
        let mut strtab: Vec<u8> = vec![0];
        let mut name_off = Vec::new();
        for (name, _, _) in symbols {
            name_off.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        let strtab_off = b.len() as u64;
        b.extend_from_slice(&strtab);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        // .symtab: one null entry, then one per symbol (Elf64_Sym = 24 bytes).
        let symtab_off = b.len() as u64;
        b.extend_from_slice(&[0u8; 24]);
        for (index, (_, rva, size)) in symbols.iter().enumerate() {
            p32(&mut b, name_off[index]);
            b.push(0x12); // STB_GLOBAL | STT_FUNC
            b.push(0);
            p16(&mut b, 1); // st_shndx = .text
            p64(&mut b, base + rva);
            p64(&mut b, *size);
        }
        let sym_count = symbols.len() as u64 + 1;
        // .shstrtab
        let shstrtab_off = b.len() as u64;
        let mut shstr: Vec<u8> = vec![0];
        let mut sh_name = Vec::new();
        for name in [".text", ".rodata", ".symtab", ".strtab", ".shstrtab"] {
            sh_name.push(shstr.len() as u32);
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
        }
        b.extend_from_slice(&shstr);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        let shoff = b.len() as u64;
        let section = |b: &mut Vec<u8>,
                       name: u32,
                       kind: u32,
                       flags: u64,
                       addr: u64,
                       off: u64,
                       size: u64,
                       link: u32,
                       entsize: u64| {
            p32(b, name);
            p32(b, kind);
            p64(b, flags);
            p64(b, addr);
            p64(b, off);
            p64(b, size);
            p32(b, link);
            p32(b, 0);
            p64(b, 0);
            p64(b, entsize);
        };
        section(&mut b, 0, 0, 0, 0, 0, 0, 0, 0); // null
        section(
            &mut b,
            sh_name[0],
            1,
            6,
            base + TEXT_RVA,
            text_off,
            code.len() as u64,
            0,
            0,
        ); // .text
           // .rodata: allocated but not executable, at RVA 0x2000, so a formed address
           // can be checked against a section that is genuinely data.
        section(
            &mut b,
            sh_name[1],
            1,
            2, // SHF_ALLOC
            base + RODATA_RVA,
            rodata_off,
            rodata.len() as u64,
            0,
            0,
        ); // .rodata
        section(
            &mut b,
            sh_name[2],
            2,
            0,
            0,
            symtab_off,
            sym_count * 24,
            4,
            24,
        ); // .symtab
        section(
            &mut b,
            sh_name[3],
            3,
            0,
            0,
            strtab_off,
            strtab.len() as u64,
            0,
            0,
        ); // .strtab
        section(
            &mut b,
            sh_name[4],
            3,
            0,
            0,
            shstrtab_off,
            shstr.len() as u64,
            0,
            0,
        ); // .shstrtab
        let shoff_bytes = shoff.to_le_bytes();
        b[40..48].copy_from_slice(&shoff_bytes);
        LoadedModule::parse(&b).expect("synthetic RISC-V ELF must parse")
    }

    fn words(encodings: &[u32]) -> Vec<u8> {
        encodings.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    #[test]
    fn a_symbol_size_is_an_exact_boundary_not_an_inference() {
        let code = words(&[0x0000_0013, 0x0000_0013, 0x0000_8067]);
        let m = module(&code, &[("f", 0x1000, 8)]);
        let found = discover_riscv(&m);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].size, found[0].size_inferred), (8, false));
    }

    #[test]
    fn the_entry_point_is_seeded_with_entry_evidence() {
        let code = words(&[0x0000_8067]);
        let m = module(&code, &[]);
        let found = discover_riscv(&m);
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.contains(&Evidence::Entry));
    }

    #[test]
    fn an_auipc_jalr_call_seeds_its_target() {
        // 0x1000: auipc x1, 0 ; 0x1004: jalr x1, x1, 0  -> calls 0x1000. Use a
        // forward call instead: jalr offset 8 lands on the ret at 0x100c.
        let code = words(&[0x0000_0097, 0x0080_80e7, 0x0000_0013, 0x0000_8067]);
        let m = module(&code, &[("caller", 0x1000, 12)]);
        let found = discover_riscv(&m);
        let target = found
            .iter()
            .find(|f| f.rva == 0x1008)
            .expect("the call target must be seeded");
        assert!(target.evidence.contains(&Evidence::CallTarget));
    }

    #[test]
    fn a_call_edge_is_recorded_and_self_edges_are_not() {
        let code = words(&[0x0000_0097, 0x0080_80e7, 0x0000_0013, 0x0000_8067]);
        let m = module(&code, &[("caller", 0x1000, 12), ("callee", 0x1008, 4)]);
        let found = discover_riscv(&m);
        let edges = call_graph_riscv(&m, &found);
        assert_eq!(edges.len(), 1);
        assert_eq!((edges[0].from, edges[0].to), (0x1000, 0x1008));
    }

    #[test]
    fn a_self_call_is_not_an_edge() {
        // jalr offset 0 on a base of 0x1000 calls the function itself.
        let code = words(&[0x0000_0097, 0x0000_80e7]);
        let m = module(&code, &[("rec", 0x1000, 8)]);
        let found = discover_riscv(&m);
        assert!(call_graph_riscv(&m, &found).is_empty());
    }

    #[test]
    fn seeds_outside_executable_sections_are_dropped() {
        let code = words(&[0x0000_8067]);
        let m = module(&code, &[("data", 0x5000, 8)]);
        // The entry point is inside .text, so exactly one function survives.
        let found = discover_riscv(&m);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rva, 0x1000);
    }

    #[test]
    fn the_result_is_sorted_by_address() {
        let code = words(&[0x0000_0013, 0x0000_0013, 0x0000_0013, 0x0000_8067]);
        let m = module(
            &code,
            &[("c", 0x1008, 4), ("a", 0x1000, 4), ("b", 0x1004, 4)],
        );
        let found = discover_riscv(&m);
        let rvas: Vec<u64> = found.iter().map(|f| f.rva).collect();
        assert_eq!(rvas, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn the_public_entry_point_routes_riscv_modules_here() {
        // The tests above call discover_riscv directly, which would keep passing even
        // if the architecture gate stopped recognising RISC-V. This goes through the
        // public entry point, so the routing itself is covered.
        let code = words(&[0x0000_0013, 0x0000_8067]);
        let m = module(&code, &[("f", 0x1000, 4)]);
        assert!(m.arch.is_riscv64());
        let found = crate::discover(&m);
        // The file's entry point and the symbol share 0x1000, so they merge into one
        // entry carrying both pieces of evidence.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rva, 0x1000);
        assert!(found[0].evidence.contains(&Evidence::Symtab));
        assert!(found[0].evidence.contains(&Evidence::Entry));
    }

    #[test]
    fn a_lui_addi_pair_pointing_at_rodata_becomes_a_string_xref() {
        // lui x10, 0x2000 ; addi x10, x10, 0  ->  address 0x2000, which is .rodata.
        let code = words(&[0x0000_2537, 0x0005_0513, 0x0000_8067]);
        let m = module_with_rodata(&code, &[("f", 0x1000, 12)], b"a_literal\0");
        let fns = discover_riscv(&m);
        let xrefs = string_xrefs_riscv(&m, &fns);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].func_rva, 0x1000);
        assert_eq!(xrefs[0].string_rva, 0x2000);
        assert_eq!(xrefs[0].text, "a_literal");
    }

    #[test]
    fn an_address_outside_any_data_section_is_not_a_string_xref() {
        // The pair forms 0x9000, which no section covers, so nothing is recorded.
        let code = words(&[0x0000_9537, 0x0005_0513, 0x0000_8067]);
        let m = module_with_rodata(&code, &[("f", 0x1000, 12)], b"a_literal\0");
        let fns = discover_riscv(&m);
        assert!(string_xrefs_riscv(&m, &fns).is_empty());
    }

    #[test]
    fn a_data_address_holding_non_printable_bytes_is_not_a_string_xref() {
        // 0x2000 is inside .rodata, but its contents are not a printable C string.
        let code = words(&[0x0000_2537, 0x0005_0513, 0x0000_8067]);
        let m = module_with_rodata(&code, &[("f", 0x1000, 12)], &[0x00, 0x01, 0x02, 0x00]);
        let fns = discover_riscv(&m);
        assert!(string_xrefs_riscv(&m, &fns).is_empty());
    }

    #[test]
    fn a_formed_address_is_rebased_by_the_image_base() {
        // The same code with the image linked at 0x400000: the pair computes the
        // absolute virtual address 0x402000, and only subtracting the image base
        // yields the .rodata RVA of 0x2000. A reader that skipped the subtraction
        // would look for a string at 0x402000 and find nothing.
        let code = words(&[0x0040_2537, 0x0005_0513, 0x0000_8067]);
        let m = module_at(0x40_0000, &code, &[("f", 0x1000, 12)], b"rebased\0");
        assert_eq!(m.image_base, 0x40_0000, "fixture assumption");
        let fns = discover_riscv(&m);
        let xrefs = string_xrefs_riscv(&m, &fns);
        assert_eq!(xrefs.len(), 1, "rebased xref must be found: {xrefs:?}");
        assert_eq!(xrefs[0].string_rva, 0x2000);
        assert_eq!(xrefs[0].text, "rebased");
    }

    #[test]
    fn an_address_inside_executable_code_is_not_a_string_xref() {
        // lui x10, 1 ; addi x10, x10, 8  ->  0x1008, which is inside .text. The bytes
        // there are printable, so only the data-section filter keeps this out; a reader
        // that skipped the filter would report a string out of executable memory.
        let mut code = words(&[0x0000_1537, 0x0085_0513]);
        code.extend_from_slice(b"HELLO\0\0\0");
        let m = module_with_rodata(&code, &[("f", 0x1000, 16)], b"data_literal\0");
        let fns = discover_riscv(&m);
        let xrefs = string_xrefs_riscv(&m, &fns);
        assert!(
            xrefs.iter().all(|x| x.string_rva != 0x1008),
            "an executable address must not be reported as a string: {xrefs:?}"
        );
    }
}
