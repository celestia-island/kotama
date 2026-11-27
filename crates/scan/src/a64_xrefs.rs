//! Aarch64 cross-references: call graph and string references.
//!
//! The x86 paths rely on two x86-only shapes: RIP-relative memory operands and
//! absolute `imm32` addresses. A64 forms a data address with an `ADRP` + `ADD` pair
//! instead, so the pairing lives in the architecture crate and this view only
//! consumes the resulting addresses. Both functions are deterministic and I/O-free.

use std::collections::BTreeSet;

use crate::ScanView;
use kotama::{AddressSpace, FunctionEntry};
use kotama_lift_a64::{address_forms, lift, Flow};

use crate::{read_cstring, CallEdge, StringXref};

/// Function-level call graph for an Aarch64 view.
///
/// Every `BL` with a direct target that lands inside a known function is an edge.
/// Indirect calls (`BLR`) have no static target and are skipped, as are
/// self-edges and targets outside the table.
#[must_use]
pub fn call_graph_a64(
    _view: &ScanView,
    space: &dyn AddressSpace,
    functions: &[FunctionEntry],
) -> Vec<CallEdge> {
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
        let (instructions, _) = lift(bytes, function.rva);
        for instruction in instructions {
            if instruction.flow != Flow::Call {
                continue;
            }
            let Some(target) = instruction.target else {
                continue;
            };
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

/// String references for an Aarch64 view.
///
/// An `ADRP` + `ADD` pair is a reference only when the address lands in a data
/// section and a printable NUL-terminated string can be read there.
#[must_use]
pub fn string_xrefs_a64(
    view: &ScanView,
    space: &dyn AddressSpace,
    functions: &[FunctionEntry],
) -> Vec<StringXref> {
    let data_sections: Vec<(u64, u64)> = view
        .sections
        .iter()
        .filter(|section| !section.executable && section.size > 0 && section.rva > 0)
        .map(|section| (section.rva, section.size))
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
        for form in address_forms(bytes, function.rva) {
            if !in_data(form.target) {
                continue;
            }
            if let Some(text) = read_cstring(space, form.target) {
                out.insert((function.rva, form.target, text));
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
    use kotama_image::LoadedModule;

    /// Build a minimal Mach-O 64 with an A64 `__text` and a `__cstring` section.
    ///
    /// `LoadedModule` can only be built by parsing bytes, so the fixture is assembled
    /// here. Layout mirrors the image crate's own Mach-O tests.
    fn view(code: &[u8], cstrings: &[u8], symbols: &[(&str, u64)]) -> LoadedModule {
        const BASE: u64 = 0x1_0000_0000;
        const TEXT_RVA: u64 = 0x1000;
        const CSTR_RVA: u64 = 0x2000;
        let mut b = Vec::new();
        let p64 = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        let p32 = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
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
        // __PAGEZERO
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
        // __TEXT with two sections: __text and __cstring
        let text_off = 0x2000u32;
        let cstr_off = text_off + code.len() as u32;
        p32(&mut b, 0x19);
        p32(&mut b, 72 + 80 * 2);
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        p64(&mut b, BASE);
        p64(&mut b, 0x2000);
        p64(&mut b, 0);
        p64(&mut b, 0x2000);
        p32(&mut b, 7);
        p32(&mut b, 7);
        p32(&mut b, 2);
        p32(&mut b, 0);
        // section 1: __text
        b.extend_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        p64(&mut b, BASE + TEXT_RVA);
        p64(&mut b, code.len() as u64);
        p32(&mut b, text_off);
        p32(&mut b, 4);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0x80000400);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        // section 2: __cstring (not executable)
        b.extend_from_slice(b"__cstring\0\0\0\0\0\0\0");
        b.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        p64(&mut b, BASE + CSTR_RVA);
        p64(&mut b, cstrings.len() as u64);
        p32(&mut b, cstr_off);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        p32(&mut b, 0);
        // LC_SYMTAB
        p32(&mut b, 0x2);
        p32(&mut b, 24);
        let symoff_pos = b.len();
        p32(&mut b, 0);
        p32(&mut b, symbols.len() as u32);
        let stroff_pos = b.len();
        p32(&mut b, 0);
        let strsize_pos = b.len();
        p32(&mut b, 0);
        // LC_MAIN
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
        for (name, _) in symbols {
            strx.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        for (index, (_, rva)) in symbols.iter().enumerate() {
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
        if let Some((_, entry)) = symbols.first() {
            b[entryoff_pos..entryoff_pos + 8].copy_from_slice(&entry.to_le_bytes());
        }
        b.resize(text_off as usize, 0);
        b.extend_from_slice(code);
        b.extend_from_slice(cstrings);
        LoadedModule::parse(&b).expect("synthetic Mach-O must parse")
    }

    fn words(encodings: &[u32]) -> Vec<u8> {
        encodings.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    #[test]
    fn bl_edges_become_call_edges() {
        // 0x1000: bl .+8 -> 0x1008 ; 0x1004: ret ; 0x1008: ret
        let code = words(&[0x9400_0002, 0xd65f_03c0, 0xd65f_03c0]);
        let view = view(&code, &[], &[("_main", 0x1000)]);
        let fns = crate::discover(&view);
        let edges = crate::call_graph(&view, &fns);
        assert_eq!(edges.len(), 1);
        assert_eq!((edges[0].from, edges[0].to), (0x1000, 0x1008));
    }

    #[test]
    fn a_self_call_is_not_an_edge() {
        // 0x1000: bl .-4 -> 0x1000 (recursive) ; 0x1004: ret
        let code = words(&[0x97ff_ffff, 0xd65f_03c0]);
        let view = view(&code, &[], &[("_rec", 0x1000)]);
        let fns = crate::discover(&view);
        assert!(crate::call_graph(&view, &fns).is_empty());
    }

    #[test]
    fn adrp_plus_add_finds_a_cstring() {
        // adrp x0, page(0x2000) ; add x0, x0, #0 ; ret
        // At 0x1000 the page of 0x2000 is one page ahead: offset = 0x1000.
        let code = words(&[0xb000_0000, 0x9100_0000, 0xd65f_03c0]);
        let cstrings = b"hello_a64\0";
        let view = view(&code, cstrings, &[("_main", 0x1000)]);
        let fns = crate::discover(&view);
        let xrefs = crate::string_xrefs(&view, &fns);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].func_rva, 0x1000);
        assert_eq!(xrefs[0].string_rva, 0x2000);
        assert_eq!(xrefs[0].text, "hello_a64");
    }

    #[test]
    fn adrp_plus_ldr_finds_a_cstring() {
        // adrp x0, page(0x2000) ; ldr w1, [x0, #0] ; ret
        let code = words(&[0xb000_0000, 0xb940_0001, 0xd65f_03c0]);
        let cstrings = b"via_ldr\0";
        let view = view(&code, cstrings, &[("_main", 0x1000)]);
        let fns = crate::discover(&view);
        let xrefs = crate::string_xrefs(&view, &fns);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].text, "via_ldr");
    }

    #[test]
    fn a_page_without_an_adder_is_not_a_reference() {
        // adrp alone materialises a page, not an object address.
        let code = words(&[0xb000_0000, 0xd65f_03c0]);
        let view = view(&code, b"unused\0", &[("_main", 0x1000)]);
        let fns = crate::discover(&view);
        assert!(crate::string_xrefs(&view, &fns).is_empty());
    }

    #[test]
    fn a_non_string_page_is_not_a_reference() {
        // The page points at data that is not a printable C string.
        let code = words(&[0xb000_0000, 0x9100_0000, 0xd65f_03c0]);
        let view = view(&code, &[0x00, 0x01, 0x02, 0x00], &[("_main", 0x1000)]);
        let fns = crate::discover(&view);
        assert!(crate::string_xrefs(&view, &fns).is_empty());
    }
}
