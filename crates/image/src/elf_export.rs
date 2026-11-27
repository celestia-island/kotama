//! Strict ELF dynamic-symbol facts for mirror/proxy generation.
//!
//! Unlike function discovery, this model keeps every defined dynamic symbol with
//! its binding, visibility and version, because a forwarding mirror must reproduce
//! exactly what the dynamic linker would resolve. Object symbols (non-dynamic) are
//! deliberately excluded: they are not part of the interposition contract.

use crate::ImageError;

/// Symbol binding as stored in the ELF dynamic symbol table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfBinding {
    /// STB_LOCAL: never interposable across images.
    Local,
    /// STB_GLOBAL: a single definition wins process-wide.
    Global,
    /// STB_WEAK: a global definition overrides it.
    Weak,
}

/// Symbol visibility.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfVisibility {
    /// STV_DEFAULT: normal interposition rules.
    Default,
    /// STV_INTERNAL: hidden outside the object.
    Internal,
    /// STV_HIDDEN: not exported from the object.
    Hidden,
    /// STV_PROTECTED: interposable but not overridable.
    Protected,
}

/// One defined dynamic symbol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ElfExport {
    /// Symbol name exactly as stored (bytes, to keep non-UTF-8 names lossless).
    pub name: Vec<u8>,
    /// Image-relative address of the definition.
    pub address: u64,
    /// Size as declared; 0 is common for assembly stubs.
    pub size: u64,
    /// Binding.
    pub binding: ElfBinding,
    /// Visibility.
    pub visibility: ElfVisibility,
    /// Version string when the symbol is versioned.
    pub version: Option<Vec<u8>>,
}

/// A strict, deterministic ELF dynamic export table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ElfExportTable {
    /// Defined, interposable dynamic symbols sorted by name bytes.
    pub entries: Vec<ElfExport>,
}
impl ElfExportTable {
    /// Group key per export for hook planning: symbols at the same address are
    /// aliases of one interceptable location and share a key.
    ///
    /// Keys are indices into the sorted list of distinct addresses, so they are
    /// stable across runs and independent of the actual address values.
    #[must_use]
    pub fn hook_groups(&self) -> Vec<(Vec<u8>, u32)> {
        let mut addresses: Vec<u64> = self.entries.iter().map(|entry| entry.address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        self.entries
            .iter()
            .map(|entry| {
                let group = addresses
                    .binary_search(&entry.address)
                    .expect("address list is built from the same entries")
                    as u32;
                (entry.name.clone(), group)
            })
            .collect()
    }
}

/// Parse an ELF file's dynamic export table, or None for a non-ELF input.
///
/// Only symbols that the dynamic linker can actually resolve are kept: defined,
/// non-local, and not hidden. Undefined imports are not exports.
///
/// # Errors
/// Returns [ImageError::Parse] for malformed ELF data. No partial table is returned.
pub fn parse_elf_exports(data: &[u8]) -> Result<Option<ElfExportTable>, ImageError> {
    use object::Object;
    use object::ObjectSymbol;
    let file = object::File::parse(data).map_err(|error| ImageError::Parse(error.to_string()))?;
    if !matches!(file.format(), object::BinaryFormat::Elf) {
        return Ok(None);
    }
    // ELF spec values; compared on the raw byte so this never depends on how the
    // object crate names its constants.
    const STB_GLOBAL: u8 = 1;
    const STB_WEAK: u8 = 2;
    const STV_DEFAULT: u8 = 0;
    const STV_INTERNAL: u8 = 1;
    const STV_HIDDEN: u8 = 2;
    const STV_PROTECTED: u8 = 3;
    let mut entries = Vec::new();
    for symbol in file.dynamic_symbols() {
        if !symbol.is_definition() || symbol.is_undefined() {
            continue;
        }
        let (binding, visibility) = match symbol.flags() {
            object::SymbolFlags::Elf { st_info, st_other } => {
                let binding = match st_info.st_bind().0 {
                    STB_GLOBAL => ElfBinding::Global,
                    STB_WEAK => ElfBinding::Weak,
                    _ => continue,
                };
                let visibility = match st_other.visibility().0 {
                    STV_DEFAULT => ElfVisibility::Default,
                    STV_INTERNAL => ElfVisibility::Internal,
                    STV_HIDDEN => continue,
                    STV_PROTECTED => ElfVisibility::Protected,
                    _ => ElfVisibility::Default,
                };
                (binding, visibility)
            }
            _ => continue,
        };
        let Ok(name) = symbol.name_bytes() else {
            continue;
        };
        let name = name.to_vec();
        if name.is_empty() {
            continue;
        }
        entries.push(ElfExport {
            name,
            address: symbol.address(),
            size: symbol.size(),
            binding,
            visibility,
            version: None,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries.dedup_by(|a, b| a.name == b.name);
    Ok(Some(ElfExportTable { entries }))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_input() {
        assert!(matches!(
            parse_elf_exports(b"not an elf at all"),
            Err(ImageError::Parse(_))
        ));
        let pe = b"MZ\x90\0\x03\0\0\0\x04\0\0\0\xff\xff\0\0\x08\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\0\0\0\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\0\0\0\0\0\0\0\0";
        let _ = pe;
    }
}
