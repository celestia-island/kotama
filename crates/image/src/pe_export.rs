//! Strict PE export-table facts for mirror/proxy generation.
//!
//! Unlike function discovery, this model retains aliases, ordinal-only exports,
//! and forwarded targets. No executable-section filtering or lossy name handling
//! is applied, and malformed tables fail the whole parse.

use std::collections::BTreeMap;

use object::read::pe::ExportTable as ObjectExportTable;
use object::read::pe::ExportTarget as ObjectExportTarget;

use crate::ImageError;

/// The target of a forwarded export.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeForwardTarget {
    /// Another DLL's named export.
    Name(Vec<u8>),
    /// Another DLL's ordinal export.
    Ordinal(u16),
}

/// Where one export-address-table entry points.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeExportTarget {
    /// An RVA in this image. It is not implicitly assumed to be code.
    Address(u32),
    /// A forwarder to another image.
    Forward {
        /// The backing image name exactly as stored in the PE file.
        library: Vec<u8>,
        /// The name or ordinal in that image.
        target: PeForwardTarget,
    },
}

/// One ordinal and all public names that alias it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeExport {
    /// The public ordinal, including the directory's ordinal base.
    pub ordinal: u16,
    /// Public names for this ordinal, sorted by raw bytes. Empty means NONAME.
    pub names: Vec<Vec<u8>>,
    /// The original address or forward target.
    pub target: PeExportTarget,
}

/// A strict, deterministic PE export table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeExportTable {
    /// The ordinal base declared by the export directory.
    pub ordinal_base: u16,
    /// Non-null export-address entries sorted by ordinal.
    pub entries: Vec<PeExport>,
}

/// Parse a PE file's complete export table, or return None for a non-PE input.
///
/// # Errors
/// Returns [ImageError::Parse] for malformed PE/export data. No partial table is returned.
pub fn parse_pe_exports(data: &[u8]) -> Result<Option<PeExportTable>, ImageError> {
    let file = object::File::parse(data).map_err(|error| ImageError::Parse(error.to_string()))?;
    let table = match &file {
        object::File::Pe32(pe) => pe.export_table(),
        object::File::Pe64(pe) => pe.export_table(),
        _ => return Ok(None),
    }
    .map_err(|error| ImageError::Parse(error.to_string()))?;
    table.map(collect).transpose()
}

fn collect(table: ObjectExportTable<'_>) -> Result<PeExportTable, ImageError> {
    let ordinal_base = table.ordinal_base();
    let mut entries = BTreeMap::new();
    for (_index, ordinal, address) in table.address_iter() {
        if address == 0 {
            continue;
        }
        let target = table
            .target_from_address(address)
            .map_err(|error| ImageError::Parse(error.to_string()))?;
        let target = match target {
            ObjectExportTarget::Address(address) => PeExportTarget::Address(address),
            ObjectExportTarget::ForwardByName(library, name) => PeExportTarget::Forward {
                library: library.to_vec(),
                target: PeForwardTarget::Name(name.to_vec()),
            },
            ObjectExportTarget::ForwardByOrdinal(library, ordinal) => PeExportTarget::Forward {
                library: library.to_vec(),
                target: PeForwardTarget::Ordinal(ordinal.0),
            },
        };
        entries.insert(
            ordinal.0,
            PeExport {
                ordinal: ordinal.0,
                names: Vec::new(),
                target,
            },
        );
    }
    for (name_pointer, index) in table.name_iter() {
        let ordinal = table
            .ordinal_from_index(index)
            .map_err(|error| ImageError::Parse(error.to_string()))?;
        let name = table
            .name_from_pointer(name_pointer)
            .map_err(|error| ImageError::Parse(error.to_string()))?;
        let entry = entries.get_mut(&ordinal.0).ok_or_else(|| {
            ImageError::Parse(format!(
                "export name points to missing ordinal {}",
                ordinal.0
            ))
        })?;
        entry.names.push(name.to_vec());
    }
    let mut entries: Vec<PeExport> = entries.into_values().collect();
    for entry in &mut entries {
        entry.names.sort();
        entry.names.dedup();
    }
    Ok(PeExportTable {
        ordinal_base,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_section() -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[16..20].copy_from_slice(&5u32.to_le_bytes());
        data[20..24].copy_from_slice(&3u32.to_le_bytes());
        data[24..28].copy_from_slice(&2u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x1100u32.to_le_bytes());
        data[32..36].copy_from_slice(&0x1200u32.to_le_bytes());
        data[36..40].copy_from_slice(&0x1300u32.to_le_bytes());
        data[0x100..0x104].copy_from_slice(&0x5000u32.to_le_bytes());
        data[0x104..0x108].copy_from_slice(&0x6000u32.to_le_bytes());
        data[0x108..0x10c].copy_from_slice(&0x1150u32.to_le_bytes());
        data[0x200..0x204].copy_from_slice(&0x1180u32.to_le_bytes());
        data[0x204..0x208].copy_from_slice(&0x1190u32.to_le_bytes());
        data[0x300..0x302].copy_from_slice(&0u16.to_le_bytes());
        data[0x302..0x304].copy_from_slice(&0u16.to_le_bytes());
        let forward = b"OTHER.#9\0";
        data[0x150..0x150 + forward.len()].copy_from_slice(forward);
        data[0x180..0x186].copy_from_slice(b"Alpha\0");
        data[0x190..0x195].copy_from_slice(b"Beta\0");
        data
    }

    #[test]
    fn preserves_aliases_ordinals_and_forwarders() {
        let table =
            collect(ObjectExportTable::parse(&synthetic_section(), 0x1000).unwrap()).unwrap();
        assert_eq!(table.ordinal_base, 5);
        assert_eq!(table.entries.len(), 3);
        assert_eq!(table.entries[0].ordinal, 5);
        assert_eq!(
            table.entries[0].names,
            vec![b"Alpha".to_vec(), b"Beta".to_vec()]
        );
        assert_eq!(table.entries[0].target, PeExportTarget::Address(0x5000));
        assert!(table.entries[1].names.is_empty());
        assert_eq!(table.entries[1].target, PeExportTarget::Address(0x6000));
        assert_eq!(table.entries[2].ordinal, 7);
        assert_eq!(
            table.entries[2].target,
            PeExportTarget::Forward {
                library: b"OTHER".to_vec(),
                target: PeForwardTarget::Ordinal(9),
            }
        );
    }

    #[test]
    fn rejects_a_name_that_points_outside_the_eat() {
        let mut data = synthetic_section();
        data[0x300..0x302].copy_from_slice(&9u16.to_le_bytes());
        let error = collect(ObjectExportTable::parse(&data, 0x1000).unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("address index"),
            "unexpected error: {error}"
        );
    }
}
