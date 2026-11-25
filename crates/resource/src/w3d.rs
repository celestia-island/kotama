//! W3D chunk container scanner.
//!
//! A chunk is a little-endian u32 type followed by a u32 size whose high bit
//! marks a container. Chunk payloads stay opaque; this module only produces
//! deterministic offset/size/depth evidence.

use crate::ResourceError;

/// One flattened W3D chunk header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct W3dChunk {
    /// Chunk type ID.
    pub type_id: u32,
    /// Byte offset of the chunk header.
    pub offset: u64,
    /// Payload size, excluding the 8-byte header.
    pub size: u32,
    /// Zero for top-level chunks.
    pub depth: u8,
    /// True when the chunk contains sub-chunks.
    pub has_subchunks: bool,
}

/// A parsed W3D chunk tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct W3dFile<'a> {
    /// Original file bytes.
    pub data: &'a [u8],
    /// Chunks in depth-first file order.
    pub chunks: Vec<W3dChunk>,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn scan(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: u8,
    chunks: &mut Vec<W3dChunk>,
) -> Result<(), ResourceError> {
    if depth > 32 {
        return Err(ResourceError::Invalid(
            "W3D chunk nesting exceeds 32 levels".to_string(),
        ));
    }
    let mut offset = start;
    while offset < end {
        let Some(header_end) = offset.checked_add(8) else {
            return Err(ResourceError::Invalid(
                "W3D chunk header overflows".to_string(),
            ));
        };
        if header_end > end {
            return Err(ResourceError::Invalid(format!(
                "W3D chunk header at {offset} is truncated"
            )));
        }
        let type_id = u32_at(bytes, offset).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk type at {offset} is unreadable"))
        })?;
        let raw_size = u32_at(bytes, offset + 4).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk size at {offset} is unreadable"))
        })?;
        let has_subchunks = raw_size & 0x8000_0000 != 0;
        let size = raw_size & 0x7fff_ffff;
        let payload_start = header_end;
        let payload_end = payload_start.checked_add(size as usize).ok_or_else(|| {
            ResourceError::Invalid(format!("W3D chunk at {offset} payload overflows"))
        })?;
        if payload_end > end {
            return Err(ResourceError::Invalid(format!(
                "W3D chunk at {offset} payload {size} exceeds its parent"
            )));
        }
        chunks.push(W3dChunk {
            type_id,
            offset: offset as u64,
            size,
            depth,
            has_subchunks,
        });
        if has_subchunks {
            scan(bytes, payload_start, payload_end, depth + 1, chunks)?;
        }
        offset = payload_end;
    }
    Ok(())
}

/// Parse and validate a W3D chunk tree.
///
/// # Errors
/// Returns ResourceError::Invalid for truncated headers, oversized payloads or
/// excessive nesting.
pub fn parse(bytes: &[u8]) -> Result<W3dFile<'_>, ResourceError> {
    let mut chunks = Vec::new();
    scan(bytes, 0, bytes.len(), 0, &mut chunks)?;
    if chunks.is_empty() {
        return Err(ResourceError::Invalid(
            "W3D file contains no chunks".to_string(),
        ));
    }
    Ok(W3dFile {
        data: bytes,
        chunks,
    })
}

impl W3dFile<'_> {
    /// Return a chunk payload when its recorded bounds are valid.
    #[must_use]
    pub fn payload(&self, chunk: W3dChunk) -> Option<&'_ [u8]> {
        let start = chunk.offset.checked_add(8)?;
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(chunk.size as usize)?;
        self.data.get(start..end)
    }
}

/// Return the conventional W3D chunk name for a known type ID.
#[must_use]
pub const fn chunk_name(type_id: u32) -> Option<&'static str> {
    Some(match type_id {
        0x0000_0000 => "mesh",
        0x0000_0002 => "vertices",
        0x0000_0003 => "vertex_normals",
        0x0000_000c => "mesh_user_text",
        0x0000_000e => "vertex_influences",
        0x0000_001f => "mesh_header3",
        0x0000_0020 => "triangles",
        0x0000_0022 => "vertex_shade_indices",
        0x0000_0023 => "prelit_unlit",
        0x0000_0024 => "prelit_vertex",
        0x0000_0025 => "prelit_lightmap_multi_pass",
        0x0000_0026 => "prelit_lightmap_multi_texture",
        0x0000_0028 => "material_info",
        0x0000_0029 => "shaders",
        0x0000_002a => "vertex_materials",
        0x0000_002b => "vertex_material",
        0x0000_002c => "vertex_material_name",
        0x0000_002d => "vertex_material_info",
        0x0000_002e => "vertex_mapper_args0",
        0x0000_002f => "vertex_mapper_args1",
        0x0000_0030 => "textures",
        0x0000_0031 => "texture",
        0x0000_0032 => "texture_name",
        0x0000_0033 => "texture_info",
        0x0000_0038 => "material_pass",
        0x0000_0039 => "vertex_material_ids",
        0x0000_003a => "shader_ids",
        0x0000_003b => "dcg",
        0x0000_003c => "dig",
        0x0000_003e => "scg",
        0x0000_003f => "shader_material_id",
        0x0000_0048 => "texture_stage",
        0x0000_0049 => "texture_ids",
        0x0000_004a => "stage_texcoords",
        0x0000_004b => "per_face_texcoord_ids",
        0x0000_0050 => "shader_materials",
        0x0000_0051 => "shader_material",
        0x0000_0052 => "shader_material_header",
        0x0000_0053 => "shader_material_property",
        0x0000_0058 => "deform",
        0x0000_0059 => "deform_set",
        0x0000_005a => "deform_keyframe",
        0x0000_005b => "deform_data",
        0x0000_0060 => "tangents",
        0x0000_0061 => "bitangents",
        0x0000_0080 => "ps2_shaders",
        0x0000_0090 => "aabtree",
        0x0000_0091 => "aabtree_header",
        0x0000_0092 => "aabtree_polyindices",
        0x0000_0093 => "aabtree_nodes",
        0x0000_0100 => "hierarchy",
        0x0000_0101 => "hierarchy_header",
        0x0000_0102 => "pivots",
        0x0000_0103 => "pivot_fixups",
        0x0000_0200 => "animation",
        0x0000_0201 => "animation_header",
        0x0000_0202 => "animation_channel",
        0x0000_0203 => "bit_channel",
        0x0000_0280 => "compressed_animation",
        0x0000_0281 => "compressed_animation_header",
        0x0000_0282 => "compressed_animation_channel",
        0x0000_0283 => "compressed_bit_channel",
        0x0000_0284 => "compressed_animation_motion_channel",
        0x0000_02c0 => "morph_animation",
        0x0000_02c1 => "morphanim_header",
        0x0000_02c2 => "morphanim_channel",
        0x0000_02c3 => "morphanim_posename",
        0x0000_02c4 => "morphanim_keydata",
        0x0000_02c5 => "morphanim_pivotchanneldata",
        0x0000_0300 => "hmodel",
        0x0000_0301 => "hmodel_header",
        0x0000_0302 => "node",
        0x0000_0303 => "collision_node",
        0x0000_0304 => "skin_node",
        0x0000_0400 => "lodmodel",
        0x0000_0401 => "lodmodel_header",
        0x0000_0402 => "lod",
        0x0000_0420 => "collection",
        0x0000_0421 => "collection_header",
        0x0000_0422 => "collection_obj_name",
        0x0000_0423 => "placeholder",
        0x0000_0424 => "transform_node",
        0x0000_0440 => "points",
        0x0000_0460 => "light",
        0x0000_0461 => "light_info",
        0x0000_0462 => "spot_light_info",
        0x0000_0463 => "near_attenuation",
        0x0000_0464 => "far_attenuation",
        0x0000_0500 => "emitter",
        0x0000_0501 => "emitter_header",
        0x0000_0502 => "emitter_user_data",
        0x0000_0503 => "emitter_info",
        0x0000_0504 => "emitter_infov2",
        0x0000_0505 => "emitter_props",
        0x0000_0600 => "aggregate",
        0x0000_0601 => "aggregate_header",
        0x0000_0602 => "aggregate_info",
        0x0000_0603 => "texture_replacer_info",
        0x0000_0604 => "aggregate_class_info",
        0x0000_0700 => "hlod",
        0x0000_0701 => "hlod_header",
        0x0000_0702 => "hlod_lod_array",
        0x0000_0703 => "hlod_sub_object_array_header",
        0x0000_0704 => "hlod_sub_object",
        0x0000_0705 => "hlod_aggregate_array",
        0x0000_0706 => "hlod_proxy_array",
        0x0000_0740 => "box",
        0x0000_0741 => "sphere",
        0x0000_0742 => "ring",
        0x0000_0750 => "null_object",
        0x0000_0800 => "lightscape",
        0x0000_0801 => "lightscape_light",
        0x0000_0802 => "light_transform",
        0x0000_0900 => "dazzle",
        0x0000_0901 => "dazzle_name",
        0x0000_0902 => "dazzle_typename",
        0x0000_0a00 => "soundrobj",
        0x0000_0a01 => "soundrobj_header",
        0x0000_0a02 => "soundrobj_definition",
        0x0000_0c00 => "vertices_2",
        0x0000_0c01 => "normals_2",
        _ => return None,
    })
}

/// A W3D vector (three little-endian f32 values).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct W3dVector {
    /// X component.
    pub x: f32,
    /// Y component.
    pub y: f32,
    /// Z component.
    pub z: f32,
}

/// A W3D triangle record.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct W3dTriangle {
    /// Vertex indices.
    pub vindex: [u32; 3],
    /// Surface type.
    pub surface_type: u32,
    /// Plane normal.
    pub normal: W3dVector,
    /// Plane distance.
    pub distance: f32,
}

/// The fixed W3D mesh header record.
#[derive(Clone, PartialEq, Debug)]
pub struct W3dMeshHeader {
    /// Version.
    pub version: u32,
    /// Attribute flags.
    pub attributes: u32,
    /// Mesh name.
    pub mesh_name: String,
    /// Container name.
    pub container_name: String,
    /// Triangle count.
    pub num_tris: u32,
    /// Vertex count.
    pub num_vertices: u32,
    /// Material count.
    pub num_materials: u32,
    /// Damage stage count.
    pub num_damage_stages: u32,
    /// Sort level.
    pub sort_level: u32,
    /// Prelit version.
    pub prelit_version: u32,
    /// Future counts.
    pub future_counts: u32,
    /// Vertex channel flags.
    pub vertex_channels: u32,
    /// Face channel flags.
    pub face_channels: u32,
    /// Bounding-box minimum.
    pub min: W3dVector,
    /// Bounding-box maximum.
    pub max: W3dVector,
    /// Bounding-sphere center.
    pub sphere_center: W3dVector,
    /// Bounding-sphere radius.
    pub sphere_radius: f32,
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn le_f32(bytes: &[u8], offset: usize) -> Option<f32> {
    le_u32(bytes, offset).map(f32::from_bits)
}

fn fixed_name(bytes: &[u8], offset: usize, len: usize) -> Option<String> {
    let raw = bytes.get(offset..offset.checked_add(len)?)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(len);
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn vector_at(bytes: &[u8], offset: usize) -> Option<W3dVector> {
    Some(W3dVector {
        x: le_f32(bytes, offset)?,
        y: le_f32(bytes, offset + 4)?,
        z: le_f32(bytes, offset + 8)?,
    })
}

fn parse_mesh_header(payload: &[u8]) -> Option<W3dMeshHeader> {
    if payload.len() < 116 {
        return None;
    }
    Some(W3dMeshHeader {
        version: le_u32(payload, 0)?,
        attributes: le_u32(payload, 4)?,
        mesh_name: fixed_name(payload, 8, 16)?,
        container_name: fixed_name(payload, 24, 16)?,
        num_tris: le_u32(payload, 40)?,
        num_vertices: le_u32(payload, 44)?,
        num_materials: le_u32(payload, 48)?,
        num_damage_stages: le_u32(payload, 52)?,
        sort_level: le_u32(payload, 56)?,
        prelit_version: le_u32(payload, 60)?,
        future_counts: le_u32(payload, 64)?,
        vertex_channels: le_u32(payload, 68)?,
        face_channels: le_u32(payload, 72)?,
        min: vector_at(payload, 76)?,
        max: vector_at(payload, 88)?,
        sphere_center: vector_at(payload, 100)?,
        sphere_radius: le_f32(payload, 112)?,
    })
}

fn parse_vector_list(payload: &[u8]) -> Vec<W3dVector> {
    let mut values = Vec::new();
    let mut offset: usize = 0;
    while offset
        .checked_add(12)
        .is_some_and(|end| end <= payload.len())
    {
        if let Some(value) = vector_at(payload, offset) {
            values.push(value);
        }
        offset += 12;
    }
    values
}

fn parse_triangles(payload: &[u8]) -> Vec<W3dTriangle> {
    let mut values = Vec::new();
    let mut offset: usize = 0;
    while offset
        .checked_add(32)
        .is_some_and(|end| end <= payload.len())
    {
        if let (Some(a), Some(b), Some(c), Some(surface), Some(normal), Some(distance)) = (
            le_u32(payload, offset),
            le_u32(payload, offset + 4),
            le_u32(payload, offset + 8),
            le_u32(payload, offset + 12),
            vector_at(payload, offset + 16),
            le_f32(payload, offset + 28),
        ) {
            values.push(W3dTriangle {
                vindex: [a, b, c],
                surface_type: surface,
                normal,
                distance,
            });
        }
        offset += 32;
    }
    values
}

impl W3dFile<'_> {
    /// Return the first mesh_header3 record.
    #[must_use]
    pub fn mesh_header(&self) -> Option<W3dMeshHeader> {
        let chunk = self.chunks.iter().find(|chunk| chunk.type_id == 0x1f)?;
        parse_mesh_header(self.payload(*chunk)?)
    }

    /// Return the first vertex array.
    #[must_use]
    pub fn vertices(&self) -> Vec<W3dVector> {
        self.vector_list(0x02)
    }

    /// Return the first normal array.
    #[must_use]
    pub fn normals(&self) -> Vec<W3dVector> {
        self.vector_list(0x03)
    }

    fn vector_list(&self, type_id: u32) -> Vec<W3dVector> {
        self.chunks
            .iter()
            .find(|chunk| chunk.type_id == type_id)
            .and_then(|chunk| self.payload(*chunk))
            .map(parse_vector_list)
            .unwrap_or_default()
    }

    /// Return the first triangle array.
    #[must_use]
    pub fn triangles(&self) -> Vec<W3dTriangle> {
        self.chunks
            .iter()
            .find(|chunk| chunk.type_id == 0x20)
            .and_then(|chunk| self.payload(*chunk))
            .map(parse_triangles)
            .unwrap_or_default()
    }

    /// Return all NUL-terminated strings stored under a chunk type.
    #[must_use]
    pub fn strings_by_type(&self, type_id: u32) -> Vec<String> {
        self.chunks
            .iter()
            .filter(|chunk| chunk.type_id == type_id)
            .filter_map(|chunk| {
                let payload = self.payload(*chunk)?;
                let end = payload
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(payload.len());
                Some(String::from_utf8_lossy(&payload[..end]).trim().to_string())
            })
            .filter(|value| !value.is_empty())
            .collect()
    }

    /// Vertex material names (type 0x2c).
    #[must_use]
    pub fn vertex_material_names(&self) -> Vec<String> {
        self.strings_by_type(0x2c)
    }

    /// Texture names (type 0x32).
    #[must_use]
    pub fn texture_names(&self) -> Vec<String> {
        self.strings_by_type(0x32)
    }

    /// Mesh user text (type 0x0c).
    #[must_use]
    pub fn user_text(&self) -> Vec<String> {
        self.strings_by_type(0x0c)
    }

    /// Return material pass/vertex-material/shader/texture counts.
    #[must_use]
    pub fn material_info(&self) -> Option<[u32; 4]> {
        let chunk = self.chunks.iter().find(|chunk| chunk.type_id == 0x28)?;
        let payload = self.payload(*chunk)?;
        Some([
            le_u32(payload, 0)?,
            le_u32(payload, 4)?,
            le_u32(payload, 8)?,
            le_u32(payload, 12)?,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(type_id: u32, payload: &[u8], subchunks: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&type_id.to_le_bytes());
        let size = if subchunks {
            0x8000_0000 | payload.len() as u32
        } else {
            payload.len() as u32
        };
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn mesh_header_payload() -> Vec<u8> {
        let mut bytes = vec![0u8; 116];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..11].copy_from_slice(b"box");
        bytes[24..29].copy_from_slice(b"scene");
        bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&2u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&(-1.0f32).to_bits().to_le_bytes());
        bytes[88..92].copy_from_slice(&1.0f32.to_bits().to_le_bytes());
        bytes[112..116].copy_from_slice(&2.5f32.to_bits().to_le_bytes());
        bytes
    }

    #[test]
    fn mesh_records_are_parsed() {
        let mut vertices = Vec::new();
        for value in [0.0f32, 1.0, 0.0, 1.0, 0.0, 0.0] {
            vertices.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        let mut triangle = Vec::new();
        for index in [0u32, 1, 0, 0] {
            triangle.extend_from_slice(&index.to_le_bytes());
        }
        for value in [0.0f32, 0.0, 1.0, 0.0] {
            triangle.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        let mut material = Vec::new();
        for value in [1u32, 1, 0, 1] {
            material.extend_from_slice(&value.to_le_bytes());
        }
        let payload = [
            chunk(0x1f, &mesh_header_payload(), false),
            chunk(0x02, &vertices, false),
            chunk(0x20, &triangle, false),
            chunk(0x28, &material, false),
        ]
        .concat();
        let root = chunk(0, &payload, true);
        let parsed = parse(&root).unwrap();
        let header = parsed.mesh_header().unwrap();
        assert_eq!(header.mesh_name, "box");
        assert_eq!(header.container_name, "scene");
        assert_eq!(header.num_vertices, 2);
        assert_eq!(parsed.vertices().len(), 2);
        assert_eq!(parsed.triangles().len(), 1);
        assert_eq!(parsed.material_info(), Some([1, 1, 0, 1]));
    }

    #[test]
    fn mesh_names_are_collected() {
        let header = chunk(0x1f, &mesh_header_payload(), false);
        let material_name = chunk(0x2c, b"mat1\0", false);
        let material = chunk(0x2b, &material_name, true);
        let materials = chunk(0x2a, &material, true);
        let texture_name = chunk(0x32, b"tex.tga\0", false);
        let texture = chunk(0x31, &texture_name, true);
        let textures = chunk(0x30, &texture, true);
        let user_text = chunk(0x0c, b"comment\0", false);
        let payload = [header, materials, textures, user_text].concat();
        let root = chunk(0, &payload, true);
        let parsed = parse(&root).unwrap();
        assert_eq!(parsed.vertex_material_names(), vec!["mat1"]);
        assert_eq!(parsed.texture_names(), vec!["tex.tga"]);
        assert_eq!(parsed.user_text(), vec!["comment"]);
    }

    #[test]
    fn scans_nested_chunks_and_payloads() {
        let child = chunk(31, b"abcd", false);
        let root = chunk(0, &child, true);
        let parsed = parse(&root).unwrap();
        assert_eq!(parsed.chunks.len(), 2);
        assert_eq!(parsed.chunks[0].type_id, 0);
        assert_eq!(parsed.chunks[0].depth, 0);
        assert!(parsed.chunks[0].has_subchunks);
        assert_eq!(parsed.chunks[1].type_id, 31);
        assert_eq!(parsed.chunks[1].depth, 1);
        assert_eq!(parsed.chunks[1].offset, 8);
        assert_eq!(parsed.payload(parsed.chunks[1]), Some(b"abcd".as_slice()));
    }

    #[test]
    fn rejects_truncated_payload_and_empty_input() {
        let mut bytes = chunk(0, b"abcd", false);
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse(&bytes).is_err());
        assert!(parse(&[]).is_err());
    }
}
