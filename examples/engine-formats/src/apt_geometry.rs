//! APT geometry text parser.
//!
//! Compiled .ru geometry uses short lines: c (finish style), s (style header),
//! t (triangle, six colon-separated floats) and l (line). This module keeps the
//! inventory generic: styles, triangles, line count and bounds.

use crate::ResourceError;

/// One APT style header.
#[derive(Clone, PartialEq, Debug)]
pub struct AptStyle {
    /// Style token (for example s for solid or t for textured).
    pub kind: String,
    /// RGBA color bytes.
    pub color: [u8; 4],
}

/// One APT triangle.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AptTriangle {
    /// Index into the style table, when a style was active.
    pub style: Option<usize>,
    /// x1,y1,x2,y2,x3,y3.
    pub points: [f32; 6],
}

/// Parsed APT geometry.
#[derive(Clone, PartialEq, Debug)]
pub struct AptGeometry {
    /// Style headers in file order.
    pub styles: Vec<AptStyle>,
    /// Triangles in file order.
    pub triangles: Vec<AptTriangle>,
    /// Number of line records.
    pub lines: usize,
}

fn parse_floats(value: &str, count: usize) -> Option<Vec<f32>> {
    let values = value
        .split(':')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if values.len() != count {
        return None;
    }
    values
        .into_iter()
        .map(|part| part.trim().parse::<f32>().ok())
        .collect()
}

/// Parse APT geometry text.
///
/// # Errors
/// Returns ResourceError::Invalid for non-UTF-8 text or malformed records.
pub fn parse(bytes: &[u8]) -> Result<AptGeometry, ResourceError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ResourceError::Invalid("APT geometry is not UTF-8".to_string()))?;
    let mut geometry = AptGeometry {
        styles: Vec::new(),
        triangles: Vec::new(),
        lines: 0,
    };
    let mut current_style = None;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut chars = line.chars();
        let mode = chars.next().ok_or_else(|| {
            ResourceError::Invalid(format!("APT geometry line {} is empty", number + 1))
        })?;
        let rest = chars.as_str().trim();
        match mode {
            'c' => current_style = None,
            's' => {
                let parts = rest.split(':').map(str::trim).collect::<Vec<_>>();
                if parts.len() < 5 {
                    return Err(ResourceError::Invalid(format!(
                        "APT style on line {} needs a kind and RGBA",
                        number + 1
                    )));
                }
                let mut color = [0u8; 4];
                for (index, slot) in color.iter_mut().enumerate() {
                    *slot = parts[index + 1].parse::<u8>().map_err(|_| {
                        ResourceError::Invalid(format!(
                            "APT style color on line {} is invalid",
                            number + 1
                        ))
                    })?;
                }
                current_style = Some(geometry.styles.len());
                geometry.styles.push(AptStyle {
                    kind: parts[0].to_string(),
                    color,
                });
            }
            't' => {
                let values = parse_floats(rest, 6).ok_or_else(|| {
                    ResourceError::Invalid(format!(
                        "APT triangle on line {} is malformed",
                        number + 1
                    ))
                })?;
                let mut points = [0.0f32; 6];
                points.copy_from_slice(&values);
                geometry.triangles.push(AptTriangle {
                    style: current_style,
                    points,
                });
            }
            'l' => geometry.lines += 1,
            other => {
                return Err(ResourceError::Invalid(format!(
                    "unsupported APT geometry mode {other} on line {}",
                    number + 1
                )))
            }
        }
    }
    Ok(geometry)
}

impl AptGeometry {
    /// Bounding box over all triangle coordinates.
    #[must_use]
    pub fn bounds(&self) -> Option<[f32; 4]> {
        let mut bounds: Option<[f32; 4]> = None;
        for triangle in &self.triangles {
            for pair in triangle.points.chunks(2) {
                let x = pair[0];
                let y = pair[1];
                bounds = Some(match bounds {
                    Some([min_x, min_y, max_x, max_y]) => {
                        [min_x.min(x), min_y.min(y), max_x.max(x), max_y.max(y)]
                    }
                    None => [x, y, x, y],
                });
            }
        }
        bounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_styles_triangles_and_bounds() {
        let text = "c\ns s:255:255:255:255\nt -1:-1:-2:-2:2:-2\nt 1:1:2:2:2:2\nl 0:0:1:1\n";
        let geometry = parse(text.as_bytes()).unwrap();
        assert_eq!(geometry.styles.len(), 1);
        assert_eq!(geometry.styles[0].kind, "s");
        assert_eq!(geometry.triangles.len(), 2);
        assert_eq!(geometry.lines, 1);
        assert_eq!(geometry.bounds(), Some([-2.0, -2.0, 2.0, 2.0]));
    }

    #[test]
    fn rejects_malformed_triangle() {
        assert!(parse(b"t 1:2:3\n").is_err());
    }
}
