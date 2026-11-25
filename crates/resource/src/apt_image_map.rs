//! APT image-map text parser.
//!
//! `.dat` files map internal image ids to texture ids and optional bounds.
//! Comments start with `;`; assignments use `->` or `=`.

use crate::ResourceError;

/// One image-map assignment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptImageAssignment {
    /// Internal image id.
    pub image_id: i32,
    /// Texture id, if present.
    pub texture_id: Option<i32>,
    /// Optional rectangle (x, y, width, height).
    pub rectangle: Option<[i32; 4]>,
}

/// Parsed image map.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptImageMap {
    /// Assignments in file order.
    pub assignments: Vec<AptImageAssignment>,
}

/// Parse an APT image map.
///
/// # Errors
/// Returns ResourceError::Invalid for malformed lines or non-integer fields.
pub fn parse(bytes: &[u8]) -> Result<AptImageMap, ResourceError> {
    let text = String::from_utf8_lossy(bytes);
    let anchor = text.find(';').or_else(|| text.find("->")).unwrap_or(0);
    let line_start = text[..anchor]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(anchor);
    let text = &text[line_start..];
    let mut assignments = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.split(';').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((image_text, assignment_text)) =
            line.split_once("->").or_else(|| line.split_once('='))
        else {
            return Err(ResourceError::Invalid(format!(
                "APT image map line has no assignment: {line}"
            )));
        };
        let image_id = image_text
            .trim()
            .parse::<i32>()
            .map_err(|_| ResourceError::Invalid(format!("APT image id is invalid: {line}")))?;
        let fields: Vec<&str> = assignment_text
            .split([' ', '(', ')'])
            .filter(|field| !field.is_empty())
            .collect();
        if fields.is_empty() {
            assignments.push(AptImageAssignment {
                image_id,
                texture_id: None,
                rectangle: None,
            });
            continue;
        }
        let texture_id = fields[0]
            .parse::<i32>()
            .map_err(|_| ResourceError::Invalid(format!("APT texture id is invalid: {line}")))?;
        let rectangle = match fields.len() {
            1 => None,
            4 | 5 => {
                let mut values = [0i32; 4];
                for (slot, field) in values.iter_mut().zip(&fields[fields.len() - 4..]) {
                    *slot = field.parse::<i32>().map_err(|_| {
                        ResourceError::Invalid(format!("APT rectangle is invalid: {line}"))
                    })?;
                }
                Some(values)
            }
            _ => {
                return Err(ResourceError::Invalid(format!(
                    "APT image map assignment has an unsupported field count: {line}"
                )));
            }
        };
        assignments.push(AptImageAssignment {
            image_id,
            texture_id: Some(texture_id),
            rectangle,
        });
    }
    Ok(AptImageMap { assignments })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assignments() {
        let text = b"; comment\n19->1\n26 = 1\n23->1 (2 3 4 5)\n9->\n";
        let map = parse(text).unwrap();
        assert_eq!(map.assignments.len(), 4);
        assert_eq!(map.assignments[0].image_id, 19);
        assert_eq!(map.assignments[0].texture_id, Some(1));
        assert_eq!(map.assignments[2].rectangle, Some([2, 3, 4, 5]));
        assert_eq!(map.assignments[3].texture_id, None);
    }

    #[test]
    fn rejects_bad_line() {
        assert!(parse(b"not-a-mapping").is_err());
    }
}
