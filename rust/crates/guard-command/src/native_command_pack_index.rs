//! Bounded authenticated lookup. Discovery never requires decoding other packs.
use super::*;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Page {
    Leaf {
        schema: String,
        prefix: String,
        entries: Vec<(String, ObjectRef)>,
    },
    Branch {
        schema: String,
        prefix: String,
        children: Vec<(String, usize, ObjectRef)>,
    },
}

/// The root and total count must come from one authenticated release manifest.
/// This validates integrity and completeness along the requested lookup path.
/// It grants no policy authority and does not admit a program for execution.
pub fn lookup(
    root: &ObjectRef,
    total: usize,
    id: &str,
    fetch: &mut impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
) -> Result<Option<ObjectRef>, &'static str> {
    let hash = hex::encode(Sha256::digest(id.as_bytes()));
    let mut reference = root.clone();
    let mut expected_prefix = String::new();
    let mut expected_count = total;
    if total == 0 || id.is_empty() || id.len() > 256 {
        return Err("command_pack_index_invalid");
    }
    for _ in 0..=64 {
        if reference.expanded_length > OBJECT_BYTES {
            return Err("command_pack_index_bounds_invalid");
        }
        let page: Page = serde_json::from_slice(&read_blob(&reference, fetch)?)
            .map_err(|_| "command_pack_index_invalid")?;
        match page {
            Page::Leaf {
                schema,
                prefix,
                entries,
            } => {
                if schema != "guard.pack-index.v1"
                    || prefix != expected_prefix
                    || entries.len() != expected_count
                    || entries.is_empty()
                    || entries.len() > FANOUT
                    || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                    || entries.iter().any(|(id, _)| {
                        id.is_empty()
                            || id.len() > 256
                            || !hex::encode(Sha256::digest(id.as_bytes())).starts_with(&prefix)
                    })
                {
                    return Err("command_pack_index_invalid");
                }
                return Ok(entries
                    .into_iter()
                    .find(|entry| entry.0 == id)
                    .map(|entry| entry.1));
            }
            Page::Branch {
                schema,
                prefix,
                children,
            } => {
                let count = children
                    .iter()
                    .try_fold(0usize, |sum, child| sum.checked_add(child.1));
                if schema != "guard.pack-index.v1"
                    || prefix != expected_prefix
                    || prefix.len() >= 64
                    || children.is_empty()
                    || children.len() > 16
                    || count != Some(expected_count)
                    || children.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                    || children.iter().any(|(key, count, _)| {
                        *count == 0
                            || key.len() != prefix.len() + 1
                            || !key.starts_with(&prefix)
                            || !key
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                {
                    return Err("command_pack_index_invalid");
                }
                let Some((prefix, count, next)) = children
                    .into_iter()
                    .find(|child| hash.starts_with(&child.0))
                else {
                    return Ok(None);
                };
                expected_prefix = prefix;
                expected_count = count;
                reference = next;
            }
        }
    }
    Err("command_pack_index_bounds_invalid")
}
