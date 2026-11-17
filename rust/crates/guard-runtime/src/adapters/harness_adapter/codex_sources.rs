//! Codex: the strict source check an install runs before it plans anything.
//! Each config and hooks file must be a readable regular file, or absent, and
//! must parse strictly; a captured generation is parsed as it was captured.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex_migration::{read_json, read_toml};
use super::{path_text, Failure, Step};

const UNREADABLE: &str = "codex_hook_inventory_source_unreadable";

/// The strict parse of each named config and hooks source (from disk, or
/// over captured bytes); the parsed values are not needed.
pub(super) fn check_sources(fields: &Map<String, Value>) -> Step<Value> {
    let Some(Value::Array(sources)) = fields.get("sources") else {
        return Err(Failure::Invalid);
    };
    for source in sources {
        let Value::Object(source) = source else {
            return Err(Failure::Invalid);
        };
        let text = |key: &str| {
            source
                .get(key)
                .and_then(Value::as_str)
                .ok_or(Failure::Invalid)
        };
        let path = Path::new(text("path")?);
        let label = text("label")?;
        let data = match source.get("data") {
            None => read_source(path, label)?,
            Some(Value::Null) => None,
            Some(Value::String(encoded)) => Some(decode(encoded)?),
            Some(_) => return Err(Failure::Invalid),
        };
        match text("kind")? {
            "toml" => read_toml(data.as_deref(), path, label).map(drop)?,
            "json" => read_json(data.as_deref(), path, label).map(drop)?,
            _ => return Err(Failure::Invalid),
        }
    }
    Ok(json!({ "checked": sources.len() }))
}

fn decode(encoded: &str) -> Step<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Failure::Invalid)
}

/// The disk read `strict_*_object` makes: a link or other non-file refuses,
/// an absent file reads as nothing, and a failed read refuses.
fn read_source(path: &Path, label: &str) -> Step<Option<Vec<u8>>> {
    let shown = path_text(path);
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            Err(Failure::Runtime(format!(
                "{UNREADABLE}: Guard refused to overwrite non-file {label} at {shown}. Replace it \
                 with a readable regular file before retrying install."
            )))
        }
        Ok(_) => std::fs::read(path).map(Some).map_err(|_| {
            Failure::Runtime(format!(
                "{UNREADABLE}: Guard could not read {label} at {shown}. Repair file permissions \
                 before retrying install."
            ))
        }),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
#[path = "codex_sources_tests.rs"]
mod tests;
