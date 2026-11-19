//! Codex: the strict source check an install runs before it plans anything.
//! Each config and hooks file must be a readable regular file, or absent, and
//! must parse strictly; a captured generation is parsed as it was captured.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex_migration::{read_json, read_toml};
use super::{path_text, Failure, Step};

const UNREADABLE: &str = "codex_hook_inventory_source_unreadable";
const CONFIG_LABEL: &str = "Codex config file";
const HOOKS_LABEL: &str = "Codex hooks file";

/// The strict parse of each config and hooks pair named in `pairs`, from
/// disk or over the bytes `contents` captured for it (a path mapped to
/// base64, or null for an absent file). A captured generation must name
/// every path of every pair; the parsed values are not needed.
pub(super) fn check_sources(fields: &Map<String, Value>) -> Step<Value> {
    let Some(Value::Array(pairs)) = fields.get("pairs") else {
        return Err(Failure::Invalid);
    };
    let captured = match fields.get("contents") {
        None => None,
        Some(Value::Object(contents)) => Some(contents),
        Some(_) => return Err(Failure::Invalid),
    };
    let mut sources = Vec::new();
    for pair in pairs {
        let Some([Value::String(config), Value::String(hooks)]) =
            pair.as_array().map(Vec::as_slice)
        else {
            return Err(Failure::Invalid);
        };
        for (path, label, kind) in [(config, CONFIG_LABEL, "toml"), (hooks, HOOKS_LABEL, "json")] {
            let mut source = json!({ "path": path, "label": label, "kind": kind });
            if let Some(contents) = captured {
                let data = contents.get(path).ok_or(Failure::Invalid)?;
                source["data"] = data.clone();
            }
            sources.push(source);
        }
    }
    check(&sources)
}

/// The strict parse of each named source (from disk, or over captured
/// bytes).
fn check(sources: &[Value]) -> Step<Value> {
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
