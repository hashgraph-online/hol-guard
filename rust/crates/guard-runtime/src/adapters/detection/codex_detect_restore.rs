//! Codex detection paths spelled the way the caller's context did. Python
//! reads the sources at their anchored (absolute) paths; the reply names them
//! as the context spelled them.

use serde_json::{Map, Value};

use super::ERR_INVALID;

/// The `[anchored, original]` spellings the caller's context used, in order.
pub(super) fn restorations(args: &Map<String, Value>) -> Result<Vec<(&str, &str)>, &'static str> {
    let Some(pairs) = args.get("restore") else {
        return Ok(Vec::new());
    };
    pairs
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(anchored), Value::String(original)]) => {
                Ok((anchored.as_str(), original.as_str()))
            }
            _ => Err(ERR_INVALID),
        })
        .collect()
}

fn restored<'a>(restore: &'a [(&str, &str)], text: &'a str) -> &'a str {
    restore
        .iter()
        .find(|(anchored, _)| *anchored == text)
        .map_or(text, |(_, original)| original)
}

fn restore_value(restore: &[(&str, &str)], value: &mut Value) {
    match value {
        Value::String(text) => *text = restored(restore, text).to_owned(),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| restore_value(restore, item)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| restore_value(restore, item)),
        _ => {}
    }
}

/// Spells anchored source paths the way the caller's context did: each
/// artifact's config path and metadata strings and each found path exactly,
/// and every anchored spelling inside a warning's text.
pub(super) fn restore_paths(
    restore: &[(&str, &str)],
    artifacts: &mut [Value],
    found: &mut [String],
    warnings: &mut [String],
) {
    for artifact in artifacts.iter_mut() {
        if let Some(path) = artifact.get_mut("config_path") {
            restore_value(restore, path);
        }
        if let Some(metadata) = artifact.get_mut("metadata") {
            restore_value(restore, metadata);
        }
    }
    for path in found.iter_mut() {
        *path = restored(restore, path).to_owned();
    }
    for warning in warnings.iter_mut() {
        for (anchored, original) in restore {
            *warning = warning.replace(anchored, original);
        }
    }
}

#[cfg(test)]
#[path = "codex_detect_restore_tests.rs"]
mod tests;
