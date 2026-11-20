//! Codex detection paths spelled the way the caller's context did. Python
//! reads the sources at their anchored (absolute) paths; the reply names them
//! as the context spelled them.

use std::borrow::Cow;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::ERR_INVALID;

/// `anchor_to_process_directory`: a relative path joined to `cwd`, with no
/// normalization.
fn anchored(cwd: &str, text: &str) -> String {
    let path = Path::new(text);
    if path.is_absolute() {
        text.to_owned()
    } else {
        Path::new(cwd).join(path).to_string_lossy().into_owned()
    }
}

/// The request over `pairs` the caller's context named (`config`, `hooks`
/// and `scope` each), as the `sources`, `restore` and anchored `contents`
/// the detection reads. `cwd` is the process directory the sources are
/// anchored to, and `authenticated_config` the one config whose hooks the
/// authenticated bindings cover. A request without `pairs` passes through.
pub(super) fn expand(
    args: &Map<String, Value>,
) -> Result<Cow<'_, Map<String, Value>>, &'static str> {
    let Some(pairs) = args.get("pairs") else {
        return Ok(Cow::Borrowed(args));
    };
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let (cwd, authenticated_config) = (text("cwd")?, text("authenticated_config")?);
    let mut sources = Vec::new();
    let mut restore: Vec<(String, &str)> = Vec::new();
    for pair in pairs.as_array().ok_or(ERR_INVALID)? {
        let pair = pair.as_object().ok_or(ERR_INVALID)?;
        let field = |key: &str| pair.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
        let (config, hooks, scope) = (field("config")?, field("hooks")?, field("scope")?);
        for original in [config, hooks] {
            let spelled = anchored(cwd, original);
            if spelled != original {
                match restore.iter().position(|(known, _)| *known == spelled) {
                    Some(index) => restore[index].1 = original,
                    None => restore.push((spelled, original)),
                }
            }
        }
        sources.push(json!({
            "config_path": anchored(cwd, config),
            "hooks_path": anchored(cwd, hooks),
            "config_scope": scope,
            "hooks_scope": scope,
            "authenticated": config == authenticated_config,
        }));
    }
    let mut expanded = args.clone();
    expanded.remove("pairs");
    expanded.insert("sources".to_owned(), Value::Array(sources));
    expanded.insert(
        "restore".to_owned(),
        restore
            .into_iter()
            .map(|(spelled, original)| json!([spelled, original]))
            .collect(),
    );
    match args.get("contents") {
        None | Some(Value::Null) => {}
        Some(Value::Object(captured)) => {
            let keyed: Map<String, Value> = captured
                .iter()
                .map(|(path, data)| (anchored(cwd, path), data.clone()))
                .collect();
            expanded.insert("contents".to_owned(), Value::Object(keyed));
        }
        Some(_) => return Err(ERR_INVALID),
    }
    Ok(Cow::Owned(expanded))
}

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
