//! Codex marketplace discovery (`marketplace_support` + the plugin half of
//! `aibom_detection`). A marketplace file that escapes the workspace, or is
//! not a JSON object, is a typed refusal: the caller never gets a partial
//! plugin list.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::aibom_artifact::{content_version_info, guard_artifact, sha256_hex};
use super::aibom_paths::{
    exists, file_content_hash, is_dir, is_file, is_safe_relative_path, py_join, resolve,
    resolves_within_root, ERR_NON_UTF8,
};
use super::context_digest::python_strip;

pub(crate) const ERR_MARKETPLACE: &str = "native_runner_authority_aibom_marketplace_invalid";

struct Context {
    file_path: PathBuf,
    payload: Map<String, Value>,
}

fn load_context(repo_root: &Path) -> Result<Option<Context>, &'static str> {
    let preferred = py_join(repo_root, ".agents/plugins/marketplace.json");
    let file = if exists(&preferred) {
        preferred
    } else {
        let legacy = py_join(repo_root, "marketplace.json");
        if !exists(&legacy) {
            return Ok(None);
        }
        legacy
    };
    if !resolves_within_root(repo_root, &file, true) {
        return Err(ERR_MARKETPLACE);
    }
    let resolved = resolve(&file).map_err(|()| ERR_MARKETPLACE)?;
    let text = fs::read_to_string(&file).map_err(|_| ERR_MARKETPLACE)?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(payload)) => Ok(Some(Context {
            file_path: resolved,
            payload,
        })),
        _ => Err(ERR_MARKETPLACE),
    }
}

fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// `extract_marketplace_source`.
fn marketplace_source(entry: &Map<String, Value>) -> (Option<String>, Option<String>) {
    match entry.get("source") {
        Some(Value::String(source)) => (Some(source.clone()), None),
        Some(Value::Object(source)) => (
            non_empty_string(source.get("source")),
            non_empty_string(source.get("path")),
        ),
        _ => (None, None),
    }
}

fn plugin_manifest(workspace: &Path, source_path: Option<&str>) -> Option<PathBuf> {
    let relative = source_path?.strip_prefix("./")?;
    if !is_safe_relative_path(workspace, relative) {
        return None;
    }
    let candidate = py_join(workspace, relative);
    if !is_dir(&candidate) || !resolves_within_root(workspace, &candidate, true) {
        return None;
    }
    ["plugin.json", ".codex-plugin/plugin.json"]
        .iter()
        .map(|name| py_join(&candidate, name))
        .find(|manifest| is_file(manifest) && resolves_within_root(workspace, manifest, true))
}

/// `_discover_codex_marketplace_plugins`.
pub(crate) fn marketplace_plugins(
    harness: &str,
    workspace: &Path,
) -> Result<Vec<Value>, &'static str> {
    let Some(context) = load_context(workspace)? else {
        return Ok(Vec::new());
    };
    let Some(Value::Array(plugins)) = context.payload.get("plugins") else {
        return Ok(Vec::new());
    };
    let manifest_hash = file_content_hash(&context.file_path);
    let file_text = context.file_path.to_str().ok_or(ERR_NON_UTF8)?;
    let marketplace_id = sha256_hex(file_text)[..12].to_owned();
    let mut artifacts = Vec::new();
    if let Some(digest) = &manifest_hash {
        let mut metadata = Map::new();
        metadata.insert("marketplace_root".to_owned(), json!(true));
        metadata.insert("content_hash".to_owned(), json!(digest));
        metadata.insert(
            "versionInfo".to_owned(),
            content_version_info(digest, "marketplace.json"),
        );
        artifacts.push(guard_artifact(
            format!("{harness}:project:marketplace:{marketplace_id}"),
            "marketplace.json".to_owned(),
            harness,
            "plugin",
            "project",
            &context.file_path,
            metadata,
        ));
    }
    for (index, entry) in plugins.iter().enumerate() {
        let Value::Object(entry) = entry else {
            continue;
        };
        let plugin_name = match entry.get("name") {
            Some(Value::String(name)) if !python_strip(name).is_empty() => name.clone(),
            _ => format!("plugin_{index}"),
        };
        let (source_ref, source_path) = marketplace_source(entry);
        let mut metadata = Map::new();
        metadata.insert(
            "enabled".to_owned(),
            json!(entry.get("enabled") != Some(&Value::Bool(false))),
        );
        metadata.insert("marketplace_index".to_owned(), json!(index));
        metadata.insert("source_ref".to_owned(), json!(source_ref));
        metadata.insert("source_path".to_owned(), json!(source_path));
        let manifest = plugin_manifest(workspace, source_path.as_deref());
        if let Some(digest) = manifest.as_deref().and_then(file_content_hash) {
            metadata.insert("content_hash".to_owned(), json!(digest));
            metadata.insert(
                "versionInfo".to_owned(),
                content_version_info(&digest, &plugin_name),
            );
        }
        artifacts.push(guard_artifact(
            format!("{harness}:project:marketplace-plugin:{marketplace_id}:{plugin_name}"),
            plugin_name,
            harness,
            "plugin",
            "project",
            manifest.as_deref().unwrap_or(&context.file_path),
            metadata,
        ));
    }
    Ok(artifacts)
}
