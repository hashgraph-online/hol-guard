//! Sensitive file read/write request matching and their runtime artifacts
//! (`runtime/secret_file_request_services/request_models.py` and
//! `request_artifacts.py`).

// Items without a caller yet are consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::codex_output_py::{py_strip, shlex_join, PyPath};
use crate::home_path_text::{expand_home, normalize_path};
use crate::hook_adapter_envelope_text::apply_patch_target_paths;
use crate::hook_adapter_value::{OMap, OValue};
use crate::launch_identity_common::sha256_hex;
use crate::sfrs_constants::{
    FILE_READ_TOOL_NAMES, FILE_WRITE_TOOL_NAMES, PATH_KEYS, PATH_LIST_KEYS,
};
use crate::sfrs_json::dumps_sorted;
use crate::shell_secret_read_support::classify_request_secret_path;

/// `SecretPathMatch` with owned fields.
#[derive(Clone, Debug)]
pub(crate) struct SensitivePath {
    pub family: String,
    pub path: String,
    pub sensitivity: String,
    pub reason: String,
    pub requested_path: String,
}

/// `classify_sensitive_path`.
pub(crate) fn classify_sensitive_path(
    path: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<SensitivePath> {
    classify_request_secret_path(path, cwd, home_dir).map(|found| SensitivePath {
        family: found.family,
        path: found.path,
        sensitivity: found.sensitivity.to_owned(),
        reason: found.reason.to_owned(),
        requested_path: found.requested_path,
    })
}

/// `FileReadRequestMatch`.
#[derive(Clone, Debug)]
pub(crate) struct FileReadRequest {
    pub tool_name: String,
    pub normalized_tool_name: String,
    pub path_match: SensitivePath,
}

/// `FileWriteRequestMatch`.
#[derive(Clone, Debug)]
pub(crate) struct FileWriteRequest {
    pub tool_name: String,
    pub normalized_tool_name: String,
    pub normalized_path: String,
    pub path_class: String,
    pub reason: String,
    pub action_class: String,
}

/// `is_file_read_tool_name`.
pub(crate) fn is_file_read_tool_name(tool_name: Option<&str>) -> bool {
    tool_name.is_some_and(|name| {
        let stripped = py_strip(name);
        !stripped.is_empty() && FILE_READ_TOOL_NAMES.contains(&stripped.to_lowercase().as_str())
    })
}

/// `_normalize_tool_name`.
pub(crate) fn normalize_tool_name(tool_name: &OValue) -> Option<String> {
    match tool_name {
        OValue::Str(text) if !py_strip(text).is_empty() => Some(py_strip(text).to_lowercase()),
        _ => None,
    }
}

/// `_is_lossy_redacted_path`.
fn is_lossy_redacted_path(path: &str) -> bool {
    py_strip(path).starts_with(".../")
}

/// `_normalized_candidate_path`.
fn normalized_candidate_path(
    value: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<String> {
    let stripped = py_strip(value)
        .trim_matches('\'')
        .trim_matches('"')
        .to_owned();
    if stripped.is_empty() {
        return None;
    }
    Some(normalize_path(&expand_home(&stripped, home_dir), cwd))
}

fn non_blank(value: &OValue) -> Option<&str> {
    match value {
        OValue::Str(text) if !py_strip(text).is_empty() => Some(text),
        _ => None,
    }
}

/// `_candidate_paths` / `_collect_candidate_paths`.
pub(crate) fn candidate_paths(value: &OValue, include_apply_patch: bool) -> Vec<String> {
    let mut results = Vec::new();
    collect_candidate_paths(value, &mut results, 0);
    if include_apply_patch {
        if let OValue::Map(map) = value {
            results.extend(apply_patch_target_paths(map));
        }
    }
    results
}

fn collect_candidate_paths(value: &OValue, results: &mut Vec<String>, depth: usize) {
    if depth > 4 {
        return;
    }
    match value {
        OValue::Map(map) => {
            for key in PATH_KEYS {
                if let Some(candidate) = map.get(key).and_then(non_blank) {
                    results.push(candidate.to_owned());
                }
            }
            for key in PATH_LIST_KEYS {
                if let Some(OValue::List(items)) = map.get(key) {
                    results.extend(items.iter().filter_map(non_blank).map(str::to_owned));
                }
            }
            for (_, child) in map.iter() {
                if matches!(child, OValue::Map(_) | OValue::List(_)) {
                    collect_candidate_paths(child, results, depth + 1);
                }
            }
        }
        OValue::List(items) => {
            for child in items {
                if let Some(text) = non_blank(child) {
                    results.push(text.to_owned());
                } else if matches!(child, OValue::Map(_) | OValue::List(_)) {
                    collect_candidate_paths(child, results, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// `extract_sensitive_file_read_request`.
pub(crate) fn extract_sensitive_file_read_request(
    tool_name: &OValue,
    arguments: &OValue,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<FileReadRequest> {
    let normalized = normalize_tool_name(tool_name)?;
    if !FILE_READ_TOOL_NAMES.contains(&normalized.as_str()) {
        return None;
    }
    for candidate in candidate_paths(arguments, false) {
        if let Some(path_match) = classify_sensitive_path(&candidate, cwd, home_dir) {
            return Some(FileReadRequest {
                tool_name: py_strip(tool_name.as_str().unwrap_or_default()).to_owned(),
                normalized_tool_name: normalized,
                path_match,
            });
        }
    }
    None
}

/// `extract_sensitive_file_read_request_from_action` over the action
/// envelope's `action_type`, `tool_name` and `target_paths`.
pub(crate) fn extract_sensitive_file_read_request_from_action(
    action: &OMap,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<FileReadRequest> {
    if action.get_str("action_type") != Some("file_read") {
        return None;
    }
    let tool_value = action.get("tool_name").cloned().unwrap_or(OValue::Null);
    let normalized = normalize_tool_name(&tool_value).unwrap_or_else(|| "read".to_owned());
    let tool_name = match non_blank(&tool_value) {
        Some(text) => py_strip(text).to_owned(),
        None => "Read".to_owned(),
    };
    if !FILE_READ_TOOL_NAMES.contains(&normalized.as_str()) {
        return None;
    }
    let Some(OValue::List(paths)) = action.get("target_paths") else {
        return None;
    };
    for candidate in paths.iter().filter_map(OValue::as_str) {
        if is_lossy_redacted_path(candidate) {
            continue;
        }
        if let Some(path_match) = classify_sensitive_path(candidate, cwd, home_dir) {
            return Some(FileReadRequest {
                tool_name,
                normalized_tool_name: normalized,
                path_match,
            });
        }
    }
    None
}

/// The harness configuration files a write may not reach without a review,
/// derived here from the harness and the directories the request already carries
/// (`cli/commands_support_runtime_artifacts._runtime_protected_file_write_paths`).
///
/// The caller used to compute this table and hand it over, so a caller that
/// sent an empty one left every Codex configuration file writable without a
/// review. The paths follow from the harness name and the two directories the
/// request already carries, and nothing about them is the caller's to decide,
/// so they are decided here instead and the caller's table is only added to
/// what this returns.
///
/// Each path is normalized the way a candidate path is, so an entry matches
/// exactly when the write names that same file, however the caller spelled it.
pub(crate) fn harness_protected_write_paths(
    harness: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<(String, String)> {
    if harness != "codex" {
        return Vec::new();
    }
    let mut protected = Vec::new();
    let mut push = |root: &Path, name: &str, label: &str| {
        let path = root.join(".codex").join(name);
        let spelled = path.to_string_lossy().into_owned();
        let normalized = normalized_candidate_path(&spelled, cwd, home_dir).unwrap_or(spelled);
        if !protected
            .iter()
            .any(|(existing, _)| *existing == normalized)
        {
            protected.push((normalized, label.to_owned()));
        }
    };
    if let Some(home) = home_dir {
        push(home, "config.toml", "Codex config");
        push(home, "hooks.json", "Codex hooks");
    }
    if let Some(workspace) = cwd {
        push(workspace, "config.toml", "Codex config");
        push(workspace, "hooks.json", "Codex hooks");
    }
    protected
}

/// `extract_sensitive_file_write_request`. `protected_paths` maps normalized
/// paths to the harness configuration label that owns them.
pub(crate) fn extract_sensitive_file_write_request(
    tool_name: &OValue,
    arguments: &OValue,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    protected_paths: &[(String, String)],
) -> Option<FileWriteRequest> {
    let normalized = normalize_tool_name(tool_name)?;
    if !FILE_WRITE_TOOL_NAMES.contains(&normalized.as_str()) {
        return None;
    }
    let requested = match tool_name {
        OValue::Str(text) if !py_strip(text).is_empty() => py_strip(text).to_owned(),
        _ => "Write".to_owned(),
    };
    for candidate in candidate_paths(arguments, normalized == "apply_patch") {
        if let Some(normalized_candidate) = normalized_candidate_path(&candidate, cwd, home_dir) {
            if let Some((_, label)) = protected_paths
                .iter()
                .find(|(path, _)| *path == normalized_candidate)
            {
                return Some(FileWriteRequest {
                    tool_name: requested,
                    normalized_tool_name: normalized,
                    normalized_path: normalized_candidate,
                    path_class: label.clone(),
                    reason: format!(
                        "Guard treats writes to {label} as sensitive because changing harness \
                         configuration can weaken approvals or bypass protections before the user \
                         confirms the action."
                    ),
                    action_class: "guard-managed config write".to_owned(),
                });
            }
        }
        if let Some(path_match) = classify_sensitive_path(&candidate, cwd, home_dir) {
            return Some(FileWriteRequest {
                tool_name: requested,
                normalized_tool_name: normalized,
                normalized_path: path_match.path,
                path_class: path_match.family,
                reason: path_match.reason,
                action_class: "sensitive local file write".to_owned(),
            });
        }
    }
    None
}

/// The artifact wire every request artifact is sent on. The fields a request
/// artifact never carries are still named, as their empty forms, so a reader
/// that validates the shape sees one key set whatever built it.
pub(crate) fn request_artifact_wire(
    artifact_id: String,
    name: String,
    harness: &str,
    artifact_type: &str,
    source_scope: &str,
    config_path: &str,
    metadata: Value,
) -> Value {
    json!({
        "artifact_id": artifact_id,
        "name": name,
        "harness": harness,
        "artifact_type": artifact_type,
        "source_scope": source_scope,
        "config_path": config_path,
        "command": Value::Null,
        "args": [],
        "url": Value::Null,
        "transport": Value::Null,
        "publisher": Value::Null,
        "metadata": metadata,
        "runtime_private_metadata": {},
    })
}

/// The last component of `path` for an artifact's display name, as the
/// retired Python builders read it with `Path(...).name`: on Windows that
/// splits on `\` as well as `/`, so a review names `id_rsa` rather than the
/// whole path.
pub(crate) fn artifact_file_name(path: &str) -> String {
    let parsed = PyPath::new(path);
    let name = parsed.name();
    if cfg!(windows) {
        let name = name.trim_end_matches('\\');
        name.rsplit('\\').next().unwrap_or(name).to_owned()
    } else {
        name.to_owned()
    }
}

/// `build_file_read_request_artifact`.
pub(crate) fn build_file_read_request_artifact(
    harness: &str,
    request: &FileReadRequest,
    config_path: &str,
    source_scope: &str,
) -> Value {
    let mut payload = Map::new();
    payload.insert("harness".into(), json!(harness));
    payload.insert("tool_name".into(), json!(request.normalized_tool_name));
    payload.insert("normalized_path".into(), json!(request.path_match.path));
    let fingerprint = sha256_hex(dumps_sorted(&Value::Object(payload)).as_bytes());
    let family = &request.path_match.family;
    let metadata = json!({
        "tool_name": request.tool_name,
        "normalized_path": request.path_match.path,
        "path_class": family,
        "request_summary": format!(
            "Requested `{}` access to `{}` ({family}).",
            request.tool_name, request.path_match.path
        ),
        "runtime_request_signals": ["requests access to a sensitive local file"],
        "runtime_request_summary": format!("Requests access to a sensitive local file: {family}."),
        "runtime_request_reason": request.path_match.reason,
    });
    request_artifact_wire(
        format!("{harness}:{source_scope}:file-read:{fingerprint}"),
        format!(
            "{} {}",
            request.tool_name,
            artifact_file_name(&request.path_match.path)
        ),
        harness,
        "file_read_request",
        source_scope,
        config_path,
        metadata,
    )
}

/// `build_file_write_request_artifact`.
pub(crate) fn build_file_write_request_artifact(
    harness: &str,
    request: &FileWriteRequest,
    config_path: &str,
    source_scope: &str,
) -> Value {
    let fingerprint = sha256_hex(
        dumps_sorted(&json!({
            "harness": harness,
            "tool_name": request.normalized_tool_name,
            "normalized_path": request.normalized_path,
            "action_class": request.action_class,
        }))
        .as_bytes(),
    );
    let metadata = json!({
        "tool_name": request.tool_name,
        "normalized_path": request.normalized_path,
        "path_class": request.path_class,
        "action_class": request.action_class,
        "request_summary": format!(
            "Requested `{}` write access to `{}` ({}).",
            request.tool_name, request.normalized_path, request.path_class
        ),
        "runtime_request_signals": [format!("writes a sensitive local path: {}", request.path_class)],
        "runtime_request_summary": format!(
            "Requests a {}: {}.",
            request.action_class, request.path_class
        ),
        "runtime_request_reason": request.reason,
    });
    request_artifact_wire(
        format!("{harness}:{source_scope}:file-write:{fingerprint}"),
        format!(
            "{} {}",
            request.tool_name,
            artifact_file_name(&request.normalized_path)
        ),
        harness,
        "tool_action_request",
        source_scope,
        config_path,
        metadata,
    )
}

/// `command_list_candidate_texts`.
pub(crate) fn command_list_candidate_texts(values: &[OValue], preserve_items: bool) -> Vec<String> {
    let strings: Vec<String> = values
        .iter()
        .filter_map(non_blank)
        .map(|item| py_strip(item).to_owned())
        .collect();
    if strings.is_empty() {
        return Vec::new();
    }
    if preserve_items {
        return strings;
    }
    if strings.len() == 1 {
        return strings;
    }
    vec![shlex_join(&strings)]
}
