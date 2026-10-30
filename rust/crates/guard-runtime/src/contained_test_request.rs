//! `contained_test_request`: the contained sink's read of the private request
//! snapshot a routed call hands it.
//!
//! The hook writes the snapshot (`hook_direct_contained_request` on Unix,
//! `codex_hook_bridge_contain_windows` on Windows) and pins its digest in the
//! rewritten command. The sink reads it back only where and how the writer
//! left it, without following a link, at that digest, and only as the one
//! shape the writer produces, so a call the hook never saw cannot reach a
//! sandbox. Any other answer refuses the run.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "guard-contained-test-request.v1";
const DIRECTORY_PREFIX: &str = "hol-guard-contained-test-";
const FILE_NAME: &str = "request.json";
const MAX_BYTES: usize = 1_048_576;
const REFUSED: &str = "contained_run_authorization_failed";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: PathBuf,
    sha256: String,
    workspace: PathBuf,
    /// Every restricted operation is sent the caller's search path; this
    /// one never resolves a program.
    #[serde(default, rename = "search_path")]
    _search_path: String,
}

/// The call the snapshot carries, or the refusal the sink reports.
pub(crate) fn evaluate(input: &Value) -> Value {
    match read(input) {
        Some(payload) => json!({ "value": payload }),
        None => json!({
            "reason_code": REFUSED,
            "message": "Guard could not authorize this contained run.",
        }),
    }
}

fn read(input: &Value) -> Option<Map<String, Value>> {
    let input = Input::deserialize(input).ok()?;
    if input.sha256.len() != 64
        || !input
            .sha256
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || !input.path.is_absolute()
        || input.path.file_name() != Some(OsStr::new(FILE_NAME))
        || !input
            .path
            .parent()?
            .file_name()?
            .to_str()?
            .starts_with(DIRECTORY_PREFIX)
    {
        return None;
    }
    let raw = read_snapshot(&input.path)?;
    decode(&raw, &input.sha256, &input.workspace)
}

/// The snapshot's bytes, held to the digest the command pins and to the one
/// document the writer produces: the schema, the workspace the sink runs in,
/// and a shell call that names no other directory.
fn decode(raw: &[u8], sha256: &str, workspace: &Path) -> Option<Map<String, Value>> {
    if raw.len() > MAX_BYTES || format!("{:x}", Sha256::digest(raw)) != sha256 {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    // A repeated key would let two readers of one snapshot see two calls.
    guard_runtime_pyjson::parse_unique(text).ok()?;
    let Value::Object(mut document) = serde_json::from_str::<Value>(text).ok()? else {
        return None;
    };
    let workspace = workspace.canonicalize().ok()?;
    if document.len() != 3
        || document.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || resolved(document.get("workspace")?)? != workspace
    {
        return None;
    }
    let Value::Object(payload) = document.remove("payload")? else {
        return None;
    };
    if let Some(cwd) = payload.get("cwd") {
        if resolved(cwd)? != workspace {
            return None;
        }
    }
    let command = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|tool_input| tool_input.get("command"));
    if payload.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse")
        || payload.get("tool_name").and_then(Value::as_str) != Some("bash")
        || !command.is_some_and(Value::is_string)
    {
        return None;
    }
    Some(payload)
}

/// An absolute directory the snapshot names, resolved as it exists now.
fn resolved(value: &Value) -> Option<PathBuf> {
    let path = Path::new(value.as_str()?);
    if !path.is_absolute() {
        return None;
    }
    path.canonicalize().ok()
}

#[cfg(unix)]
fn read_snapshot(path: &Path) -> Option<Vec<u8>> {
    crate::hook_direct::contained::request::read_snapshot(path)
}

#[cfg(windows)]
fn read_snapshot(path: &Path) -> Option<Vec<u8>> {
    crate::codex_hook_bridge::contain::windows::read_snapshot(path)
}

#[cfg(not(any(unix, windows)))]
fn read_snapshot(_: &Path) -> Option<Vec<u8>> {
    None
}

#[cfg(all(test, unix))]
#[path = "contained_test_request_tests.rs"]
mod tests;
