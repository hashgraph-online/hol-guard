//! The Codex operation that queued a request, read the way
//! `get_guard_operation_for_approval_request` reads it, and the live hook
//! wait it proves.
//!
//! Its metadata is decoded as `json.loads` decodes it: a repeated key keeps
//! its first position and its last value, nonfinite floats survive, and a
//! lone surrogate escape is held in the mapped plane. The metadata is then
//! enriched with its project identity, and carried as the continuation
//! writer expects it: every nonfinite float and every string holding a lone
//! surrogate is `null` beside a record of its `json.dumps` token, so the
//! writer persists the bytes the Python store wrote.

use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::codex_hook_bridge::MAX_APPROVAL_WAIT_SECONDS;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::{add_micros_aware_isoformat, py_str, py_strip};
use crate::project_identity::PortableIdentity;
use crate::pyjson::{float_repr, in_surrogate_plane, PyVal, SURROGATE_PLANE_BASE};

const INVALID: &str = "codex_live_operation_invalid";
/// The configured wait when the config cannot be read.
const DEFAULT_WAIT_SECONDS: i64 = 120;

pub(crate) struct Operation {
    /// The raw row, to tell whether a later read saw the same operation.
    pub(crate) row: Value,
    /// The operation with its metadata as the continuation writer takes it.
    pub(crate) carried: Value,
    /// `[path, token]` for each metadata value carried as `null`.
    pub(crate) nonfinite: Vec<Value>,
    /// The metadata as Python reads it, nonfinite floats aside.
    pub(crate) metadata: Value,
    /// Whether the metadata held a lone surrogate escape.
    mapped: bool,
}

/// The operation listing `request_id`, or `None` when no operation does.
pub(crate) fn read(
    connection: &Connection,
    request_id: &str,
    cwd: Option<&str>,
) -> StoreResult<Option<Operation>> {
    decode(raw(connection, request_id)?, cwd)
}

pub(crate) fn raw(connection: &Connection, request_id: &str) -> StoreResult<Value> {
    let mut args = Map::new();
    args.insert("request_id".to_owned(), json!(request_id));
    crate::guard_store_sessions::operation_for_approval_request(connection, &Args(&args))
}

pub(crate) fn decode(row: Value, cwd: Option<&str>) -> StoreResult<Option<Operation>> {
    if row.is_null() {
        return Ok(None);
    }
    let text = |field: &str| py_str(&row[field]).ok_or(StoreError::Invalid(INVALID));
    let ids = crate::pyjson::parse(&text("approval_request_ids_json")?)
        .map_err(|_| StoreError::Invalid(INVALID))?;
    let parsed = crate::pyjson::parse_mapping_lone_surrogates(&text("metadata_json")?)
        .map_err(|_| StoreError::Invalid(INVALID))?;
    if parsed.mapped && parsed.collision {
        // A mapped surrogate can no longer be told from a genuine character.
        return Err(StoreError::Invalid(INVALID));
    }
    let mapped = parsed.mapped;
    let mut metadata = collapse(parsed.value);
    if let PyVal::Dict(entries) = &mut metadata {
        enrich(entries, mapped, cwd);
    }
    let mut nonfinite = Vec::new();
    let carried_metadata = carry(&metadata, &mut Vec::new(), mapped, &mut nonfinite)?;
    let resume_token = match &row["resume_token"] {
        Value::Null => Value::Null,
        value => json!(py_str(value).ok_or(StoreError::Invalid(INVALID))?),
    };
    let carried = json!({
        "operation_id": text("operation_id")?,
        "session_id": text("session_id")?,
        "harness": text("harness")?,
        "operation_type": text("operation_type")?,
        "status": text("status")?,
        "approval_request_ids": plain(&ids)?,
        "resume_token": resume_token,
        "metadata": carried_metadata,
        "created_at": text("created_at")?,
        "updated_at": text("updated_at")?,
    });
    Ok(Some(Operation {
        metadata: facts(&metadata)?,
        row,
        carried,
        nonfinite,
        mapped,
    }))
}

/// `codex_live_hook_wait_deadline`: the proven deadline of the hook waiting
/// on this operation, as `isoformat()` spells it.
pub(crate) fn wait_deadline(guard_home: &str, operation: &Operation) -> Option<String> {
    let metadata = &operation.metadata;
    if operation.carried["status"].as_str() != Some("waiting_on_approval") {
        return None;
    }
    if !crate::codex_hook_identity::process_identity_matches(
        &metadata["codex_browser_wait_process"],
    ) {
        return None;
    }
    if metadata["codex_hook_waits_for_browser_approval"] == Value::Bool(true) {
        let explicit = first_text(
            metadata,
            &["codex_browser_wait_deadline_at", "browser_wait_deadline_at"],
        );
        if let Some(deadline) = explicit.and_then(|text| add_micros_aware_isoformat(text, 0)) {
            return Some(deadline);
        }
    }
    if first_text(metadata, &["hook_event_name", "event"]) != Some("PreToolUse") {
        return None;
    }
    let started = first_text(&operation.carried, &["updated_at", "created_at"])?;
    add_micros_aware_isoformat(started, 0)?;
    let configured = match first_text(metadata, &["workspace"]) {
        // A path holding a lone surrogate cannot be encoded: a `ValueError`.
        Some(workspace) if surrogate(operation.mapped, workspace) => DEFAULT_WAIT_SECONDS,
        workspace => crate::guard_config_load::approval_wait_timeout_seconds_under(
            Path::new(guard_home),
            workspace.map(Path::new),
            &crate::codex_live_wait_build::managed_policy_source(),
        )
        .map(|seconds| seconds.clamp(0, MAX_APPROVAL_WAIT_SECONDS))
        .unwrap_or(DEFAULT_WAIT_SECONDS),
    };
    add_micros_aware_isoformat(started, (configured + 3).max(1) * 1_000_000)
}

/// The first non-blank string among `keys`, stripped.
pub(crate) fn first_text<'a>(mapping: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| mapping[*key].as_str())
        .map(py_strip)
        .find(|text| !text.is_empty())
}

/// `json.loads` keeps a repeated key at its first position with its last value.
fn collapse(value: PyVal) -> PyVal {
    match value {
        PyVal::Dict(entries) => {
            let mut collapsed: Vec<(String, PyVal)> = Vec::with_capacity(entries.len());
            for (key, item) in entries {
                let item = collapse(item);
                match collapsed.iter_mut().find(|(existing, _)| *existing == key) {
                    Some(slot) => slot.1 = item,
                    None => collapsed.push((key, item)),
                }
            }
            PyVal::Dict(collapsed)
        }
        PyVal::List(items) => PyVal::List(items.into_iter().map(collapse).collect()),
        other => other,
    }
}

/// `enrich_project_identity_metadata`: the canonical project identity in
/// `project_id`. A workspace that settles no identity keeps the explicit id.
fn enrich(entries: &mut Vec<(String, PyVal)>, mapped: bool, cwd: Option<&str>) {
    let text = |entries: &[(String, PyVal)], keys: &[&str]| -> Option<String> {
        keys.iter().find_map(|key| {
            entries
                .iter()
                .find(|(name, _)| name == key)
                .and_then(|(_, value)| match value {
                    PyVal::Str(text) if !py_strip(text).is_empty() => {
                        Some(py_strip(text).to_owned())
                    }
                    _ => None,
                })
        })
    };
    let explicit = text(entries, &["project_id", "projectId"]);
    let identity = match explicit.as_deref() {
        Some(explicit) if !looks_like_local_path(explicit) => Some(explicit.to_owned()),
        _ => {
            let workspace =
                text(entries, &["workspace_path", "workspacePath"]).or(explicit.clone());
            portable(workspace.as_deref(), mapped, cwd).or(explicit)
        }
    };
    let Some(identity) = identity else {
        return;
    };
    match entries.iter_mut().find(|(name, _)| name == "project_id") {
        Some(slot) => slot.1 = PyVal::Str(identity),
        None => entries.push(("project_id".to_owned(), PyVal::Str(identity))),
    }
}

/// `portable_project_identity_or_none`: an identity that cannot be settled,
/// including a workspace holding a lone surrogate, is none.
fn portable(workspace: Option<&str>, mapped: bool, cwd: Option<&str>) -> Option<String> {
    let workspace = workspace.filter(|workspace| !surrogate(mapped, workspace))?;
    match crate::guard_store_codex_live_authority::identity(Some(workspace), cwd) {
        PortableIdentity::Identity(identity) => Some(identity),
        PortableIdentity::Absent | PortableIdentity::Unknown => None,
    }
}

fn looks_like_local_path(value: &str) -> bool {
    let normalized = py_strip(value);
    if ["/", "~/", "./", "../", "\\\\"]
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return true;
    }
    let chars: Vec<char> = normalized.chars().take(3).collect();
    chars.len() >= 3 && chars[1] == ':' && matches!(chars[2], '\\' | '/')
}

/// Whether `text` holds a character read from a lone surrogate escape.
fn surrogate(mapped: bool, text: &str) -> bool {
    mapped && text.chars().any(in_surrogate_plane)
}

fn number(text: &str) -> StoreResult<Value> {
    serde_json::from_str(text).map_err(|_| StoreError::Invalid(INVALID))
}

/// A value holding no nonfinite float and no lone surrogate.
fn plain(value: &PyVal) -> StoreResult<Value> {
    let mut records = Vec::new();
    let value = carry(value, &mut Vec::new(), false, &mut records)?;
    if records.is_empty() {
        Ok(value)
    } else {
        Err(StoreError::Invalid(INVALID))
    }
}

/// The metadata as the facts read it: strings keep their mapped surrogates,
/// so a surrogate never matches a timestamp, an event name or a correlation.
fn facts(value: &PyVal) -> StoreResult<Value> {
    Ok(match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(*flag),
        PyVal::Int(digits) => number(digits)?,
        PyVal::Float(float) if float.is_finite() => number(&float_repr(*float))?,
        PyVal::Float(_) => Value::Null,
        PyVal::Str(text) => Value::String(text.clone()),
        PyVal::List(items) => Value::Array(items.iter().map(facts).collect::<StoreResult<_>>()?),
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| Ok((key.clone(), facts(item)?)))
                .collect::<StoreResult<_>>()?,
        ),
    })
}

/// `_metadata_carrier`.
fn carry(
    value: &PyVal,
    at: &mut Vec<Value>,
    mapped: bool,
    records: &mut Vec<Value>,
) -> StoreResult<Value> {
    Ok(match value {
        PyVal::Float(float) if !float.is_finite() => {
            let token = if float.is_nan() {
                "NaN"
            } else if *float > 0.0 {
                "Infinity"
            } else {
                "-Infinity"
            };
            records.push(json!([at.clone(), token]));
            Value::Null
        }
        PyVal::Str(text) if surrogate(mapped, text) => {
            records.push(json!([at.clone(), ascii_literal(text)]));
            Value::Null
        }
        PyVal::List(items) => {
            let mut carried = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                at.push(json!(index));
                carried.push(carry(item, at, mapped, records)?);
                at.pop();
            }
            Value::Array(carried)
        }
        PyVal::Dict(entries) => {
            let mut carried = Map::new();
            for (key, item) in entries {
                if surrogate(mapped, key) {
                    // The request envelope cannot carry the key at all.
                    return Err(StoreError::Invalid(INVALID));
                }
                at.push(json!(key));
                carried.insert(key.clone(), carry(item, at, mapped, records)?);
                at.pop();
            }
            Value::Object(carried)
        }
        other => facts(other)?,
    })
}

/// `json.dumps(text)`: ASCII only, with each mapped character written back
/// as the lone surrogate escape it was read from.
fn ascii_literal(text: &str) -> String {
    let mut literal = String::from("\"");
    for character in text.chars() {
        let code = character as u32;
        match character {
            '"' => literal.push_str("\\\""),
            '\\' => literal.push_str("\\\\"),
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            '\u{8}' => literal.push_str("\\b"),
            '\u{c}' => literal.push_str("\\f"),
            ' '..='~' => literal.push(character),
            _ if in_surrogate_plane(character) => {
                let _ = write!(literal, "\\u{:04x}", 0xD800 + code - SURROGATE_PLANE_BASE);
            }
            _ if code > 0xFFFF => {
                let offset = code - 0x1_0000;
                let _ = write!(
                    literal,
                    "\\u{:04x}\\u{:04x}",
                    0xD800 + (offset >> 10),
                    0xDC00 + (offset & 0x3FF)
                );
            }
            _ => {
                let _ = write!(literal, "\\u{code:04x}");
            }
        }
    }
    literal.push('"');
    literal
}

#[cfg(test)]
#[path = "codex_live_operation_tests.rs"]
mod tests;
