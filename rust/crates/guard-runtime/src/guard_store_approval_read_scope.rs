//! Resident boundaries of the approval queue read, kept in process.
//!
//! The Python read projected every stored row (`_project_listing_rows`) and
//! derived every payload's scope contract (`request_scope_contract_payloads`)
//! through resident requests. Their transport limits decided outcomes: a
//! value past the strict JSON depth, width or string bounds failed the read as
//! `ApprovalScopeUnavailableError`, and a single row the projection refused by
//! size projected again as unreadable. [`project`] and [`scope_contract`]
//! keep both outcomes; the byte bounds are measured on the same encodings the
//! Python transport produced.

use std::path::Path;

use guard_contracts::{
    ApprovalScopeItemV1, APPROVAL_SCOPE_REQUEST_SCHEMA, MAX_NATIVE_RESPONSE_BYTES,
    RUNNER_AUTHORITY_MAX_BYTES, RUNNER_AUTHORITY_REQUEST_SCHEMA, RUNNER_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::approval_scope_contract::{contract, text as scope_text, View};
use crate::approval_scope_op::contract_value;
use crate::claude_hook_bridge_url::resolve_absolute;
use crate::guard_store_db::{Row, StoreError, StoreResult};
use crate::guard_store_silent_review::{narrow_envelope, py_str, raw};
use crate::pyjson::{float_repr, parse_mapping_lone_surrogates, JsonFailure, PyVal};
use crate::signal_projection_receipt::surfaces;

/// The message the Python wrapper raises as `ApprovalScopeUnavailableError`.
pub(crate) const UNAVAILABLE: &str = "native_approval_scope_unavailable";
const RECURSION: &str = "maximum recursion depth exceeded while decoding a JSON document";
/// `strict_json` bounds of every resident request.
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
/// `native_approval_scope._MAX_REQUEST_BYTES`.
const SCOPE_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// `decision_boundaries._UNREADABLE_ACTION_MAX_LENGTH`.
const UNREADABLE_ACTION_MAX_CHARS: usize = 64;
/// Depth of one projection row and of one scope item inside its request.
const PROJECTION_ROW_DEPTH: usize = 4;
const SCOPE_ITEM_DEPTH: usize = 3;
const REQUEST_FIELDS: [&str; 14] = [
    "artifact_id",
    "artifact_type",
    "artifact_hash",
    "artifact_name",
    "policy_action",
    "harness",
    "publisher",
    "source_scope",
    "config_path",
    "wrapper_chain",
    "action_identity",
    "raw_command_text",
    "action_envelope_json",
    "scanner_evidence",
];

pub(crate) fn unavailable() -> StoreError {
    StoreError::Value(UNAVAILABLE.to_owned())
}

/// `json.loads(str(cell))` for a column whose readers catch decode errors:
/// `None` for a null cell or undecodable text. A lone surrogate escape is
/// reported, since no resident request or reply can carry one.
pub(crate) fn parse_cell(row: &Row, name: &str) -> StoreResult<Option<(PyVal, bool)>> {
    let cell = raw(row, name);
    if cell.is_null() {
        return Ok(None);
    }
    match parse_mapping_lone_surrogates(&py_str(Some(&cell))?) {
        Ok(parsed) => Ok(Some((parsed.value, parsed.mapped))),
        Err(JsonFailure::Unrepresentable) => Err(StoreError::Runtime(RECURSION.to_owned())),
        Err(_) => Ok(None),
    }
}

/// The decoded value as the reply carries it; floats keep CPython's text.
pub(crate) fn to_json(value: &PyVal) -> StoreResult<Value> {
    Ok(match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(*flag),
        PyVal::Int(digits) => serde_json::from_str(digits).map_err(|_| unavailable())?,
        PyVal::Float(number) if number.is_finite() => {
            serde_json::from_str(&float_repr(*number)).map_err(|_| unavailable())?
        }
        PyVal::Float(_) => return Err(unavailable()),
        PyVal::Str(text) => Value::String(text.clone()),
        PyVal::List(items) => Value::Array(items.iter().map(to_json).collect::<StoreResult<_>>()?),
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| Ok((key.clone(), to_json(item)?)))
                .collect::<StoreResult<_>>()?,
        ),
    })
}

fn non_finite(value: &PyVal) -> bool {
    match value {
        PyVal::Float(number) => !number.is_finite(),
        PyVal::List(items) => items.iter().any(non_finite),
        PyVal::Dict(entries) => entries.iter().any(|(_, item)| non_finite(item)),
        _ => false,
    }
}

enum Input {
    Ready(Value),
    NonFinite,
    Surrogate,
}

/// `_row_decision_inputs`: the stored JSON object, else the stored cell.
fn decision_input(row: &Row, name: &str) -> StoreResult<Input> {
    if let Some((value @ PyVal::Dict(_), surrogate)) = parse_cell(row, name)? {
        return Ok(if non_finite(&value) {
            Input::NonFinite
        } else if surrogate {
            Input::Surrogate
        } else {
            Input::Ready(to_json(&value)?)
        });
    }
    Ok(Input::Ready(raw(row, name)))
}

/// `_project_listing_rows` for one stored row: the canonical surfaces, or the
/// unreadable projection when the resident would have refused the row.
pub(crate) fn project(row: &Row, guard_home: &str) -> StoreResult<Value> {
    let action = raw(row, "policy_action");
    let (decision, envelope) = match (
        decision_input(row, "decision_v2_json")?,
        decision_input(row, "action_envelope_json")?,
    ) {
        (Input::NonFinite, _) | (_, Input::NonFinite) => return unreadable(&action),
        (Input::Surrogate, _) | (_, Input::Surrogate) => return Err(unavailable()),
        (Input::Ready(decision), Input::Ready(envelope)) => (decision, envelope),
    };
    let input = json!({"action": action, "decision": decision, "envelope": envelope});
    let request = json!({
        "schema": RUNNER_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "0".repeat(32),
        "guard_home": guard_home,
        "kind": "projection_surfaces_batch",
        "args": {"rows": [null], "reject": false},
    });
    let transport =
        json!({"operation": "runner_authority", "deadline_budget_ms": 5000, "request": request});
    if framed(&transport, &input, Style::Compact) > RUNNER_AUTHORITY_MAX_BYTES {
        return unreadable(&action);
    }
    if !fits(&input, PROJECTION_ROW_DEPTH) {
        return Err(unavailable());
    }
    if framed(&request, &input, Style::Canonical) > RUNNER_AUTHORITY_MAX_BYTES {
        return unreadable(&action);
    }
    let projected = checked(surfaces(&action, &decision, &envelope, false))?;
    let reply = json!({
        "schema": RUNNER_AUTHORITY_RESULT_SCHEMA,
        "request_id": "0".repeat(32),
        "request_sha256": "0".repeat(64),
        "status": "ok",
        "code": "ok",
        "payload": {"status": "ok", "value": [null]},
    });
    if framed(&reply, &projected, Style::Compact) > MAX_NATIVE_RESPONSE_BYTES {
        return unreadable(&action);
    }
    Ok(projected)
}

/// `_unreadable_row`: a non-object decision the projection fails closed on.
fn unreadable(action: &Value) -> StoreResult<Value> {
    let action = match action {
        Value::String(text) if text.chars().count() <= UNREADABLE_ACTION_MAX_CHARS => {
            action.clone()
        }
        _ => Value::Null,
    };
    checked(surfaces(&action, &json!("unreadable"), &Value::Null, false))
}

/// The result checks of `signal_projection`; a surfaces error is the plain
/// `ValueError` Python re-raised.
fn checked(projected: Result<Value, String>) -> StoreResult<Value> {
    let projected = projected.map_err(StoreError::Value)?;
    let valid = projected["policy_action"].is_string()
        && projected["decision_v2_json"].is_object()
        && (projected["action_envelope_json"].is_null()
            || projected["action_envelope_json"].is_object())
        && (projected["contract_error"].is_null() || projected["contract_error"].is_string());
    if valid {
        Ok(projected)
    } else {
        Err(unavailable())
    }
}

/// The contract `request_scope_contract_payloads` attaches to one draft.
pub(crate) fn scope_contract(
    draft: &Map<String, Value>,
    cwd: Option<&str>,
) -> StoreResult<Map<String, Value>> {
    let mut item: Map<String, Value> = REQUEST_FIELDS
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                draft.get(*name).cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    let envelope = narrow_envelope(&item["action_envelope_json"]);
    item.insert("action_envelope_json".to_owned(), envelope);
    let target = workspace_target(draft, cwd).map_or(Value::Null, Value::String);
    item.insert("workspace_target".to_owned(), target);
    let item = Value::Object(item);
    let transport = json!({
        "operation": "approval_scope",
        "request": {
            "schema": APPROVAL_SCOPE_REQUEST_SCHEMA,
            "request_id": format!("approval-scope-{}", "0".repeat(32)),
            "items": [null],
        },
        "deadline_budget_ms": 10000,
    });
    if !fits(&item, SCOPE_ITEM_DEPTH)
        || framed(&transport, &item, Style::Spaced) > SCOPE_MAX_REQUEST_BYTES
    {
        return Err(unavailable());
    }
    let item: ApprovalScopeItemV1 = serde_json::from_value(item).map_err(|_| unavailable())?;
    let Value::Object(mut contract) = contract_value(&contract(&View::new(&item))) else {
        return Err(unavailable());
    };
    contract.remove("exact_context_token");
    Ok(contract)
}

/// `_derived_workspace_scope_target`: the stored workspace, else the
/// workspace root of the resolved config path. A relative path resolves
/// against the caller's working directory.
fn workspace_target(draft: &Map<String, Value>, cwd: Option<&str>) -> Option<String> {
    if let Some(workspace) = scope_text(draft.get("workspace")) {
        return Some(workspace.to_owned());
    }
    let config_path = scope_text(draft.get("config_path"))?;
    let joined = cwd.map_or_else(
        || config_path.to_owned(),
        |cwd| {
            Path::new(cwd)
                .join(config_path)
                .to_string_lossy()
                .into_owned()
        },
    );
    let resolved = if Path::new(&joined).is_absolute() {
        resolve_absolute(&joined)
    } else {
        joined
    };
    let config_file = Path::new(&resolved);
    let parent = config_file.parent().unwrap_or(config_file);
    let dotted = parent
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('.'));
    let root = if dotted {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };
    let root = root.to_string_lossy();
    Some(if root.is_empty() {
        ".".to_owned()
    } else {
        root.into_owned()
    })
}

/// Whether the resident's strict JSON reader accepts `value` at `depth`.
fn fits(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::String(text) => text.len() <= MAX_JSON_STRING_BYTES,
        Value::Array(items) => {
            items.len() <= MAX_JSON_ITEMS && items.iter().all(|item| fits(item, depth + 1))
        }
        Value::Object(fields) => {
            fields.len() <= MAX_JSON_ITEMS
                && fields
                    .iter()
                    .all(|(key, item)| key.len() <= MAX_JSON_STRING_BYTES && fits(item, depth + 1))
        }
        _ => true,
    }
}

#[derive(Clone, Copy)]
enum Style {
    /// `json.dumps(separators=(",", ":"), ensure_ascii=False)`.
    Compact,
    /// `json.dumps(separators=(",", ":"))`, as the canonical digest encodes.
    Canonical,
    /// `json.dumps(value)`.
    Spaced,
}

/// Encoded length of `frame` with its one `null` placeholder replaced by `inner`.
fn framed(frame: &Value, inner: &Value, style: Style) -> usize {
    encoded_len(frame, style) - 4 + encoded_len(inner, style)
}

fn encoded_len(value: &Value, style: Style) -> usize {
    let separator = if matches!(style, Style::Spaced) { 2 } else { 1 };
    let ascii = !matches!(style, Style::Compact);
    match value {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => string_len(text, ascii),
        Value::Array(items) => {
            2 + items
                .iter()
                .map(|item| encoded_len(item, style))
                .sum::<usize>()
                + separator * items.len().saturating_sub(1)
        }
        Value::Object(fields) => {
            2 + fields
                .iter()
                .map(|(key, item)| string_len(key, ascii) + separator + encoded_len(item, style))
                .sum::<usize>()
                + separator * fields.len().saturating_sub(1)
        }
    }
}

fn string_len(text: &str, ascii: bool) -> usize {
    2 + text
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c if ascii && (c as u32) > 0xffff => 12,
            c if ascii && (c as u32) >= 0x7f => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}
