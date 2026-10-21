//! `add_silent_native_review_approval_request`: the safe-alternative branch
//! of `pause_native_pre_tool_for_approval` (`hook_native_review_approval.py`)
//! in one store write. The agent stays on the silent block; the inbox row and
//! its `approval.created` event are written together:
//!
//! 1. `GuardStore.add_approval_request`, as
//!    [`add_native_review_approval_request`] writes it;
//! 2. `GuardStore.get_approval_request` (`derive_scope=True`), narrowed to the
//!    fields the event reads: the canonical policy action and the scope
//!    contract's recommended allow scope are derived in process;
//! 3. `_record_silent_native_review_event`.
//!
//! A home whose legacy rows still wait for the daemon's backfill answers
//! `null` without writing. A queued row the event cannot be reproduced for
//! fails the op, so the transaction rolls back and the daemon queues it.

use guard_contracts::ApprovalScopeItemV1;
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::approval_scope_contract::{contract, text as scope_text, View};
use crate::guard_store_approval_write::add_native_review_approval_request;
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, text, Row, StoreError, StoreResult};
use crate::guard_store_guard_event::{add_guard_event, approval_created_event};
use crate::pyjson::float_repr;
use crate::signal_projection_receipt::surfaces;

/// `_PROJECTION_BATCH_BYTES`: a row the daemon would project as unreadable
/// is left to the daemon.
const PROJECTION_ROW_BYTES: usize = 3 * 1024 * 1024;
const EVENT_UNAVAILABLE: &str = "native_silent_review_event_unavailable";
const ROW_UNAVAILABLE: &str = "native_silent_review_row_unavailable";
/// `native_approval_scope._ENVELOPE_KEYS`: the envelope fields the scope
/// contract reads.
const ENVELOPE_KEYS: [&str; 26] = [
    "native_bash",
    "schema_version",
    "harness",
    "event_name",
    "action_type",
    "workspace_hash",
    "tool_name",
    "command",
    "raw_command_text",
    "command_text",
    "commandText",
    "prompt_excerpt",
    "target_paths",
    "network_hosts",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "command_category",
    "package_intent_kind",
    "package_targets",
    "script_name",
    "wrapper_chain",
    "once_only_reason",
    "exact_context_token",
    "exact_identity_kind",
];
/// `native_approval_scope._RAW_PAYLOAD_KEYS`.
const RAW_PAYLOAD_KEYS: [&str; 2] = ["permission_mode", "permissionMode"];

/// Queue the review and write its `approval.created` event. Returns the
/// stored request id, or `null` (nothing written) while legacy rows wait for
/// the daemon's backfill.
pub(crate) fn add_silent_native_review_approval_request(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let now = args.str("now")?;
    let Value::String(request_id) = add_native_review_approval_request(connection, source, args)?
    else {
        return Ok(Value::Null);
    };
    let queued = queued_request(connection, &request_id)?;
    let (payload, timestamp) =
        approval_created_event(&queued, now).ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
    add_guard_event(connection, "approval.created", &payload, &timestamp)?
        .ok_or(StoreError::Invalid(EVENT_UNAVAILABLE))?;
    Ok(Value::String(request_id))
}

/// `get_approval_request(request_id)` for the fields
/// `_record_silent_native_review_event` reads, as `_row_to_draft` and
/// `apply_scope_surfaces` produce them.
fn queued_request(connection: &Connection, request_id: &str) -> StoreResult<Map<String, Value>> {
    let row = query_one(
        connection,
        "select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, \
         publisher, policy_action, source_scope, config_path, workspace, action_identity, \
         raw_command_text, action_envelope_json, decision_v2_json, scanner_evidence_json, \
         created_at from approval_requests where request_id = ?",
        &[Value::from(request_id)],
    )?
    .ok_or(StoreError::Invalid(ROW_UNAVAILABLE))?;
    let projection = project(&row)?;
    let policy_action = projection["policy_action"].clone();
    let recommended_scope = recommended_allow_scope(&row, &projection)?;
    let mut queued = Map::new();
    for name in [
        "request_id",
        "harness",
        "artifact_id",
        "artifact_name",
        "artifact_type",
    ] {
        queued.insert(name.to_owned(), Value::String(py_str(row.get(name))?));
    }
    queued.insert("policy_action".to_owned(), policy_action);
    queued.insert("recommended_scope".to_owned(), recommended_scope);
    queued.insert(
        "source_scope".to_owned(),
        Value::String(py_str(row.get("source_scope"))?),
    );
    queued.insert("workspace".to_owned(), raw(&row, "workspace"));
    queued.insert("publisher".to_owned(), raw(&row, "publisher"));
    queued.insert(
        "created_at".to_owned(),
        Value::String(py_str(row.get("created_at"))?),
    );
    Ok(queued)
}

/// `_project_listing_rows` for one stored row (`reject=False`).
fn project(row: &Row) -> StoreResult<Value> {
    let size = ["policy_action", "decision_v2_json", "action_envelope_json"]
        .iter()
        .map(|name| text(row, name).len())
        .sum::<usize>();
    if size > PROJECTION_ROW_BYTES {
        return Err(StoreError::Invalid(
            "native_guard_store_approval_row_too_large",
        ));
    }
    surfaces(
        &raw(row, "policy_action"),
        &decision_input(row, "decision_v2_json")?,
        &decision_input(row, "action_envelope_json")?,
        false,
    )
    .map_err(StoreError::Value)
}

/// `_row_decision_inputs`: the stored JSON object, else the stored value as
/// it is. Text `json.loads` reads differently from `serde_json` (`NaN`,
/// deep nesting) is left to the daemon.
fn decision_input(row: &Row, name: &str) -> StoreResult<Value> {
    match row.get(name) {
        Some(Value::String(stored)) => match serde_json::from_str::<Value>(stored) {
            Ok(object @ Value::Object(_)) => Ok(object),
            Ok(_) => Ok(Value::String(stored.clone())),
            Err(_) => Err(StoreError::Invalid(ROW_UNAVAILABLE)),
        },
        Some(other) => Ok(other.clone()),
        None => Ok(Value::Null),
    }
}

/// `recommended_scope_by_action["allow"]` of the scope contract
/// `request_scope_contract_payloads` derives for the draft payload.
fn recommended_allow_scope(row: &Row, projection: &Value) -> StoreResult<Value> {
    let item = ApprovalScopeItemV1 {
        request_id: present(raw(row, "request_id")),
        artifact_id: Some(Value::String(py_str(row.get("artifact_id"))?)),
        artifact_type: Some(Value::String(py_str(row.get("artifact_type"))?)),
        artifact_hash: Some(Value::String(py_str(row.get("artifact_hash"))?)),
        artifact_name: Some(Value::String(py_str(row.get("artifact_name"))?)),
        policy_action: present(projection["policy_action"].clone()),
        harness: Some(Value::String(py_str(row.get("harness"))?)),
        publisher: present(raw(row, "publisher")),
        source_scope: Some(Value::String(py_str(row.get("source_scope"))?)),
        config_path: Some(Value::String(py_str(row.get("config_path"))?)),
        wrapper_chain: None,
        action_identity: present(raw(row, "action_identity")),
        raw_command_text: present(raw(row, "raw_command_text")),
        action_envelope_json: present(narrow_envelope(&projection["action_envelope_json"])),
        scanner_evidence: Some(Value::Array(evidence(row)?)),
        workspace_target: workspace_target(row)?,
    };
    Ok(contract(&View::new(&item))
        .recommended_allow
        .map_or(Value::Null, Value::from))
}

/// `_derived_workspace_scope_target`: the stored workspace, else the
/// workspace root of `str(config_path)`. Only its presence reaches the
/// recommended scope (the contract digest is not read here), so the config
/// path stands in for the root Python resolves on its filesystem.
fn workspace_target(row: &Row) -> StoreResult<Option<String>> {
    if let Some(workspace) = scope_text(row.get("workspace")) {
        return Ok(Some(workspace.to_owned()));
    }
    let config_path = Value::String(py_str(row.get("config_path"))?);
    Ok(scope_text(Some(&config_path)).map(str::to_owned))
}

/// `_json_object_list(scanner_evidence_json)`.
fn evidence(row: &Row) -> StoreResult<Vec<Value>> {
    let Some(Value::String(stored)) = row.get("scanner_evidence_json") else {
        return Ok(Vec::new());
    };
    match serde_json::from_str::<Value>(stored) {
        Ok(Value::Array(items)) => Ok(items.into_iter().filter(Value::is_object).collect()),
        Ok(_) => Ok(Vec::new()),
        Err(_) => Err(StoreError::Invalid(ROW_UNAVAILABLE)),
    }
}

/// `native_approval_scope._narrow_envelope`.
pub(crate) fn narrow_envelope(envelope: &Value) -> Value {
    let Value::Object(fields) = envelope else {
        return envelope.clone();
    };
    let mut narrowed = pick(fields, &ENVELOPE_KEYS);
    if let Some(Value::Object(raw_payload)) = fields.get("raw_payload_redacted") {
        narrowed.insert(
            "raw_payload_redacted".to_owned(),
            Value::Object(pick(raw_payload, &RAW_PAYLOAD_KEYS)),
        );
    }
    Value::Object(narrowed)
}

fn pick(source: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|key| {
            source
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect()
}

/// A JSON `null` field decodes to `None` in the resident's typed request.
fn present(value: Value) -> Option<Value> {
    (!value.is_null()).then_some(value)
}

pub(crate) fn raw(row: &Row, name: &str) -> Value {
    row.get(name).cloned().unwrap_or(Value::Null)
}

/// `str(value)` for a stored cell.
pub(crate) fn py_str(value: Option<&Value>) -> StoreResult<String> {
    Ok(match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(stored)) => stored.clone(),
        Some(Value::Number(number)) => match (number.as_i64(), number.as_f64()) {
            (Some(integer), _) => integer.to_string(),
            (None, Some(float)) => float_repr(float),
            (None, None) => return Err(StoreError::Invalid(ROW_UNAVAILABLE)),
        },
        Some(_) => return Err(StoreError::Invalid(ROW_UNAVAILABLE)),
    })
}

#[cfg(test)]
#[path = "guard_store_silent_review_tests.rs"]
mod tests;
