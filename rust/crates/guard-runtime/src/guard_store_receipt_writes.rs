//! Receipt authority writes. Every persisted receipt action is derived here in
//! the resident; Python never recalculates a verdict.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, text, value_error, Row, StoreResult};
use crate::guard_store_json::{dumps_default, py_strip};
use crate::guard_store_receipt_approval::ActionInputs;
use crate::guard_store_receipt_decision::{
    action_value, canonical_receipt_decision, canonical_rollup_action, inconsistent, json_object,
    most_restrictive,
};
use crate::guard_store_receipt_envelope::{redact_mapping, redact_typed};
use crate::guard_store_receipt_events::{
    add_guard_event, build_receipt_event, set_pending_event_decision,
};
use crate::guard_store_receipt_rollups::{
    action_query, rebuild_if_pending, record_decision_change, record_insert,
};

const DEVICE_KEY: &str = "local-device";
const APPROVAL_SQL: &str = "select request_id as linked_approval_request_id, \
     status as approval_status, resolution_action as approval_resolution_action, \
     resolved_at as approval_resolved_at, policy_action as approval_policy_action, \
     decision_v2_json as approval_decision_v2_json, \
     action_envelope_json as approval_envelope_json \
     from approval_requests where request_id = ?";

fn json_text(value: &Value) -> Value {
    dumps_default(value).map_or(Value::Null, Value::String)
}

fn optional_json_text(envelope: &Option<Map<String, Value>>) -> Value {
    envelope
        .as_ref()
        .map_or(Value::Null, |map| json_text(&Value::Object(map.clone())))
}

fn linked_approval(connection: &Connection, request_id: &Value) -> StoreResult<Option<Row>> {
    if request_id.is_null() {
        return Ok(None);
    }
    query_one(connection, APPROVAL_SQL, std::slice::from_ref(request_id))
}

fn cell(map: &Map<String, Value>, key: &str) -> Value {
    map.get(key).cloned().unwrap_or(Value::Null)
}

fn local_workspace_id(connection: &Connection) -> StoreResult<Option<String>> {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = 'oauth_local_credentials'",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(None);
    };
    let Ok(payload) = serde_json::from_str::<Value>(text(&row, "payload_json")) else {
        return value_error("native_guard_store_oauth_payload_invalid");
    };
    Ok(payload
        .get("workspace_id")
        .and_then(Value::as_str)
        .filter(|id| !py_strip(id).is_empty())
        .map(str::to_owned))
}

fn ensure_local_device(connection: &Connection, device_id: &str, now: &str) -> StoreResult<()> {
    let present = query_one(
        connection,
        "select device_key from guard_devices where device_key = ?",
        &[Value::from(DEVICE_KEY)],
    )?;
    if present.is_none() {
        exec(
            connection,
            "insert into guard_devices (device_key, installation_id, device_label, created_at, \
             updated_at) values (?, ?, ?, ?, ?)",
            &[
                Value::from(DEVICE_KEY),
                Value::from(device_id),
                Value::from("Local machine"),
                Value::from(now),
                Value::from(now),
            ],
        )?;
    }
    Ok(())
}

/// Everything `add_receipt` needs from its caller: the generated device id,
/// the wall-clock time and the pending-event queue limit.
pub(crate) struct ReceiptContext<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) now: &'a str,
    pub(crate) queue_limit: i64,
}

/// `add_receipt`: derive the final canonical action, persist the receipt with
/// its envelopes, queue the cloud event and count the rollups.
pub(crate) fn insert_receipt(
    connection: &Connection,
    receipt: &Map<String, Value>,
    action_envelope: Option<&Map<String, Value>>,
    context: &ReceiptContext<'_>,
) -> StoreResult<()> {
    rebuild_if_pending(connection)?;
    let envelope_value = action_envelope.map_or(Value::Null, |map| Value::Object(map.clone()));
    let canonical =
        canonical_receipt_decision(&cell(receipt, "policy_decision"), &envelope_value, true)?;
    let redacted = action_envelope.map(redact_typed);
    let redacted_value = redacted.clone().map_or(Value::Null, Value::Object);
    let approval_id = cell(receipt, "approval_request_id");
    let mut inputs_row = Row::new();
    inputs_row.insert("policy_decision".into(), action_value(canonical.policy));
    inputs_row.insert("envelope_full_json".into(), canonical.envelope_value());
    inputs_row.insert("envelope_redacted_json".into(), redacted_value);
    inputs_row.insert("approval_request_id".into(), approval_id.clone());
    if let Some(approval) = linked_approval(connection, &approval_id)? {
        inputs_row.extend(approval);
    }
    let final_policy = canonical_rollup_action(&ActionInputs::from_row(&inputs_row))?;
    let policy_value = action_value(final_policy);
    let final_full = canonical_receipt_decision(&policy_value, &canonical.envelope_value(), false)?;
    let final_redacted = canonical_receipt_decision(
        &policy_value,
        inputs_row
            .get("envelope_redacted_json")
            .unwrap_or(&Value::Null),
        false,
    )?;
    let mut final_receipt = receipt.clone();
    final_receipt.insert("policy_decision".into(), policy_value.clone());
    let list_text = |key: &str| json_text(&cell(receipt, key));
    exec(
        connection,
        "insert into runtime_receipts (\
         receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary, \
         changed_capabilities_json, provenance_summary, user_override, artifact_name, \
         source_scope, scanner_evidence_json, diff_summary, approval_source, \
         approval_request_id, timestamp, raw_command_text) \
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &[
            cell(receipt, "receipt_id"),
            cell(receipt, "harness"),
            cell(receipt, "artifact_id"),
            cell(receipt, "artifact_hash"),
            policy_value,
            cell(receipt, "capabilities_summary"),
            list_text("changed_capabilities"),
            cell(receipt, "provenance_summary"),
            cell(receipt, "user_override"),
            cell(receipt, "artifact_name"),
            cell(receipt, "source_scope"),
            list_text("scanner_evidence"),
            cell(receipt, "diff_summary"),
            cell(receipt, "approval_source"),
            approval_id,
            cell(receipt, "timestamp"),
            cell(receipt, "raw_command_text"),
        ],
    )?;
    if action_envelope.is_some() {
        exec(
            connection,
            "insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, \
             envelope_redacted_json) values (?, ?, ?)",
            &[
                cell(receipt, "receipt_id"),
                json_text(&final_full.envelope_value()),
                json_text(&final_redacted.envelope_value()),
            ],
        )?;
    }
    ensure_local_device(connection, context.device_id, context.now)?;
    let device = query_one(
        connection,
        "select installation_id from guard_devices where device_key = ?",
        &[Value::from(DEVICE_KEY)],
    )?;
    let device_id = device.as_ref().map(|row| text(row, "installation_id"));
    let workspace_id = local_workspace_id(connection)?;
    add_guard_event(
        connection,
        &build_receipt_event(&final_receipt, device_id, workspace_id.as_deref()),
        context.queue_limit,
        context.now,
    )?;
    record_insert(connection, &final_receipt, final_policy)
}

pub(crate) fn add_receipt(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let receipt = args.object("receipt")?;
    let envelope = args.opt_object("action_envelope")?;
    insert_receipt(
        connection,
        receipt,
        envelope,
        &ReceiptContext {
            device_id: args.str("new_device_id")?,
            now: args.str("now")?,
            queue_limit: args.int("event_queue_limit")?,
        },
    )?;
    Ok(Value::Null)
}

pub(crate) fn set_action_envelope(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let receipt_id = args.str("receipt_id")?;
    let Some(row) = query_one(
        connection,
        "select policy_decision from runtime_receipts where receipt_id = ?",
        &[Value::from(receipt_id)],
    )?
    else {
        return Ok(Value::Null);
    };
    let supplied = args.raw("action_envelope").cloned().unwrap_or(Value::Null);
    let canonical = canonical_receipt_decision(&cell(&row, "policy_decision"), &supplied, true)?;
    let redacted_input = redact_mapping(&canonical.envelope.clone().unwrap_or_default());
    let redacted = canonical_receipt_decision(
        &action_value(canonical.policy),
        &Value::Object(redacted_input),
        true,
    )?;
    exec(
        connection,
        "insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, \
         envelope_redacted_json) values (?, ?, ?) \
         on conflict(receipt_id) do update set \
         envelope_full_json = excluded.envelope_full_json, \
         envelope_redacted_json = excluded.envelope_redacted_json",
        &[
            Value::from(receipt_id),
            json_text(&canonical.envelope_value()),
            json_text(&redacted.envelope_value()),
        ],
    )?;
    Ok(Value::Null)
}

fn load_action_row(connection: &Connection, receipt_id: &str) -> StoreResult<Option<Row>> {
    query_one(
        connection,
        &action_query("where r.receipt_id = ?"),
        &[Value::from(receipt_id)],
    )
}

fn stored_envelope(row: &Row, column: &str) -> StoreResult<Value> {
    let raw = cell(row, column);
    match (&raw, json_object(&raw)) {
        (Value::Null, _) => Ok(Value::Null),
        (_, Some(map)) => Ok(Value::Object(map)),
        _ => inconsistent(),
    }
}

pub(crate) fn update_policy_decision(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let receipt_id = args.str("receipt_id")?;
    rebuild_if_pending(connection)?;
    let Some(row) = load_action_row(connection, receipt_id)? else {
        return Ok(Value::Null);
    };
    let old_policy = text(&row, "policy_decision").to_owned();
    let full_input = stored_envelope(&row, "envelope_full_json")?;
    let redacted_input = stored_envelope(&row, "envelope_redacted_json")?;
    let requested = canonical_receipt_decision(
        &args.raw("policy_decision").cloned().unwrap_or(Value::Null),
        &Value::Null,
        false,
    )?;
    let requested_value = action_value(requested.policy);
    let full = canonical_receipt_decision(&requested_value, &full_input, false)?;
    let redacted = canonical_receipt_decision(&requested_value, &redacted_input, false)?;
    let approval = ActionInputs::from_row(&row).linked_authority()?;
    let mut actions = vec![requested.policy, full.policy, redacted.policy];
    actions.extend(approval.policy);
    let final_policy = most_restrictive(&actions);
    let final_value = action_value(final_policy);
    let final_full = canonical_receipt_decision(&final_value, &full.envelope_value(), false)?;
    let final_redacted =
        canonical_receipt_decision(&final_value, &redacted.envelope_value(), false)?;
    exec(
        connection,
        "update runtime_receipts set policy_decision = ? where receipt_id = ?",
        &[final_value, Value::from(receipt_id)],
    )?;
    if !full_input.is_null() || !redacted_input.is_null() {
        exec(
            connection,
            "update runtime_receipt_envelopes set envelope_full_json = ?, \
             envelope_redacted_json = ? where receipt_id = ?",
            &[
                optional_json_text(&final_full.envelope),
                optional_json_text(&final_redacted.envelope),
                Value::from(receipt_id),
            ],
        )?;
    }
    if final_policy.as_str() != old_policy {
        set_pending_event_decision(connection, receipt_id, final_policy.as_str())?;
    }
    record_decision_change(connection, &row, &old_policy, final_policy.as_str())?;
    Ok(Value::Null)
}

pub(crate) fn update_approval_context(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let receipt_id = args.str("receipt_id")?;
    let Some(row) = load_action_row(connection, receipt_id)? else {
        return Ok(Value::Null);
    };
    let current = canonical_rollup_action(&ActionInputs::from_row(&row))?;
    let next_request = args
        .raw("approval_request_id")
        .cloned()
        .unwrap_or(Value::Null);
    let mut next_row = row.clone();
    if next_request != cell(&row, "approval_request_id") {
        for column in [
            "linked_approval_request_id",
            "approval_status",
            "approval_resolution_action",
            "approval_resolved_at",
            "approval_policy_action",
            "approval_decision_v2_json",
            "approval_envelope_json",
        ] {
            next_row.insert(column.into(), Value::Null);
        }
        if let Some(approval) = linked_approval(connection, &next_request)? {
            next_row.extend(approval);
        }
    }
    next_row.insert("approval_request_id".into(), next_request.clone());
    let next = canonical_rollup_action(&ActionInputs::from_row(&next_row))?;
    if next != current {
        return inconsistent();
    }
    exec(
        connection,
        "update runtime_receipts set approval_source = ?, approval_request_id = ? \
         where receipt_id = ?",
        &[
            args.raw("approval_source").cloned().unwrap_or(Value::Null),
            next_request,
            Value::from(receipt_id),
        ],
    )?;
    Ok(Value::Null)
}
