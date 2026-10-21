//! The `receipt.created` cloud event each receipt queues, and the bounded
//! queue it is queued into.
//!
//! The event carries the receipt's final canonical decision. While the event
//! is still pending upload, any later change to that decision is projected onto
//! it; an event that is uploaded or carries stray action authority is never
//! silently rewritten.

use guard_contracts::{is_action_bearing_key, GuardAction};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_db::{exec, query_all, query_one, text, StoreResult};
use crate::guard_store_json::dumps_default;
use crate::guard_store_receipt_decision::{inconsistent, json_object, normalized};

pub(crate) const CAPACITY_KEY: &str = "guard_event_queue_capacity";

fn receipt_idempotency_key(receipt_id: &str) -> String {
    format!("receipt.created:{receipt_id}")
}

/// `build_receipt_event(...).to_dict()`.
pub(crate) fn build_receipt_event(
    receipt: &Map<String, Value>,
    device_id: Option<&str>,
    workspace_id: Option<&str>,
) -> Value {
    let field = |key: &str| receipt.get(key).cloned().unwrap_or(Value::Null);
    let receipt_id = receipt
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let digest = hex::encode(Sha256::digest(
        format!("receipt.created:{receipt_id}").as_bytes(),
    ));
    json!({
        "schemaVersion": "guard.event.v1",
        "eventId": format!("guard-event-{}", &digest[..32]),
        "idempotencyKey": receipt_idempotency_key(receipt_id),
        "eventType": "receipt.created",
        "source": "edge",
        "occurredAt": field("timestamp"),
        "workspaceId": workspace_id,
        "deviceId": device_id,
        "payload": {
            "receiptId": field("receipt_id"),
            "harness": field("harness"),
            "artifactId": field("artifact_id"),
            "artifactHash": field("artifact_hash"),
            "artifactName": field("artifact_name"),
            "sourceScope": field("source_scope"),
            "policyDecision": field("policy_decision"),
            "capabilitiesSummary": field("capabilities_summary"),
            "changedCapabilities": field("changed_capabilities"),
            "provenanceSummary": field("provenance_summary"),
            "userOverride": field("user_override"),
        },
    })
}

fn pending_count(connection: &rusqlite::Connection) -> StoreResult<i64> {
    let row = query_one(
        connection,
        "select count(*) as count from guard_cloud_events where uploaded_at is null",
        &[],
    )?;
    Ok(row.map_or(0, |row| crate::guard_store_db::int(&row, "count")))
}

/// `_add_guard_event_v1`: queue the event, or record that the pending queue is
/// at capacity and drop it.
pub(crate) fn add_guard_event(
    connection: &rusqlite::Connection,
    event: &Value,
    queue_limit: i64,
    now: &str,
) -> StoreResult<()> {
    let field = |key: &str| event.get(key).cloned().unwrap_or(Value::Null);
    let idempotency_key = field("idempotencyKey");
    let existing = query_one(
        connection,
        "select event_id from guard_cloud_events where idempotency_key = ?",
        std::slice::from_ref(&idempotency_key),
    )?;
    if existing.is_none() {
        let pending = pending_count(connection)?;
        if pending >= queue_limit {
            return record_capacity_rejection(connection, event, queue_limit, pending, now);
        }
    }
    let payload = dumps_default(event).ok_or_else(|| {
        crate::guard_store_db::StoreError::Invalid("native_guard_store_payload_unencodable")
    })?;
    exec(
        connection,
        "insert or ignore into guard_cloud_events (\
         event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at) \
         values (?, ?, ?, ?, ?, null)",
        &[
            field("eventId"),
            idempotency_key,
            field("eventType"),
            Value::String(payload),
            field("occurredAt"),
        ],
    )?;
    Ok(())
}

fn record_capacity_rejection(
    connection: &rusqlite::Connection,
    event: &Value,
    queue_limit: i64,
    pending: i64,
    now: &str,
) -> StoreResult<()> {
    let stored = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(CAPACITY_KEY)],
    )?;
    let previous = stored
        .as_ref()
        .and_then(|row| json_object(&Value::String(text(row, "payload_json").to_owned())))
        .unwrap_or_default();
    let rejected = previous
        .get("rejectedCount")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        + 1;
    let occurred_at = event.get("occurredAt").cloned().unwrap_or(Value::Null);
    let payload = json!({
        "exhausted": true,
        "firstRejectedAt": previous.get("firstRejectedAt").cloned().unwrap_or_else(|| occurred_at.clone()),
        "lastRejectedAt": occurred_at,
        "limit": queue_limit,
        "pendingCount": pending,
        "rejectedCount": rejected,
        "rejectedEventType": event.get("eventType").cloned().unwrap_or(Value::Null),
    });
    let encoded = dumps_default(&payload).ok_or_else(|| {
        crate::guard_store_db::StoreError::Invalid("native_guard_store_payload_unencodable")
    })?;
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
         payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        &[
            Value::from(CAPACITY_KEY),
            Value::String(encoded),
            Value::from(now),
        ],
    )?;
    Ok(())
}

fn rewrite_pending_event(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    event: &Map<String, Value>,
) -> StoreResult<()> {
    let encoded = dumps_default(&Value::Object(event.clone())).ok_or_else(|| {
        crate::guard_store_db::StoreError::Invalid("native_guard_store_payload_unencodable")
    })?;
    exec(
        connection,
        "update guard_cloud_events set payload_json = ? \
         where idempotency_key = ? and uploaded_at is null",
        &[
            Value::String(encoded),
            Value::String(receipt_idempotency_key(receipt_id)),
        ],
    )?;
    Ok(())
}

fn event_with_payload(row: &crate::guard_store_db::Row) -> StoreResult<Map<String, Value>> {
    let event = json_object(&Value::String(text(row, "payload_json").to_owned()));
    match event {
        Some(map) if map.get("payload").is_some_and(Value::is_object) => Ok(map),
        _ => inconsistent(),
    }
}

/// `_update_pending_receipt_event_policy_decision`: the event must exist, be
/// pending and well formed.
pub(crate) fn set_pending_event_decision(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    policy_decision: &str,
) -> StoreResult<()> {
    let row = query_one(
        connection,
        "select payload_json, uploaded_at from guard_cloud_events where idempotency_key = ?",
        &[Value::String(receipt_idempotency_key(receipt_id))],
    )?;
    let Some(row) = row.filter(|row| row.get("uploaded_at").is_none_or(Value::is_null)) else {
        return inconsistent();
    };
    let mut event = event_with_payload(&row)?;
    if let Some(Value::Object(payload)) = event.get_mut("payload") {
        payload.insert("policyDecision".to_owned(), Value::from(policy_decision));
    }
    rewrite_pending_event(connection, receipt_id, &event)
}

fn is_decision_token_key(key: &str) -> bool {
    if is_action_bearing_key(key) {
        return true;
    }
    let mut spaced = String::with_capacity(key.len() + 4);
    let mut previous: Option<char> = None;
    for character in key.chars() {
        if character.is_ascii_uppercase()
            && previous.is_some_and(|prev| prev.is_ascii_lowercase() || prev.is_ascii_digit())
        {
            spaced.push(' ');
        }
        spaced.push(if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else {
            ' '
        });
        previous = Some(character);
    }
    spaced
        .split_whitespace()
        .any(|token| token == "decision" || token == "decisions")
}

/// `_reject_hidden_receipt_event_authority`: `payload.policyDecision` must be
/// the only action or decision field anywhere in the event.
fn reject_hidden_authority(value: &Value, in_payload: bool, path_len: usize) -> StoreResult<()> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let allowed = in_payload && path_len == 1 && key == "policyDecision";
                if !allowed && is_decision_token_key(key) {
                    return inconsistent();
                }
                reject_hidden_authority(
                    nested,
                    in_payload || (path_len == 0 && key == "payload"),
                    path_len + 1,
                )?;
            }
            Ok(())
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|nested| reject_hidden_authority(nested, in_payload, path_len + 1)),
        _ => Ok(()),
    }
}

/// `_reconcile_pending_receipt_event_action`: keep an unsent receipt event
/// aligned with its current canonical action.
pub(crate) fn reconcile_pending_event(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    policy: GuardAction,
) -> StoreResult<()> {
    let row = query_one(
        connection,
        "select payload_json from guard_cloud_events \
         where idempotency_key = ? and uploaded_at is null",
        &[Value::String(receipt_idempotency_key(receipt_id))],
    )?;
    let Some(row) = row else {
        return Ok(());
    };
    let mut event = event_with_payload(&row)?;
    reject_hidden_authority(&Value::Object(event.clone()), false, 0)?;
    let Some(Value::Object(payload)) = event.get_mut("payload") else {
        return inconsistent();
    };
    if payload.get("policyDecision").and_then(Value::as_str) == Some(policy.as_str()) {
        return Ok(());
    }
    payload.insert("policyDecision".to_owned(), Value::from(policy.as_str()));
    rewrite_pending_event(connection, receipt_id, &event)
}

/// `reconcile_pending_receipt_events`: reproject every pending receipt event
/// from its clean rollup action.
pub(crate) fn reconcile_pending_events(connection: &rusqlite::Connection) -> StoreResult<()> {
    let rows = query_all(
        connection,
        "select r.receipt_id, s.policy_decision \
         from runtime_receipts r \
         join receipt_rollup_actions s on s.receipt_id = r.receipt_id \
         join guard_cloud_events e on e.idempotency_key = 'receipt.created:' || r.receipt_id \
         where e.uploaded_at is null",
        &[],
    )?;
    for row in &rows {
        let policy = normalized(row.get("policy_decision").unwrap_or(&Value::Null));
        reconcile_pending_event(connection, text(row, "receipt_id"), policy)?;
    }
    Ok(())
}
