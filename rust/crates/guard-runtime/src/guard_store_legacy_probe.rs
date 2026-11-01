//! `read_legacy_codex_probe_receipt`: the legacy Codex writer's Rust receipt
//! for one correlated request, matched in one capped statement.
//!
//! This is evidence lookup only. It neither grants protection admission nor
//! replaces configured launch, authenticated daemon and artifact
//! verification. Legacy denied attempts salt their correlation digest with
//! the receipt and action, both the activity and the receipt must follow the
//! caller's launch boundary, and a request's matches must be unique. No
//! shared last-receipt slot, command text or newest-row heuristic is read.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, value_error, Row, StoreResult};
use crate::guard_store_json::{aware_epoch_micros, dumps_default};
use crate::resident_transport::constant_time_eq;

const MAX_ROWS: usize = 128;
/// `_MAX_COMMAND_BINDING_CHARACTERS` in `store_native_decision_receipts.py`.
const MAX_BINDING_CHARACTERS: usize = 2_048;
const MAX_TIMESTAMP_CHARACTERS: usize = 64;
const BOOL_FIELDS: [&str; 3] = [
    "workspace_bound",
    "source_ref_external_allowed",
    "observe_mode",
];

const QUERY: &str = "select r.*, a.occurred_at as activity_occurred_at, \
     a.policy_action as activity_policy_action, a.prompted as activity_prompted, \
     a.approval_reuse_status as activity_approval_reuse_status, \
     a.execution_status as activity_execution_status, c.digest as correlation_digest \
     from command_activity a join command_activity_correlations c \
     on c.activity_id = a.activity_id join native_hook_decision_receipts r \
     on r.decision_id = a.receipt_id \
     where a.harness = 'codex' and c.harness = 'codex' and c.kind = 'request' \
     and c.key_id = ? and a.hook_phase = 'pre' and a.proof_level = 'pre_hook' \
     and a.receipt_link_status = 'linked' and a.occurred_at >= ? \
     order by a.occurred_at desc, a.activity_id limit ?";

/// Args: `key_id` and `digest` of the request correlation, and `since`, the
/// aware launch boundary in UTC as `datetime.isoformat` spells it. Answers
/// the one matching receipt or null.
pub(crate) fn read_legacy_codex_probe_receipt(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let key_id = args.str("key_id")?;
    let digest = args.str("digest")?;
    let since_text = args.str("since")?;
    let Some(since) = aware_epoch_micros(since_text) else {
        return value_error("legacy_probe_identity_invalid");
    };
    let rows = query_all(
        connection,
        QUERY,
        &[
            Value::from(key_id),
            Value::from(since_text),
            Value::from(MAX_ROWS as i64 + 1),
        ],
    )?;
    matching_receipt(rows, digest, since, now_micros())
}

fn matching_receipt(
    rows: Vec<Row>,
    digest: &str,
    since: i128,
    now: i128,
) -> StoreResult<Value> {
    if rows.len() > MAX_ROWS {
        return value_error("legacy_probe_receipt_capacity");
    }
    let mut matched = Vec::new();
    for mut row in rows {
        let correlation = row.remove("correlation_digest").unwrap_or(Value::Null);
        let activity: Map<String, Value> = [
            "occurred_at",
            "policy_action",
            "prompted",
            "approval_reuse_status",
            "execution_status",
        ]
        .into_iter()
        .map(|name| {
            let value = row
                .remove(&format!("activity_{name}"))
                .unwrap_or(Value::Null);
            (name.to_owned(), value)
        })
        .collect();
        let field = |name: &str| activity.get(name).unwrap_or(&Value::Null);
        let action = field("policy_action");
        let permitted = matches!(action.as_str(), Some("allow" | "warn"));
        let expected = if permitted {
            digest.to_owned()
        } else {
            prevented_attempt_digest(
                digest,
                action,
                row.get("decision_id").unwrap_or(&Value::Null),
                truthy(field("prompted")),
                field("approval_reuse_status"),
            )
        };
        let Some(correlation) = correlation.as_str() else {
            continue;
        };
        if !constant_time_eq(correlation.as_bytes(), expected.as_bytes()) {
            continue;
        }
        let occurred = timestamp(field("occurred_at"));
        let recorded = timestamp(row.get("recorded_at").unwrap_or(&Value::Null));
        let receipt = stored_receipt(row);
        let fresh = |instant: Option<i128>| instant.is_some_and(|at| since <= at && at <= now);
        let expected_status = if permitted {
            "allowed_unconfirmed"
        } else {
            "prevented"
        };
        let Some(receipt) = receipt.filter(|receipt| {
            fresh(occurred)
                && fresh(recorded)
                && is_zero(field("prompted"))
                && field("approval_reuse_status").as_str() == Some("not-applicable")
                && receipt["harness"] == "codex"
                && receipt["event_name"] == "PreToolUse"
                && receipt["payload_kind"] == "inline"
                && receipt["observe_mode"] == Value::Bool(false)
                && receipt["policy_action"] == *action
                && field("execution_status").as_str() == Some(expected_status)
        }) else {
            return value_error("legacy_probe_receipt_invalid");
        };
        matched.push(receipt);
    }
    if matched.len() > 1 {
        return value_error("legacy_probe_receipt_ambiguous");
    }
    Ok(matched.pop().unwrap_or(Value::Null))
}

/// The shipped `native-prevented-attempt-v1` wire formula, with JSON's
/// default separators. It is not a new correlation scheme.
fn prevented_attempt_digest(
    digest: &str,
    action: &Value,
    decision_id: &Value,
    prompted: bool,
    approval_reuse_status: &Value,
) -> String {
    use sha2::{Digest, Sha256};
    let parts = Value::Array(vec![
        Value::from("native-prevented-attempt-v1"),
        Value::from(digest),
        action.clone(),
        decision_id.clone(),
        Value::Bool(prompted),
        approval_reuse_status.clone(),
    ]);
    let text = dumps_default(&parts).unwrap_or_default();
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `validate_stored_native_decision_receipt`: one stored row as the receipt
/// it recorded, or `None` when the row is not a valid receipt.
fn stored_receipt(mut row: Row) -> Option<Value> {
    row.remove("recorded_at");
    match row.remove("command_extensions_json") {
        None | Some(Value::Null) => {}
        Some(Value::String(text)) if text.chars().count() <= MAX_BINDING_CHARACTERS => {
            row.insert(
                "command_extensions".to_owned(),
                serde_json::from_str(&text).ok()?,
            );
        }
        Some(_) => return None,
    }
    for name in BOOL_FIELDS {
        let flag = match row.get(name) {
            Some(value) if is_zero(value) => false,
            Some(value) if value.as_f64() == Some(1.0) || *value == Value::Bool(true) => true,
            _ => return None,
        };
        row.insert(name.to_owned(), Value::Bool(flag));
    }
    let receipt = Value::Object(row);
    crate::edge::standalone_receipt(&receipt, &Value::Null).then_some(receipt)
}

/// `_timestamp`: an aware instant in UTC microseconds.
fn timestamp(value: &Value) -> Option<i128> {
    value
        .as_str()
        .filter(|text| text.chars().count() <= MAX_TIMESTAMP_CHARACTERS)
        .and_then(aware_epoch_micros)
}

/// Python's `value == 0` for a stored cell.
fn is_zero(value: &Value) -> bool {
    value.as_f64() == Some(0.0) || *value == Value::Bool(false)
}

/// Python's `bool(value)` for a stored cell.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

fn now_micros() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i128)
}

#[cfg(test)]
#[path = "guard_store_legacy_probe_tests.rs"]
mod tests;
