//! `workspace_assessment_delivery`, `commit_workspace_assessment_sent`,
//! `cached_policy_bundle` and `record_policy_bundle_failure_ack`: the
//! `sync_state` rows the receipts sync reads before it builds a request and
//! writes after it.
//!
//! Port of the raw row reads and writes in `runtime/workspace_assessment_sync.py`
//! and `runtime/policy_bundle_failure_ack.py`. The native runtime already builds
//! the summary and the failed acknowledgement; the store now keeps the rows
//! they are built from and recorded into.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `workspace_assessment_sync.DELIVERY_STATE_KEY`.
const DELIVERY_KEY: &str = "workspace_assessment_sync_delivery";
/// The cached policy bundle the sync validates.
const BUNDLE_KEY: &str = "policy_bundle";
/// `policy_bundle_failure_ack._ACK_STATE_KEY`.
const ACK_KEY: &str = "policy_bundle_ack";

/// Whether `method` is one of the receipts sync delivery-row methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "workspace_assessment_delivery"
            | "commit_workspace_assessment_sent"
            | "cached_policy_bundle"
            | "record_policy_bundle_failure_ack"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "workspace_assessment_delivery" => object_row(connection, DELIVERY_KEY),
        "commit_workspace_assessment_sent" => commit_sent_method(connection, args),
        "cached_policy_bundle" => object_row(connection, BUNDLE_KEY),
        "record_policy_bundle_failure_ack" => record_failure_ack_method(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The stored object at `key`, or `null` when it is missing or not an object.
fn object_row(connection: &Connection, key: &str) -> StoreResult<Value> {
    Ok(match read_payload(connection, key)? {
        Some(Value::Object(row)) => Value::Object(row),
        _ => Value::Null,
    })
}

/// A required, non-empty text argument.
fn text<'a>(args: &Args<'a>, key: &str, code: &'static str) -> StoreResult<&'a str> {
    match args.raw(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.as_str()),
        _ => value_error(code),
    }
}

/// `commit_workspace_assessment_sent`: record the digest of the summary Guard
/// Cloud accepted, stamped with the local clock that built it.
pub(crate) fn commit_sent_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let digest = text(args, "digest", "invalid_digest")?;
    let sent_at = text(args, "sent_at", "invalid_sent_at")?;
    let encoded = serde_json::to_string(&json!({"digest": digest, "sent_at": sent_at}))
        .map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, DELIVERY_KEY, &encoded, sent_at)?;
    Ok(Value::Null)
}

/// `record_policy_bundle_failure_ack`: persist a failed acknowledgement so the
/// next request resends it instead of a conflicting one. Only an object whose
/// `status` is `failed` is accepted.
pub(crate) fn record_failure_ack_method(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let acknowledgement = match args.raw("acknowledgement") {
        Some(Value::Object(ack)) if ack.get("status").and_then(Value::as_str) == Some("failed") => {
            ack
        }
        _ => return value_error("invalid_acknowledgement"),
    };
    let now = text(args, "now", "invalid_now")?;
    let encoded = serde_json::to_string(acknowledgement)
        .map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, ACK_KEY, &encoded, now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_sync_delivery_rows_tests.rs"]
mod tests;
