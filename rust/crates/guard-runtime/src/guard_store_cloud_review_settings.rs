//! `cloud_review_settings_state` and `record_cloud_review_recovery`: the
//! `sync_state` rows the local Cloud Review settings page reads and writes.
//!
//! Port of the row reads and the reconnect rule
//! `cloud_control/cloud_review_settings.py` kept in Python. Python still
//! checks the sign-in health and runs the enable and disable steps; the store
//! reads the Cloud Review sync row, decides whether its last error asks for a
//! new sign-in, and keeps the recovery row that records an unfinished change.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `_RECOVERY_KEY`.
const RECOVERY_KEY: &str = "guard_cloud_review_settings_recovery";
/// `CLOUD_REVIEW_SYNC_STATE_KEY`; a non-default Guard source appends `:source`.
const SYNC_KEY: &str = "guard_cloud_review_sync_state";
const ERROR_CODE: &str = "last_error_code";
/// Codes that say sign-in is still required.
const AUTH_CODES: [&str; 2] = ["cloud_auth_expired", "cloud_connect_required"];

/// Whether `method` is one of the Cloud Review settings methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "cloud_review_settings_state" | "record_cloud_review_recovery"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "cloud_review_settings_state" => state_method(connection, args),
        "record_cloud_review_recovery" => record_recovery_method(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The sync row key for a Guard source: the default source has no suffix.
fn sync_key(source: &str) -> StoreResult<String> {
    match source {
        "" => value_error("invalid_source"),
        "default" => Ok(SYNC_KEY.to_owned()),
        source => Ok(format!("{SYNC_KEY}:{source}")),
    }
}

/// The connection binding, an object or `null`.
fn binding(args: &Args<'_>) -> StoreResult<Value> {
    match args.raw("binding") {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::Object(binding)) => Ok(Value::Object(binding.clone())),
        Some(_) => value_error("invalid_binding"),
    }
}

/// The sync-row half of `cloud_review_reconnect_required`: whether the last
/// sync run failed in a way that asks for a new sign-in.
///
/// Only a recorded code decides; the error message text never does.
fn sync_reconnect_required(sync: &serde_json::Map<String, Value>) -> bool {
    if sync.get("state").and_then(Value::as_str) != Some("error") {
        return false;
    }
    sync.get(ERROR_CODE)
        .and_then(Value::as_str)
        .is_some_and(|code| AUTH_CODES.contains(&code))
}

/// `cloud_review_settings_state`: the Cloud Review sync row for `source` (an
/// empty object when missing or not an object), whether it asks for a new
/// sign-in, and the recovery error recorded for the same `binding`.
pub(crate) fn state_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let key = sync_key(args.str("source")?)?;
    let binding = binding(args)?;
    let sync = match read_payload(connection, &key)? {
        Some(Value::Object(sync)) => sync,
        _ => serde_json::Map::new(),
    };
    let recovery_error = match read_payload(connection, RECOVERY_KEY)? {
        Some(Value::Object(recovery)) if recovery.get("binding") == Some(&binding) => {
            recovery.get("error").cloned().unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    Ok(json!({
        "sync_reconnect_required": sync_reconnect_required(&sync),
        "sync": sync,
        "recovery_error": recovery_error,
    }))
}

/// `record_cloud_review_recovery`: record the error an unfinished settings
/// change left for `binding`. A `null` error records that the change finished.
pub(crate) fn record_recovery_method(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let binding = binding(args)?;
    let error = match args.raw("error") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(error)) if !error.is_empty() => json!(error),
        Some(_) => return value_error("invalid_error"),
    };
    let now = args.str("now")?;
    let encoded = serde_json::to_string(&json!({"binding": binding, "error": error}))
        .map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, RECOVERY_KEY, &encoded, now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_cloud_review_settings_tests.rs"]
mod tests;
