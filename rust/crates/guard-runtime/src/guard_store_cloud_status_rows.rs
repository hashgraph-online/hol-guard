//! `cloud_status_rows`: the `sync_state` rows the Guard Cloud status views
//! read, in one snapshot.
//!
//! Port of the row reads `cli/product.py`, `approvals.py`,
//! `cli/cloud_status.py`, `cli/connect_flow.py`,
//! `cli/commands_support_service.py` and `routes/headless_calls.py` made one
//! row at a time, and of the sign-in-expired rule `cli/product.py` applied to
//! three of them. Python still reads the sign-in health and the cached policy
//! bundle and builds the status text.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_sync_state::read_payload;

/// The rows the snapshot returns, each under its own `sync_state` key.
const ROWS: [&str; 8] = [
    "sync_summary",
    "alert_preferences",
    "policy_bundle_last_error",
    "headless_app_sync_summary",
    "guard_cloud_review_sync_state",
    "receipt_sync_cursor",
    "runtime_session_summary",
    "guard_events_v1_summary",
];
/// The value each sign-in row records when Guard Cloud refused the sign-in.
const AUTH_EXPIRED: &str = "auth_expired";

/// Whether `method` is the Cloud status snapshot.
pub(crate) fn handles(method: &str) -> bool {
    method == "cloud_status_rows"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    _args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "cloud_status_rows" => rows_method(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// A stored row as an object, or `None` when it is missing or not an object.
fn object_row(connection: &Connection, key: &str) -> StoreResult<Option<Map<String, Value>>> {
    match read_payload(connection, key)? {
        Some(Value::Object(row)) => Ok(Some(row)),
        _ => Ok(None),
    }
}

fn field_is(row: &Map<String, Value>, field: &str, expected: &str) -> bool {
    row.get(field).and_then(Value::as_str) == Some(expected)
}

/// Whether one of the three sign-in rows records that Guard Cloud refused the
/// sign-in: the policy fetch error, the headless app sync or the Cloud Review
/// sync.
fn cloud_auth_expired(rows: &Map<String, Value>) -> bool {
    let row = |key: &str| match rows.get(key) {
        Some(Value::Object(row)) => Some(row),
        _ => None,
    };
    row("policy_bundle_last_error").is_some_and(|row| field_is(row, "reason", AUTH_EXPIRED))
        || row("headless_app_sync_summary").is_some_and(|row| field_is(row, "status", AUTH_EXPIRED))
        || row("guard_cloud_review_sync_state")
            .is_some_and(|row| field_is(row, "state", AUTH_EXPIRED))
}

/// The `synced_at` text of the first row that records one: the receipt sync
/// summary, then the receipt sync cursor.
fn last_sync_at(rows: &Map<String, Value>) -> Value {
    ["sync_summary", "receipt_sync_cursor"]
        .iter()
        .find_map(|key| rows.get(*key)?.get("synced_at")?.as_str())
        .map_or(Value::Null, |text| json!(text))
}

/// `cloud_status_rows`: every status row (empty when missing or not an
/// object), whether a sign-in row records an expired sign-in, the last sync
/// time and the latest Guard Cloud sync.
///
/// Each row is read once, inside the snapshot transaction the store opens for
/// this method, so every derived field describes the same rows. The latest
/// Guard Cloud sync is the headless app sync summary when one is recorded (an
/// empty object counts), else the receipt sync summary.
pub(crate) fn rows_method(connection: &Connection) -> StoreResult<Value> {
    let mut rows = Map::new();
    let mut headless_recorded = false;
    for key in ROWS {
        let row = object_row(connection, key)?;
        if key == "headless_app_sync_summary" {
            headless_recorded = row.is_some();
        }
        rows.insert(key.to_owned(), Value::Object(row.unwrap_or_default()));
    }
    let latest_key = if headless_recorded {
        "headless_app_sync_summary"
    } else {
        "sync_summary"
    };
    let latest = rows.get(latest_key).cloned().unwrap_or_else(|| json!({}));
    let auth_expired = cloud_auth_expired(&rows);
    let synced_at = last_sync_at(&rows);
    Ok(json!({
        "rows": rows,
        "cloud_auth_expired": auth_expired,
        "last_sync_at": synced_at,
        "latest_cloud_sync": latest,
    }))
}

#[cfg(test)]
#[path = "guard_store_cloud_status_rows_tests.rs"]
mod tests;
