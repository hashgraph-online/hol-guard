//! The store's half of `_refresh_policy_integrity_state`
//! (`store_secret_policy_integrity.py`).
//!
//! The Python owner reads the key and the trusted control state from the host
//! secret store and decides the published integrity state. These ops answer
//! the one store question it asks and record the answer:
//!
//! - `count_legacy_policy_rows`: how many local rows are not yet signed with
//!   the current integrity version, which gates the cutover;
//! - `record_policy_integrity_state`: store the published state under
//!   `policy_integrity` when it differs from the stored one, and report
//!   whether it did, so the caller notifies listeners only on a change.

use rusqlite::Connection;
use serde_json::{json, Value};

use guard_policy_snapshot::policy_integrity::{POLICY_INTEGRITY_VERSION, REMOTE_POLICY_SOURCES};

use super::INTEGRITY_STATE_KEY;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, StoreError, StoreResult};

const UPSERT_STATE: &str = "insert into sync_state (state_key, payload_json, updated_at) \
     values (?, ?, ?) on conflict(state_key) do update set \
     payload_json = excluded.payload_json, updated_at = excluded.updated_at";

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "count_legacy_policy_rows" | "record_policy_integrity_state"
    )
}

pub(super) fn run(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "count_legacy_policy_rows" => count_legacy_policy_rows(connection),
        "record_policy_integrity_state" => record_policy_integrity_state(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_args_invalid")),
    }
}

/// `GuardStore._count_legacy_local_policy_rows`.
fn count_legacy_policy_rows(connection: &Connection) -> StoreResult<Value> {
    let remote = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(", ");
    let sql = format!(
        "select count(*) as total from policy_decisions where source not in ({remote}) and (\
         integrity_version is null or integrity_version != {POLICY_INTEGRITY_VERSION} \
         or payload_hash is null or payload_mac is null or integrity_key_id is null \
         or signed_at is null)"
    );
    let params: Vec<Value> = REMOTE_POLICY_SOURCES
        .iter()
        .map(|source| json!(source))
        .collect();
    let total = query_one(connection, &sql, &params)?
        .and_then(|row| row.get("total").and_then(Value::as_i64))
        .unwrap_or(0);
    Ok(json!({ "legacy_rows": total }))
}

/// `GuardStore._store_policy_integrity_state`, written only on a change.
fn record_policy_integrity_state(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let payload = Value::Object(args.object("payload")?.clone());
    let stored = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[json!(INTEGRITY_STATE_KEY)],
    )?
    .and_then(|row| {
        row.get("payload_json")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    .filter(Value::is_object);
    if stored.as_ref() == Some(&payload) {
        return Ok(json!({ "changed": false }));
    }
    let text = serde_json::to_string(&payload)
        .map_err(|_| StoreError::Invalid("native_guard_store_args_invalid"))?;
    exec(
        connection,
        UPSERT_STATE,
        &[json!(INTEGRITY_STATE_KEY), json!(text), json!(now)],
    )?;
    Ok(json!({ "changed": true }))
}

#[cfg(test)]
#[path = "guard_store_policy_integrity_state_tests.rs"]
mod tests;
