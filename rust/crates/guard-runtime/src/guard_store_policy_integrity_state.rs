//! The store's half of `_refresh_policy_integrity_state`
//! (`store_secret_policy_integrity.py`).
//!
//! The Python owner reads the key and the trusted control state from the host
//! secret store and decides the published integrity state. These ops answer
//! the store questions it asks and record the answer:
//!
//! - `read_policy_integrity_state`: the stored `policy_integrity` row, as its
//!   raw text (the cache marker) and as a parsed object (the state);
//! - `has_local_policy_rows`: whether any row did not come from a remote
//!   policy source, so startup knows whether a generation needs preparing;
//! - `count_legacy_policy_rows`: how many local rows are not yet signed with
//!   the current integrity version, which gates the cutover;
//! - `record_policy_integrity_state`: store the published state under
//!   `policy_integrity` when it differs from the stored one, and report
//!   whether it did, so the caller notifies listeners only on a change.

use rusqlite::Connection;
use serde_json::{json, Value};

use guard_policy_snapshot::policy_integrity::{POLICY_INTEGRITY_VERSION, REMOTE_POLICY_SOURCES};

use super::INTEGRITY_STATE_KEY;

#[path = "guard_store_policy_decision_list.rs"]
mod decision_list;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, StoreError, StoreResult};

const UPSERT_STATE: &str = "insert into sync_state (state_key, payload_json, updated_at) \
     values (?, ?, ?) on conflict(state_key) do update set \
     payload_json = excluded.payload_json, updated_at = excluded.updated_at";

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "read_policy_integrity_state"
            | "has_local_policy_rows"
            | "count_legacy_policy_rows"
            | "record_policy_integrity_state"
            | "list_policy_decision_rows"
            | "read_policy_decision_row"
            | "list_local_policy_rows"
    )
}

pub(super) fn run(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "read_policy_integrity_state" => read_policy_integrity_state(connection),
        "has_local_policy_rows" => has_local_policy_rows(connection),
        "count_legacy_policy_rows" => count_legacy_policy_rows(connection),
        "record_policy_integrity_state" => record_policy_integrity_state(connection, args),
        "list_policy_decision_rows" => decision_list::list_policy_decision_rows(connection, args),
        "read_policy_decision_row" => decision_list::read_policy_decision_row(connection, args),
        "list_local_policy_rows" => decision_list::list_local_policy_rows(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_args_invalid")),
    }
}

fn remote_source_params() -> (String, Vec<Value>) {
    let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(", ");
    let params = REMOTE_POLICY_SOURCES
        .iter()
        .map(|source| json!(source))
        .collect();
    (placeholders, params)
}

/// The stored `policy_integrity` payload text, when it is a non-empty string.
fn stored_state_text(connection: &Connection) -> StoreResult<Option<String>> {
    Ok(query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[json!(INTEGRITY_STATE_KEY)],
    )?
    .and_then(|row| {
        row.get("payload_json")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    }))
}

/// The stored payload as an object; text that is not a JSON object is no state.
fn parsed_state(text: Option<&str>) -> Option<Value> {
    text.and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(Value::is_object)
}

/// `GuardStore._load_policy_integrity_state` and its cache marker: the raw
/// text marks the cache, so a rewrite of the same state still matches.
fn read_policy_integrity_state(connection: &Connection) -> StoreResult<Value> {
    let text = stored_state_text(connection)?;
    let state = parsed_state(text.as_deref());
    Ok(json!({ "payload_json": text, "state": state }))
}

/// The startup probe for any local row, signed or not.
fn has_local_policy_rows(connection: &Connection) -> StoreResult<Value> {
    let (remote, params) = remote_source_params();
    let sql =
        format!("select 1 as present from policy_decisions where source not in ({remote}) limit 1");
    let present = query_one(connection, &sql, &params)?.is_some();
    Ok(json!({ "present": present }))
}

/// `GuardStore._count_legacy_local_policy_rows`.
fn count_legacy_policy_rows(connection: &Connection) -> StoreResult<Value> {
    let (remote, params) = remote_source_params();
    let sql = format!(
        "select count(*) as total from policy_decisions where source not in ({remote}) and (\
         integrity_version is null or integrity_version != {POLICY_INTEGRITY_VERSION} \
         or payload_hash is null or payload_mac is null or integrity_key_id is null \
         or signed_at is null)"
    );
    let total = query_one(connection, &sql, &params)?
        .and_then(|row| row.get("total").and_then(Value::as_i64))
        .unwrap_or(0);
    Ok(json!({ "legacy_rows": total }))
}

/// `GuardStore._store_policy_integrity_state`, written only on a change.
fn record_policy_integrity_state(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let payload = Value::Object(args.object("payload")?.clone());
    let stored = parsed_state(stored_state_text(connection)?.as_deref());
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
