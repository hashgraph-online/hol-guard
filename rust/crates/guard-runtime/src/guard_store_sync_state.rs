//! `get_sync_payload` and `set_sync_payload`: the `sync_state` rows that hold
//! small local preferences and cloud-sync cursors as JSON documents.
//!
//! The OAuth credential rows are not written here: their writer clears the
//! credential cache and wakes the review-event outbox, which only the cloud
//! connect path does.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, text, value_error, StoreResult};

/// `_OAUTH_LOCAL_CREDENTIALS_STATE_KEY`.
const OAUTH_CREDENTIALS_KEY: &str = "oauth_local_credentials";

/// `get_sync_payload`: the stored object or array, else `null`.
pub(crate) fn get(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    Ok(read_payload(connection, args.str("state_key")?)?.unwrap_or(Value::Null))
}

/// The stored object or array under `state_key`, if any.
pub(crate) fn read_payload(connection: &Connection, state_key: &str) -> StoreResult<Option<Value>> {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(state_key)],
    )?;
    Ok(row
        .and_then(|row| serde_json::from_str::<Value>(text(&row, "payload_json")).ok())
        .filter(|payload| payload.is_object() || payload.is_array()))
}

/// `set_sync_payload` for every key but the OAuth credential rows.
pub(crate) fn set(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let state_key = args.str("state_key")?;
    if is_credential_key(state_key) {
        return value_error("sync_payload_key_reserved");
    }
    let payload = args
        .raw("payload")
        .filter(|payload| payload.is_object() || payload.is_array())
        .map_or_else(|| value_error("invalid_payload"), Ok)?;
    let encoded =
        serde_json::to_string(payload).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, state_key, &encoded, args.str("now")?)?;
    Ok(Value::Null)
}

/// Upsert already-encoded payload text under `state_key`. Callers keep the
/// OAuth credential rows out, as `set` does.
pub(crate) fn write_encoded(
    connection: &Connection,
    state_key: &str,
    encoded: &str,
    now: &str,
) -> StoreResult<()> {
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
         payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        &[
            Value::from(state_key),
            Value::from(encoded),
            Value::from(now),
        ],
    )?;
    Ok(())
}

fn is_credential_key(state_key: &str) -> bool {
    state_key == OAUTH_CREDENTIALS_KEY
        || state_key
            .strip_prefix(OAUTH_CREDENTIALS_KEY)
            .is_some_and(|rest| rest.starts_with(':'))
}

#[path = "guard_store_queue_lease_limit.rs"]
pub(crate) mod queue_lease_limit;

#[path = "guard_store_queue_transition.rs"]
pub(crate) mod queue_transition;

#[path = "guard_store_review_replay_marker.rs"]
pub(crate) mod review_replay_marker;

#[path = "guard_store_review_sync_transition.rs"]
pub(crate) mod review_sync_transition;

#[cfg(test)]
#[path = "guard_store_sync_state_tests.rs"]
mod tests;
