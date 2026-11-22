//! The `sync_state` writes `store_cloud_events.py` still ran on its own
//! SQLite connection: the OAuth credential row upsert, the first-write-wins
//! insert and the row deletes.
//!
//! The Python `GuardStore` wrapper keeps the side effects that live in its
//! process: it clears the cached credential payload before a credential row
//! changes and wakes the review-event outbox after a credential write.

use rusqlite::Connection;
use serde_json::Value;

use super::{encoded_payload, is_credential_key, write_encoded};
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, value_error, StoreResult};

/// Whether `method` is one of these writes.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "write_credential_sync_payload"
            | "insert_sync_payload_if_absent"
            | "delete_sync_payload"
            | "delete_sync_payloads"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "write_credential_sync_payload" => write_credential(connection, args),
        "insert_sync_payload_if_absent" => insert_if_absent(connection, args),
        "delete_sync_payload" => {
            delete_keys(connection, &[args.str("state_key")?])?;
            Ok(Value::Null)
        }
        _ => {
            let state_keys = args
                .strings("state_keys")?
                .map_or_else(|| value_error("invalid_state_keys"), Ok)?;
            Ok(Value::from(delete_keys(connection, &state_keys)?))
        }
    }
}

/// `set_sync_payload` for the OAuth credential rows, which `set` refuses.
/// Any other key is refused here, so each writer keeps to its own rows.
fn write_credential(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let state_key = args.str("state_key")?;
    if !is_credential_key(state_key) {
        return value_error("sync_payload_key_not_credential");
    }
    write_encoded(
        connection,
        state_key,
        &encoded_payload(args)?,
        args.str("now")?,
    )?;
    Ok(Value::Null)
}

/// `insert_sync_payload_if_absent`: store the payload only when the key has
/// no row, so an existing row always wins. Returns whether it was stored.
fn insert_if_absent(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let state_key = args.str("state_key")?;
    if is_credential_key(state_key) {
        return value_error("sync_payload_key_reserved");
    }
    let inserted = exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do nothing",
        &[
            Value::from(state_key),
            Value::from(encoded_payload(args)?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::from(inserted > 0))
}

/// Delete every row whose key is in `state_keys`; returns how many went.
fn delete_keys(connection: &Connection, state_keys: &[&str]) -> StoreResult<i64> {
    let mut deleted = 0;
    for state_key in state_keys {
        deleted += exec(
            connection,
            "delete from sync_state where state_key = ?",
            &[Value::from(*state_key)],
        )?;
    }
    Ok(deleted)
}

#[cfg(test)]
#[path = "guard_store_sync_payload_rows_tests.rs"]
mod tests;
