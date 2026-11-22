//! `sync_payload_snapshot`: several `sync_state` rows read together.
//!
//! A caller that combines rows, such as the stale-intel check over the sync,
//! runtime session and supply-chain summaries, used to call
//! `get_sync_payload` once per row, each on its own connection, so a sync
//! committing between two reads could pair rows from different moments.
//! Here every named row is read inside one deferred transaction:
//!
//! - a row holding an object or an array comes back as stored, and a missing
//!   row or one holding another JSON value comes back as `null`, as
//!   `get_sync_payload` answered;
//! - a row whose bytes are not UTF-8 JSON is named in `unreadable`, since
//!   `get_sync_payload` raised for it, and the caller refuses the snapshot;
//! - the key list must be non-empty, hold at most [`MAX_KEYS`] distinct
//!   non-empty keys, and is refused otherwise.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};

/// The most rows one snapshot reads.
pub(crate) const MAX_KEYS: usize = 16;

const KEYS_INVALID: StoreError = StoreError::Invalid("native_sync_payload_snapshot_keys_invalid");

/// Whether `method` is the multi-row snapshot.
pub(crate) fn handles(method: &str) -> bool {
    method == "sync_payload_snapshot"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "sync_payload_snapshot" => snapshot(connection, &keys(args)?),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The requested keys, in request order.
fn keys<'a>(args: &Args<'a>) -> StoreResult<Vec<&'a str>> {
    let keys = args
        .strings("keys")
        .map_err(|_| KEYS_INVALID)?
        .ok_or(KEYS_INVALID)?;
    if keys.is_empty() || keys.len() > MAX_KEYS || keys.iter().any(|key| key.is_empty()) {
        return Err(KEYS_INVALID);
    }
    for (index, key) in keys.iter().enumerate() {
        if keys[..index].contains(key) {
            return Err(KEYS_INVALID);
        }
    }
    Ok(keys)
}

fn snapshot(connection: &Connection, keys: &[&str]) -> StoreResult<Value> {
    let mut rows = Map::new();
    let mut unreadable = Vec::new();
    for key in keys {
        let payload = match stored_row(connection, key)? {
            Row::Unreadable => {
                unreadable.push(*key);
                Value::Null
            }
            Row::Parsed(payload @ (Value::Object(_) | Value::Array(_))) => payload,
            Row::Missing | Row::Parsed(_) => Value::Null,
        };
        rows.insert((*key).to_owned(), payload);
    }
    Ok(json!({"rows": rows, "unreadable": unreadable}))
}

/// One `sync_state` row as the snapshot sees it.
enum Row {
    Missing,
    Unreadable,
    Parsed(Value),
}

/// Read `key` as bytes so a BLOB or invalid UTF-8 cell is judged here, as
/// unreadable, rather than failing the decoder.
fn stored_row(connection: &Connection, key: &str) -> StoreResult<Row> {
    let row: Option<Option<Vec<u8>>> = connection
        .query_row(
            "select cast(payload_json as blob) from sync_state where state_key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match row {
        None => Row::Missing,
        Some(bytes) => bytes
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map_or(Row::Unreadable, Row::Parsed),
    })
}

#[cfg(test)]
#[path = "guard_store_sync_payload_snapshot_tests.rs"]
mod tests;
