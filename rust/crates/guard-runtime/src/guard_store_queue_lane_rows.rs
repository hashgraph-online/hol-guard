//! `command_queue_lane_rows`: what the command queue workers read from each
//! lane's state row, for several lanes in one snapshot.
//!
//! Port of `_lane_has_pending_result` in `runtime/command_queue_drain.py` and
//! of the main-lane read in `lane_exact_lease_batch_limit` in
//! `runtime/command_queue_state.py`. Python read each lane's row on its own
//! through `get_sync_payload` and judged it there. Here every named lane is
//! read inside one deferred transaction and judged by the same rules:
//!
//! - a row whose bytes are not UTF-8 JSON is unreadable, as `get_sync_payload`
//!   raised for it, and the caller decides what an unreadable lane means; a
//!   damaged cell is judged on its own lane and never fails the other lanes;
//! - a row that is not an object holds no pending result and no limit;
//! - a pending result is any object under `pending_result`;
//! - the lease batch limit is a whole number of at least one under
//!   `exact_lease_batch_limit`, else one.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::command_queue_repair::lane_state_key;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};

/// The most lanes one call may name: the main lane and its drain workers fit
/// many times over.
const MAX_LANES: usize = 64;
/// The state field that holds the lease batch limit.
const LIMIT_KEY: &str = "exact_lease_batch_limit";
/// The state field that holds a result the lane has not sent yet.
const PENDING_KEY: &str = "pending_result";

/// Whether `method` is the lane snapshot.
pub(crate) fn handles(method: &str) -> bool {
    method == "command_queue_lane_rows"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "command_queue_lane_rows" => lane_rows(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn lane_rows(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let Some(keys) = args.strings("state_keys")? else {
        return value_error("invalid_state_keys");
    };
    if keys.is_empty() || keys.len() > MAX_LANES {
        return value_error("invalid_state_keys");
    }
    let mut lanes = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(key) = lane_state_key(Some(key)) else {
            return value_error("invalid_state_key");
        };
        lanes.push(lane(connection, key)?);
    }
    Ok(json!({"lanes": lanes}))
}

/// One lane's answer.
fn lane(connection: &Connection, key: &str) -> StoreResult<Value> {
    // The cell is read as bytes so a BLOB or invalid UTF-8 payload is judged
    // here, as unreadable, rather than failing every lane in the snapshot.
    let row: Option<Option<Vec<u8>>> = connection
        .query_row(
            "select cast(payload_json as blob) from sync_state where state_key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?;
    let (readable, state) = match row {
        None => (true, Map::new()),
        Some(bytes) => match bytes.and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()) {
            None => (false, Map::new()),
            Some(Value::Object(state)) => (true, state),
            Some(_) => (true, Map::new()),
        },
    };
    Ok(json!({
        "state_key": key,
        "readable": readable,
        "pending_result": state.get(PENDING_KEY).is_some_and(Value::is_object),
        "has_lease_batch_limit": state.contains_key(LIMIT_KEY),
        "exact_lease_batch_limit": lease_batch_limit(&state),
    }))
}

/// `exact_lease_batch_limit`: the stored whole number when it is at least one,
/// else one. JSON `true` and `2.0` are not whole numbers here, as Python's
/// `isinstance(value, int)` check (with `bool` excluded) refused them.
fn lease_batch_limit(state: &Map<String, Value>) -> u64 {
    state
        .get(LIMIT_KEY)
        .and_then(Value::as_u64)
        .filter(|limit| *limit >= 1)
        .unwrap_or(1)
}

#[cfg(test)]
#[path = "guard_store_queue_lane_rows_tests.rs"]
mod tests;
