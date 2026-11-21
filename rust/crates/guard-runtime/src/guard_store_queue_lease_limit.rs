//! `record_command_queue_lease_limit`: remember how many exact Review jobs
//! Guard Cloud says one lease may return, in a queue lane's state row.
//!
//! Port of the write half of `record_exact_lease_batch_limit` in
//! `runtime/command_queue_state.py`. Python saved the worker's whole
//! in-memory state to record a changed limit, so a write another thread or
//! process made to the same row since that state was loaded was lost. Here the
//! limit alone is merged into the stored row inside the store's write
//! transaction, and every other field keeps its stored value.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::command_queue_repair::lane_state_key;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// The state field that holds the limit.
const LIMIT_KEY: &str = "exact_lease_batch_limit";

pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let Some(state_key) = lane_state_key(Some(args.str("state_key")?)) else {
        return value_error("invalid_state_key");
    };
    let limit = args
        .raw("limit")
        .and_then(Value::as_u64)
        .filter(|limit| *limit >= 1)
        .map_or_else(|| value_error("invalid_limit"), Ok)?;
    let now = args.str("now")?;
    // `load_command_queue_state` reads a row that is not an object as empty.
    let mut state = match read_payload(connection, state_key)? {
        Some(Value::Object(state)) => state,
        _ => Map::new(),
    };
    if state.get(LIMIT_KEY).and_then(Value::as_u64) == Some(limit) {
        return Ok(json!({"saved": false}));
    }
    state.insert(LIMIT_KEY.to_owned(), json!(limit));
    let encoded = serde_json::to_string(&Value::Object(state))
        .map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, state_key, &encoded, now)?;
    Ok(json!({"saved": true}))
}

#[cfg(test)]
#[path = "guard_store_queue_lease_limit_tests.rs"]
mod tests;
