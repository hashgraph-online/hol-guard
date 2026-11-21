//! `command-state` op `queue_repair`: puts a damaged command-queue state row
//! back into a shape the queue worker can run from.
//!
//! Port of `repair_command_queue_state` in `runtime/command_queue_state.py`.
//! Python read the lane's state row, dropped an `active_job` that was not an
//! object and a `pending_result` without an object `job` and `payload`, and
//! wrote the row back. A queue worker writing the same row in between could
//! lose its write or have it overwritten. Here the read and the write share one
//! immediate transaction.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::command_state::{INVALID, UNAVAILABLE, UNREADABLE};
use crate::sync_state_ledger::{read_payload, write_payload};

/// The main worker's queue state row.
pub(crate) const MAIN_STATE_KEY: &str = "guard_command_queue_state";
/// Review drain worker `N` keeps its own row, `<main key>.review_drain.N`.
const DRAIN_KEY_PREFIX: &str = "guard_command_queue_state.review_drain.";

/// The queue state row a request may name: the main row, or a drain worker's
/// row by its slot number. Anything else is not a queue lane, so the op never
/// rewrites an unrelated `sync_state` row.
pub(crate) fn lane_state_key(requested: Option<&str>) -> Option<&str> {
    let Some(key) = requested else {
        return Some(MAIN_STATE_KEY);
    };
    if key == MAIN_STATE_KEY {
        return Some(key);
    }
    let slot = key.strip_prefix(DRAIN_KEY_PREFIX)?;
    (!slot.is_empty() && slot.bytes().all(|byte| byte.is_ascii_digit())).then_some(key)
}

/// What `queue_repair` answers: the fields it dropped, in Python's order.
fn answer(repaired: &[&str]) -> Value {
    json!({"repaired": repaired})
}

/// A pending result the worker can upload: an object with an object `job`
/// and an object `payload`.
fn pending_result_is_usable(value: &Value) -> bool {
    value.get("job").is_some_and(Value::is_object)
        && value.get("payload").is_some_and(Value::is_object)
}

/// A present, non-null field that fails `usable`.
fn damaged(state: &Map<String, Value>, field: &str, usable: fn(&Value) -> bool) -> bool {
    state
        .get(field)
        .is_some_and(|value| !value.is_null() && !usable(value))
}

pub(crate) fn queue_repair(
    conn: &Connection,
    state_key: Option<&str>,
    now: &str,
) -> Result<Value, String> {
    let key = lane_state_key(state_key).ok_or(INVALID)?;
    let Some(raw) = read_payload(conn, key).map_err(|()| UNAVAILABLE.to_owned())? else {
        return Ok(answer(&[]));
    };
    let payload: Value = serde_json::from_str(&raw).map_err(|_| UNREADABLE.to_owned())?;
    // `load_command_queue_state` treats a row that is not an object as an
    // empty state, which has nothing to repair and is not written back.
    let Value::Object(mut state) = payload else {
        return Ok(answer(&[]));
    };
    let mut repaired = Vec::new();
    if damaged(&state, "active_job", Value::is_object) {
        state.remove("active_job");
        repaired.push("active_job");
    }
    if damaged(&state, "pending_result", pending_result_is_usable) {
        state.remove("pending_result");
        repaired.push("pending_result");
    }
    if !repaired.is_empty() {
        state.insert("state".to_owned(), Value::String("idle".to_owned()));
        state.insert("last_error".to_owned(), Value::Null);
        write_payload(conn, key, &Value::Object(state), now)
            .map_err(|()| UNAVAILABLE.to_owned())?;
    }
    Ok(answer(&repaired))
}
