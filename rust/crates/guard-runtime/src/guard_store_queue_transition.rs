//! `transition_command_queue_state`: move a queue lane's state row through
//! one named step of a command job's life.
//!
//! Port of the state edits `runtime/command_queue.py` and
//! `runtime/command_queue_pending.py` made in Python before saving the
//! worker's whole in-memory state. Each step names the fields it sets and
//! removes here, and the store merges them into the stored row inside its
//! write transaction, so every other field keeps its stored value. The
//! caller reads the merged row back as its in-memory state.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::command_queue_repair::lane_state_key;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

const HEARTBEAT_FAILED: &str = "Guard command heartbeat failed.";

/// The fields one step removes, then the fields it sets.
struct Step {
    remove: &'static [&'static str],
    set: Vec<(&'static str, Value)>,
}

fn step(name: &str, at: &str, pending: Option<&Map<String, Value>>) -> StoreResult<Step> {
    const JOB_AND_RESULT: &[&str] = &["active_job", "pending_result"];
    let step = match name {
        // The lane may not poll: nothing is leased and no error stands.
        "disabled" => Step {
            remove: &[],
            set: vec![
                ("state", json!("disabled")),
                ("last_error", Value::Null),
                ("active_job", Value::Null),
            ],
        },
        "polling" => Step {
            remove: &[],
            set: vec![
                ("state", json!("polling")),
                ("last_poll_at", json!(at)),
                ("last_error", Value::Null),
                ("last_poll_was_empty", json!(false)),
            ],
        },
        // A 401 is being refreshed; the job stays leased.
        "auth_expired" => Step {
            remove: &[],
            set: vec![("state", json!("auth_expired"))],
        },
        "heartbeat_failed" => Step {
            remove: &["active_job"],
            set: vec![
                ("state", json!("error")),
                ("last_error", json!(HEARTBEAT_FAILED)),
            ],
        },
        // The settled result is kept until an upload succeeds.
        "result_pending" => {
            let Some(pending) = pending else {
                return value_error("invalid_pending_result");
            };
            let (Some(Value::Object(job)), Some(Value::Object(payload))) =
                (pending.get("job"), pending.get("payload"))
            else {
                return value_error("invalid_pending_result");
            };
            Step {
                remove: &[],
                set: vec![
                    ("state", json!("result_pending")),
                    (
                        "pending_result",
                        json!({"job": job, "payload": payload, "recorded_at": at}),
                    ),
                ],
            }
        }
        // The result reached Guard Cloud.
        "settled" => Step {
            remove: JOB_AND_RESULT,
            set: vec![
                ("state", json!("idle")),
                ("last_result_at", json!(at)),
                ("last_error", Value::Null),
                ("last_poll_was_empty", json!(false)),
            ],
        },
        // Guard Cloud refused the result, so it is dropped.
        "result_refused" => Step {
            remove: JOB_AND_RESULT,
            set: vec![
                ("state", json!("idle")),
                ("last_error", Value::Null),
                ("last_poll_was_empty", json!(false)),
            ],
        },
        // The kept result's lease is past saving, so it is dropped.
        "stale_result_dropped" => Step {
            remove: JOB_AND_RESULT,
            set: vec![("state", json!("idle")), ("last_error", Value::Null)],
        },
        // The kept result cannot be read, so it is dropped as it stands.
        "malformed_result_dropped" => Step {
            remove: JOB_AND_RESULT,
            set: Vec::new(),
        },
        _ => return value_error("invalid_transition"),
    };
    Ok(step)
}

pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let Some(state_key) = lane_state_key(Some(args.str("state_key")?)) else {
        return value_error("invalid_state_key");
    };
    let now = args.str("now")?;
    let at = args.opt_str("at")?.unwrap_or(now);
    let step = step(args.str("transition")?, at, args.opt_object("pending")?)?;
    // `load_command_queue_state` reads a row that is not an object as empty.
    let mut state = match read_payload(connection, state_key)? {
        Some(Value::Object(state)) => state,
        _ => Map::new(),
    };
    for key in step.remove {
        state.remove(*key);
    }
    for (key, value) in step.set {
        state.insert(key.to_owned(), value);
    }
    let merged = Value::Object(state);
    let encoded =
        serde_json::to_string(&merged).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, state_key, &encoded, now)?;
    Ok(json!({"state": merged}))
}

#[cfg(test)]
#[path = "guard_store_queue_transition_tests.rs"]
mod tests;
