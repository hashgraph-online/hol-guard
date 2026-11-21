//! `transition_cloud_review_sync_state`: move the Cloud Review sync state row
//! through one named step of a sync run.
//!
//! Port of the state edits `runtime/cloud_review_sync.py` and
//! `runtime/cloud_review_sync_worker.py` made in Python before saving the
//! whole in-memory state. Each step names the fields it sets here, and the
//! store merges them into the stored row inside its write transaction, so
//! every other field keeps its stored value. The caller reads the merged row
//! back as its in-memory state.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `CLOUD_REVIEW_SYNC_STATE_KEY`; a non-default Guard source appends `:source`.
const STATE_KEY: &str = "guard_cloud_review_sync_state";
const ERROR_CODE: &str = "last_error_code";
/// Codes that say sign-in is still required.
const AUTH_CODES: [&str; 2] = ["cloud_auth_expired", "cloud_connect_required"];

fn valid_state_key(state_key: &str) -> bool {
    state_key == STATE_KEY
        || state_key
            .strip_prefix(STATE_KEY)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|source| !source.is_empty())
}

fn int_field(fields: &Map<String, Value>, key: &str, code: &'static str) -> StoreResult<i64> {
    fields
        .get(key)
        .and_then(Value::as_i64)
        .map_or_else(|| value_error(code), Ok)
}

/// `batch_limits`: the batch size a delivery binding settled on.
fn batch_limits(args: &Args<'_>) -> StoreResult<Vec<(&'static str, Value)>> {
    let binding_key = args.str("binding_key")?;
    let limits = args.object("limits")?;
    Ok(vec![
        ("batch_binding_key", json!(binding_key)),
        (
            "batch_events",
            json!(int_field(limits, "events", "invalid_limits")?),
        ),
        (
            "batch_max_bytes",
            json!(int_field(limits, "bytes", "invalid_limits")?),
        ),
        (
            "batch_event_cap",
            json!(int_field(limits, "event_cap", "invalid_limits")?),
        ),
    ])
}

/// `completed`: the run finished; the outbox says what is still waiting.
fn completed(args: &Args<'_>, at: &str) -> StoreResult<Vec<(&'static str, Value)>> {
    let counts = args.object("counts")?;
    let accepted = int_field(counts, "accepted", "invalid_counts")?;
    let delivered = int_field(counts, "delivered", "invalid_counts")?;
    let rejected = int_field(counts, "rejected", "invalid_counts")?;
    let outbox = args.object("outbox")?;
    let depth = int_field(outbox, "depth", "invalid_outbox")?;
    let oldest = match outbox.get("oldest_changed_at") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(at)) => json!(at),
        Some(_) => return value_error("invalid_outbox"),
    };
    let error = args.opt_str("error")?;
    let mut set = Vec::new();
    if accepted > 0 || depth == 0 {
        set.push(("last_success_at", json!(at)));
    }
    if delivered > 0 {
        set.push(("last_delivery_at", json!(at)));
        set.push((
            "last_delivery_binding",
            Value::Object(args.object("delivery_binding")?.clone()),
        ));
    }
    // Python tested the error's truth: an empty message is no error.
    let failing = error.is_some_and(|error| !error.is_empty()) && depth != 0;
    let state = if failing { "error" } else { "idle" };
    set.extend([
        ("state", json!(state)),
        ("last_sync_at", json!(at)),
        ("synced_count", json!(accepted)),
        ("rejected_count", json!(rejected)),
        (
            "last_error",
            error.map_or(Value::Null, |error| json!(error)),
        ),
        ("outbox_depth", json!(depth)),
        ("outbox_oldest_changed_at", oldest),
    ]);
    Ok(set)
}

/// `failed`: the run or the worker loop caught an error.
///
/// A missing `error_code` keeps the stored code. With `keep_auth_code`, a
/// stored code saying sign-in is still required outlives a transient failure.
fn failed(
    args: &Args<'_>,
    at: &str,
    stored: &Map<String, Value>,
) -> StoreResult<Vec<(&'static str, Value)>> {
    let Some(error) = args.opt_str("error")? else {
        return value_error("invalid_error");
    };
    let mut set = vec![
        ("state", json!("error")),
        ("last_error", json!(error)),
        ("last_error_at", json!(at)),
    ];
    let keep_auth_code = args.flag("keep_auth_code")?;
    match args.opt_str("error_code")? {
        Some(code) => {
            let kept = stored
                .get(ERROR_CODE)
                .and_then(Value::as_str)
                .filter(|stored| keep_auth_code && AUTH_CODES.contains(stored));
            set.push((ERROR_CODE, json!(kept.unwrap_or(code))));
        }
        None if keep_auth_code => return value_error("invalid_error_code"),
        None => {}
    }
    Ok(set)
}

pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let state_key = args.str("state_key")?;
    if !valid_state_key(state_key) {
        return value_error("invalid_state_key");
    }
    let now = args.str("now")?;
    let at = args.opt_str("at")?.unwrap_or(now);
    // `_load_sync_state` reads a row that is not an object as empty.
    let mut state = match read_payload(connection, state_key)? {
        Some(Value::Object(state)) => state,
        _ => Map::new(),
    };
    let set = match args.str("transition")? {
        // A run starts and clears the last error and its code.
        "started" => vec![
            ("state", json!("syncing")),
            ("last_sync_attempt_at", json!(at)),
            ("last_error", Value::Null),
            (ERROR_CODE, Value::Null),
        ],
        "batch_limits" => batch_limits(args)?,
        "completed" => completed(args, at)?,
        "failed" => failed(args, at, &state)?,
        _ => return value_error("invalid_transition"),
    };
    for (key, value) in set {
        state.insert(key.to_owned(), value);
    }
    let merged = Value::Object(state);
    let encoded =
        serde_json::to_string(&merged).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, state_key, &encoded, now)?;
    Ok(json!({"state": merged}))
}

#[cfg(test)]
#[path = "guard_store_review_sync_transition_tests.rs"]
mod tests;
