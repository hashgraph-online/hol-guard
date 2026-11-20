//! `auto-update-state --stdin`: the bookkeeping behind Guard's automatic
//! update check.
//!
//! Port of the state half of `runtime/auto_update.py`. The Python daemon still
//! fetches the update status and runs the installer; this op owns the saved
//! `guard_auto_update_state` row and every decision drawn from it: whether a
//! check is due, whether a fetched status should be applied, and what a run
//! leaves behind. Each step reads, changes and writes the row in one immediate
//! transaction, and `begin` claims the check in that same transaction, so two
//! daemons cannot both start an update inside one throttle window.

use std::io::Read;
use std::path::PathBuf;

use guard_contracts::utc_timestamp_micros;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::approval_proof_op::py_equal;
use crate::sync_state_ledger::{read_payload, write_payload, LedgerCodes, SyncStateLedger};

pub(crate) const COMMAND: &str = "auto-update-state";
pub(crate) const FEATURE: &str = "native-auto-update-state-v1";
const SCHEMA: &str = "auto-update-state.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

const STATE_KEY: &str = "guard_auto_update_state";
const THROTTLE_MICROS: i64 = 6 * 3600 * 1_000_000;

const INVALID: &str = "auto_update_state_request_invalid";
const UNAVAILABLE: &str = "auto_update_state_unavailable";
const BUSY: &str = "auto_update_state_busy";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    schema: String,
    guard_home: PathBuf,
    op: String,
    /// The caller's clock, already in the ISO form the row stores.
    now: String,
    /// `record_check`: the fetched update status. Absent when the fetch failed.
    #[serde(default)]
    status: Option<Map<String, Value>>,
    /// `record_update`: the version the run tried to install.
    #[serde(default)]
    latest_version: Value,
    /// `record_update`: the installer's payload. Absent when it raised.
    #[serde(default)]
    update_payload: Option<Value>,
    #[serde(default)]
    exit_code: Value,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "auto_update_state_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("auto_update_state_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
    let response = match handle(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(code) => json!({"ok": false, "error": code}),
    };
    serde_json::to_vec(&response).map_err(|_| "auto_update_state_response_encode_failed".to_owned())
}

pub(crate) fn handle(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(INVALID.to_owned());
    }
    let now = utc_timestamp_micros(request.now.trim()).ok_or("invalid_current_time")?;
    let ledger = SyncStateLedger::new(
        &request.guard_home,
        LedgerCodes {
            busy: BUSY,
            unavailable: UNAVAILABLE,
        },
    );
    match request.op.as_str() {
        "begin" => ledger.transact(|tx| begin(tx, request, now)),
        "record_check" => ledger.transact(|tx| record_check(tx, request)),
        "record_update" => ledger.transact(|tx| record_update(tx, request)),
        _ => Err(INVALID.to_owned()),
    }
}

/// The saved row as an object. A row that is missing, unreadable or not an
/// object starts over empty, as `dict(raw) if isinstance(raw, dict) else {}`.
fn load(conn: &Connection) -> Result<Map<String, Value>, String> {
    let raw = read_payload(conn, STATE_KEY).map_err(|()| UNAVAILABLE.to_owned())?;
    Ok(raw
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| match value {
            Value::Object(state) => Some(state),
            _ => None,
        })
        .unwrap_or_default())
}

fn save(conn: &Connection, state: Map<String, Value>, now: &str) -> Result<(), String> {
    write_payload(conn, STATE_KEY, &Value::Object(state), now).map_err(|()| UNAVAILABLE.to_owned())
}

/// Whether the last check is recent enough to skip this one. Python compared
/// an aware clock with `datetime.fromisoformat(last_check_at)`, so a value it
/// could not parse, or one with no UTC offset, never held a check back.
fn checked_recently(state: &Map<String, Value>, now: i64) -> bool {
    let Some(last) = state.get("last_check_at").and_then(Value::as_str) else {
        return false;
    };
    if !has_utc_offset(last) {
        return false;
    }
    utc_timestamp_micros(last).is_some_and(|last| now.saturating_sub(last) < THROTTLE_MICROS)
}

/// An ISO timestamp names its offset after the date: `Z`, `+hh:mm` or
/// `-hh:mm`. The date's own dashes sit inside its first ten characters.
fn has_utc_offset(value: &str) -> bool {
    value
        .get(10..)
        .is_some_and(|time| time.contains(['Z', 'z', '+', '-']))
}

/// `begin`: claims the check when one is due by stamping `last_check_at`,
/// in the same transaction that read the stamp.
fn begin(conn: &Connection, request: &Request, now: i64) -> Result<Value, String> {
    let mut state = load(conn)?;
    if checked_recently(&state, now) {
        return Ok(json!({"due": false}));
    }
    state.insert(
        "last_check_at".to_owned(),
        Value::from(request.now.as_str()),
    );
    save(conn, state, &request.now)?;
    Ok(json!({"due": true}))
}

/// `record_check`: saves the fetched status, or the failed fetch, and says
/// whether the update should be applied now.
fn record_check(conn: &Connection, request: &Request) -> Result<Value, String> {
    let mut state = load(conn)?;
    state.insert(
        "last_check_at".to_owned(),
        Value::from(request.now.as_str()),
    );
    let Some(status) = &request.status else {
        state.insert("last_check_error".to_owned(), Value::Bool(true));
        save(conn, state, &request.now)?;
        return Ok(json!({"apply": false, "latest_version": null}));
    };
    let latest = status.get("latest_version").cloned().unwrap_or(Value::Null);
    let apply = should_apply(status, &state, &latest);
    state.insert("last_status".to_owned(), Value::Object(status.clone()));
    save(conn, state, &request.now)?;
    Ok(json!({"apply": apply, "latest_version": latest}))
}

fn should_apply(status: &Map<String, Value>, state: &Map<String, Value>, latest: &Value) -> bool {
    let automatic = status
        .get("update_mode")
        .is_none_or(|mode| py_equal(mode, &Value::from("automatic")));
    let field = |key: &str| status.get(key).is_some_and(py_truthy);
    let failed = state.get("failed_version").unwrap_or(&Value::Null);
    automatic
        && field("auto_updatable")
        && !field("blocked_reason")
        && field("update_available")
        && !py_equal(failed, latest)
}

/// `record_update`: what one installer run leaves behind. A version whose
/// run failed is not retried until a newer one is published.
fn record_update(conn: &Connection, request: &Request) -> Result<Value, String> {
    let mut state = load(conn)?;
    let latest = request.latest_version.clone();
    match &request.update_payload {
        None => {
            state.insert("last_update_error".to_owned(), Value::Bool(true));
            state.insert("failed_version".to_owned(), latest);
        }
        Some(payload) => {
            state.insert("last_update_result".to_owned(), payload.clone());
            state.insert(
                "last_update_exit_code".to_owned(),
                request.exit_code.clone(),
            );
            state.insert(
                "last_update_at".to_owned(),
                Value::from(request.now.as_str()),
            );
            let failed_status = payload
                .get("status")
                .is_some_and(|status| py_equal(status, &Value::from("failed")));
            if py_equal(&request.exit_code, &Value::from(0)) && !failed_status {
                state.remove("failed_version");
            } else {
                state.insert("failed_version".to_owned(), latest);
            }
        }
    }
    save(conn, state, &request.now)?;
    Ok(Value::Null)
}

/// Python truthiness over decoded JSON.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "auto_update_state_tests.rs"]
mod tests;
