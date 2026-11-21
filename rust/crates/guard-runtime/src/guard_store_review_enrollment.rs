//! `workspace_review_enrollment_due` and `record_workspace_review_enrollment`:
//! the schedule row for the background Cloud Review workspace enrollment.
//!
//! Port of the binding, cooldown and outcome bookkeeping
//! `runtime/native_workspace_review_enrollment.py` kept in Python. Python
//! still fetches the root-signed authority and hands it to the native
//! installer; the store decides whether a check is due and records what the
//! check found.

use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_json::{add_micros_aware_isoformat, aware_epoch_micros};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `_STATE_KEY`.
const STATE_KEY: &str = "guard_cloud_review_workspace_enrollment";
/// `_CHECK_INTERVAL`: five minutes.
const CHECK_INTERVAL_MICROS: i64 = 5 * 60 * 1_000_000;
/// The connection fields a binding is made of, in order.
const BINDING_FIELDS: [&str; 3] = ["workspace_id", "machine_installation_id", "sync_url"];
const SUBJECT_FIELD: &str = "oauth_subject_hash";
/// Failure codes recorded as they are; any other failure records its type name.
const ERROR_CODE_PREFIX: &str = "native_workspace_review_";

fn non_empty(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

/// `_binding`: the connection the enrollment belongs to, or `None` when a
/// field is missing, empty or not text. The OAuth subject is optional.
fn binding(auth: &Map<String, Value>) -> Option<Vec<String>> {
    let mut binding = BINDING_FIELDS
        .iter()
        .map(|field| auth.get(*field).and_then(non_empty).map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    match auth.get(SUBJECT_FIELD) {
        None | Some(Value::Null) => {}
        Some(subject) => binding.push(non_empty(subject)?.to_owned()),
    }
    Some(binding)
}

/// `_due`: a check is due when the row is for another binding, its schedule
/// is unreadable or naive, the schedule is further out than one interval (a
/// clock moved back), or the scheduled time has come.
fn due(state: Option<&Value>, binding: &[String], now: i128) -> bool {
    let Some(Value::Object(state)) = state else {
        return true;
    };
    let same_binding = state
        .get("binding")
        .and_then(Value::as_array)
        .is_some_and(|stored| {
            stored.len() == binding.len()
                && stored
                    .iter()
                    .zip(binding)
                    .all(|(stored, field)| stored.as_str() == Some(field.as_str()))
        });
    if !same_binding {
        return true;
    }
    let Some(scheduled) = state
        .get("next_check_at")
        .and_then(Value::as_str)
        .and_then(aware_epoch_micros)
    else {
        return true;
    };
    scheduled - now > i128::from(CHECK_INTERVAL_MICROS) || scheduled <= now
}

fn aware_now<'a>(args: &Args<'a>) -> StoreResult<(&'a str, i128)> {
    let now = args.str("now")?;
    aware_epoch_micros(now).map_or_else(|| value_error("invalid_now"), |micros| Ok((now, micros)))
}

/// `workspace_review_enrollment_due`: the binding for `auth` and whether a
/// check is due for it. Without a complete binding nothing is due.
pub(crate) fn due_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let auth = args.object("auth")?;
    let (_, now) = aware_now(args)?;
    let Some(binding) = binding(auth) else {
        return Ok(json!({"binding": null, "due": false}));
    };
    let state = read_payload(connection, STATE_KEY)?;
    let due = due(state.as_ref(), &binding, now);
    Ok(json!({"binding": binding, "due": due}))
}

fn stored_binding<'a>(args: &Args<'a>) -> StoreResult<Vec<&'a str>> {
    let Some(binding) = args.strings("binding")? else {
        return value_error("invalid_binding");
    };
    let complete = matches!(binding.len(), 3 | 4) && binding.iter().all(|field| !field.is_empty());
    if complete {
        Ok(binding)
    } else {
        value_error("invalid_binding")
    }
}

/// The code a failed check records: a `native_workspace_review_*` code the
/// failure carried, else the failure's type name.
fn failure_code<'a>(args: &Args<'a>) -> StoreResult<&'a str> {
    let error_type = args.str("error_type")?;
    if error_type.is_empty() {
        return value_error("invalid_outcome");
    }
    let code = args.opt_str("error_code")?;
    Ok(code
        .filter(|code| code.starts_with(ERROR_CODE_PREFIX))
        .unwrap_or(error_type))
}

/// The outcome fields of one check.
fn outcome(args: &Args<'_>) -> StoreResult<Vec<(&'static str, Value)>> {
    match args.str("outcome")? {
        "enrolled" => {
            let record = args.str("record")?;
            let digest = hex::encode(Sha256::digest(record.as_bytes()));
            Ok(vec![
                ("record_digest", json!(digest)),
                ("status", json!("enrolled")),
            ])
        }
        "unavailable" => {
            let detail = match args.raw("http_status") {
                Some(status) => match status.as_i64() {
                    Some(status) => ("http_status", json!(status)),
                    None => return value_error("invalid_outcome"),
                },
                None => ("error_code", json!(failure_code(args)?)),
            };
            Ok(vec![("status", json!("unavailable")), detail])
        }
        _ => value_error("invalid_outcome"),
    }
}

/// `record_workspace_review_enrollment`: store what one check found and
/// schedule the next one interval after `now`.
pub(crate) fn record_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let binding = stored_binding(args)?;
    let (now, _) = aware_now(args)?;
    let next_check_at = add_micros_aware_isoformat(now, CHECK_INTERVAL_MICROS)
        .map_or_else(|| value_error("invalid_now"), Ok)?;
    let mut state = Map::new();
    state.insert("binding".to_owned(), json!(binding));
    state.insert("next_check_at".to_owned(), json!(next_check_at));
    for (key, value) in outcome(args)? {
        state.insert(key.to_owned(), value);
    }
    let state = Value::Object(state);
    let encoded =
        serde_json::to_string(&state).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, STATE_KEY, &encoded, now)?;
    Ok(json!({"state": state}))
}

#[cfg(test)]
#[path = "guard_store_review_enrollment_tests.rs"]
mod tests;
