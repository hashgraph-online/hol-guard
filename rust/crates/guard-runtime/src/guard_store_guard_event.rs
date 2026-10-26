//! `GuardStore.add_event` (`store_cloud_events.py`): one `guard_events` row
//! whose `payload_json` is `json.dumps(payload)` — insertion order, CPython's
//! default `, ` / `: ` separators, `ensure_ascii`, and `NaN` / `Infinity` for
//! non-finite floats. The write has no outbox, cloud-queue or wake effect.
//!
//! Payloads are [`PyVal`] dicts so key order survives exactly as Python built
//! it. A payload Python could not encode (an integer past CPython's digit
//! limit) or could not hold (a repeated key) answers `None` without writing,
//! and the daemon records the event.

use guard_contracts::write_json_string;
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{exec, StoreResult};
use crate::pyjson::{float_repr, PyVal};

/// CPython's default `sys.get_int_max_str_digits()`: `json.dumps` raises
/// `ValueError` for an integer with more decimal digits.
const MAX_INT_DIGITS: usize = 4300;
/// Nesting the encoder accepts. Python's limit sits near the interpreter
/// recursion limit; deeper payloads are left to the daemon.
const MAX_DEPTH: usize = 256;
/// `_record_silent_native_review_event`: the payload keys, in order.
const APPROVAL_CREATED_KEYS: [&str; 10] = [
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "policy_action",
    "recommended_scope",
    "source_scope",
    "workspace",
    "publisher",
];

/// `GuardStore.add_event(event_name, payload, now)`. Returns the new
/// `event_id`, or `None` (nothing written) for a payload whose Python
/// encoding cannot be reproduced. The caller owns the transaction.
pub(crate) fn add_guard_event(
    connection: &Connection,
    event_name: &str,
    payload: &[(String, PyVal)],
    now: &str,
) -> StoreResult<Option<i64>> {
    let Some(payload_json) = dumps_dict(payload) else {
        return Ok(None);
    };
    exec(
        connection,
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        &[
            Value::String(event_name.to_owned()),
            Value::String(payload_json),
            Value::String(now.to_owned()),
        ],
    )?;
    Ok(Some(connection.last_insert_rowid()))
}

/// `json.dumps(payload)` for a dict built in insertion order.
fn dumps_dict(payload: &[(String, PyVal)]) -> Option<String> {
    let mut out = Vec::new();
    write_dict(payload, 0, &mut out)?;
    String::from_utf8(out).ok()
}

/// The `approval.created` event `_record_silent_native_review_event` writes
/// for a queued request: the payload in Python's key order and the event
/// time (`created_at` when it is non-empty text, else `now`). `None` when a
/// field holds an object, whose Python key order a `serde_json` map no longer
/// carries.
pub(crate) fn approval_created_event(
    queued: &Map<String, Value>,
    now: &str,
) -> Option<(Vec<(String, PyVal)>, String)> {
    let mut payload = Vec::with_capacity(APPROVAL_CREATED_KEYS.len());
    for key in APPROVAL_CREATED_KEYS {
        let value = queued.get(key).map_or(Some(PyVal::Null), from_json)?;
        payload.push((key.to_owned(), value));
    }
    let timestamp = match queued.get("created_at") {
        Some(Value::String(created_at)) if !created_at.is_empty() => created_at.clone(),
        _ => now.to_owned(),
    };
    Some((payload, timestamp))
}

/// A decoded scalar or list as the Python value `json.loads` produced.
pub(crate) fn from_json(value: &Value) -> Option<PyVal> {
    Some(match value {
        Value::Null => PyVal::Null,
        Value::Bool(flag) => PyVal::Bool(*flag),
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                PyVal::Float(number.as_f64()?)
            } else if text == "-0" {
                PyVal::Int("0".to_owned())
            } else {
                PyVal::Int(text)
            }
        }
        Value::String(text) => PyVal::Str(text.clone()),
        Value::Array(items) => PyVal::List(items.iter().map(from_json).collect::<Option<_>>()?),
        Value::Object(_) => return None,
    })
}

fn write_value(value: &PyVal, depth: usize, out: &mut Vec<u8>) -> Option<()> {
    match value {
        PyVal::Null => out.extend_from_slice(b"null"),
        PyVal::Bool(true) => out.extend_from_slice(b"true"),
        PyVal::Bool(false) => out.extend_from_slice(b"false"),
        PyVal::Int(digits) => write_int(digits, out)?,
        PyVal::Float(number) => out.extend_from_slice(float_text(*number).as_bytes()),
        PyVal::Str(text) => write_json_string(text, out),
        PyVal::List(items) => write_list(items, depth, out)?,
        PyVal::Dict(entries) => write_dict(entries, depth, out)?,
    }
    Some(())
}

fn write_list(items: &[PyVal], depth: usize, out: &mut Vec<u8>) -> Option<()> {
    if depth >= MAX_DEPTH {
        return None;
    }
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_value(item, depth + 1, out)?;
    }
    out.push(b']');
    Some(())
}

fn write_dict(entries: &[(String, PyVal)], depth: usize, out: &mut Vec<u8>) -> Option<()> {
    if depth >= MAX_DEPTH {
        return None;
    }
    out.push(b'{');
    for (index, (key, value)) in entries.iter().enumerate() {
        if entries[..index].iter().any(|(earlier, _)| earlier == key) {
            return None;
        }
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(key, out);
        out.extend_from_slice(b": ");
        write_value(value, depth + 1, out)?;
    }
    out.push(b'}');
    Some(())
}

/// `int.__repr__`, refusing what Python refuses or would spell differently.
fn write_int(digits: &str, out: &mut Vec<u8>) -> Option<()> {
    let magnitude = digits.strip_prefix('-').unwrap_or(digits);
    let canonical = !magnitude.is_empty()
        && magnitude.bytes().all(|byte| byte.is_ascii_digit())
        && (magnitude == "0" || !magnitude.starts_with('0'))
        && digits != "-0";
    if !canonical || magnitude.len() > MAX_INT_DIGITS {
        return None;
    }
    out.extend_from_slice(digits.as_bytes());
    Some(())
}

/// `json`'s `floatstr` with the default `allow_nan=True`.
fn float_text(number: f64) -> String {
    if number.is_nan() {
        "NaN".to_owned()
    } else if number.is_infinite() {
        if number.is_sign_positive() {
            "Infinity"
        } else {
            "-Infinity"
        }
        .to_owned()
    } else {
        float_repr(number)
    }
}
