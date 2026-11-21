//! `runner_authority` kind `cloud_review_ack`: checks Guard Cloud's
//! acknowledgement of one Review event batch and normalizes it
//! (`cloud_review_event_delivery._normalize_response` before it moved here).
//!
//! The request carries the decoded Cloud response, the batch's event ids and
//! their local stream sequences, in order. The answer is either
//! `{"response": ...}`, the normalized acknowledgement, or `{"error": ...}`,
//! the protocol message Python raises as `CloudReviewEventProtocolError`.
//!
//! Comparisons follow the Python they replace: the version and the counts
//! compare equal the way Python's `==` does (`1.0` and `true` equal `1`),
//! while sequences, retry hints and batch limits must be integers.

use serde_json::{json, Map, Number, Value};

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const PROTOCOL_VERSION: i128 = 2;
const MAX_RETRY_AFTER_MS: i128 = 3_600_000;
const MAX_SAFE_INTEGER: i128 = (1 << 53) - 1;
const SUCCESS: [&str; 3] = ["accepted", "duplicate", "stale"];
const KNOWN: [&str; 5] = ["accepted", "duplicate", "stale", "quarantined", "rejected"];
/// Rejections that name their event so the store can rebase it: a snapshot
/// that collided, or any event whose sequence Cloud already holds.
pub(crate) const SEQUENCE_COLLISIONS: [&str; 2] = [
    "review_event_snapshot_sequence_collision",
    "review_event_sequence_conflict",
];

const ERR_ACK: &str =
    "Guard Cloud Review returned an invalid protocol 2 acknowledgement. Update HOL Guard before retrying.";
const ERR_EVENT: &str =
    "Guard Cloud Review returned an acknowledgement for a different event. Retry after updating HOL Guard.";
const ERR_STATUS: &str =
    "Guard Cloud Review returned an unsupported event status. Update HOL Guard before retrying.";
const ERR_STOPPED: &str = "Guard Cloud Review acknowledgement stopped before an accepted event. \
     Retry sync after updating HOL Guard.";
const ERR_COUNTS: &str =
    "Guard Cloud Review acknowledgement counts are inconsistent. Retry after updating HOL Guard.";
const ERR_LIMIT: &str =
    "Guard Cloud Review returned an invalid batch limit. Update HOL Guard before retrying.";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != 3 {
        return Err(ERR_INVALID);
    }
    let response = fields
        .get("response")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let event_ids = fields
        .get("event_ids")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let sequences = fields
        .get("sequences")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|value| strict_int(value).filter(|sequence| *sequence > 0))
        .collect::<Option<Vec<_>>>()
        .ok_or(ERR_INVALID)?;
    if sequences.len() != event_ids.len() {
        return Err(ERR_INVALID);
    }
    Ok(match normalize(response, event_ids, &sequences) {
        Ok(normalized) => json!({ "response": normalized }),
        Err(message) => json!({ "error": message }),
    })
}

fn normalize(
    response: &Map<String, Value>,
    event_ids: &[Value],
    sequences: &[i128],
) -> Result<Value, String> {
    let version = response.get("protocolVersion").unwrap_or(&Value::Null);
    if !py_equals_int(version, PROTOCOL_VERSION) {
        let rendered = match version {
            Value::Null => "missing".to_owned(),
            other => py_str(other),
        };
        return Err(format!(
            "Guard Cloud Review returned unsupported protocol version {rendered}. \
             Update HOL Guard and reconnect Guard Cloud before retrying."
        ));
    }
    let results = match response.get("results") {
        Some(Value::Array(results)) if results.len() == event_ids.len() => results,
        _ => return Err(ERR_ACK.to_owned()),
    };
    let acknowledged_through = response
        .get("acknowledgedThrough")
        .and_then(strict_int)
        .filter(|value| (0..=MAX_SAFE_INTEGER).contains(value))
        .ok_or_else(|| ERR_ACK.to_owned())?;
    let mut retry_after_ms = response
        .get("retryAfterMs")
        .and_then(retry_after)
        .unwrap_or(0);
    let mut normalized = Vec::with_capacity(results.len());
    let (mut accepted_count, mut delivered) = (0_usize, 0_usize);
    for (index, item) in results.iter().enumerate() {
        let expected_event_id = &event_ids[index];
        let item = match item.as_object() {
            Some(item) if item.get("eventId").unwrap_or(&Value::Null) == expected_event_id => item,
            _ => return Err(ERR_EVENT.to_owned()),
        };
        let status = match item.get("status").and_then(Value::as_str) {
            Some(status) if KNOWN.contains(&status) => status,
            _ => return Err(ERR_STATUS.to_owned()),
        };
        let accepted = SUCCESS.contains(&status);
        if accepted && sequences[index] > acknowledged_through {
            return Err(ERR_STOPPED.to_owned());
        }
        let code = item.get("code").cloned().unwrap_or(Value::Null);
        let error = if accepted {
            Value::Null
        } else if py_truthy(&code) {
            code.clone()
        } else {
            Value::String(status.to_owned())
        };
        let mut entry = Map::new();
        entry.insert("index".to_owned(), json!(index));
        entry.insert("accepted".to_owned(), json!(accepted));
        entry.insert("code".to_owned(), code.clone());
        entry.insert("error".to_owned(), error);
        if !accepted {
            entry.insert("status".to_owned(), json!(status));
            if let Some(item_retry) = item.get("retryAfterMs").and_then(retry_after) {
                entry.insert("retryAfterMs".to_owned(), int_value(item_retry));
                retry_after_ms = retry_after_ms.max(item_retry);
            }
        }
        if matches!(status, "accepted" | "duplicate")
            && item.get("nativeContextCommitted") == Some(&Value::Bool(true))
        {
            entry.insert("nativeContextCommitted".to_owned(), json!(true));
        }
        if status == "rejected"
            && code
                .as_str()
                .is_some_and(|code| SEQUENCE_COLLISIONS.contains(&code))
        {
            entry.insert("eventId".to_owned(), expected_event_id.clone());
        }
        accepted_count += usize::from(accepted);
        delivered += usize::from(status == "accepted");
        normalized.push(Value::Object(entry));
    }
    let rejected = event_ids.len() - accepted_count;
    let counted = |key: &str, count: usize| {
        response
            .get(key)
            .is_some_and(|value| py_equals_int(value, count as i128))
    };
    if !counted("accepted", accepted_count) || !counted("rejected", rejected) {
        return Err(ERR_COUNTS.to_owned());
    }
    let mut answer = Map::new();
    answer.insert("accepted".to_owned(), json!(accepted_count));
    answer.insert("delivered".to_owned(), json!(delivered));
    answer.insert("rejected".to_owned(), json!(rejected));
    answer.insert("perEventResults".to_owned(), Value::Array(normalized));
    answer.insert(
        "acknowledgedThrough".to_owned(),
        int_value(acknowledged_through),
    );
    answer.insert("protocolVersion".to_owned(), json!(PROTOCOL_VERSION as i64));
    if retry_after_ms > 0 {
        answer.insert("retryAfterMs".to_owned(), int_value(retry_after_ms));
    }
    for field in ["maxBatchEvents", "maxBatchBytes"] {
        match response.get(field) {
            None | Some(Value::Null) => {}
            Some(value) if strict_int(value).is_some_and(|limit| limit > 0) => {
                answer.insert(field.to_owned(), value.clone());
            }
            Some(_) => return Err(ERR_LIMIT.to_owned()),
        }
    }
    Ok(Value::Object(answer))
}

/// A JSON integer, as Python's `type(value) is int` sees it: digits only, no
/// fraction or exponent, and never a boolean. Integers past `i128` saturate.
pub(crate) fn strict_int(value: &Value) -> Option<i128> {
    let Value::Number(number) = value else {
        return None;
    };
    let text = number.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(text.parse::<i128>().unwrap_or(if text.starts_with('-') {
        i128::MIN
    } else {
        i128::MAX
    }))
}

/// A positive server retry hint in milliseconds, capped at an hour.
fn retry_after(value: &Value) -> Option<i128> {
    strict_int(value)
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_RETRY_AFTER_MS))
}

pub(crate) fn int_value(value: i128) -> Value {
    Value::Number(Number::from(value as i64))
}

/// Python's `value == expected` for an int `expected`: booleans count as 0
/// and 1, and a float compares by value.
pub(crate) fn py_equals_int(value: &Value, expected: i128) -> bool {
    match value {
        Value::Bool(flag) => i128::from(*flag) == expected,
        Value::Number(number) => match strict_int(value) {
            Some(integer) => integer == expected,
            None => number.as_f64() == Some(expected as f64),
        },
        _ => false,
    }
}

/// Python's `str()` of a decoded JSON value.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

/// Python's `repr()` of a decoded JSON value, for refusal messages.
pub(crate) fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => py_repr_str(text),
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(entries) => {
            let entries: Vec<String> = entries
                .iter()
                .map(|(key, item)| format!("{}: {}", py_repr_str(key), py_repr(item)))
                .collect();
            format!("{{{}}}", entries.join(", "))
        }
    }
}

fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if character == quote => {
                out.push('\\');
                out.push(quote);
            }
            _ if (character as u32) < 0x20 || character as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", character as u32));
            }
            _ => out.push(character),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
#[path = "cloud_review_ack_tests.rs"]
mod tests;
