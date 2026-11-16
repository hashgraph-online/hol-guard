//! `runner_authority` kind `cloud_review_batch`: sizes the Review event
//! batches Cloud Review sync uploads and settles Cloud's answer to each one
//! (`cloud_review_batching` and the per-event loop of
//! `cloud_review_sync.sync_cloud_review_events_once` before they moved here).
//!
//! Operations, chosen by `op`:
//!
//! - `select`: `{events, limit_events, limit_bytes}` answers `{"count": n}`,
//!   the longest ordered prefix of at most `limit_events` events whose request
//!   body fits `limit_bytes`, or `{"too_large": true}` when not even the first
//!   event fits. An event without a valid source sequence answers
//!   `{"error": ...}`, the protocol message Python raises.
//! - `limits`: `{state, binding_key}` answers the batch limits the sync state
//!   saved for that binding, clamped to the client maxima.
//! - `next`: `{limits, response}` answers the limits for the next batch: twice
//!   the events after a success, within what Cloud advertised.
//! - `settle`: `{response, sequences, snapshot_keys}` answers the counts Cloud
//!   reported and what to do with the batch (`plan`): settle each event
//!   (`per_event`, with the sequences to acknowledge, those to retry and the
//!   snapshot repairs), retry everything (`count_mismatch` or `rejected`), or
//!   acknowledge everything (`acknowledge`).
//!
//! Limits travel as `{"events", "bytes", "event_cap"}`. Comparisons follow
//! the Python they replace, so a count of `1.0` or `true` still counts as 1.

use guard_contracts::write_canonical_json;
use serde_json::{json, Map, Value};

use crate::cloud_review_ack::{int_value, py_equals_int, strict_int};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const DEFAULT_BATCH_EVENTS: i128 = 50;
const MAX_BATCH_EVENTS: i128 = 250;
const MAX_BATCH_BYTES: i128 = 512 * 1024;
const PROTOCOL_VERSION: i128 = 2;
const SNAPSHOT_REQUIRED: &str = "review_event_snapshot_required";
const SUPERSEDED_ERRORS: [&str; 3] = [
    "decision_queued",
    "stale_regression_rejected",
    "stale_sequence",
];
const STALE_SEQUENCE_PREFIX: &str = "stale event sequence ";
const ERR_SEQUENCE: &str =
    "A Review event has no valid source sequence. Repair local Review data before retrying sync.";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("select") => select(fields),
        Some("limits") => persisted(fields),
        Some("next") => next(fields),
        Some("settle") => settle(fields),
        _ => Err(ERR_INVALID),
    }
}

fn exact<'a>(
    fields: &'a Map<String, Value>,
    keys: &[&str],
) -> Result<Vec<&'a Value>, &'static str> {
    if fields.len() != keys.len() + 1 {
        return Err(ERR_INVALID);
    }
    keys.iter()
        .map(|key| fields.get(*key).ok_or(ERR_INVALID))
        .collect()
}

/// `select_review_event_batch` over the body `post_review_events` sends.
fn select(fields: &Map<String, Value>) -> KindResult {
    let values = exact(fields, &["events", "limit_events", "limit_bytes"])?;
    let events = values[0].as_array().ok_or(ERR_INVALID)?;
    let limit_events = strict_int(values[1]).ok_or(ERR_INVALID)?;
    let limit_bytes = strict_int(values[2]).ok_or(ERR_INVALID)?;
    let considered = usize::try_from(limit_events.max(0))
        .unwrap_or(usize::MAX)
        .min(events.len());
    let mut first_sequence = None;
    let mut events_bytes = 0_i128;
    let mut count = 0_usize;
    for event in &events[..considered] {
        if !event.is_object() {
            return Err(ERR_INVALID);
        }
        let sequence = event.get("localStreamSequence").unwrap_or(&Value::Null);
        if strict_int(sequence).is_none_or(|value| value <= 0) {
            return Ok(json!({ "error": ERR_SEQUENCE }));
        }
        let first = *first_sequence.get_or_insert(encoded_len(sequence)?);
        let event_bytes = encoded_len(event)? + i128::from(count > 0);
        if body_len(first, encoded_len(sequence)?, events_bytes + event_bytes) > limit_bytes {
            break;
        }
        events_bytes += event_bytes;
        count += 1;
    }
    Ok(if count == 0 && !events.is_empty() {
        json!({ "too_large": true })
    } else {
        json!({ "count": count })
    })
}

/// Length of `json.dumps({"protocolVersion": 2, "firstSequence": ..,
/// "lastSequence": .., "events": [..]}, separators=(",", ":"))`. Key order
/// does not change a compact body's length, so the sorted encoding measures it.
fn body_len(first: i128, last: i128, events: i128) -> i128 {
    let fixed = r#"{"protocolVersion":,"firstSequence":,"lastSequence":,"events":[]}"#;
    fixed.len() as i128 + PROTOCOL_VERSION.to_string().len() as i128 + first + last + events
}

fn encoded_len(value: &Value) -> Result<i128, &'static str> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out).map_err(|_| ERR_INVALID)?;
    Ok(out.len() as i128)
}

/// `type(value) is int and value > 0`, else `fallback`.
fn positive_int(value: Option<&Value>, fallback: i128) -> i128 {
    value
        .and_then(strict_int)
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn limits_value(events: i128, bytes: i128, event_cap: i128) -> Value {
    json!({
        "events": int_value(events),
        "bytes": int_value(bytes),
        "event_cap": int_value(event_cap),
    })
}

/// `persisted_review_batch_limits`.
fn persisted(fields: &Map<String, Value>) -> KindResult {
    let values = exact(fields, &["state", "binding_key"])?;
    let state = values[0].as_object().ok_or(ERR_INVALID)?;
    let binding_key = values[1].as_str().ok_or(ERR_INVALID)?;
    if state.get("batch_binding_key").and_then(Value::as_str) != Some(binding_key) {
        return Ok(limits_value(
            DEFAULT_BATCH_EVENTS,
            MAX_BATCH_BYTES,
            MAX_BATCH_EVENTS,
        ));
    }
    let event_cap =
        positive_int(state.get("batch_event_cap"), MAX_BATCH_EVENTS).min(MAX_BATCH_EVENTS);
    let bytes = positive_int(state.get("batch_max_bytes"), MAX_BATCH_BYTES).min(MAX_BATCH_BYTES);
    let events = positive_int(state.get("batch_events"), DEFAULT_BATCH_EVENTS).min(event_cap);
    Ok(limits_value(events, bytes, event_cap))
}

/// `next_review_batch_limits`.
fn next(fields: &Map<String, Value>) -> KindResult {
    let values = exact(fields, &["limits", "response"])?;
    let limits = values[0].as_object().ok_or(ERR_INVALID)?;
    let response = values[1].as_object().ok_or(ERR_INVALID)?;
    let current = |key: &str| limits.get(key).and_then(strict_int).ok_or(ERR_INVALID);
    let (events, bytes, event_cap) = (current("events")?, current("bytes")?, current("event_cap")?);
    let event_cap = positive_int(response.get("maxBatchEvents"), event_cap).min(MAX_BATCH_EVENTS);
    let bytes = positive_int(response.get("maxBatchBytes"), bytes).min(MAX_BATCH_BYTES);
    let events = events
        .saturating_mul(2)
        .max(DEFAULT_BATCH_EVENTS)
        .min(event_cap);
    Ok(limits_value(events, bytes, event_cap))
}

/// `int(value) if isinstance(value, (int, float)) else 0`.
fn py_count(value: Option<&Value>) -> i128 {
    match value {
        Some(Value::Bool(flag)) => i128::from(*flag),
        Some(number @ Value::Number(_)) => strict_int(number).unwrap_or_else(|| {
            // Saturating, like the integer path; Python's int() of a float
            // truncates toward zero.
            number.as_f64().map_or(0, |float| float.trunc() as i128)
        }),
        _ => 0,
    }
}

/// `_is_terminally_superseded_result`: refreshes superseded by an
/// authoritative Cloud decision, whose acknowledgement travels separately.
fn superseded(item: &Map<String, Value>) -> bool {
    if item.get("code").and_then(Value::as_str) == Some("stale_sequence") {
        return true;
    }
    item.get("error")
        .and_then(Value::as_str)
        .is_some_and(|error| {
            SUPERSEDED_ERRORS.contains(&error) || error.starts_with(STALE_SEQUENCE_PREFIX)
        })
}

#[derive(Default)]
struct PerEvent {
    acknowledged: Vec<Value>,
    retry: Vec<Value>,
    retry_results: Vec<Value>,
    snapshot_repairs: Map<String, Value>,
    accepted: i128,
}

/// The per-event loop: `None` when a result is malformed.
fn per_event(results: &[Value], sequences: &[Value], snapshot_keys: &[Value]) -> Option<PerEvent> {
    let mut settled = PerEvent::default();
    let mut repairs: Vec<(String, i128)> = Vec::new();
    for (index, item) in results.iter().enumerate() {
        let entry = item.as_object()?;
        let accepted = entry.get("accepted").and_then(Value::as_bool)?;
        if !py_equals_int(entry.get("index").unwrap_or(&Value::Null), index as i128) {
            return None;
        }
        settled.accepted += i128::from(accepted);
        if accepted || superseded(entry) {
            settled.acknowledged.push(sequences[index].clone());
            continue;
        }
        settled.retry.push(sequences[index].clone());
        settled.retry_results.push(item.clone());
        if entry.get("code").and_then(Value::as_str) != Some(SNAPSHOT_REQUIRED) {
            continue;
        }
        let key = snapshot_keys[index].as_array();
        let request_id = key.and_then(|key| key.first()).and_then(Value::as_str);
        let request_sequence = key.and_then(|key| key.get(1)).and_then(strict_int);
        if let (Some(request_id), Some(request_sequence)) = (request_id, request_sequence) {
            match repairs.iter_mut().find(|(known, _)| known == request_id) {
                Some((_, sequence)) => *sequence = (*sequence).max(request_sequence),
                None => repairs.push((request_id.to_owned(), request_sequence.max(0))),
            }
        }
    }
    for (request_id, sequence) in repairs {
        settled
            .snapshot_repairs
            .insert(request_id, int_value(sequence));
    }
    Some(settled)
}

fn settle(fields: &Map<String, Value>) -> KindResult {
    let values = exact(fields, &["response", "sequences", "snapshot_keys"])?;
    let response = values[0].as_object().ok_or(ERR_INVALID)?;
    let sequences = values[1].as_array().ok_or(ERR_INVALID)?;
    let snapshot_keys = values[2].as_array().ok_or(ERR_INVALID)?;
    if snapshot_keys.len() != sequences.len() {
        return Err(ERR_INVALID);
    }
    let size = sequences.len() as i128;
    let accepted = py_count(response.get("accepted"));
    let rejected = py_count(response.get("rejected"));
    let delivered = response
        .get("delivered")
        .and_then(strict_int)
        .filter(|delivered| (0..=accepted).contains(delivered))
        .unwrap_or(0);
    let retry_after_ms = positive_int(response.get("retryAfterMs"), 0);
    let mut answer = Map::new();
    answer.insert("accepted".to_owned(), int_value(accepted));
    answer.insert("rejected".to_owned(), int_value(rejected));
    answer.insert("delivered".to_owned(), int_value(delivered));
    answer.insert("retry_after_ms".to_owned(), int_value(retry_after_ms));
    let settled = match response.get("perEventResults") {
        Some(Value::Array(results)) if results.len() == sequences.len() => {
            per_event(results, sequences, snapshot_keys).filter(|settled| {
                settled.accepted == accepted && size.saturating_sub(accepted) == rejected
            })
        }
        _ => None,
    };
    let plan = if let Some(settled) = settled {
        answer.insert(
            "acknowledged".to_owned(),
            Value::Array(settled.acknowledged),
        );
        answer.insert("retry".to_owned(), Value::Array(settled.retry));
        answer.insert(
            "retry_results".to_owned(),
            Value::Array(settled.retry_results),
        );
        answer.insert(
            "snapshot_repairs".to_owned(),
            Value::Object(settled.snapshot_repairs),
        );
        "per_event"
    } else if accepted.saturating_add(rejected) != size {
        "count_mismatch"
    } else if rejected != 0 {
        "rejected"
    } else {
        "acknowledge"
    };
    answer.insert("plan".to_owned(), json!(plan));
    Ok(Value::Object(answer))
}

#[cfg(test)]
#[path = "cloud_review_batch_tests.rs"]
mod tests;
