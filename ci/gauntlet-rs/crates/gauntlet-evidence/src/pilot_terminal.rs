//! Data-only parity with the initial terminal branch of Python `run_pilot`.
//! The caller must independently authenticate the process and event stream.

use crate::{EvidenceError, Result};
use serde_json::{json, Map, Value};

const MAX_EVENTS: usize = 50_000;

fn required_object<'a>(value: &'a Value, message: &'static str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or(EvidenceError::Invalid(message))
}

fn required_bool(object: &Map<String, Value>, key: &str) -> Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(EvidenceError::Invalid("invalid pilot terminal boolean"))
}

/// Recompute only Python's first `execution_valid`, `retryable_startup`,
/// `controller_error` and last `episode_end` values. Subsequent model-budget,
/// provider-usage and qualification decisions are outside this reducer.
pub fn reduce_pilot_terminal(input: &Value) -> Result<Value> {
    let object = required_object(input, "pilot terminal input must be an object")?;
    const KEYS: [&str; 6] = [
        "exit_code",
        "controller_error",
        "events",
        "isolated",
        "isolation",
        "active",
    ];
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(EvidenceError::Invalid("invalid pilot terminal fields"));
    }

    let exit_code = object["exit_code"].as_i64().or_else(|| {
        object["exit_code"]
            .as_u64()
            .and_then(|value| i64::try_from(value).ok())
    });
    if !object["exit_code"].is_null() && exit_code.is_none() {
        return Err(EvidenceError::Invalid("invalid pilot exit code"));
    }
    let mut controller_error = object["controller_error"].clone();
    if !controller_error.is_null() && !controller_error.is_string() {
        return Err(EvidenceError::Invalid("invalid pilot controller error"));
    }
    let isolated = required_bool(object, "isolated")?;
    let isolation = &object["isolation"];
    if !isolation.is_null() && !isolation.is_object() {
        return Err(EvidenceError::Invalid("invalid pilot isolation"));
    }
    let active = required_object(&object["active"], "invalid pilot active state")?;
    const ACTIVE_KEYS: [&str; 3] = ["active_sessions", "active_children", "active_workers"];
    if active.len() != ACTIVE_KEYS.len() || ACTIVE_KEYS.iter().any(|key| !active.contains_key(*key))
    {
        return Err(EvidenceError::Invalid("invalid pilot active fields"));
    }
    let active_count = ACTIVE_KEYS.iter().try_fold(0_u64, |sum, key| {
        let count = active[*key]
            .as_u64()
            .ok_or(EvidenceError::Invalid("invalid pilot active count"))?;
        sum.checked_add(count)
            .ok_or(EvidenceError::Invalid("pilot active count overflow"))
    })?;

    let events = object["events"]
        .as_array()
        .ok_or(EvidenceError::Invalid("invalid pilot events"))?;
    if events.len() > MAX_EVENTS {
        return Err(EvidenceError::Invalid("too many pilot events"));
    }
    for event in events {
        if !event.is_object() || !event.get("type").is_some_and(Value::is_string) {
            return Err(EvidenceError::Invalid("invalid pilot event"));
        }
    }
    let event_is = |event: &&Value, kind: &str| event["type"] == kind;
    let mut execution_valid = exit_code == Some(0)
        && controller_error.is_null()
        && events.iter().any(|event| event_is(&event, "episode_start"))
        && events.iter().any(|event| event_is(&event, "episode_end"))
        && !events.iter().any(|event| event_is(&event, "episode_error"));
    if isolated {
        if !execution_valid || isolation.is_null() {
            execution_valid = false;
        } else {
            let record = isolation
                .get("record")
                .ok_or(EvidenceError::Invalid("missing pilot isolation record"))?;
            let record = required_object(record, "invalid pilot isolation record")?;
            execution_valid = required_bool(record, "isolation_observed")?
                && required_bool(record, "assets_unchanged")?
                && required_bool(record, "cleanup_complete")?;
        }
    }
    if active_count != 0 {
        execution_valid = false;
        if controller_error.is_null() || controller_error == "" {
            controller_error = json!("service cleanup incomplete");
        }
    }
    let retryable_startup = !execution_valid
        && controller_error.is_null()
        && !events
            .iter()
            .any(|event| event_is(&event, "inference_start"))
        && events.iter().any(|event| {
            event_is(&event, "episode_error")
                && event.get("phase") == Some(&json!("startup"))
                && event.get("retryableInfrastructure") == Some(&json!(true))
                && matches!(
                    event.get("error").and_then(Value::as_str),
                    Some(
                        "Error: MCP endpoint connection failed"
                            | "Error: declared MCP endpoint did not finish connecting"
                    )
                )
        });
    let episode_end = events
        .iter()
        .rev()
        .find(|event| event_is(event, "episode_end"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(json!({
        "execution_valid": execution_valid,
        "controller_error": controller_error,
        "retryable_startup": retryable_startup,
        "episode_end": episode_end,
    }))
}
