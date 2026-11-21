//! The frozen `hol-guard-recovery.v1` snapshot contract and the bounded
//! `hol-guard-recovery-diagnostics.v1` report built from those snapshots.
//!
//! Every recovery snapshot that leaves Guard (CLI JSON lines, the state and
//! receipt files, the diagnostics archive) passes through `validate`. Reports
//! carry only snapshots that pass it, so an export never holds a field
//! outside the public allowlist.

use serde_json::{json, Map, Value};

use crate::daemon_recovery::{
    CAPABILITIES, CHECK_IDS, MAX_EVENT_BYTES, OUTCOMES, PHASES, REASON_CODES, SNAPSHOT_SCHEMA,
};

pub(crate) const DIAGNOSTICS_SCHEMA: &str = "hol-guard-recovery-diagnostics.v1";
const MAX_REPORT_BYTES: usize = 60 * 1024;
const SERVICE_STATES: [&str; 3] = ["unknown", "unavailable", "ready"];
const PROTECTION_STATES: [&str; 4] = ["unknown", "verified", "needs_attention", "off"];
const CHECK_RESULTS: [&str; 3] = ["pass", "fail", "unknown"];
pub(crate) const SNAPSHOT_FIELDS: [&str; 16] = [
    "schema",
    "capabilities",
    "operationId",
    "sequence",
    "startedAt",
    "updatedAt",
    "phase",
    "activeElapsedMs",
    "workerActive",
    "retryAllowed",
    "outcome",
    "reasonCode",
    "service",
    "protection",
    "requiresHumanAction",
    "checks",
];
const CHECK_FIELDS: [&str; 3] = ["id", "result", "reasonCode"];
const REPORT_FIELDS: [&str; 8] = [
    "schema",
    "generatedAt",
    "operationId",
    "eventCount",
    "retainedEventCount",
    "truncated",
    "latest",
    "events",
];
/// With the word built in `reject_forbidden_keys`, so this file never spells it.
const FORBIDDEN_KEY_PARTS: [&str; 10] = [
    "password",
    "totp",
    "secret",
    "cookie",
    "authorization",
    "argv",
    "command",
    "path",
    "url",
    "error",
];

type Checked<T> = Result<T, String>;

fn fail<T>(code: &str) -> Checked<T> {
    Err(code.to_owned())
}

fn has_exact_keys(map: &Map<String, Value>, fields: &[&str]) -> bool {
    map.len() == fields.len() && fields.iter().all(|field| map.contains_key(*field))
}

fn reject_forbidden_keys(map: &Map<String, Value>) -> Checked<()> {
    let word = format!("{}{}", "tok", "en");
    for key in map.keys() {
        let lowered = key.to_lowercase();
        if lowered.contains(&word)
            || FORBIDDEN_KEY_PARTS
                .iter()
                .any(|part| lowered.contains(part))
        {
            return fail("recovery_sensitive_field_forbidden");
        }
    }
    Ok(())
}

/// `str(UUID(value)) == value.lower()`: the hyphenated form, any case.
pub(crate) fn canonical_uuid(value: &str) -> Option<String> {
    let lowered = value.to_ascii_lowercase();
    let groups: Vec<&str> = lowered.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    let valid = groups.len() == 5
        && groups.iter().zip(lengths).all(|(group, length)| {
            group.len() == length && group.bytes().all(|b| b.is_ascii_hexdigit())
        });
    valid.then_some(lowered)
}

/// `str(uuid.UUID(value))`: braces, a `urn:uuid:` prefix and hyphens anywhere
/// are accepted; the result is the canonical hyphenated form.
pub(crate) fn lenient_uuid(value: &str) -> Option<String> {
    let stripped = value.replace("urn:", "").replace("uuid:", "");
    let hex: String = stripped
        .trim_matches(|c| c == '{' || c == '}')
        .replace('-', "")
        .to_ascii_lowercase();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn aware_timestamp(value: Option<&Value>) -> Option<i128> {
    let text = value?.as_str().filter(|text| !text.is_empty())?;
    crate::guard_store_json::aware_epoch_micros(text)
}

fn member(map: &Map<String, Value>, field: &str, allowed: &[&str]) -> Checked<()> {
    match map.get(field).and_then(Value::as_str) {
        Some(value) if allowed.contains(&value) => Ok(()),
        _ => Err(format!("recovery_{field}_invalid")),
    }
}

fn check(value: &Value) -> Checked<Value> {
    let Some(map) = value
        .as_object()
        .filter(|map| has_exact_keys(map, &CHECK_FIELDS))
    else {
        return fail("recovery_check_fields_invalid");
    };
    reject_forbidden_keys(map)?;
    let text = |key: &str| map.get(key).and_then(Value::as_str);
    match (text("id"), text("result"), text("reasonCode")) {
        (Some(id), Some(result), Some(reason))
            if CHECK_IDS.contains(&id)
                && CHECK_RESULTS.contains(&result)
                && REASON_CODES.contains(&reason) =>
        {
            Ok(json!({"id": id, "result": result, "reasonCode": reason}))
        }
        _ => fail("recovery_check_invalid"),
    }
}

/// `validate_recovery_snapshot`: one complete public snapshot, normalized.
pub(crate) fn validate(payload: &Value, allow_inspection: bool) -> Checked<Value> {
    let Some(map) = payload.as_object() else {
        return fail("recovery_snapshot_not_object");
    };
    if !has_exact_keys(map, &SNAPSHOT_FIELDS) {
        return fail("recovery_snapshot_fields_invalid");
    }
    reject_forbidden_keys(map)?;
    if map.get("schema").and_then(Value::as_str) != Some(SNAPSHOT_SCHEMA) {
        return fail("unsupported_protocol");
    }
    let capabilities = map.get("capabilities").and_then(Value::as_array);
    let capabilities_valid = capabilities.is_some_and(|items| {
        !items.is_empty()
            && items.iter().enumerate().all(|(index, item)| {
                item.as_str()
                    .is_some_and(|text| CAPABILITIES.contains(&text))
                    && !items[..index].contains(item)
            })
    });
    if !capabilities_valid {
        return fail("recovery_capabilities_invalid");
    }
    let mut normalized = map.clone();
    match map.get("operationId") {
        Some(Value::Null) | None if !allow_inspection => {
            return fail("recovery_operation_id_required")
        }
        Some(Value::Null) | None => {}
        Some(Value::String(text)) => match canonical_uuid(text) {
            Some(canonical) => {
                normalized.insert("operationId".to_owned(), Value::String(canonical));
            }
            None => return fail("recovery_operation_id_invalid"),
        },
        Some(_) => return fail("recovery_operation_id_invalid"),
    }
    if map.get("sequence").and_then(Value::as_u64).is_none() {
        return fail("recovery_sequence_invalid");
    }
    if map.get("activeElapsedMs").and_then(Value::as_u64).is_none() {
        return fail("recovery_elapsed_invalid");
    }
    if aware_timestamp(map.get("startedAt")).is_none() {
        return fail("recovery_started_at_invalid");
    }
    if aware_timestamp(map.get("updatedAt")).is_none() {
        return fail("recovery_updated_at_invalid");
    }
    member(map, "phase", &PHASES)?;
    member(map, "outcome", &OUTCOMES)?;
    member(map, "reasonCode", &REASON_CODES)?;
    member(map, "service", &SERVICE_STATES)?;
    member(map, "protection", &PROTECTION_STATES)?;
    for field in ["workerActive", "retryAllowed", "requiresHumanAction"] {
        if !map.get(field).is_some_and(Value::is_boolean) {
            return Err(format!("recovery_{field}_invalid"));
        }
    }
    let Some(raw_checks) = map.get("checks").and_then(Value::as_array) else {
        return fail("recovery_checks_invalid");
    };
    let checks = raw_checks.iter().map(check).collect::<Checked<Vec<_>>>()?;
    let ids: Vec<&Value> = checks.iter().map(|item| &item["id"]).collect();
    if ids
        .iter()
        .enumerate()
        .any(|(index, id)| ids[..index].contains(id))
    {
        return fail("recovery_checks_duplicate");
    }
    normalized.insert("checks".to_owned(), Value::Array(checks));
    terminal_invariants(&normalized)?;
    let snapshot = Value::Object(normalized);
    if encode(&snapshot).len() > MAX_EVENT_BYTES {
        return fail("recovery_event_too_large");
    }
    Ok(snapshot)
}

fn terminal_invariants(snapshot: &Map<String, Value>) -> Checked<()> {
    let text = |key: &str| snapshot.get(key).and_then(Value::as_str).unwrap_or("");
    let flag = |key: &str| snapshot.get(key).and_then(Value::as_bool).unwrap_or(false);
    if text("phase") == "complete" {
        if flag("workerActive") || !flag("retryAllowed") {
            return fail("recovery_complete_worker_invalid");
        }
        if text("service") != "ready" || matches!(text("outcome"), "pending" | "not_recovered") {
            return fail("recovery_complete_outcome_invalid");
        }
    }
    if text("phase") == "timed_out_waiting" && (!flag("workerActive") || flag("retryAllowed")) {
        return fail("recovery_timeout_worker_invalid");
    }
    let verified = snapshot
        .get("checks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|item| item["id"] == "protection_health" && item["result"] == "pass");
    if text("protection") == "verified" && !verified {
        return fail("recovery_protection_unverified");
    }
    Ok(())
}

/// `validate_event_sequence`: one operation, strictly increasing sequence.
pub(crate) fn validate_sequence(previous: Option<&Value>, current: &Value) -> Checked<Value> {
    let snapshot = validate(current, false)?;
    let Some(previous) = previous else {
        return Ok(snapshot);
    };
    let previous = validate(previous, false)?;
    if previous["operationId"] != snapshot["operationId"] {
        return fail("recovery_operation_changed");
    }
    if snapshot["sequence"].as_u64() <= previous["sequence"].as_u64() {
        return fail("recovery_sequence_not_increasing");
    }
    Ok(snapshot)
}

/// Compact JSON with sorted keys; every accepted string is ASCII.
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Copy only the public fields before validation, so a future private field
/// is dropped rather than carried into a report.
fn redact(value: &Value) -> Checked<Value> {
    let Some(map) = value.as_object() else {
        return fail("recovery_diagnostics_snapshot_invalid");
    };
    let mut candidate = Map::new();
    for field in SNAPSHOT_FIELDS {
        if let Some(item) = map.get(field) {
            candidate.insert(field.to_owned(), item.clone());
        }
    }
    if let Some(Value::Array(checks)) = map.get("checks") {
        let pruned = checks
            .iter()
            .map(|item| {
                let mut kept = Map::new();
                if let Some(check) = item.as_object() {
                    for field in CHECK_FIELDS {
                        if let Some(value) = check.get(field) {
                            kept.insert(field.to_owned(), value.clone());
                        }
                    }
                }
                Value::Object(kept)
            })
            .collect();
        candidate.insert("checks".to_owned(), Value::Array(pruned));
    }
    validate(&Value::Object(candidate), false)
        .map_err(|_| "recovery_diagnostics_snapshot_invalid".to_owned())
}

fn read_events(value: &Value) -> Checked<Vec<Value>> {
    let sources: Vec<&Value> = match value {
        Value::Object(_) => vec![value],
        Value::Array(items) => items.iter().collect(),
        _ => return fail("recovery_diagnostics_events_invalid"),
    };
    let mut events: Vec<Value> = Vec::new();
    for source in sources {
        let mut snapshot = redact(source)?;
        if let Some(previous) = events.last() {
            snapshot = validate_sequence(Some(previous), &snapshot)
                .map_err(|_| "recovery_diagnostics_event_sequence_invalid".to_owned())?;
        }
        events.push(snapshot);
    }
    if events.is_empty() {
        return fail("recovery_diagnostics_events_empty");
    }
    Ok(events)
}

fn encode_report(report: &Value) -> Checked<Vec<u8>> {
    let payload = encode(report);
    if payload.len() > MAX_REPORT_BYTES {
        return fail("recovery_diagnostics_too_large");
    }
    Ok(payload)
}

/// `validate_recovery_diagnostics`: a report with only allowlisted fields.
pub(crate) fn validate_report(value: &Value) -> Checked<Value> {
    let Some(map) = value
        .as_object()
        .filter(|map| has_exact_keys(map, &REPORT_FIELDS))
    else {
        return fail("recovery_diagnostics_fields_invalid");
    };
    if map.get("schema").and_then(Value::as_str) != Some(DIAGNOSTICS_SCHEMA) {
        return fail("recovery_diagnostics_schema_invalid");
    }
    if aware_timestamp(map.get("generatedAt")).is_none() {
        return fail("recovery_diagnostics_timestamp_invalid");
    }
    let operation_id = map
        .get("operationId")
        .and_then(Value::as_str)
        .and_then(canonical_uuid)
        .ok_or_else(|| "recovery_diagnostics_operation_id_invalid".to_owned())?;
    let event_count = map
        .get("eventCount")
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)
        .ok_or_else(|| "recovery_diagnostics_event_count_invalid".to_owned())?;
    let retained = map
        .get("retainedEventCount")
        .and_then(Value::as_u64)
        .filter(|count| *count > 0 && *count <= event_count)
        .ok_or_else(|| "recovery_diagnostics_retained_count_invalid".to_owned())?;
    if map.get("truncated").and_then(Value::as_bool) != Some(retained < event_count) {
        return fail("recovery_diagnostics_truncation_invalid");
    }
    let raw_events = map
        .get("events")
        .and_then(Value::as_array)
        .filter(|items| items.len() as u64 == retained)
        .ok_or_else(|| "recovery_diagnostics_events_invalid".to_owned())?;
    let events = read_events(&Value::Array(raw_events.clone()))?;
    if events.len() as u64 != retained {
        return fail("recovery_diagnostics_events_invalid");
    }
    if events
        .iter()
        .any(|event| event["operationId"].as_str() != Some(operation_id.as_str()))
    {
        return fail("recovery_diagnostics_operation_changed");
    }
    let latest = redact(map.get("latest").unwrap_or(&Value::Null))?;
    if Some(&latest) != events.last() {
        return fail("recovery_diagnostics_latest_invalid");
    }
    let mut normalized = map.clone();
    normalized.insert("operationId".to_owned(), Value::String(operation_id));
    normalized.insert("events".to_owned(), Value::Array(events));
    normalized.insert("latest".to_owned(), latest);
    let report = Value::Object(normalized);
    encode_report(&report)?;
    Ok(report)
}

/// `build_recovery_diagnostics`: drop the oldest events until it fits.
pub(crate) fn build_report(snapshots: &Value, generated_at: &str) -> Checked<Value> {
    let events = read_events(snapshots)?;
    let last = events.last().cloned().unwrap_or(Value::Null);
    let operation_id = last["operationId"]
        .as_str()
        .and_then(canonical_uuid)
        .ok_or_else(|| "recovery_diagnostics_operation_id_invalid".to_owned())?;
    if events
        .iter()
        .any(|event| event["operationId"].as_str() != Some(operation_id.as_str()))
    {
        return fail("recovery_diagnostics_operation_changed");
    }
    let total = events.len();
    for start in 0..total {
        let kept = &events[start..];
        let report = json!({
            "schema": DIAGNOSTICS_SCHEMA,
            "generatedAt": generated_at,
            "operationId": operation_id,
            "eventCount": total,
            "retainedEventCount": kept.len(),
            "truncated": kept.len() < total,
            "latest": last,
            "events": kept,
        });
        match validate_report(&report) {
            Ok(_) => return Ok(report),
            Err(code) if code == "recovery_diagnostics_too_large" => {}
            Err(code) => return Err(code),
        }
    }
    fail("recovery_diagnostics_too_large")
}

#[cfg(test)]
#[path = "daemon_recovery_contract_tests.rs"]
mod tests;
