//! The Cloud exceptions a signed policy bundle carries, for `RunnerAuthority`.
//!
//! Python hands over the bundle, the device and its stored acknowledgement.
//! The answer is the deduplicated exception records the sync stores and the
//! dashboard lists. With `active_at` the records are narrowed to exceptions
//! still in force at that instant, and with `harness` to the ones that apply
//! to that harness.

use serde_json::{json, Map, Value};

use super::cloud_exception_lift::SCOPES;
use super::cloud_request_text::{py_strip, py_truthy};
use super::policy_bundle_time::{from_isoformat, micros_to_utc_isoformat};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const ACK_STATUSES: [&str; 4] = ["pending", "synced", "failed", "offline"];

pub(crate) fn cloud_exceptions(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let Some(Value::Object(bundle)) = args.get("policy_bundle") else {
        return Err(ERR_INVALID);
    };
    let device_id = optional_text(args, "device_id")?;
    let harness = optional_text(args, "harness")?;
    let active_at = optional_text(args, "active_at")?;
    let acknowledgement = match args.get("policy_bundle_ack") {
        Some(Value::Object(acknowledgement)) => Some(acknowledgement),
        _ => None,
    };

    let Some(Value::Array(entries)) = bundle.get("cloudExceptions") else {
        return Ok(json!({ "items": [] }));
    };
    let bundle_hash = non_blank(bundle.get("bundleHash"));
    let ack_status = ack_status(bundle, device_id, acknowledgement);
    // `dict[item.id] = item`: a later duplicate replaces the record but keeps
    // the position the first one took.
    let mut records: Vec<Map<String, Value>> = Vec::new();
    for entry in entries {
        let Value::Object(entry) = entry else {
            continue;
        };
        let Some(record) = exception_record(entry, bundle_hash, ack_status) else {
            continue;
        };
        match records.iter_mut().find(|kept| kept["id"] == record["id"]) {
            Some(kept) => *kept = record,
            None => records.push(record),
        }
    }
    if let Some(active_at) = active_at {
        let now = utc_micros(active_at);
        records.retain(|record| {
            let expiry = record["expiry"].as_str().and_then(utc_micros);
            matches!((expiry, now), (Some(expiry), Some(now)) if expiry > now)
        });
    }
    if let Some(harness) = harness {
        // An exception that names no harness applies to every harness.
        records.retain(|record| match &record["harness"] {
            Value::String(named) => named == harness || named == "*",
            _ => true,
        });
    }
    let items: Vec<Value> = records.into_iter().map(with_legacy_fields).collect();
    Ok(json!({ "items": items }))
}

fn optional_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(ERR_INVALID),
    }
}

/// `_non_empty_string`: a string with a non-blank character, kept as written.
fn non_blank(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
}

/// `entry.get(a) or entry.get(b)`: the first truthy value.
fn either<'a>(entry: &'a Map<String, Value>, first: &str, second: &str) -> Option<&'a Value> {
    match entry.get(first) {
        Some(value) if py_truthy(value) => Some(value),
        _ => entry.get(second),
    }
}

/// `_parse_iso_timestamp` as UTC microseconds: every `Z` reads as `+00:00`
/// and a naive instant is UTC.
fn utc_micros(text: &str) -> Option<i64> {
    if py_strip(text).is_empty() {
        return None;
    }
    from_isoformat(&text.replace('Z', "+00:00"))?.utc_micros()
}

/// `_normalized_timestamp_string`: the instant as `astimezone(utc).isoformat()`.
fn normalized_timestamp(value: Option<&Value>) -> Option<String> {
    micros_to_utc_isoformat(utc_micros(value?.as_str()?)?, "+00:00")
}

/// `str(value)` for the JSON scalars an acknowledgement's device id can be.
fn python_str(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => Some("None".to_owned()),
        Some(Value::Bool(true)) => Some("True".to_owned()),
        Some(Value::Bool(false)) => Some("False".to_owned()),
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(_) => None,
    }
}

fn valid_ack_status(value: Option<&Value>) -> Option<&'static str> {
    let status = value?.as_str()?;
    ACK_STATUSES.into_iter().find(|known| *known == status)
}

/// `_resolve_cloud_exception_ack_status`: the stored acknowledgement when it
/// names this exact bundle and device, else the bundle's own record for it.
fn ack_status(
    bundle: &Map<String, Value>,
    device_id: Option<&str>,
    acknowledgement: Option<&Map<String, Value>>,
) -> Option<&'static str> {
    let device_id = device_id?;
    if let Some(acknowledgement) = acknowledgement {
        let status = valid_ack_status(acknowledgement.get("status"));
        let bundle_hash = non_blank(bundle.get("bundleHash"));
        let bundle_version = non_blank(bundle.get("bundleVersion"));
        if let (Some(status), Some(bundle_hash), Some(bundle_version)) =
            (status, bundle_hash, bundle_version)
        {
            let names = |key: &str, expected: &str| {
                acknowledgement.get(key).and_then(Value::as_str) == Some(expected)
            };
            if names("bundleHash", bundle_hash)
                && names("bundleVersion", bundle_version)
                && names("deviceId", device_id)
                && normalized_timestamp(acknowledgement.get("appliedAt")).is_some()
            {
                return Some(status);
            }
        }
    }
    let Some(Value::Array(acknowledgements)) = bundle.get("acknowledgements") else {
        return None;
    };
    acknowledgements.iter().find_map(|item| {
        let Value::Object(item) = item else {
            return None;
        };
        if python_str(item.get("deviceId")).as_deref() != Some(device_id) {
            return None;
        }
        valid_ack_status(item.get("status"))
    })
}

/// `cloud_exception_from_mapping` with policy-bundle provenance, as the
/// `asdict` record; `None` for an entry the bundle cannot carry.
fn exception_record(
    entry: &Map<String, Value>,
    bundle_hash: Option<&str>,
    ack_status: Option<&str>,
) -> Option<Map<String, Value>> {
    let id = non_blank(either(entry, "exceptionId", "id"))?;
    let scope = entry.get("scope").and_then(Value::as_str)?;
    if !SCOPES.contains(&scope) {
        return None;
    }
    let effect = match entry.get("effect") {
        Some(value) if py_truthy(value) => value.as_str()?,
        _ => "allow",
    };
    if effect != "allow" {
        return None;
    }
    let owner = non_blank(entry.get("owner"))?;
    let expiry = normalized_timestamp(either(entry, "expiresAt", "expiry"))?;
    let harness = non_blank(entry.get("harness"));
    if scope == "harness" && harness.is_none() {
        return None;
    }
    let ack_status = ack_status
        .or_else(|| non_blank(either(entry, "ackStatus", "ack_status")))
        .filter(|status| ACK_STATUSES.contains(status));
    let record = json!({
        "id": id,
        "effect": effect,
        "scope": scope,
        "harness": harness,
        "owner": owner,
        "approver": non_blank(entry.get("approver")),
        "expiry": expiry,
        "source_receipt_id": non_blank(either(entry, "sourceReceiptId", "source_receipt_id")),
        "bundle_hash": non_blank(either(entry, "bundleHash", "bundle_hash")).or(bundle_hash),
        "ack_status": ack_status,
        "last_used_at": normalized_timestamp(either(entry, "lastUsedAt", "last_used_at")),
        "rejection_reason": non_blank(either(entry, "rejectionReason", "rejection_reason")),
        "provenance": "policy-bundle",
    });
    match record {
        Value::Object(record) => Some(record),
        _ => None,
    }
}

/// `cloud_exception_to_dict`: the record plus `expires_at`, and the scope's
/// value under its legacy field when the id spells `<scope>:<value>`.
fn with_legacy_fields(mut record: Map<String, Value>) -> Value {
    let expiry = record["expiry"].clone();
    record.insert("expires_at".to_owned(), expiry);
    let id = record["id"].as_str().unwrap_or_default().to_owned();
    let scope = record["scope"].as_str().unwrap_or_default().to_owned();
    let field = match scope.as_str() {
        "artifact" => Some("artifact_id"),
        "publisher" => Some("publisher"),
        _ => None,
    };
    if let (Some(field), Some(value)) = (field, id.strip_prefix(&format!("{scope}:"))) {
        if !py_strip(value).is_empty() {
            record.insert(field.to_owned(), json!(value));
        }
    }
    Value::Object(record)
}
