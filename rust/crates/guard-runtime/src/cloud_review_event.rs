//! The Cloud review event one local request row becomes (the event body of
//! `build_cloud_review_event` in `runtime/cloud_review_event_projection.py`
//! before it moved here). Python keeps what reads the store, the review
//! claim and the continuation offer, and sends them beside the row as the
//! `event` argument of `cloud_review_event_display`; the resident adds the
//! display fields and the Cloud-safe payload it already computes.

use serde_json::{json, Map, Value};

use super::approval_queue_identity_op::py_str;
use super::cloud_request_text::py_truthy;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const EVENT_KEYS: [&str; 6] = [
    "sequence",
    "event_type",
    "claim",
    "continuation",
    "now",
    "columns",
];
/// Row columns the display projection does not carry.
const COLUMN_KEYS: [&str; 4] = [
    "updated_at",
    "guard_version",
    "first_seen_guard_version",
    "last_seen_guard_version",
];
const CONTINUATION_KEYS: [&str; 5] = [
    "correlationId",
    "capability",
    "hookAttached",
    "opaqueTargetId",
    "waitDeadline",
];
const DEFAULT_HARNESS: &str = "guard-review";

/// Python `str(value)` of a truthy column, `None` for a falsy one. A list or
/// object column is refused: it has no Cloud text form.
fn text(value: Option<&Value>) -> Result<Option<String>, &'static str> {
    match value.filter(|value| py_truthy(value)) {
        None => Ok(None),
        Some(value) => py_str(value).map(Some).ok_or(ERR_INVALID),
    }
}

/// `str(value or fallback)`.
fn text_or(value: Option<&Value>, fallback: &str) -> Result<String, &'static str> {
    Ok(text(value)?.unwrap_or_else(|| fallback.to_owned()))
}

/// `str(value or "") or None`.
fn optional(value: Option<&Value>) -> Result<Value, &'static str> {
    Ok(text(value)?.map_or(Value::Null, Value::String))
}

/// Row text a risk level is read from, in the order
/// `review_contracts._risk_category` reads it.
const RISK_TEXT_KEYS: [&str; 3] = ["risk_headline", "risk_summary", "policy_action"];
/// Words naming each level, highest first.
const RISK_LEVEL_WORDS: [(&str, &[&str]); 3] = [
    (
        "high",
        &["critical", "high", "block", "blocked", "destructive"],
    ),
    ("medium", &["medium", "review", "reapproval"]),
    ("low", &["low", "allow", "allowed"]),
];

/// The row's own `risk_category`, or else the level its risk text names. The
/// local store keeps no risk column, so a Cloud card would otherwise always
/// read Unknown. Whole words only: "follow" is not "low". A row whose text
/// names no level sends null and stays Unknown.
fn risk_category(item: &Map<String, Value>) -> Result<Value, &'static str> {
    if let Some(category) = text(item.get("risk_category"))? {
        return Ok(Value::String(category));
    }
    for key in RISK_TEXT_KEYS {
        let Some(value) = item.get(key).and_then(Value::as_str) else {
            continue;
        };
        let lowered = value.to_lowercase();
        let words: Vec<&str> = lowered
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|word| !word.is_empty())
            .collect();
        for (level, names) in RISK_LEVEL_WORDS {
            if words.iter().any(|word| names.contains(word)) {
                return Ok(Value::String(level.to_owned()));
            }
        }
    }
    Ok(Value::Null)
}

fn exact<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, &'static str> {
    let fields = args_object(value)?;
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    Ok(fields)
}

/// The event body for `item` (the projected row) from the `event` argument
/// and the display answer, which it consumes.
pub(crate) fn review_event(
    item: &Map<String, Value>,
    event: &Value,
    mut display: Map<String, Value>,
) -> KindResult {
    let event = exact(event, &EVENT_KEYS)?;
    let columns = exact(&event["columns"], &COLUMN_KEYS)?;
    let sequence = &event["sequence"];
    if sequence.as_i64().is_none() && sequence.as_u64().is_none() {
        return Err(ERR_INVALID);
    }
    let event_type = event["event_type"]
        .as_str()
        .filter(|kind| !kind.is_empty())
        .ok_or(ERR_INVALID)?;
    let now = event["now"].as_str().ok_or(ERR_INVALID)?;
    let claim = &event["claim"];
    if !claim.is_null() && !claim.is_object() {
        return Err(ERR_INVALID);
    }
    // The offer may carry more than the Cloud reads; a missing fact refuses.
    let offer = args_object(&event["continuation"])?;
    let offer = CONTINUATION_KEYS
        .iter()
        .map(|key| offer.get(*key).cloned().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let [correlation, capability, hook_attached, target, deadline] =
        <[Value; 5]>::try_from(offer).map_err(|_| ERR_INVALID)?;
    let mut shown = |key: &str| display.remove(key).ok_or(ERR_INVALID);
    let (provenance, command, summary) = (
        shown("display_provenance")?,
        shown("display_command")?,
        shown("display_summary")?,
    );
    let (raw, redacted, payload) = (
        shown("raw_command")?,
        shown("redacted_command")?,
        shown("payload")?,
    );
    let harness = text_or(item.get("harness"), DEFAULT_HARNESS)?;
    let request_kind = match text(item.get("review_kind"))? {
        Some(kind) => kind,
        None => harness.clone(),
    };
    let created_at = text_or(item.get("created_at"), now)?;
    let last_seen_at = text_or(item.get("last_seen_at"), &created_at)?;
    let updated_at = text_or(columns.get("updated_at"), &last_seen_at)?;
    Ok(json!({
        "localRequestId": item.get("request_id").cloned().unwrap_or(Value::Null),
        "correlationId": correlation,
        "localEventSequence": sequence,
        "eventType": event_type,
        "harnessId": harness,
        "requestKind": request_kind,
        "displayProvenance": provenance,
        "displayCommand": command,
        "displaySummary": summary,
        "rawCommand": raw,
        "redactedCommand": redacted,
        "reviewClaim": claim,
        "requestPayload": payload,
        "continuationCapability": capability,
        "continuationHookAttached": hook_attached,
        "continuationOpaqueTargetId": target,
        "continuationWaitDeadline": deadline,
        "riskCategory": risk_category(item)?,
        "policyAction": optional(item.get("policy_action"))?,
        "recommendedScope": optional(item.get("recommended_scope"))?,
        "localCreatedAt": created_at,
        "localUpdatedAt": updated_at,
        "localLastSeenAt": last_seen_at,
        "guardVersion": optional(columns.get("guard_version"))?,
        "firstSeenGuardVersion": optional(columns.get("first_seen_guard_version"))?,
        "lastSeenGuardVersion": optional(columns.get("last_seen_guard_version"))?,
        "localEmittedAt": now,
        "sentAt": now,
    }))
}

#[cfg(test)]
#[path = "cloud_review_event_tests.rs"]
mod tests;
