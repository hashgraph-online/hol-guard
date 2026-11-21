//! Apply the advisories and alert preferences Guard Cloud answered across the
//! receipt batches of one sync. Ported from `runner.sync_receipts`: the
//! advisory cache, the stored alert preferences and one `premium_advisory`
//! event per advisory while the workspace keeps advisory alerts on.
//!
//! The upload calls this once, after its last batch, so a broker round that
//! is run again never applies the same answers twice.

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::cloud_bundle_fetch::SyncError;
use crate::guard_store_json::{dumps_default, dumps_sorted, py_strip};

/// `store_base` sync-state key of the workspace's alert preferences.
pub(crate) const ALERT_PREFERENCES_KEY: &str = "alert_preferences";
const ADVISORY_EVENT: &str = "premium_advisory";
/// Escaped payload bytes per `cache_advisories` call, well under the store's
/// request limit (`store_advisory_cache._advisory_batches`).
const CACHE_BATCH_BYTES: usize = 1024 * 1024;

/// A Guard store method call, as [`crate::cloud_event_sync::EventStore::call`].
pub(crate) type StoreCall<'a> = &'a dyn Fn(&str, Value) -> Result<Value, SyncError>;
/// A sync-state write, as [`crate::cloud_event_sync::EventStore::save`].
pub(crate) type StoreSave<'a> = &'a dyn Fn(&str, &Value, &str) -> Result<(), SyncError>;

/// Cache `advisories` (each once), store `preferences` (`{}` when Cloud sent
/// none) and record the advisory events. Answers how many advisories the
/// cache wrote.
pub(crate) fn apply(
    call: StoreCall<'_>,
    save: StoreSave<'_>,
    advisories: &[Value],
    preferences: Option<&Value>,
    now: &str,
) -> Result<i64, SyncError> {
    let advisories = deduped(advisories)?;
    let mut stored = 0;
    if !advisories.is_empty() {
        let payloads = advisories
            .iter()
            .map(|advisory| dumps_default(advisory).ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        for batch in batches(payloads)? {
            let answer = call("cache_advisories", json!({"payloads": batch, "now": now}))?;
            stored += answer
                .as_i64()
                .ok_or_else(|| SyncError::Failed("native_advisory_cache_invalid".to_owned()))?;
        }
    }
    let preferences = preferences
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    save(ALERT_PREFERENCES_KEY, &preferences, now)?;
    if preferences.get("advisoriesEnabled") == Some(&Value::Bool(false)) {
        return Ok(stored);
    }
    for advisory in &advisories {
        if let Some(payload) = advisory_event(advisory)? {
            call(
                "add_event",
                json!({"event_name": ADVISORY_EVENT, "payload_json": payload, "occurred_at": now}),
            )?;
        }
    }
    Ok(stored)
}

/// `payloads` split so each batch's payloads, escaped again as request
/// strings, stay under [`CACHE_BATCH_BYTES`]. A payload larger than the
/// budget goes alone.
fn batches(payloads: Vec<String>) -> Result<Vec<Vec<String>>, SyncError> {
    let mut out: Vec<Vec<String>> = vec![Vec::new()];
    let mut used = 0;
    for payload in payloads {
        let size = dumps_default(&Value::from(payload.as_str()))
            .ok_or_else(invalid)?
            .len();
        if used + size > CACHE_BATCH_BYTES && out.last().is_some_and(|batch| !batch.is_empty()) {
            out.push(Vec::new());
            used = 0;
        }
        used += size;
        if let Some(batch) = out.last_mut() {
            batch.push(payload);
        }
    }
    Ok(out)
}

/// The advisory objects in answer order, each kept once: Python's
/// `_dedupe_sync_payload_items` fingerprint, `json.dumps(item, sort_keys=True)`.
fn deduped(advisories: &[Value]) -> Result<Vec<&Value>, SyncError> {
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for advisory in advisories.iter().filter(|item| item.is_object()) {
        if seen.insert(dumps_sorted(advisory).ok_or_else(invalid)?) {
            kept.push(advisory);
        }
    }
    Ok(kept)
}

/// The `premium_advisory` event text for `advisory`, as `json.dumps` wrote the
/// runner's dict (its key order, default separators), or `None` when the
/// advisory names no artifact.
fn advisory_event(advisory: &Value) -> Result<Option<String>, SyncError> {
    let Some(artifact_id) = text(advisory, "artifactId") else {
        return Ok(None);
    };
    let fields = [
        ("artifact_id", Value::from(artifact_id)),
        (
            "artifact_name",
            Value::from(text(advisory, "artifactName").unwrap_or(artifact_id)),
        ),
        (
            "severity",
            text(advisory, "severity").map_or(Value::Null, Value::from),
        ),
        (
            "reason",
            text(advisory, "reason").map_or(Value::Null, Value::from),
        ),
    ];
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&dumps_default(&Value::from(*key)).ok_or_else(invalid)?);
        out.push_str(": ");
        out.push_str(&dumps_default(value).ok_or_else(invalid)?);
    }
    out.push('}');
    Ok(Some(out))
}

/// `_optional_string`: a string field with something besides whitespace.
fn text<'a>(advisory: &'a Value, key: &str) -> Option<&'a str> {
    advisory
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !py_strip(value).is_empty())
}

fn invalid() -> SyncError {
    SyncError::Failed("Guard Cloud sync returned an invalid response payload.".to_owned())
}

#[cfg(test)]
#[path = "cloud_receipt_answers_tests.rs"]
mod tests;
