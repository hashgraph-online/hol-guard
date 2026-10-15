//! Preserve the first valid retry lineage while finalizing an operation.
use crate::guard_store_db::StoreResult;
use serde_json::{Map, Value};

fn identifier(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        !text.is_empty()
            && text == crate::guard_store_json::py_strip(text)
            && text.chars().count() <= 256
            && !text.chars().any(|c| c < '\u{20}' || c == '\u{7f}')
    })
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub(crate) fn preserve(existing: &Value, requested: &mut Map<String, Value>) -> StoreResult<bool> {
    let Some(lineage) = existing["retry_lineage"].as_object() else {
        return Ok(false);
    };
    const KEYS: &[&str] = &[
        "version",
        "source",
        "harness",
        "session_id",
        "thread_id",
        "tool_call_id",
        "turn_id",
        "invocation_id",
        "provider_request_id",
        "original_request_id",
        "workspace_sha256",
        "device_sha256",
        "action_sha256",
        "lineage_id",
    ];
    const PROVIDER: &[&str] = &[
        "session_id",
        "thread_id",
        "tool_call_id",
        "turn_id",
        "invocation_id",
    ];
    if lineage.keys().any(|k| !KEYS.contains(&k.as_str()))
        || lineage.get("version").and_then(Value::as_i64) != Some(1)
        || lineage.get("source").and_then(Value::as_str) != Some("hook")
        || !identifier(lineage.get("harness").unwrap_or(&Value::Null))
        || !PROVIDER.iter().any(|k| lineage.contains_key(*k))
    {
        return Ok(false);
    }
    if PROVIDER
        .iter()
        .copied()
        .chain(["provider_request_id", "original_request_id"])
        .any(|k| lineage.get(k).is_some_and(|v| !identifier(v)))
        || ["workspace_sha256", "device_sha256", "action_sha256"]
            .iter()
            .any(|k| lineage.get(*k).is_some_and(|v| !digest(v)))
        || !lineage.get("lineage_id").is_some_and(digest)
    {
        return Ok(false);
    }
    let unsigned: Map<String, Value> = lineage
        .iter()
        .filter(|(key, _)| key.as_str() != "lineage_id")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut encoded = Vec::new();
    if guard_contracts::write_canonical_json_utf8(&Value::Object(unsigned), &mut encoded).is_err() {
        return Ok(false);
    }
    if lineage["lineage_id"] == guard_policy_snapshot::digest_bytes(&encoded) {
        requested.insert("retry_lineage".into(), Value::Object(lineage.clone()));
        return Ok(true);
    }
    Ok(false)
}
