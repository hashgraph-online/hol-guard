use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) const MAX_HARNESS_BYTES: usize = 64;
pub(super) const MAX_EVENT_BYTES: usize = 64;
pub(super) const MAX_PATH_BYTES: usize = 32 * 1024;

pub(super) fn request_id_is_safe(value: &str) -> bool {
    let opaque_token = !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    let compact_uuid = value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let dashed_uuid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                .then_some(byte == b'-')
                .unwrap_or_else(|| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    opaque_token || compact_uuid || dashed_uuid
}

pub(super) fn request_payload_identity(
    payload: &Value,
    harness: &str,
    event: &str,
) -> Result<Value, String> {
    let Some(record) = payload.as_object() else {
        return Err("native_hook_payload_invalid".to_owned());
    };
    // Event aliases and adapter timestamps are transport metadata, not request
    // semantics. Event aliases are validated for agreement by
    // `authoritative_event`, then omitted here so a harness spelling change
    // cannot change an otherwise identical request. Timestamps are removed
    // only at the envelope root: a nested timestamp may be an actual tool
    // argument and must remain part of the action commitment.
    let mut identity = record.clone();
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
        "timestamp",
        "timestamp_ms",
        "timestampMs",
        "created_at",
        "createdAt",
        "received_at",
        "receivedAt",
    ] {
        identity.remove(key);
    }
    // Pi retries create a new transport call ID for the unchanged action.
    // Keep nested tool arguments and session identity in the commitment.
    if matches!(harness, "pi" | "omp")
        && event == "PreToolUse"
        && identity
            .get("session_id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        identity.remove("tool_call_id");
    }
    Ok(Value::Object(identity))
}

/// True when the snapshot's own `generation` agrees with the claimed one.
pub(crate) fn policy_generation_matches(snapshot: &Value, generation: u64) -> bool {
    generation != 0 && snapshot.get("generation").and_then(Value::as_u64) == Some(generation)
}

pub(crate) fn stable_policy_identity(snapshot: &Value, generation: u64) -> Value {
    let object = snapshot.as_object();
    let runtime_identity = object
        .and_then(|value| value.get("runtime_identity"))
        .cloned()
        .unwrap_or(Value::Null);
    let policy_digest = object
        .and_then(|value| value.get("policy_digest"))
        .cloned()
        .unwrap_or(Value::Null);
    let rule_digest = object
        .and_then(|value| value.get("rule_digest"))
        .cloned()
        .unwrap_or(Value::Null);
    let scope_digest = object
        .and_then(|value| value.get("scope_contract"))
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("scope_digest"))
        .cloned()
        .unwrap_or(Value::Null);
    serde_json::json!({
        "generation": generation,
        "policy_digest": policy_digest,
        "rule_digest": rule_digest,
        "runtime_identity": runtime_identity,
        "scope_digest": scope_digest,
    })
}

pub(super) fn canonical_identity_digest(value: &Value, error_code: &str) -> Result<String, String> {
    let canonical =
        guard_policy_snapshot::canonical_json_bytes(value).map_err(|_| error_code.to_owned())?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}
