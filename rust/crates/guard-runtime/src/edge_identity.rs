use guard_policy_snapshot::PolicySnapshotV3;
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

fn claimed_field(snapshot: &Value, key: &str) -> Value {
    snapshot
        .as_object()
        .and_then(|value| value.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn claimed_scope_digest(snapshot: &Value) -> Value {
    snapshot
        .as_object()
        .and_then(|value| value.get("scope_contract"))
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("scope_digest"))
        .cloned()
        .unwrap_or(Value::Null)
}

pub(crate) fn stable_policy_identity(snapshot: &Value, generation: u64) -> Value {
    serde_json::json!({
        "generation": generation,
        "policy_digest": claimed_field(snapshot, "policy_digest"),
        "rule_digest": claimed_field(snapshot, "rule_digest"),
        "runtime_identity": claimed_field(snapshot, "runtime_identity"),
        "scope_digest": claimed_scope_digest(snapshot),
    })
}

/// Effective-policy entries the publisher merges from what the agent has been
/// observed doing rather than from configuration. They accumulate while the
/// agent works, so they republish the snapshot on their own, and the publisher
/// merges them with a stricter-wins rule: they can only tighten an action, and
/// a tightening that matters is already applied by the fresh evaluation that
/// precedes any approval lookup.
const OBSERVED_POLICY_KEYS: [&str; 3] = [
    "mcp_provider_actions",
    "mcp_provider_catalog_hash",
    "mcp_tool_actions",
];

const ANCHOR_DIGEST_FAILED: &str = "native_hook_review_anchor_digest_failed";

/// The part of a policy snapshot that can decide a verdict, without the
/// snapshot bookkeeping that moves on its own. `request_identity` keeps the
/// whole snapshot identity; only a one-time review approval is anchored to
/// this narrower identity, so an identical retry still matches after a
/// republish that changed nothing a verdict depends on.
pub(crate) fn verdict_policy_identity(
    snapshot: Option<&PolicySnapshotV3>,
    claimed: &Value,
) -> Result<Value, String> {
    let Some(snapshot) = snapshot else {
        // Nothing authenticated to read: keep the whole published identity
        // rather than widen what a retry may be matched against.
        return Ok(serde_json::json!({
            "authority": "claimed",
            "policy_digest": claimed_field(claimed, "policy_digest"),
            "rule_digest": claimed_field(claimed, "rule_digest"),
            "runtime_identity": claimed_field(claimed, "runtime_identity"),
            "scope_digest": claimed_scope_digest(claimed),
        }));
    };
    let mut configured_policy = serde_json::to_value(&snapshot.effective_policy)
        .map_err(|_| ANCHOR_DIGEST_FAILED.to_owned())?;
    let entries = configured_policy
        .as_object_mut()
        .ok_or_else(|| ANCHOR_DIGEST_FAILED.to_owned())?;
    for key in OBSERVED_POLICY_KEYS {
        entries.remove(key);
    }
    let business_policy = serde_json::to_value(&snapshot.business_policy)
        .map_err(|_| ANCHOR_DIGEST_FAILED.to_owned())?;
    Ok(serde_json::json!({
        "authority": "snapshot",
        "business_policy": business_policy,
        // The extension set's own content digest, not its revision counters:
        // the counters move when the set is republished unchanged.
        "command_extensions": snapshot
            .command_extensions
            .as_ref()
            .map(|binding| binding.effective_digest.as_str()),
        "configured_policy": configured_policy,
        "mode": snapshot.mode,
        "rule_digest": snapshot.rule_digest,
        "runtime_identity": snapshot.runtime_identity,
        "scope_digest": snapshot.scope_contract.scope_digest,
    }))
}

pub(super) fn canonical_identity_digest(value: &Value, error_code: &str) -> Result<String, String> {
    let canonical =
        guard_policy_snapshot::canonical_json_bytes(value).map_err(|_| error_code.to_owned())?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}
