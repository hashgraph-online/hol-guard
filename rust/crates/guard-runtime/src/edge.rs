#![forbid(unsafe_code)]

use guard_contracts::{
    GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookOutputSummaryV1,
    HookSourceFileRefV1, NativeHookRequestV1, GUARD_HOOK_EDGE_RESULT_V2_SCHEMA,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA, MAX_NATIVE_REQUEST_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_HARNESS_BYTES: usize = 64;
const MAX_EVENT_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 32 * 1024;
fn request_id_is_safe(value: &str) -> bool {
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

fn request_payload_identity(payload: &Value) -> Result<Value, String> {
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
    Ok(Value::Object(identity))
}

fn stable_policy_identity(snapshot: &Value, generation: u64) -> Value {
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

/// Derive a stable opaque identity when the harness omitted a request ID.
/// The digest covers semantic request inputs only. Transport deadlines,
/// object field order, and event-alias spelling are deliberately excluded.
/// Raw request material remains inside the resident and never appears in an
/// approval result.
pub(crate) fn request_identity(envelope: &GuardHookEnvelopeV2) -> Result<(String, String), String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event = authoritative_event(envelope)?;
    let payload = request_payload_identity(&envelope.raw_payload)?;
    let source = serde_json::json!({
        "cwd": envelope.source.cwd,
        "guard_home": envelope.source.guard_home,
        "home_dir": envelope.source.home_dir,
        "source_ref_external_allowed": envelope.source.source_ref_external_allowed,
    });
    let value = serde_json::json!({
        "schema": "guard-native-request-identity.v3",
        "version": 3,
        "event": event,
        "harness": harness,
        "payload": payload,
        "policy": stable_policy_identity(&envelope.policy_snapshot, envelope.policy_generation),
        "source": source,
    });
    let value =
        serde_json::to_value(value).map_err(|_| "native_hook_request_digest_failed".to_owned())?;
    let canonical = guard_policy_snapshot::canonical_json_bytes(&value)
        .map_err(|_| "native_hook_request_digest_failed".to_owned())?;
    let digest = hex::encode(Sha256::digest(&canonical));
    let request_id = match envelope.request_id.as_deref() {
        Some(value) if request_id_is_safe(value) => value.to_owned(),
        Some(_) => return Err("native_hook_request_id_invalid".to_owned()),
        None => format!("sha256:{digest}"),
    };
    Ok((request_id, digest))
}

fn bounded_nonempty(value: &str, maximum: usize, code: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum {
        return Err(code.to_owned());
    }
    Ok(())
}

fn canonical_harness(value: &str) -> Result<String, String> {
    bounded_nonempty(value, MAX_HARNESS_BYTES, "native_hook_harness_invalid")?;
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    let canonical = match normalized.as_str() {
        "claude" => "claude-code",
        "cline-cli" | "cline-vscode" => "cline",
        "kimi-code" | "kimi-cli" => "kimi",
        "grok-build" | "grok-build-cli" | "xai-grok" => "grok",
        "pi-agent" | "pi-coding-agent" => "pi",
        "oh-my-pi" => "omp",
        "zai" | "z-code" | "zai-zcode" => "zcode",
        _ => normalized.as_str(),
    };
    if !canonical
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("native_hook_harness_invalid".to_owned());
    }
    if !matches!(
        canonical,
        "antigravity"
            | "claude-code"
            | "cline"
            | "codex"
            | "copilot"
            | "cursor"
            | "gemini"
            | "grok"
            | "hermes"
            | "kimi"
            | "omp"
            | "openclaw"
            | "opencode"
            | "pi"
            | "zcode"
    ) {
        return Err("native_hook_harness_unsupported".to_owned());
    }
    Ok(canonical.to_owned())
}

fn canonical_event(value: &str) -> Result<String, String> {
    bounded_nonempty(value, MAX_EVENT_BYTES, "native_hook_event_invalid")?;
    let compact = value.trim().to_ascii_lowercase().replace(['_', '-'], "");
    match compact.as_str() {
        "pretool" | "pretooluse" => Ok("PreToolUse".to_owned()),
        "beforeshellexecution" | "beforereadfile" | "beforewritefile" | "beforemcpexecution" => {
            Ok("PreToolUse".to_owned())
        }
        "posttool" | "posttooluse" => Ok("PostToolUse".to_owned()),
        "aftershellexecution" | "afterreadfile" | "afterwritefile" | "aftermcpexecution" => {
            Ok("PostToolUse".to_owned())
        }
        "prompt" | "userpromptsubmit" | "userpromptsubmitted" => Ok("UserPromptSubmit".to_owned()),
        "permissionrequest" => Ok("PermissionRequest".to_owned()),
        _ => Err("native_hook_event_unsupported".to_owned()),
    }
}

fn payload_event(payload: &Value) -> Result<Option<String>, String> {
    let Some(record) = payload.as_object() else {
        return Err("native_hook_payload_invalid".to_owned());
    };
    let mut extracted: Option<String> = None;
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        if let Some(value) = record.get(key) {
            let raw = value
                .as_str()
                .ok_or_else(|| "native_hook_event_invalid".to_owned())?;
            let candidate = canonical_event(raw)?;
            if extracted.as_ref().is_some_and(|event| event != &candidate) {
                return Err("native_hook_event_mismatch".to_owned());
            }
            extracted = Some(candidate);
        }
    }
    Ok(extracted)
}

fn authoritative_event(envelope: &GuardHookEnvelopeV2) -> Result<String, String> {
    let declared = canonical_event(&envelope.event)?;
    if let Some(extracted) = payload_event(&envelope.raw_payload)? {
        if extracted != declared {
            return Err("native_hook_event_mismatch".to_owned());
        }
        return Ok(extracted);
    }
    Ok(declared)
}

fn payload_kind(payload: &Value) -> Result<GuardHookPayloadKindV2, String> {
    let Some(record) = payload.as_object() else {
        return Err("native_hook_payload_invalid".to_owned());
    };
    if let Some(reference) = record.get("guard_payload_ref") {
        if !reference.is_object() {
            return Err("native_hook_payload_ref_invalid".to_owned());
        }
        return Ok(GuardHookPayloadKindV2::EncryptedPayloadRef);
    }
    if let Some(reference) = record.get("guard_source_ref") {
        serde_json::from_value::<HookSourceFileRefV1>(reference.clone())
            .map_err(|_| "native_hook_source_ref_invalid".to_owned())?;
        return Ok(GuardHookPayloadKindV2::SourceFileRef);
    }
    if let Some(summary) = record.get("tool_response_summary") {
        serde_json::from_value::<HookOutputSummaryV1>(summary.clone())
            .map_err(|_| "native_hook_output_summary_invalid".to_owned())?;
    }
    Ok(GuardHookPayloadKindV2::Inline)
}

fn validate_envelope_shape(envelope: &GuardHookEnvelopeV2) -> Result<(), String> {
    if envelope.schema != GUARD_HOOK_ENVELOPE_V2_SCHEMA {
        return Err("native_hook_envelope_schema_mismatch".to_owned());
    }
    if envelope.policy_generation == 0 {
        return Err("native_hook_policy_generation_invalid".to_owned());
    }
    if envelope
        .policy_snapshot
        .get("generation")
        .and_then(Value::as_u64)
        != Some(envelope.policy_generation)
    {
        return Err("native_hook_policy_generation_mismatch".to_owned());
    }
    let encoded = serde_json::to_vec(envelope)
        .map_err(|_| "native_hook_request_bounds_exceeded".to_owned())?;
    if encoded.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_hook_request_bounds_exceeded".to_owned());
    }
    let _ = request_identity(envelope)?;
    for path in [
        envelope.source.cwd.as_deref(),
        Some(envelope.source.home_dir.as_str()),
        Some(envelope.source.guard_home.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        bounded_nonempty(path, MAX_PATH_BYTES, "native_hook_source_metadata_invalid")?;
    }
    Ok(())
}

fn evaluate_validated_envelope(
    envelope: GuardHookEnvelopeV2,
    policy_snapshot: Option<&PolicySnapshotV3>,
) -> Result<Vec<u8>, String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event_name = authoritative_event(&envelope)?;
    let kind = payload_kind(&envelope.raw_payload)?;
    let (request_id, _request_digest) = request_identity(&envelope)?;
    if kind == GuardHookPayloadKindV2::EncryptedPayloadRef {
        return Err("native_hook_encrypted_payload_unsupported".to_owned());
    }
    let result = match event_name.as_str() {
        "PreToolUse" => {
            let native = guard_command::pretool::evaluate_pre_tool_envelope(
                &harness,
                &event_name,
                &envelope.raw_payload,
            );
            let evaluated = if let Some(snapshot) = policy_snapshot {
                crate::policy_enforcement::apply_pre_tool_policy(
                    snapshot,
                    &envelope.raw_payload,
                    native,
                )?
            } else {
                native
            };
            serde_json::to_value(evaluated)
                .map_err(|_| "native_hook_edge_response_invalid".to_owned())?
        }
        "PostToolUse" => {
            let payload_kind = kind.clone();
            let request = NativeHookRequestV1 {
                protocol_version: NATIVE_PROTOCOL_VERSION,
                request_id: envelope.request_id.clone(),
                harness: harness.clone(),
                event_name: event_name.clone(),
                payload: envelope.raw_payload,
                cwd: envelope.source.cwd,
                home_dir: envelope.source.home_dir,
                guard_home: envelope.source.guard_home,
                source_ref_external_allowed: envelope.source.source_ref_external_allowed,
                // Keep the intrinsic result intact. The authenticated policy
                // join below owns observe-mode semantics and suppresses only
                // policy-only escalation; passing observe here would erase a
                // native source/content block before that join runs.
                observe_mode: false,
                deadline_budget_ms: envelope.deadline_budget_ms,
            };
            let native = review_post_tool(&request);
            let evaluated = if let Some(snapshot) = policy_snapshot {
                crate::policy_enforcement::apply_post_tool_policy(
                    snapshot,
                    &request,
                    payload_kind,
                    native,
                )?
            } else {
                native
            };
            serde_json::to_value(evaluated)
                .map_err(|_| "native_hook_edge_response_invalid".to_owned())?
        }
        _ => return Err("native_hook_event_unsupported".to_owned()),
    };
    crate::encode_response(&GuardHookEdgeResultV2 {
        schema: GUARD_HOOK_EDGE_RESULT_V2_SCHEMA.to_owned(),
        authority: "rust".to_owned(),
        request_id: Some(request_id),
        harness,
        event_name,
        payload_kind: kind,
        result,
    })
}

/// Evaluate a resident hook envelope against the already-installed in-memory
/// policy snapshot. No request can install, replace, or downgrade policy.
pub(crate) fn evaluate_envelope_with_store(
    envelope: GuardHookEnvelopeV2,
    policy_store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    validate_envelope_shape(&envelope)?;
    let snapshot = policy_store.validate_request_snapshot(
        &envelope.policy_snapshot,
        &envelope.source.guard_home,
        envelope.policy_generation,
    )?;
    evaluate_validated_envelope(envelope, Some(snapshot.as_ref()))
}

/// Evaluate against a snapshot while the policy store's request fence is
/// held. Approval challenge creation uses this entry point so the action,
/// snapshot, and derived bindings describe one coherent state.
pub(crate) fn evaluate_envelope_with_snapshot(
    envelope: GuardHookEnvelopeV2,
    snapshot: &PolicySnapshotV3,
) -> Result<Vec<u8>, String> {
    validate_envelope_shape(&envelope)?;
    evaluate_validated_envelope(envelope, Some(snapshot))
}

#[cfg(test)]
#[path = "edge_tests.rs"]
mod tests;
