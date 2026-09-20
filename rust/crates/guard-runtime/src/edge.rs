#![forbid(unsafe_code)]

use crate::policy_enforcement::AdmittedPolicySnapshot;
use guard_contracts::{
    GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookOutputSummaryV1,
    HookSourceFileRefV1, NativeHookRequestV1, PreToolResultV1, GUARD_HOOK_EDGE_RESULT_V2_SCHEMA,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA, MAX_NATIVE_REQUEST_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool_with_deadline;
use serde_json::Value;
use std::time::{Duration, Instant};

use crate::native_hook_receipt::{receipt_from_post_tool, receipt_from_pre_tool};

const MAX_HARNESS_BYTES: usize = 64;
const MAX_EVENT_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 32 * 1024;

#[path = "edge_encrypted.rs"]
mod encrypted;
#[path = "edge_identity.rs"]
mod identity;
#[path = "edge_serialization.rs"]
mod serialization;
use identity::request_identity_for_event;
/// Derive a stable opaque identity when the harness omitted a request ID.
/// The digest covers semantic request inputs only. Transport deadlines,
/// object field order, and event-alias spelling are deliberately excluded.
/// Raw request material remains inside the resident and never appears in an
/// approval result.
pub(crate) fn request_identity(envelope: &GuardHookEnvelopeV2) -> Result<(String, String), String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event = authoritative_event(envelope)?;
    request_identity_for_event(envelope, &harness, &event)
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

struct ValidatedEnvelope {
    envelope: GuardHookEnvelopeV2,
    harness: String,
    event_name: String,
    request_id: String,
    request_digest: String,
    deadline: Option<Instant>,
}

fn validate_envelope_shape(
    envelope: GuardHookEnvelopeV2,
    started_at: Instant,
) -> Result<ValidatedEnvelope, String> {
    let deadline = envelope
        .deadline_budget_ms
        .map(|budget| started_at + Duration::from_millis(budget.min(9_000)));
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
    serialization::serialized_size_within(&envelope, MAX_NATIVE_REQUEST_BYTES)
        .map_err(|_| "native_hook_request_bounds_exceeded".to_owned())?;
    let harness = canonical_harness(&envelope.harness)?;
    let event_name = authoritative_event(&envelope)?;
    let (request_id, request_digest) =
        request_identity_for_event(&envelope, &harness, &event_name)?;
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
    Ok(ValidatedEnvelope {
        envelope,
        harness,
        event_name,
        request_id,
        request_digest,
        deadline,
    })
}

fn validate_pre_tool_result(result: &PreToolResultV1) -> Result<(), String> {
    if result.schema != "guard-pre-tool-result.v1" || result.authority != "rust" {
        return Err("native_hook_pre_tool_result_schema_invalid".to_owned());
    }
    crate::policy_enforcement::validate_pre_tool_result_matrix(result)
}

fn evaluate_validated_envelope(
    validated: ValidatedEnvelope,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
) -> Result<Vec<u8>, String> {
    let ValidatedEnvelope {
        mut envelope,
        harness,
        event_name,
        request_id,
        request_digest,
        deadline,
    } = validated;
    let kind = payload_kind(&envelope.raw_payload)?;
    let inner_payload = if kind == GuardHookPayloadKindV2::EncryptedPayloadRef {
        if event_name != "PostToolUse" || !matches!(harness.as_str(), "pi" | "omp") {
            return Err("native_hook_encrypted_payload_unsupported".to_owned());
        }
        Some(encrypted::hydrate(&envelope.raw_payload, deadline)?)
    } else {
        None
    };
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err("native_request_deadline_exceeded".to_owned());
    }
    let (result, receipt) = match event_name.as_str() {
        "PreToolUse" => {
            let (native, command_absent) =
                guard_command::pretool::evaluate_pre_tool_envelope_with_extensions_and_scope(
                    &harness,
                    &event_name,
                    &envelope.raw_payload,
                    policy_snapshot.and_then(|snapshot| snapshot.command_extensions.as_ref()),
                    deadline,
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
            validate_pre_tool_result(&evaluated)?;
            let receipt = receipt_from_pre_tool(
                &envelope,
                policy_snapshot.map(AdmittedPolicySnapshot::snapshot),
                &request_id,
                &request_digest,
                &harness,
                &kind,
                (&evaluated, command_absent),
            )?;
            let value = serde_json::to_value(evaluated)
                .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
            (value, receipt)
        }
        "PostToolUse" => {
            // Classify authenticated inner content for the existing policy join;
            // the public receipt still commits to the original outer reference.
            let payload_kind = match inner_payload.as_ref() {
                Some(payload) => payload_kind(payload)?,
                None => kind.clone(),
            };
            let request = NativeHookRequestV1 {
                protocol_version: NATIVE_PROTOCOL_VERSION,
                request_id: envelope.request_id.clone(),
                harness: harness.clone(),
                event_name: event_name.clone(),
                // Transfer the already-bound payload into the typed hook
                // request, then restore ownership before building its receipt.
                payload: inner_payload.unwrap_or_else(|| std::mem::take(&mut envelope.raw_payload)),
                cwd: envelope.source.cwd.clone(),
                home_dir: envelope.source.home_dir.clone(),
                guard_home: envelope.source.guard_home.clone(),
                source_ref_external_allowed: envelope.source.source_ref_external_allowed,
                // Keep the intrinsic result intact. The authenticated policy
                // join below owns observe-mode semantics and suppresses only
                // policy-only escalation; passing observe here would erase a
                // native source/content block before that join runs.
                observe_mode: false,
                deadline_budget_ms: envelope.deadline_budget_ms,
            };
            let native = review_post_tool_with_deadline(&request, deadline);
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
            if kind != GuardHookPayloadKindV2::EncryptedPayloadRef {
                envelope.raw_payload = request.payload;
            }
            let receipt = receipt_from_post_tool(
                &envelope,
                policy_snapshot.map(AdmittedPolicySnapshot::snapshot),
                &request_id,
                &request_digest,
                &harness,
                &kind,
                &evaluated,
            )?;
            let value = serde_json::to_value(evaluated)
                .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
            (value, receipt)
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
        receipt,
    })
}

/// Evaluate a resident hook envelope against the already-installed in-memory
/// policy snapshot. No request can install, replace, or downgrade policy.
#[cfg(test)]
pub(crate) fn evaluate_envelope_with_store(
    envelope: GuardHookEnvelopeV2,
    policy_store: &crate::policy_store::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    evaluate_envelope_with_store_started(envelope, policy_store, Instant::now())
}

pub(crate) fn evaluate_envelope_with_store_started(
    envelope: GuardHookEnvelopeV2,
    policy_store: &crate::policy_store::PolicySnapshotStore,
    started_at: Instant,
) -> Result<Vec<u8>, String> {
    let validated = validate_envelope_shape(envelope, started_at)?;
    let envelope = &validated.envelope;
    let snapshot = policy_store.validate_request_snapshot(
        &envelope.policy_snapshot,
        &envelope.source.guard_home,
        envelope.policy_generation,
    )?;
    let _command_lease = policy_store.command_authority_lease(snapshot.snapshot())?;
    evaluate_validated_envelope(validated, Some(snapshot.as_ref()))
}

/// Evaluate against a snapshot while the policy store's request fence is
/// held. Approval challenge creation uses this entry point so the action,
/// snapshot, and derived bindings describe one coherent state.
pub(crate) fn evaluate_envelope_with_snapshot(
    envelope: GuardHookEnvelopeV2,
    snapshot: &AdmittedPolicySnapshot,
) -> Result<Vec<u8>, String> {
    let validated = validate_envelope_shape(envelope, Instant::now())?;
    evaluate_validated_envelope(validated, Some(snapshot))
}

#[cfg(test)]
#[path = "edge_tests.rs"]
mod tests;

#[cfg(all(test, feature = "diagnostic-allocations"))]
#[path = "edge_allocation_diagnostic.rs"]
mod allocation_diagnostic;
