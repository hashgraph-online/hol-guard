#![forbid(unsafe_code)]

use crate::hook_decision_containment_route::edge_route;
use crate::policy_enforcement::AdmittedPolicySnapshot;
use guard_contracts::{
    GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookOutputSummaryV1,
    HookSourceFileRefV1, NativeHookRequestV1, PreToolResultV1, GUARD_HOOK_EDGE_RESULT_V2_SCHEMA,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA, MAX_NATIVE_REQUEST_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use serde_json::Value;
use std::time::{Duration, Instant};

use crate::native_hook_receipt::{
    receipt_from_post_tool, receipt_from_pre_tool, NativeReceiptIdentity,
};

#[path = "edge_identity.rs"]
mod edge_identity;
use edge_identity::{
    canonical_identity_digest, request_id_is_safe, request_payload_identity,
    verdict_policy_identity, MAX_EVENT_BYTES, MAX_HARNESS_BYTES, MAX_PATH_BYTES,
};
pub(crate) use edge_identity::{policy_generation_matches, stable_policy_identity};

/// Bind the exact validated tool intent without policy-generation identity.
/// Policy evaluation remains bound by `request_identity`; this commitment is
/// the stable action/source input a native review's retry binding anchors to.
/// `home_dir` is bound because path resolution (`~`, dotfiles) depends on it.
pub(crate) fn execution_intent_digest(envelope: &GuardHookEnvelopeV2) -> Result<String, String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event = authoritative_event(envelope)?;
    let payload = request_payload_identity(&envelope.raw_payload, &harness, &event)?;
    let mut value = serde_json::json!({
        "schema": "guard-native-execution-intent.v2",
        "version": 2,
        "event": event,
        "harness": harness,
        "payload": payload,
        "source": {
            "cwd": envelope.source.cwd,
            "home_dir": envelope.source.home_dir,
        },
    });
    if let Some(context) = &envelope.source.execution_environment {
        value["source"]["execution_environment"] = serde_json::to_value(context)
            .map_err(|_| "native_hook_execution_intent_digest_failed")?;
    }
    canonical_identity_digest(&value, "native_hook_execution_intent_digest_failed")
}

/// Derive a stable opaque identity when the harness omitted a request ID.
/// The digest covers semantic request inputs only. Transport deadlines,
/// object field order, and event-alias spelling are deliberately excluded.
/// Raw request material remains inside the resident and never appears in an
/// approval result.
pub(crate) fn request_identity(envelope: &GuardHookEnvelopeV2) -> Result<(String, String), String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event = authoritative_event(envelope)?;
    let payload = request_payload_identity(&envelope.raw_payload, &harness, &event)?;
    let source = request_source(envelope, "native_hook_request_digest_failed")?;
    let value = serde_json::json!({
        "schema": "guard-native-request-identity.v3",
        "version": 3,
        "event": event,
        "harness": harness,
        "payload": payload,
        "policy": stable_policy_identity(&envelope.policy_snapshot, envelope.policy_generation),
        "source": source,
    });
    let digest = canonical_identity_digest(&value, "native_hook_request_digest_failed")?;
    let request_id = match envelope.request_id.as_deref() {
        Some(value) if request_id_is_safe(value) => value.to_owned(),
        Some(_) => return Err("native_hook_request_id_invalid".to_owned()),
        None => format!("sha256:{digest}"),
    };
    Ok((request_id, digest))
}

/// The full source material of a request. `execution_intent_digest` carries a
/// deliberately narrower source, so anything that has to stay bound to the
/// guard home, the home directory or the external source-ref flag builds its
/// commitment from this instead.
fn request_source(envelope: &GuardHookEnvelopeV2, error: &str) -> Result<Value, String> {
    let mut source = serde_json::json!({
        "cwd": envelope.source.cwd,
        "guard_home": envelope.source.guard_home,
        "home_dir": envelope.source.home_dir,
        "source_ref_external_allowed": envelope.source.source_ref_external_allowed,
    });
    if let Some(context) = &envelope.source.execution_environment {
        source["execution_environment"] =
            serde_json::to_value(context).map_err(|_| error.to_owned())?;
    }
    Ok(source)
}

/// Fence a one-time review approval to the action, its full source and the
/// part of policy that can decide a verdict. The snapshot `generation` and
/// `policy_digest` are deliberately absent: both move whenever the publisher
/// republishes, including for observed state that cannot weaken a verdict, and
/// a moved anchor strands the approval the identical retry was meant to find.
pub(crate) fn review_anchor_digest(
    envelope: &GuardHookEnvelopeV2,
    snapshot: Option<&guard_policy_snapshot::PolicySnapshotV3>,
) -> Result<String, String> {
    const FAILED: &str = "native_hook_review_anchor_digest_failed";
    let harness = canonical_harness(&envelope.harness)?;
    let event = authoritative_event(envelope)?;
    let payload = request_payload_identity(&envelope.raw_payload, &harness, &event)?;
    let value = serde_json::json!({
        "schema": "guard-native-review-anchor.v1",
        "version": 1,
        "event": event,
        "harness": harness,
        "payload": payload,
        "policy": verdict_policy_identity(snapshot, &envelope.policy_snapshot)?,
        "source": request_source(envelope, FAILED)?,
    });
    canonical_identity_digest(&value, FAILED)
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
        "devin-cli" | "cognition-devin" => "devin",
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
            | "devin"
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

pub(crate) fn payload_kind(payload: &Value) -> Result<GuardHookPayloadKindV2, String> {
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
    if !policy_generation_matches(&envelope.policy_snapshot, envelope.policy_generation) {
        return Err("native_hook_policy_generation_mismatch".to_owned());
    }
    let encoded = serde_json::to_vec(envelope)
        .map_err(|_| "native_hook_request_bounds_exceeded".to_owned())?;
    if encoded.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_hook_request_bounds_exceeded".to_owned());
    }
    // Optional lookup context is bounded by the whole-envelope transport cap.
    // Its tighter Git-specific limits are checked by git_config before quiet
    // admission; oversized environments must not reject unrelated file hooks.
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

fn validate_pre_tool_result(result: &Value) -> Result<(), String> {
    let typed: guard_contracts::PreToolResultV1 = serde_json::from_value(result.clone())
        .map_err(|_| "native_hook_pre_tool_result_invalid".to_owned())?;
    if typed.schema != "guard-pre-tool-result.v1" || typed.authority != "rust" {
        return Err("native_hook_pre_tool_result_schema_invalid".to_owned());
    }
    Ok(())
}

fn evaluate_validated_envelope(
    envelope: GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    origin_store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event_name = authoritative_event(&envelope)?;
    let kind = payload_kind(&envelope.raw_payload)?;
    let (request_id, request_digest) = request_identity(&envelope)?;
    let intent_digest = execution_intent_digest(&envelope)?;
    let anchor_digest = review_anchor_digest(
        &envelope,
        policy_snapshot.map(AdmittedPolicySnapshot::snapshot),
    )?;
    let receipt_identity = NativeReceiptIdentity {
        request_id: &request_id,
        request_digest: &request_digest,
        execution_intent_digest: Some(&intent_digest),
        review_anchor_digest: Some(&anchor_digest),
    };
    if kind == GuardHookPayloadKindV2::EncryptedPayloadRef {
        return Err("native_hook_encrypted_payload_unsupported".to_owned());
    }
    let (mut result, mut receipt) = match event_name.as_str() {
        "PreToolUse" | "UserPromptSubmit" => {
            let unavailable_environment =
                guard_contracts::GuardExecutionEnvironmentV1::unavailable();
            crate::edge_git_push::install();
            let native = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
                &harness,
                &event_name,
                &envelope.raw_payload,
                policy_snapshot.and_then(|snapshot| snapshot.command_extensions.as_ref()),
                Some(
                    Instant::now()
                        + Duration::from_millis(
                            envelope.deadline_budget_ms.unwrap_or(9_000).min(9_000),
                        ),
                ),
                guard_command::pretool::PathContext {
                    home_dir: Some(envelope.source.home_dir.as_str()),
                    cwd: envelope.source.cwd.as_deref(),
                    cdpath_unset: false,
                    rustup_override_absent: false,
                    npm_config_inert: false,
                    pip_config_inert: false,
                    shell_home_matches: false,
                    ripgrep_config_absent: false,
                    psql_environment: Default::default(),
                },
                Some(
                    envelope
                        .source
                        .execution_environment
                        .as_ref()
                        .unwrap_or(&unavailable_environment),
                ),
            );
            let native = crate::omp_yield_input_scan::scan(
                &envelope.raw_payload,
                envelope.deadline_budget_ms,
                native,
            )?;
            let evaluated = if let Some(snapshot) = policy_snapshot {
                crate::policy_enforcement::apply_pre_tool_policy(
                    snapshot,
                    &envelope.raw_payload,
                    native,
                )?
            } else {
                native
            };
            let evaluated = crate::native_exact_action_op::require_bash_owner(
                &envelope,
                policy_snapshot,
                evaluated,
            );
            let evaluated = crate::network_protection::apply_to_envelope(&envelope, evaluated);
            let value = serde_json::to_value(evaluated)
                .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
            validate_pre_tool_result(&value)?;
            let typed = serde_json::from_value::<PreToolResultV1>(value.clone())
                .map_err(|_| "native_hook_pre_tool_result_invalid".to_owned())?;
            let receipt = receipt_from_pre_tool(
                &envelope,
                policy_snapshot.map(AdmittedPolicySnapshot::snapshot),
                &receipt_identity,
                &harness,
                &kind,
                &typed,
            )?;
            (value, receipt)
        }
        "PostToolUse" => {
            let payload_kind = kind.clone();
            let request = NativeHookRequestV1 {
                protocol_version: NATIVE_PROTOCOL_VERSION,
                request_id: envelope.request_id.clone(),
                harness: harness.clone(),
                event_name: event_name.clone(),
                payload: envelope.raw_payload.clone(),
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
            let native = review_post_tool(&request);
            let mut evaluated = if let Some(snapshot) = policy_snapshot {
                let delivery = origin_store
                    .and_then(|store| crate::bash_post_delivery::verify(&request, store));
                crate::policy_enforcement::apply_post_tool_policy_with_delivery(
                    snapshot,
                    &request,
                    payload_kind,
                    native,
                    delivery.as_ref(),
                )?
            } else {
                native
            };
            // The policy join above may rewrite the verdict or the output
            // action, so the answer to "may the model read this" is settled
            // here, once, after everything that can change it has run.
            evaluated.seal_output_mask();
            let receipt = receipt_from_post_tool(
                &envelope,
                policy_snapshot.map(AdmittedPolicySnapshot::snapshot),
                &receipt_identity,
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
    if let Some(store) = origin_store {
        crate::policy_store::native_review_origin::authenticate(store, &mut receipt)?;
    }
    if event_name == "PreToolUse" {
        crate::command_policy_repair::apply(
            &mut result,
            policy_snapshot
                .and_then(|snapshot| snapshot.command_extensions.as_ref())
                .map(guard_command::native_command_controls::CompiledNativeCommandControls::health),
            std::path::Path::new(&envelope.source.guard_home),
        );
    }
    let harness_response = guard_command::hook_responses::render_edge_response(
        &harness,
        &event_name,
        &result,
        envelope.recording_only,
    )
    .map(Value::Object);
    crate::encode_response(&GuardHookEdgeResultV2 {
        // Every edge carries its route so no hook asks again; only PreToolUse is routed.
        containment_route: Some(edge_route(&event_name, &result, envelope.recording_only)),
        schema: GUARD_HOOK_EDGE_RESULT_V2_SCHEMA.to_owned(),
        authority: "rust".to_owned(),
        request_id: Some(request_id),
        harness,
        event_name,
        payload_kind: kind,
        result,
        harness_response,
        receipt,
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
    let _command_lease = policy_store.command_authority_lease(snapshot.snapshot())?;
    evaluate_validated_envelope(envelope, Some(snapshot.as_ref()), Some(policy_store))
}

/// Evaluate against a snapshot while the policy store's request fence is
/// held. Approval challenge creation uses this entry point so the action,
/// snapshot, and derived bindings describe one coherent state.
pub(crate) fn evaluate_envelope_with_snapshot(
    envelope: GuardHookEnvelopeV2,
    snapshot: &AdmittedPolicySnapshot,
) -> Result<Vec<u8>, String> {
    validate_envelope_shape(&envelope)?;
    evaluate_validated_envelope(envelope, Some(snapshot), None)
}

#[cfg(test)]
#[path = "edge_tests.rs"]
mod tests;
