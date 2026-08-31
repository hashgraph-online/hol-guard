#![forbid(unsafe_code)]

use guard_contracts::{
    GuardHookEdgeResultV2, GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookOutputSummaryV1,
    HookSourceFileRefV1, NativeHookRequestV1, GUARD_HOOK_EDGE_RESULT_V2_SCHEMA,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::Value;

const MAX_HARNESS_BYTES: usize = 64;
const MAX_EVENT_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 256;

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
    if let Some(request_id) = envelope.request_id.as_deref() {
        bounded_nonempty(
            request_id,
            MAX_REQUEST_ID_BYTES,
            "native_hook_request_id_invalid",
        )?;
    }
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
        request_id: envelope.request_id,
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
    evaluate_validated_envelope(envelope, Some(&snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    static EDGE_FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn envelope(event: &str, payload: Value) -> GuardHookEnvelopeV2 {
        let digest = "a".repeat(64);
        let guard_home = std::env::temp_dir().join(format!(
            "hol-guard-native-edge-generation-test-{}-{}",
            std::process::id(),
            EDGE_FIXTURE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&guard_home).expect("create edge generation fixture");
        std::fs::write(
            guard_home.join("native-policy-generation.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "hol-guard-native-policy-generation.v1",
                "generation": 1,
                "policy_digest": digest.clone(),
            }))
            .expect("encode edge generation fixture"),
        )
        .expect("write edge generation fixture");
        GuardHookEnvelopeV2 {
            schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
            request_id: Some("edge-test".to_owned()),
            harness: "Claude".to_owned(),
            event: event.to_owned(),
            raw_payload: payload,
            deadline_budget_ms: Some(100),
            policy_generation: 1,
            policy_snapshot: serde_json::json!({
                "schema": "hol-guard-native-policy.v1",
                "generation": 1,
                "policy_digest": digest,
                "config_digest": "b".repeat(64),
                "rule_digest": guard_rule_contract::rule_digest(),
                "mode": "enforce"
            }),
            source: guard_contracts::GuardHookSourceMetadataV2 {
                cwd: Some("/workspace".to_owned()),
                home_dir: "/home/test".to_owned(),
                guard_home: guard_home.to_string_lossy().into_owned(),
                source_ref_external_allowed: false,
            },
        }
    }

    fn evaluate_isolated(envelope: GuardHookEnvelopeV2) -> Result<Vec<u8>, String> {
        let guard_home = std::path::PathBuf::from(&envelope.source.guard_home);
        let result = validate_envelope_shape(&envelope)
            .and_then(|_| evaluate_validated_envelope(envelope, None));
        std::fs::remove_dir_all(guard_home).expect("remove edge generation fixture");
        result
    }

    #[test]
    fn normalizes_harness_event_and_extracts_pretool_command() {
        let bytes = evaluate_isolated(envelope(
            "pre_tool_use",
            serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_input": {"command": "pwd"}
            }),
        ))
        .unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.harness, "claude-code");
        assert_eq!(result.event_name, "PreToolUse");
        assert_eq!(result.result["minimum_action"], "allow");
    }

    #[test]
    fn rejects_declared_and_payload_event_mismatch() {
        let error = evaluate_isolated(envelope(
            "PreToolUse",
            serde_json::json!({"hook_event_name": "PostToolUse"}),
        ))
        .unwrap_err();
        assert_eq!(error, "native_hook_event_mismatch");
    }

    #[test]
    fn rejects_conflicting_payload_event_aliases() {
        let error = evaluate_isolated(envelope(
            "PreToolUse",
            serde_json::json!({
                "event": "PreToolUse",
                "hook_event_name": "PostToolUse",
                "tool_input": {"command": "pwd"}
            }),
        ))
        .unwrap_err();
        assert_eq!(error, "native_hook_event_mismatch");
    }

    #[test]
    fn rejects_unknown_harness_before_command_evaluation() {
        let mut request = envelope(
            "PreToolUse",
            serde_json::json!({"tool_input": {"command": "pwd"}}),
        );
        request.harness = "unknown-agent".to_owned();
        let error = evaluate_isolated(request).unwrap_err();
        assert_eq!(error, "native_hook_harness_unsupported");
    }

    #[test]
    fn rejects_malformed_source_reference_before_review() {
        let error = evaluate_isolated(envelope(
            "PostToolUse",
            serde_json::json!({"guard_source_ref": {"path": 1}}),
        ))
        .unwrap_err();
        assert_eq!(error, "native_hook_source_ref_invalid");
    }

    #[test]
    fn evaluates_complete_cursor_file_envelope_as_native_generic_result() {
        let bytes = evaluate_isolated(envelope(
            "beforeReadFile",
            serde_json::json!({
                "event": "beforeReadFile",
                "toolName": "read_file",
                "toolInput": {"file_path": "README.md"}
            }),
        ))
        .unwrap();
        let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.event_name, "PreToolUse");
        assert_eq!(result.result["schema"], "guard-pre-tool-result.v1");
        assert_eq!(result.result["authority"], "rust");
        assert_eq!(result.result["action"]["action_type"], "file_read");
        assert_eq!(result.result["minimum_action"], "review");
        assert!(result.result.get("raw_payload").is_none());
    }

    #[test]
    fn evaluates_generic_pretool_for_supported_harness_aliases() {
        for (harness, expected) in [
            ("Claude", "claude-code"),
            ("Codex", "codex"),
            ("Cline", "cline"),
            ("Cursor", "cursor"),
            ("Copilot", "copilot"),
            ("Grok", "grok"),
            ("Z-Code", "zcode"),
        ] {
            let mut request = envelope(
                "PreToolUse",
                serde_json::json!({
                    "hook_event_name": "PreToolUse",
                    "toolName": "read_file",
                    "toolInput": {"file_path": "README.md"}
                }),
            );
            request.harness = harness.to_owned();
            let bytes = evaluate_isolated(request).unwrap();
            let result: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(result.harness, expected);
            assert_eq!(result.result["action"]["harness"], expected);
            assert_eq!(result.result["action"]["action_type"], "file_read");
            assert_eq!(result.result["minimum_action"], "review");
        }
    }

    #[test]
    fn unknown_and_ambiguous_pretool_payloads_never_receive_an_allow_floor() {
        let unknown = evaluate_isolated(envelope(
            "PreToolUse",
            serde_json::json!({"toolName": "future_tool", "opaque": true}),
        ))
        .unwrap();
        let unknown_result: GuardHookEdgeResultV2 = serde_json::from_slice(&unknown).unwrap();
        assert_eq!(unknown_result.result["minimum_action"], "review");

        let ambiguous = evaluate_isolated(envelope(
            "PreToolUse",
            serde_json::json!({"command": "pwd", "cmd": "whoami"}),
        ))
        .unwrap();
        let ambiguous_result: GuardHookEdgeResultV2 = serde_json::from_slice(&ambiguous).unwrap();
        assert_eq!(ambiguous_result.result["minimum_action"], "block");
        assert_eq!(
            ambiguous_result.result["reason_code"],
            "native_pre_tool_ambiguous_payload"
        );
    }
}
