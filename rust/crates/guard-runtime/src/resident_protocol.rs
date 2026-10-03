use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ApprovalChallengeRequestV3, ApprovalChallengeRequestV4, ApprovalConsumeRequestV3,
    ApprovalConsumeRequestV4, ApprovalValidateRequestV3, ApprovalValidateRequestV4,
    ContextDigestRequestV1, GuardHookEnvelopeV2, NativeHookRequestV1, RuntimeCapabilitiesV1,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA, MAX_NATIVE_RESPONSE_BYTES, NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_APPROVAL_MAX_BYTES, NATIVE_PROTOCOL_VERSION, NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
};
use guard_hook_core::review_post_tool;
use guard_policy_snapshot::canonical_json_bytes;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;

use crate::policy_store::PolicySnapshotStore;

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
pub(crate) enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
    PreToolUse(CommandModelRequestV1),
    PolicySnapshotPush(Value),
    ApprovalChallenge(ApprovalChallengeRequestV3),
    ApprovalValidate(ApprovalValidateRequestV3),
    ApprovalConsume(ApprovalConsumeRequestV3),
    ApprovalChallengeV4(ApprovalChallengeRequestV4),
    ApprovalValidateV4(ApprovalValidateRequestV4),
    ApprovalConsumeV4(ApprovalConsumeRequestV4),
    WorkspaceReviewAuthorityEnroll(WorkspaceReviewAuthorityEnrollRequestV1),
    WorkspaceReviewContext(WorkspaceReviewContextRequestV1),
    WorkspaceReviewDecision(WorkspaceReviewDecisionRequestV1),
    ContextDigest(ContextDigestRequestV1),
    Health(Value),
    Shutdown(Value),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewDecisionRequestV1 {
    pub(crate) request_id: String,
    pub(crate) decision: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewContextRequestV1 {
    pub(crate) request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewAuthorityEnrollRequestV1 {
    pub(crate) record_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ResidentRequestV1 {
    Operation(Box<ResidentOperationV1>),
    Edge(GuardHookEnvelopeV2),
    Hook(NativeHookRequestV1),
}

pub(crate) fn capabilities() -> RuntimeCapabilitiesV1 {
    let mut features = vec![
        "post-tool-inline-v1".into(),
        "post-tool-source-read-v1".into(),
        "oneshot-v1".into(),
        "framed-serve-v1".into(),
        "resident-protocol-v2".into(),
        "bounded-admission-v2".into(),
        "overload-signal-v1".into(),
        "panic-containment-v1".into(),
        "rule-contract-v2".into(),
        "pre-tool-command-model-shadow-v1".into(),
        "resident-command-model-shadow-v1".into(),
        "pre-tool-command-authority-v1".into(),
        "pre-tool-generic-authority-v1".into(),
        guard_contracts::NATIVE_COMMAND_PROGRAM_CAPABILITY.into(),
        guard_contracts::NATIVE_COMMAND_CONTROL_FENCE_CAPABILITY.into(),
        "policy-snapshot-v3".into(),
        "policy-snapshot-push-v1".into(),
        "policy-snapshot-resident-generation-v1".into(),
        "native-approval-artifact-v3".into(),
        "native-approval-challenge-v3".into(),
        "native-approval-validation-v3".into(),
        "native-approval-consume-v3".into(),
        "native-approval-webauthn-v4".into(),
        "native-approval-challenge-v4".into(),
        "native-approval-validation-v4".into(),
        "native-approval-consume-v4".into(),
        "native-approval-replay-memory-v1".into(),
        "native-workspace-review-authority-v1".into(),
        "native-workspace-review-enrollment-resident-v1".into(),
        "native-workspace-review-context-v1".into(),
        "native-workspace-review-decision-v1".into(),
        "native-policy-in-memory-v1".into(),
        "hook-envelope-v2".into(),
        "native-resident-client-v1".into(),
        "native-resident-lifecycle-v1".into(),
        guard_contracts::ARCHIVE_INSPECTION_FEATURE.into(),
        guard_contracts::CONTEXT_DIGEST_FEATURE.into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
    }
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: crate::PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: crate::BUILD_SHA.to_owned(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        features,
    }
}

pub(crate) fn evaluate_resident_bytes(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    if matches!(
        value.get("operation").and_then(Value::as_str),
        Some(
            "workspace_review_authority_enroll"
                | "workspace_review_context"
                | "workspace_review_decision"
        )
    ) {
        let canonical = canonical_json_bytes(&value)
            .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
        if canonical != bytes {
            return Err("native_workspace_review_decision_noncanonical".to_owned());
        }
    }
    if bytes.len() > NATIVE_APPROVAL_MAX_BYTES
        && matches!(
            value.get("operation").and_then(Value::as_str),
            Some(
                "approval_challenge"
                    | "approval_validate"
                    | "approval_consume"
                    | "approval_challenge_v4"
                    | "approval_validate_v4"
                    | "approval_consume_v4",
            )
        )
    {
        return Err("native_approval_request_bounds_exceeded".to_owned());
    }
    if value.get("operation").and_then(Value::as_str) == Some("policy_snapshot_push") {
        let object = value
            .as_object()
            .ok_or_else(|| "native_policy_snapshot_push_invalid".to_owned())?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "operation" | "request" | "deadline_budget_ms"))
        {
            return Err("native_policy_snapshot_push_invalid".to_owned());
        }
    }
    if value.get("operation").is_none()
        && value.get("schema").and_then(Value::as_str) != Some(GUARD_HOOK_ENVELOPE_V2_SCHEMA)
    {
        crate::oneshot::validate_request_policy_snapshot(&value)?;
    }
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
    match request {
        ResidentRequestV1::Edge(request) => {
            let policy_store =
                policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
            crate::edge::evaluate_envelope_with_store(request, policy_store)
        }
        ResidentRequestV1::Operation(request) => match *request {
            ResidentOperationV1::CommandModel(request) => {
                crate::oneshot::evaluate_command_model_request(&request)
            }
            ResidentOperationV1::PreToolUse(request) => {
                crate::oneshot::evaluate_pre_tool_request(&request)
            }
            ResidentOperationV1::PolicySnapshotPush(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                policy_store.push(&request)
            }
            ResidentOperationV1::ApprovalChallenge(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::create_challenge(request, policy_store)
            }
            ResidentOperationV1::ApprovalValidate(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::validate_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalConsume(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::consume_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalChallengeV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::create_challenge(request, policy_store)
            }
            ResidentOperationV1::ApprovalValidateV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::validate_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalConsumeV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::consume_approval(request, policy_store)
            }
            ResidentOperationV1::WorkspaceReviewAuthorityEnroll(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                if request.record_path.is_empty()
                    || request.record_path.len() > 4096
                    || !Path::new(&request.record_path).is_absolute()
                {
                    return Err("native_workspace_review_authority_invalid".to_owned());
                }
                crate::policy_store::workspace_review_authority::install_record(
                    policy_store.state_base(),
                    Path::new(&request.record_path),
                )?;
                encode_response(&serde_json::json!({"status": "enrolled"}))
            }
            ResidentOperationV1::WorkspaceReviewContext(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                let context =
                    crate::policy_store::resident_workspace_review_context::build_context(
                        policy_store,
                        &request.request_id,
                    )?;
                encode_response(&context)
            }
            ResidentOperationV1::WorkspaceReviewDecision(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                let verified =
                    crate::policy_store::workspace_review_decision::verify_and_claim_request(
                        policy_store,
                        &request.request_id,
                        &request.decision,
                    )?;
                encode_response(&serde_json::json!({
                    "status": if verified.replayed { "replayed" } else { "verified" },
                    "replayed": verified.replayed,
                    "request_id": request.request_id,
                    "decision": verified.decision,
                    "claim_id": verified.claim_id,
                    "authority_record_digest": verified.authority_record_digest,
                    "workspace_binding": verified.workspace_binding,
                    "device_binding": verified.device_binding,
                    "installation_binding": verified.installation_binding,
                    "scope_binding": verified.scope_binding,
                    "request_binding": verified.request_binding,
                    "action_binding": verified.action_binding,
                    "intent_binding": verified.intent_binding,
                    "revision_binding": verified.revision_binding,
                    "policy_binding": verified.policy_binding,
                    "retry_scope_binding": verified.retry_scope_binding,
                    "request_snapshot_digest": verified.request_snapshot_digest,
                    "envelope_digest": verified.envelope_digest,
                }))
            }
            ResidentOperationV1::ContextDigest(request) => {
                crate::context_digest::evaluate_context_digest_request(&request)
            }
            ResidentOperationV1::Health(_request) => encode_response(&serde_json::json!({
                "status": "ready",
                "protocol_version": crate::RESIDENT_PROTOCOL_VERSION,
            })),
            ResidentOperationV1::Shutdown(_request) => {
                crate::managed_resident::request_shutdown();
                encode_response(&serde_json::json!({"status": "stopping"}))
            }
        },
        ResidentRequestV1::Hook(request) => {
            // Managed residents always carry a v3 policy store. The legacy
            // request has no generation-bound snapshot and must never reach a
            // semantic evaluator in that path.
            if policy_store.is_some() {
                Err("native_policy_snapshot_required".to_owned())
            } else {
                encode_response(&review_post_tool(&request))
            }
        }
    }
}

pub(crate) fn strict_json_value(bytes: &[u8]) -> Result<Value, String> {
    crate::strict_json::parse(bytes)
}

pub(crate) fn encode_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    Ok(encoded)
}

pub(crate) fn error_response(code: &'static str, retryable: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": code, "retryable": retryable})).unwrap_or_else(
        |_| b"{\"error\":\"native_response_encode_failed\",\"retryable\":false}".to_vec(),
    )
}

pub(crate) fn safe_error_response(code: &str, retryable: bool) -> Vec<u8> {
    if NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES.contains(&code)
        || NATIVE_APPROVAL_ERROR_CODES.contains(&code)
        || guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.contains(&code)
    {
        return serde_json::to_vec(&serde_json::json!({
            "error": code,
            "retryable": retryable,
        }))
        .unwrap_or_else(|_| error_response("native_response_encode_failed", false));
    }
    error_response("native_request_invalid_json", retryable)
}

#[cfg(test)]
mod tests {
    use super::{evaluate_resident_bytes, safe_error_response};
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn policy_store() -> (crate::policy_store::PolicySnapshotStore, PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-resident-enrollment-test-{}-{suffix}",
            std::process::id()
        ));
        #[cfg(windows)]
        let root = crate::resident_state::ensure_private_directory(&root, true).unwrap();
        #[cfg(not(windows))]
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key_path = root.join("policy-verifier.key");
        #[cfg(windows)]
        {
            use std::io::Write;
            let mut file = crate::resident_state::private_file(&key_path, false, &root).unwrap();
            file.write_all(&[23u8; 32]).unwrap();
        }
        #[cfg(not(windows))]
        fs::write(&key_path, [23u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        (store, root)
    }

    #[test]
    fn approval_error_transport_is_finite() {
        let known: Value =
            serde_json::from_slice(&safe_error_response("native_approval_replay", false))
                .expect("known approval error is JSON");
        assert_eq!(known["error"], "native_approval_replay");

        let unknown: Value = serde_json::from_slice(&safe_error_response(
            "native_approval_future_unregistered_code",
            false,
        ))
        .expect("redacted approval error is JSON");
        assert_eq!(unknown["error"], "native_request_invalid_json");

        let lifecycle: Value = serde_json::from_slice(&safe_error_response(
            "native_resident_start_in_progress",
            true,
        ))
        .expect("known lifecycle error is JSON");
        assert_eq!(lifecycle["error"], "native_resident_start_in_progress");

        let unknown_lifecycle: Value = serde_json::from_slice(&safe_error_response(
            "native_resident_future_unregistered_code",
            false,
        ))
        .expect("redacted lifecycle error is JSON");
        assert_eq!(unknown_lifecycle["error"], "native_request_invalid_json");

        let unknown_policy: Value = serde_json::from_slice(&safe_error_response(
            "native_policy_snapshot_future_unregistered_code",
            false,
        ))
        .expect("redacted policy error is JSON");
        assert_eq!(unknown_policy["error"], "native_request_invalid_json");
    }

    #[test]
    fn approval_requests_have_a_smaller_raw_payload_bound() {
        let padding = "x".repeat(super::NATIVE_APPROVAL_MAX_BYTES);
        let request =
            format!(r#"{{"operation":"approval_challenge","request":{{"padding":"{padding}"}}}}"#);
        assert_eq!(
            evaluate_resident_bytes(request.as_bytes(), None).unwrap_err(),
            "native_approval_request_bounds_exceeded"
        );
    }

    #[test]
    fn resident_workspace_enrollment_requires_canonical_absolute_candidate() {
        let (store, root) = policy_store();
        let relative = br#"{"operation":"workspace_review_authority_enroll","request":{"record_path":"relative.json"}}"#;
        assert_eq!(
            evaluate_resident_bytes(relative, Some(&store)).unwrap_err(),
            "native_workspace_review_authority_invalid"
        );
        let noncanonical = br#"{"request":{"record_path":"relative.json"},"operation":"workspace_review_authority_enroll"}"#;
        assert_eq!(
            evaluate_resident_bytes(noncanonical, Some(&store)).unwrap_err(),
            "native_workspace_review_decision_noncanonical"
        );
        let absent = serde_json::json!({
            "operation": "workspace_review_authority_enroll",
            "request": {"record_path": root.join("absent.json").to_string_lossy()},
        });
        let canonical = guard_policy_snapshot::canonical_json_bytes(&absent).unwrap();
        assert_eq!(
            evaluate_resident_bytes(&canonical, Some(&store)).unwrap_err(),
            "native_workspace_review_authority_missing"
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
