use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ApplyStoredPackagePolicyRequestV1, ApprovalChallengeRequestV3, ApprovalChallengeRequestV4,
    ApprovalConsumeRequestV3, ApprovalConsumeRequestV4, ApprovalGateRequestV1,
    ApprovalReuseRequestV1, ApprovalValidateRequestV3, ApprovalValidateRequestV4,
    ClaimApprovalReuseDecisionsRequestV1, CommandEffectRequestV1, ContainedExecuteRequestV1,
    ContainedNodeExecuteRequestV1, ContainedPackageScriptExecuteRequestV1,
    ContainedTestHookRequestV1, ContainedTypescriptExecuteRequestV1,
    ContainedWorkspaceWriteExecuteRequestV1, ContextDigestRequestV1, DataFlowAnalyzeRequestV1,
    GitExecutionSafetyRequestV1, GithubCliClassifyRequestV1, GuardHookEnvelopeV2,
    LocalCliGrantRequestV1, LocalMcpGrantRequestV1, McpRuntimeEvidenceRequestV1,
    McpStdioProbeRequestV1, McpStdioSessionCloseRequestV1, McpStdioSessionOpenRequestV1,
    McpStdioSessionRecvRequestV1, McpStdioSessionSendRequestV1, McpToolEvidenceRequestV1,
    NativeHookRequestV1, PackageAdvisoryIdsRequestV1, PackageAuthorityDecideRequestV1,
    PackageEvaluationComposeRequestV1, PackageIntentParseRequestV1, PolicyDecisionLookupRequestV1,
    PromptAnalyzeRequestV1, RuntimeCapabilitiesV1, ShimAdminRequestV1,
    SkillDirectoryIdentityRequestV1, SupplyChainEvalRequestV1, MAX_NATIVE_RESPONSE_BYTES,
    NATIVE_APPROVAL_ERROR_CODES, NATIVE_PROTOCOL_VERSION, NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
};
use serde::Deserialize;
use serde_json::Value;

// Evaluation (`capabilities`/`evaluate_resident_bytes`) lives in
// `resident_ops.rs`; re-exported so `crate::resident_protocol::` call sites
// and the approval-contract token surface stay stable.
pub(crate) use crate::resident_ops::evaluate_resident_bytes;

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
        "native-local-business-review-summary-v1".into(),
        "native-local-business-review-queue-v1".into(),
        "native-workspace-review-decision-v1".into(),
        "native-policy-in-memory-v1".into(),
        "native-policy-snapshot-build-v1".into(),
        "native-policy-snapshot-inspect-v1".into(),
        "native-business-policy-retained-floor-v1".into(),
        "native-business-policy-document-compile-v1".into(),
        "native-business-source-codec-v1".into(),
        "native-business-source-anchor-codec-v1".into(),
        "native-business-source-current-fence-v2".into(),
        "hook-envelope-v2".into(),
        "git-execution-context-v1".into(),
        "native-resident-client-v1".into(),
        "native-resident-lifecycle-v1".into(),
        guard_contracts::ARCHIVE_INSPECTION_FEATURE.into(),
        guard_contracts::CONTEXT_DIGEST_FEATURE.into(),
        guard_contracts::COMMAND_EFFECT_FEATURE.into(),
        guard_contracts::APPROVAL_REUSE_FEATURE.into(),
        guard_contracts::GITHUB_CLI_CLASSIFY_FEATURE.into(),
        guard_contracts::CLAIM_APPROVAL_REUSE_FEATURE.into(),
        guard_contracts::APPROVAL_GATE_FEATURE.into(),
        guard_contracts::PACKAGE_AUTHORITY_FEATURE.into(),
        guard_contracts::PACKAGE_EVALUATION_COMPOSE_FEATURE.into(),
        guard_contracts::SHIM_ADMIN_FEATURE.into(),
        guard_contracts::MCP_STDIO_PROBE_FEATURE.into(),
        guard_contracts::PROMPT_ANALYZE_FEATURE.into(),
        guard_contracts::DATA_FLOW_ANALYZE_FEATURE.into(),
        guard_contracts::POLICY_DECISION_LOOKUP_FEATURE.into(),
        guard_contracts::GIT_EXECUTION_SAFETY_FEATURE.into(),
        guard_contracts::MCP_RUNTIME_EVIDENCE_FEATURE.into(),
        guard_contracts::LOCAL_CLI_GRANT_FEATURE.into(),
        guard_contracts::MCP_TOOL_EVIDENCE_FEATURE.into(),
        guard_contracts::LOCAL_MCP_GRANT_FEATURE.into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
        // Capability flags must reflect dispatch reality: features gated
        // cfg(unix) in resident_ops::evaluate_resident_bytes must not be
        // advertised on other platforms, or callers route work the binary
        // cannot honor.
        features.push(guard_contracts::CONTAINED_EXECUTION_FEATURE.into());
        features.push(guard_contracts::MCP_STDIO_SESSION_FEATURE.into());
        features.push(guard_contracts::SKILL_DIRECTORY_IDENTITY_FEATURE.into());
    }
    let (program_digest, catalog_digest, trust_digest) =
        guard_command::native_command_program::packaged_program_digests();
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: crate::PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: crate::BUILD_SHA.to_owned(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        features,
        program_digest,
        catalog_digest,
        trust_digest,
    }
}

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
    WorkspaceReviewLocalSummary(WorkspaceReviewContextRequestV1),
    WorkspaceReviewLocalQueue(WorkspaceReviewLocalQueueRequestV1),
    WorkspaceReviewDecision(WorkspaceReviewDecisionRequestV1),
    ContextDigest(ContextDigestRequestV1),
    CommandEffectDecide(CommandEffectRequestV1),
    ApprovalReuseDecide(ApprovalReuseRequestV1),
    GithubCliClassify(GithubCliClassifyRequestV1),
    ClaimApprovalReuseDecisions(ClaimApprovalReuseDecisionsRequestV1),
    ApprovalGate(ApprovalGateRequestV1),
    PackageIntentParse(PackageIntentParseRequestV1),
    SupplyChainEval(SupplyChainEvalRequestV1),
    ApplyStoredPackagePolicy(ApplyStoredPackagePolicyRequestV1),
    PackageAuthorityDecide(PackageAuthorityDecideRequestV1),
    #[allow(dead_code)]
    ContainedNodeExecute(ContainedNodeExecuteRequestV1),
    #[allow(dead_code)]
    ContainedTypescriptExecute(ContainedTypescriptExecuteRequestV1),
    #[allow(dead_code)]
    ContainedPackageScriptExecute(ContainedPackageScriptExecuteRequestV1),
    #[allow(dead_code)]
    ContainedWorkspaceWriteExecute(ContainedWorkspaceWriteExecuteRequestV1),
    #[allow(dead_code)]
    ContainedExecute(ContainedExecuteRequestV1),
    #[allow(dead_code)]
    ContainedTestHook(ContainedTestHookRequestV1),
    ShimAdmin(ShimAdminRequestV1),
    McpStdioProbe(McpStdioProbeRequestV1),
    McpStdioCancel(McpStdioCancelRequest),
    McpStdioSessionOpen(McpStdioSessionOpenRequestV1),
    McpStdioSessionSend(McpStdioSessionSendRequestV1),
    McpStdioSessionRecv(McpStdioSessionRecvRequestV1),
    McpStdioSessionClose(McpStdioSessionCloseRequestV1),
    PackageAdvisoryIds(PackageAdvisoryIdsRequestV1),
    PackageEvaluationCompose(PackageEvaluationComposeRequestV1),
    PolicyDecisionLookup(PolicyDecisionLookupRequestV1),
    GitExecutionSafety(GitExecutionSafetyRequestV1),
    McpRuntimeEvidence(McpRuntimeEvidenceRequestV1),
    LocalCliGrantDecide(LocalCliGrantRequestV1),
    McpToolEvidence(McpToolEvidenceRequestV1),
    LocalMcpGrantDecide(LocalMcpGrantRequestV1),
    SkillDirectoryIdentity(SkillDirectoryIdentityRequestV1),
    #[allow(dead_code)]
    PromptAnalyze(PromptAnalyzeRequestV1),
    DataFlowAnalyze(DataFlowAnalyzeRequestV1),
    Health(Value),
    Shutdown(Value),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpStdioCancelRequest {
    pub(crate) request_id: String,
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
pub(crate) struct WorkspaceReviewLocalQueueRequestV1 {}

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
    serde_json::to_vec(&serde_json::json!({
        "error": "native_request_invalid_json",
        "retryable": retryable,
    }))
    .unwrap_or_else(|_| error_response("native_request_invalid_json", retryable))
}

#[cfg(test)]
mod tests {
    use super::{evaluate_resident_bytes, safe_error_response};
    use guard_contracts::NATIVE_APPROVAL_MAX_BYTES;
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
        for code in [
            "native_business_policy_floor_invalid",
            "native_business_policy_removal_requires_authority",
            "native_business_source_authority_missing",
            "native_business_source_authority_invalid",
            "native_business_source_authority_not_current",
            "native_business_source_mutation_in_progress",
            "native_business_source_enforce_required",
        ] {
            let response: Value =
                serde_json::from_slice(&safe_error_response(code, false)).unwrap();
            assert_eq!(response["error"], code);
            assert_eq!(response["retryable"], false);
        }
        let unknown_business: Value = serde_json::from_slice(&safe_error_response(
            "native_business_policy_future_unregistered_code",
            false,
        ))
        .unwrap();
        assert_eq!(unknown_business["error"], "native_request_invalid_json");
    }

    #[test]
    fn approval_requests_have_a_smaller_raw_payload_bound() {
        let padding = "x".repeat(NATIVE_APPROVAL_MAX_BYTES);
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

#[cfg(test)]
mod capability_platform_tests {
    #[test]
    fn prompt_capability_is_portable_and_containment_matches_dispatch() {
        let features = super::capabilities().features;
        assert!(features
            .iter()
            .any(|feature| feature == guard_contracts::PROMPT_ANALYZE_FEATURE));
        assert!(features
            .iter()
            .any(|feature| feature == guard_contracts::DATA_FLOW_ANALYZE_FEATURE));
        assert_eq!(
            features
                .iter()
                .any(|feature| feature == guard_contracts::CONTAINED_EXECUTION_FEATURE),
            cfg!(unix)
        );
    }
}
