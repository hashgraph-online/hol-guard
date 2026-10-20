use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ApplyStoredPackagePolicyRequestV1, ApprovalBulkEligibilityRequestV1,
    ApprovalChallengeRequestV3, ApprovalChallengeRequestV4, ApprovalConsumeRequestV3,
    ApprovalConsumeRequestV4, ApprovalGateRequestV1, ApprovalProofRequestV1,
    ApprovalQueueIdentityRequestV1, ApprovalResolutionPlanRequestV1,
    ApprovalReuseDiagnosticRequestV1, ApprovalReuseRequestV1, ApprovalScopeRequestV1,
    ApprovalValidateRequestV3, ApprovalValidateRequestV4, ArtifactRiskRequestV1,
    CiscoPreflightRequestV1, ClaimApprovalReuseDecisionsRequestV1, CodexRequestResumeRequestV1,
    CodexToolOutputRequestV1, CommandEffectBatchRequestV1, CommandEffectRequestV1,
    CompoundGitInspectionRequestV1, ConnectorSetupContextRequestV1,
    ConsumerArtifactComposeRequestV1, ConsumerArtifactProjectRequestV1, ContainedExecuteRequestV1,
    ContainedNodeExecuteRequestV1, ContainedPackageScriptExecuteRequestV1,
    ContainedTypescriptExecuteRequestV1, ContainedWorkspaceWriteExecuteRequestV1,
    ContextDigestRequestV1, ContributedMcpDecisionRequestV1, CursorObserverProofRequestV1,
    DaemonHandlerRequestV1, DaemonLifecycleDecisionRequestV1, DaemonRouteRequestV1,
    DataFlowAnalyzeRequestV1, GitExecutionSafetyRequestV1, GithubCliClassifyRequestV1,
    GuardHookEnvelopeV2, GuardStoreRequestV1, HookAdapterRequestV1, HookArtifactComposeRequestV1,
    HookAuthorityStateRequestV1, HookDecisionRequestV1, LocalCliGrantRequestV1,
    LocalCliHookRequestV1, LocalMcpGrantRequestV1, LocalToolEligibilityRequestV1,
    McpClassificationRequestV1, McpProxyDecisionRequestV1, McpRuntimeEvidenceRequestV1,
    McpStdioProbeRequestV1, McpStdioSessionCloseRequestV1, McpStdioSessionOpenRequestV1,
    McpStdioSessionRecvRequestV1, McpStdioSessionSendRequestV1, McpToolCallIdentityRequestV1,
    McpToolEvidenceRequestV1, McpToolPolicyDecideRequestV1, NativeExactActionRequestV1,
    NativeHookRequestV1, PackageAdvisoryIdsRequestV1, PackageApprovalHashRequestV1,
    PackageAuditProjectionRequestV1, PackageAuthorityDecideRequestV1, PackageContextBuildRequestV1,
    PackageEvaluationComposeRequestV1, PackageIntentParseRequestV1, PackagePolicyResolveRequestV1,
    PackagePostureRequestV1, PackageProtectFinalizeRequestV1, PackageRequestArtifactRequestV1,
    PolicyBundleAuthorityRequestV1, PolicyDecisionLookupRequestV1, PolicyIntegrityRowsRequestV1,
    PromptAnalyzeRequestV1, ProtectRequestRequestV1, RequestContextRequestV1,
    RunnerAuthorityRequestV1, RuntimeCapabilitiesV1, RuntimeDetectorRunRequestV1,
    ShimAdminRequestV2, SkillDirectoryIdentityRequestV1, SupplyChainEvalRequestV1,
    WorkspaceInventoryRequestV1, MAX_NATIVE_RESPONSE_BYTES, NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_PROTOCOL_VERSION, NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
};
use serde::Deserialize;
use serde_json::Value;

// Evaluation lives in `resident_ops.rs`; re-exported so `crate::resident_protocol::`
// call sites and the approval-contract token surface stay stable.
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
        "rich-command-model-v1".into(),
        "pre-tool-command-authority-v1".into(),
        crate::oneshot::PRE_TOOL_PATH_CONTEXT_FEATURE.into(),
        crate::oneshot::PRE_TOOL_EXECUTION_ENVIRONMENT_FEATURE.into(),
        "pre-tool-generic-authority-v1".into(),
        guard_contracts::NATIVE_COMMAND_PROGRAM_CAPABILITY.into(),
        guard_contracts::NATIVE_COMMAND_CONTROL_FENCE_CAPABILITY.into(),
        "policy-snapshot-v3".into(),
        "policy-snapshot-push-v1".into(),
        "policy-snapshot-resident-generation-v1".into(),
        "policy-snapshot-direct-lane-v1".into(),
        crate::hook_direct::HOOK_DIRECT_FEATURE.into(),
        crate::hook_direct::HOOK_DIRECT_CONTAINED_ROUTE_FEATURE.into(),
        crate::hook_direct::HOOK_DIRECT_PERMISSION_NOTICE_FEATURE.into(),
        crate::hook_direct::HOOK_DIRECT_SAVED_DECISION_FEATURE.into(),
        crate::hook_direct::HOOK_DIRECT_STRUCTURED_OUTPUT_FEATURE.into(),
        crate::policy_store::policy_store_direct_lane::HOOK_DIRECT_REVIEW_FACTS_FEATURE.into(),
        crate::hook_direct_evidence::HOOK_DIRECT_EVIDENCE_FEATURE.into(),
        crate::directory_trust::DIRECTORY_TRUST_FEATURE.into(),
        crate::directory_trust::HOOK_PATH_RULES_FEATURE.into(),
        crate::mcp_relay_decide::MCP_RELAY_DECIDE_FEATURE.into(),
        crate::mcp_relay_servers::MCP_RELAY_SERVER_REPORT_FEATURE.into(),
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
        "native-guard-config-load-v1".into(),
        "native-guard-config-update-v1".into(),
        "native-policy-effective-v1".into(),
        "native-business-source-codec-v1".into(),
        "native-business-source-anchor-codec-v1".into(),
        "native-business-source-current-fence-v2".into(),
        "hook-envelope-v2".into(),
        "hook-harness-response-v1".into(),
        "git-execution-context-v1".into(),
        "native-resident-client-v1".into(),
        "shell-helpers-v1".into(),
        "native-resident-lifecycle-v1".into(),
        "secrets-cli-v1".into(),
    ];
    features.extend(
        crate::resident_op_features::RESIDENT_OP_FEATURES
            .iter()
            .map(|feature| (*feature).into()),
    );
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    // The MCP stdio session child runs in a process group on unix and in a
    // kill-on-close JobObject on Windows.
    if cfg!(any(unix, windows)) {
        features.push(guard_contracts::MCP_STDIO_SESSION_FEATURE.into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
        // Features gated cfg(unix) in resident_ops::evaluate_resident_bytes must
        // not be advertised elsewhere, or callers route work the binary cannot honor.
        features.push(guard_contracts::CONTAINED_EXECUTION_FEATURE.into());
        // The module is #[cfg(unix)]. A runtime cfg! check still type-checks
        // this path on Windows, where the module is not compiled.
        #[cfg(unix)]
        features.push(crate::binding_capture_op::BINDING_CAPTURE_FEATURE.into());
    }
    features.push(crate::mcp_relay::RELAY_FEATURE.into());
    features.push(crate::hook_evidence_writer_op::HOOK_EVIDENCE_WRITER_FEATURE.into());
    features.push(crate::claude_session_start::SESSION_START_FEATURE.into());
    features.push(crate::claude_hook_bridge::BRIDGE_FEATURE.into());
    features.push(crate::codex_hook_bridge::BRIDGE_FEATURE.into());
    features.push(crate::bounded_hook_bridge::BRIDGE_FEATURE.into());
    features.push(crate::cursor_hook_bridge::BRIDGE_FEATURE.into());
    features.push(crate::pi_hook_bridge::BRIDGE_FEATURE.into());
    features.push(guard_contracts::SKILL_DIRECTORY_IDENTITY_FEATURE.into());
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
    ArchiveAcquisition(guard_contracts::ArchiveAcquisitionRequestV1),
    CommandModel(CommandModelRequestV1),
    RichCommandModel(crate::rich_command_model_op::RichCommandModelRequest),
    PreToolUse(crate::oneshot::PreToolRequestV1),
    PolicySnapshotPush(Value),
    HookDirect(crate::hook_direct::HookDirectRequestV1),
    HookDirectEvidenceDrain(crate::hook_direct_evidence::HookDirectEvidenceDrainRequestV1),
    McpRelayDecide(crate::mcp_relay_decide::McpRelayDecideRequestV1),
    McpRelayCommit(crate::mcp_relay_pending::McpRelayCommitRequestV1),
    McpRelayReady(crate::mcp_relay_ready::McpRelayReadyRequestV1),
    McpRelayClaim(crate::mcp_relay_claims::McpRelayClaimRequestV1),
    McpRelayServerReport(crate::mcp_relay_servers::McpRelayServerReportRequestV1),
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
    DirectoryTrust(crate::directory_trust::DirectoryTrustRequestV1),
    CommandEffectDecide(CommandEffectRequestV1),
    CommandEffectDecideBatch(CommandEffectBatchRequestV1),
    ApprovalReuseDecide(ApprovalReuseRequestV1),
    NativeBashPrepare(guard_contracts::NativeBashPrepareRequestV1),
    NativeBashExecute(guard_contracts::NativeBashExecuteRequestV1),
    NativeBashCancel(guard_contracts::NativeBashCancelRequestV1),
    NativeBashActivity(guard_contracts::NativeBashActivityRequestV1),
    NativeBashAck(guard_contracts::NativeBashAckRequestV1),
    NativeBashReviewCheck(guard_contracts::NativeBashReviewCheckRequestV1),
    ComposioRole(guard_contracts::ComposioRoleRequestV1),
    GithubCliClassify(GithubCliClassifyRequestV1),
    GithubWorkflowPrepare(guard_contracts::GithubWorkflowPrepareRequestV1),
    ProtectRequest(ProtectRequestRequestV1),
    ClaimApprovalReuseDecisions(ClaimApprovalReuseDecisionsRequestV1),
    ApprovalReuseDiagnostic(ApprovalReuseDiagnosticRequestV1),
    ApprovalBulkEligibility(ApprovalBulkEligibilityRequestV1),
    CodexRequestResume(CodexRequestResumeRequestV1),
    ApprovalQueueIdentity(ApprovalQueueIdentityRequestV1),
    ApprovalResolutionPlan(ApprovalResolutionPlanRequestV1),
    ApprovalScope(ApprovalScopeRequestV1),
    ApprovalScopeSelect(guard_contracts::ApprovalScopeSelectRequestV1),
    ApprovalResolutionEligibility(guard_contracts::ApprovalResolutionEligibilityRequestV1),
    ApprovalPersistSelect(guard_contracts::ApprovalPersistSelectRequestV1),
    HookRender(guard_contracts::HookRenderRequestV1),
    GuardStore(GuardStoreRequestV1),
    HookEvidenceWriter(crate::hook_evidence_writer_op::HookEvidenceWriterRequestV1),
    ApprovalGate(ApprovalGateRequestV1),
    PackageIntentParse(PackageIntentParseRequestV1),
    PackageRequestArtifact(PackageRequestArtifactRequestV1),
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
    ShimAdmin(ShimAdminRequestV2),
    PackageContextBuild(PackageContextBuildRequestV1),
    McpStdioProbe(McpStdioProbeRequestV1),
    McpStdioCancel(McpStdioCancelRequest),
    McpStdioSessionOpen(McpStdioSessionOpenRequestV1),
    McpStdioSessionSend(McpStdioSessionSendRequestV1),
    McpStdioSessionRecv(McpStdioSessionRecvRequestV1),
    McpStdioSessionClose(McpStdioSessionCloseRequestV1),
    PackageAdvisoryIds(PackageAdvisoryIdsRequestV1),
    PackageEvaluationCompose(PackageEvaluationComposeRequestV1),
    PackageApprovalHash(PackageApprovalHashRequestV1),
    PackagePolicyResolve(PackagePolicyResolveRequestV1),
    PackageProtectFinalize(PackageProtectFinalizeRequestV1),
    PackagePosture(PackagePostureRequestV1),
    PackageAuditProjection(PackageAuditProjectionRequestV1),
    WorkspaceInventory(WorkspaceInventoryRequestV1),
    PolicyDecisionLookup(Box<PolicyDecisionLookupRequestV1>),
    PolicyDocumentDecide(guard_contracts::PolicyDocumentDecisionRequestV1),
    CommandPolicyDecide(guard_contracts::CommandPolicyDecisionRequestV1),
    CommandExpressionValidate(guard_contracts::CommandExpressionValidationRequestV1),
    ReviewedInvocationBindingsValidate(guard_contracts::ReviewedInvocationBindingsRequestV1),
    GitExecutionSafety(GitExecutionSafetyRequestV1),
    CompoundGitInspection(CompoundGitInspectionRequestV1),
    CodexToolOutput(CodexToolOutputRequestV1),
    PolicyBundleAuthority(PolicyBundleAuthorityRequestV1),
    McpRuntimeEvidence(McpRuntimeEvidenceRequestV1),
    RuntimeDetectorRun(RuntimeDetectorRunRequestV1),
    RunnerAuthority(RunnerAuthorityRequestV1),
    LocalCliGrantDecide(LocalCliGrantRequestV1),
    LocalCliHook(LocalCliHookRequestV1),
    ConnectorSetupContext(ConnectorSetupContextRequestV1),
    ArtifactRisk(ArtifactRiskRequestV1),
    LocalToolEligibility(LocalToolEligibilityRequestV1),
    ShellHelpers(crate::shell_helpers_op::ShellHelpersRequest),
    ApprovalProofDecide(ApprovalProofRequestV1),
    CursorObserverProof(CursorObserverProofRequestV1),
    HookAuthorityState(HookAuthorityStateRequestV1),
    PolicyIntegrityRows(PolicyIntegrityRowsRequestV1),
    HookDecide(HookDecisionRequestV1),
    DaemonRoute(DaemonRouteRequestV1),
    DaemonHandler(DaemonHandlerRequestV1),
    HookAdapter(HookAdapterRequestV1),
    HookArtifactCompose(HookArtifactComposeRequestV1),
    HookArtifactFacts(guard_contracts::HookArtifactFactsRequestV1),
    ConsumerArtifactCompose(ConsumerArtifactComposeRequestV1),
    ConsumerArtifactProject(ConsumerArtifactProjectRequestV1),
    McpToolEvidence(McpToolEvidenceRequestV1),
    LocalMcpGrantDecide(LocalMcpGrantRequestV1),
    McpProxyDecide(McpProxyDecisionRequestV1),
    CiscoPreflight(CiscoPreflightRequestV1),
    DaemonLifecycleDecide(DaemonLifecycleDecisionRequestV1),
    ContributedMcpDecide(ContributedMcpDecisionRequestV1),
    RequestContextBuild(RequestContextRequestV1),
    McpToolPolicyDecide(McpToolPolicyDecideRequestV1),
    McpToolCallIdentity(McpToolCallIdentityRequestV1),
    McpClassify(McpClassificationRequestV1),
    NativeExactAction(NativeExactActionRequestV1),
    SkillDirectoryIdentity(SkillDirectoryIdentityRequestV1),
    SkillWorkflowPreflight(guard_contracts::SkillWorkflowPreflightRequestV1),
    #[cfg(unix)]
    CodexBindingCapture(crate::binding_capture_op::CodexBindingCaptureRequestV1),
    #[allow(dead_code)]
    PromptAnalyze(PromptAnalyzeRequestV1),
    CatalogRead(guard_command::catalog_read_model::CatalogReadRequestV1),
    CatalogReadV2(guard_command::catalog_read_model::discovery::CatalogReadRequestV2),
    CatalogPrepareV1(guard_command::catalog_prepare::Request),
    CatalogReadPreparedV1(guard_command::catalog_prepare::ReadRequest),
    CloudCatalog(Value),
    DiscoveryPlacementProject(crate::discovery_placement_op::DiscoveryPlacementProjectRequest),
    DataFlowAnalyze(DataFlowAnalyzeRequestV1),
    ToolActionRequestIdentity(guard_contracts::ToolActionRequestIdentityRequestV1),
    RuntimeArtifactIdentity(guard_contracts::RuntimeArtifactIdentityRequestV1),
    VerifiedReadDecision(guard_contracts::VerifiedReadDecisionRequestV1),
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
    Edge(Box<GuardHookEnvelopeV2>),
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
#[path = "resident_protocol_tests.rs"]
mod tests;
