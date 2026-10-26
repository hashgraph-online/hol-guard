//! Resident-operation dispatch — `capabilities()` + `evaluate_resident_bytes`
//! live here so `resident_protocol.rs` (approval-contract gated at 500 lines
//! by `scripts/ci/native_approval_contract_gate.py`) stays a thin frame/enum
//! surface. The `ResidentOperationV1` enum and `ResidentRequestV1` frame are
//! defined in `resident_protocol.rs`; this module owns evaluation.

use guard_contracts::{GUARD_HOOK_ENVELOPE_V2_SCHEMA, NATIVE_APPROVAL_MAX_BYTES};
use guard_hook_core::review_post_tool;
use guard_policy_snapshot::canonical_json_bytes;
use serde_json::Value;
use std::path::Path;

use crate::policy_store::PolicySnapshotStore;
use crate::resident_protocol::{
    encode_response, strict_json_value, ResidentOperationV1, ResidentRequestV1,
};

pub(crate) fn evaluate_resident_bytes(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    evaluate_resident_bytes_with_cancellation(bytes, policy_store, None)
}

pub(crate) fn evaluate_resident_bytes_with_cancellation(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    if matches!(
        value.get("operation").and_then(Value::as_str),
        Some(
            "workspace_review_authority_enroll"
                | "workspace_review_context"
                | "workspace_review_local_summary"
                | "workspace_review_local_queue"
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
    // The frame parsed as strict JSON but names no request shape this runtime
    // supports. A client of another runtime version is told apart from a
    // transient failure by this code alone.
    let request: ResidentRequestV1 = crate::strict_json::from_value(value)
        .map_err(|_| "native_request_schema_unsupported".to_owned())?;
    if let (Some(policy_store), ResidentRequestV1::Operation(operation)) = (policy_store, &request)
    {
        if let Some(guard_home) = operation_guard_home(operation) {
            policy_store.require_guard_home(guard_home)?;
        }
        if let Some(store_path) = operation_store_path(operation) {
            policy_store.require_store_path(store_path)?;
        }
    }
    match request {
        ResidentRequestV1::Edge(request) => {
            let policy_store =
                policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
            crate::edge::evaluate_envelope_with_store(*request, policy_store)
        }
        ResidentRequestV1::Operation(request) => match *request {
            ResidentOperationV1::ArchiveAcquisition(request) => {
                crate::archive_acquisition_op::evaluate_archive_acquisition_request(&request)
            }
            ResidentOperationV1::RichCommandModel(request) => {
                crate::rich_command_model_op::evaluate(&request)
            }
            ResidentOperationV1::CommandModel(request) => {
                crate::oneshot::evaluate_command_model_request(&request)
            }
            ResidentOperationV1::PreToolUse(request) if request.extension_evidence => {
                crate::pre_tool_extension_evidence_op::evaluate_with_store(&request, policy_store)
            }
            ResidentOperationV1::PreToolUse(request) => {
                crate::oneshot::evaluate_pre_tool_request(&request)
            }
            ResidentOperationV1::PolicySnapshotPush(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                policy_store.push(&request)
            }
            ResidentOperationV1::HookDirect(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::hook_direct::evaluate(request, policy_store)
            }
            ResidentOperationV1::HookDirectEvidenceDrain(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::hook_direct_evidence::drain(&request, policy_store.direct_evidence())
            }
            ResidentOperationV1::McpRelayDecide(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::mcp_relay_decide::evaluate(request, policy_store)
            }
            ResidentOperationV1::McpRelayReady(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::mcp_relay_ready::evaluate(&request, policy_store)
            }
            ResidentOperationV1::McpRelayCommit(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                let pending = policy_store.mcp_relay_pending();
                crate::mcp_relay_pending::commit(&request, pending, policy_store.direct_evidence())
            }
            ResidentOperationV1::McpRelayClaim(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::mcp_relay_decide::claim(&request, policy_store)
            }
            ResidentOperationV1::McpRelayServerReport(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::mcp_relay_servers::report(&request, policy_store.mcp_relay_servers())
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
            ResidentOperationV1::WorkspaceReviewLocalSummary(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                let summary = crate::policy_store::workspace_review_local_summary::build(
                    policy_store,
                    &request.request_id,
                )?;
                encode_response(&summary)
            }
            ResidentOperationV1::WorkspaceReviewLocalQueue(_) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                let queue =
                    crate::policy_store::workspace_review_local_summary::queue(policy_store)?;
                encode_response(&queue)
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
            ResidentOperationV1::DirectoryTrust(request) => {
                crate::directory_trust::evaluate_directory_trust_request(&request)
            }
            ResidentOperationV1::ContextDigest(request) => {
                crate::context_digest::evaluate_context_digest_request(&request)
            }
            ResidentOperationV1::NativeBashPrepare(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::prepare_bash_request(&request, store)
            }
            ResidentOperationV1::NativeBashReviewCheck(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::check_bash_review(&request, store)
            }
            ResidentOperationV1::NativeBashExecute(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::execute_bash_request(&request, store, cancellation)
            }
            ResidentOperationV1::NativeBashCancel(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::cancel_bash_request(&request, store)
            }
            ResidentOperationV1::NativeBashActivity(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::bash_activity_request(&request, store)
            }
            ResidentOperationV1::NativeBashAck(request) => {
                let store = policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::native_exact_action_op::acknowledge_bash_request(&request, store)
            }
            ResidentOperationV1::CommandEffectDecide(request) => {
                crate::command_effect::evaluate_with_store(&request, policy_store)
            }
            ResidentOperationV1::CommandEffectDecideBatch(request) => {
                crate::command_effect::evaluate_batch_with_store(&request, policy_store)
            }
            ResidentOperationV1::ApprovalReuseDecide(request) => {
                crate::approval_reuse::evaluate_approval_reuse_request(&request)
            }
            ResidentOperationV1::ExtensionControl(request) => {
                crate::extension_control_op::evaluate_extension_control_request(&request)
            }
            ResidentOperationV1::ExtensionAllowHint(request) => {
                crate::extension_allow_hint_op::evaluate_with_store(&request, policy_store)
            }
            ResidentOperationV1::ExtensionReviewHint(request) => {
                crate::hook_direct::saved_decision::review_hint::op::evaluate_with_store(
                    &request,
                    policy_store,
                )
            }
            ResidentOperationV1::ApprovalExtensionRecommendation(request) => {
                crate::approval_extension_recommendation_op::evaluate_with_store(&request, policy_store)
            }
            ResidentOperationV1::ComposioRole(request) => {
                crate::composio_role_op::evaluate_composio_role_request(&request)
            }
            ResidentOperationV1::SkillWorkflowPreflight(request) => {
                crate::skill_workflow_preflight_op::evaluate_skill_workflow_preflight_request(
                    &request,
                )
            }
            ResidentOperationV1::GithubCliClassify(request) => {
                crate::github_cli_classify_op::evaluate_github_cli_classify_request(&request)
            }
            ResidentOperationV1::GithubWorkflowPrepare(request) => {
                crate::github_workflow_prepare_op::evaluate_github_workflow_prepare_request(
                    &request,
                )
            }
            ResidentOperationV1::ProtectRequest(request) => {
                crate::protect_request_op::evaluate_protect_request_op(&request)
            }
            ResidentOperationV1::ApprovalReuseDiagnostic(request) => {
                crate::approval_reuse_diagnostic_op::evaluate_approval_reuse_diagnostic_request(
                    &request,
                )
            }
            ResidentOperationV1::ApprovalBulkEligibility(request) => {
                crate::approval_bulk_eligibility_op::evaluate_approval_bulk_eligibility_request(
                    &request,
                )
            }
            ResidentOperationV1::CodexRequestResume(request) => {
                crate::codex_request_resume_op::evaluate_codex_request_resume_request(&request)
            }
            ResidentOperationV1::ApprovalQueueIdentity(request) => {
                crate::approval_queue_identity_op::evaluate_approval_queue_identity_request(
                    &request,
                )
            }
            ResidentOperationV1::HookRender(request) => {
                crate::hook_render_op::evaluate_hook_render_request(&request)
            }
            ResidentOperationV1::ApprovalScope(request) => {
                crate::approval_scope_op::evaluate_approval_scope_request(&request, policy_store)
            }
            ResidentOperationV1::ApprovalScopeSelect(request) => {
                crate::approval_scope_select_op::evaluate_approval_scope_select_request(
                    &request,
                    policy_store,
                )
            }
            ResidentOperationV1::ApprovalResolutionEligibility(request) => {
                crate::approval_resolution_eligibility_op::evaluate_approval_resolution_eligibility_request(
                    &request,
                )
            }
            ResidentOperationV1::ContainedWrapperPlan(request) => {
                crate::contained_wrapper_plan_op::evaluate_contained_wrapper_plan_request(&request)
            }
            ResidentOperationV1::ApprovalPersistSelect(request) => {
                crate::approval_persist_select_op::evaluate_approval_persist_select_request(
                    &request,
                    policy_store,
                )
            }
            ResidentOperationV1::ApprovalResolutionPlan(request) => {
                crate::approval_resolution_plan_op::evaluate_approval_resolution_plan_request(
                    &request,
                )
            }
            ResidentOperationV1::ClaimApprovalReuseDecisions(request) => {
                crate::claim_approval_reuse_op::evaluate_claim_approval_reuse_request(&request)
            }
            ResidentOperationV1::GuardStore(request) => {
                crate::guard_store_op::evaluate_guard_store_request_with_owner(&request, policy_store)
            }
            ResidentOperationV1::HookEvidenceWriter(request) => {
                crate::hook_evidence_writer_op::evaluate_hook_evidence_writer_request(&request)
            }
            ResidentOperationV1::ApprovalGate(request) => {
                crate::approval_gate_op::evaluate_approval_gate_request(&request)
            }
            ResidentOperationV1::PackageIntentParse(request) => {
                crate::package_authority_op::evaluate_package_intent_parse(&request)
            }
            ResidentOperationV1::PackageIntentExtract(request) => {
                crate::package_intent_extract_op::evaluate_package_intent_extract(&request)
            }
            ResidentOperationV1::PackageRequestArtifact(request) => {
                crate::package_authority_op::evaluate_package_request_artifact_request(&request)
            }
            ResidentOperationV1::SupplyChainEval(request) => {
                crate::package_authority_op::evaluate_supply_chain_eval(&request)
            }
            ResidentOperationV1::ApplyStoredPackagePolicy(request) => {
                crate::package_authority_op::evaluate_apply_stored_package_policy(&request)
            }
            ResidentOperationV1::PackageAuthorityDecide(request) => {
                crate::package_authority_op::evaluate_package_authority_decide(&request)
            }
            ResidentOperationV1::PackageEvaluationCompose(request) => {
                crate::package_evaluation_compose_op::evaluate_package_evaluation_compose(&request)
            }
            ResidentOperationV1::PackageReviewPlan(request) => {
                crate::package_review_plan_op::evaluate_package_review_plan(&request)
            }
            ResidentOperationV1::PolicyDocumentDecide(request) => {
                crate::policy_document_decide_op::evaluate_policy_document_decision_request(
                    &request,
                )
            }
            ResidentOperationV1::CommandPolicyDecide(request) => {
                crate::command_policy_decide_op::evaluate_command_policy_decision_request(&request)
            }
            ResidentOperationV1::CommandExpressionValidate(request) => {
                crate::command_expression_validate_op::evaluate_command_expression_validation_request(
                    &request,
                )
            }
            ResidentOperationV1::ReviewedInvocationBindingsValidate(request) => {
                crate::reviewed_invocation_bindings_op::evaluate_reviewed_invocation_bindings_request(
                    &request,
                )
            }
            ResidentOperationV1::PolicyDecisionLookup(request) => {
                crate::policy_decision_lookup_op::evaluate_policy_decision_lookup_request(&request)
            }
            ResidentOperationV1::CompoundGitInspection(request) => {
                crate::compound_git_inspection_op::evaluate_compound_git_inspection_request(
                    &request,
                )
            }
            ResidentOperationV1::CodexToolOutput(request) => {
                crate::codex_tool_output_op::evaluate_codex_tool_output_request(&request)
            }
            ResidentOperationV1::PolicyBundleAuthority(request) => {
                crate::policy_bundle_op::evaluate_policy_bundle_authority_request(&request)
            }
            ResidentOperationV1::CiscoPreflight(request) => {
                crate::cisco_preflight_op::evaluate_cisco_preflight(&request)
            }
            ResidentOperationV1::McpProxyDecide(request) => {
                crate::mcp_proxy_decision_op::evaluate_mcp_proxy_decision(&request)
            }
            ResidentOperationV1::DaemonLifecycleDecide(request) => {
                crate::daemon_lifecycle_decision_op::evaluate_daemon_lifecycle_decision(&request)
            }
            ResidentOperationV1::GitExecutionSafety(request) => {
                crate::git_execution_safety_op::evaluate_git_execution_safety_request(&request)
            }
            ResidentOperationV1::LocalCliGrantDecide(request) => {
                crate::local_cli_grant_op::evaluate_local_cli_grant_request(&request)
            }
            ResidentOperationV1::LocalCliHelpParse(request) => {
                crate::local_cli_help::evaluate_local_cli_help_parse_request(&request)
            }
            ResidentOperationV1::LocalCliHook(request) => {
                crate::local_cli_hook_op::evaluate_local_cli_hook_request(&request)
            }
            ResidentOperationV1::HookLocalCliRule(request) => {
                crate::hook_direct::local_cli::rule_op::evaluate_hook_local_cli_rule_request(
                    &request,
                )
            }
            ResidentOperationV1::ConnectorSetupContext(request) => {
                crate::connector_setup_context_op::evaluate_connector_setup_context_request(
                    &request,
                )
            }
            ResidentOperationV1::ArtifactRisk(request) => {
                crate::artifact_risk_op::evaluate_artifact_risk_request(&request)
            }
            ResidentOperationV1::LocalToolEligibility(request) => {
                crate::local_tool_eligibility_op::evaluate_local_tool_eligibility_request(&request)
            }
            ResidentOperationV1::ShellHelpers(request) => {
                crate::shell_helpers_op::evaluate(&request)
            }
            ResidentOperationV1::ApprovalProofDecide(request) => {
                crate::approval_proof_op::evaluate_approval_proof_request(&request)
            }
            ResidentOperationV1::CursorObserverProof(request) => {
                crate::cursor_observer_proof_op::evaluate_cursor_observer_proof_request(&request)
            }
            ResidentOperationV1::HookAuthorityState(request) => {
                crate::hook_authority_state_op::evaluate_hook_authority_state_request(&request)
            }
            ResidentOperationV1::ExtensionControlAuthority(request) => {
                crate::extension_control_authority_op::evaluate_extension_control_authority_request(
                    &request,
                )
            }
            ResidentOperationV1::CommandPackRecord(request) => {
                crate::command_pack_record_op::evaluate_command_pack_record_request(&request)
            }
            ResidentOperationV1::PolicyIntegrityRows(request) => {
                crate::policy_integrity_rows_op::evaluate_policy_integrity_rows_request(&request)
            }
            ResidentOperationV1::HookDecide(request) => {
                crate::hook_decision_op::evaluate_hook_decision_request(&request)
            }
            ResidentOperationV1::DaemonHandler(request) => {
                crate::daemon_handler_op::evaluate_daemon_handler_request(&request)
            }
            ResidentOperationV1::NativeExactAction(request) => {
                crate::native_exact_action_op::evaluate_native_exact_action_request(
                    &request,
                    policy_store.map(PolicySnapshotStore::guard_home),
                )
            }
            ResidentOperationV1::DaemonRoute(request) => {
                crate::daemon_route_op::evaluate_daemon_route_request(&request)
            }
            ResidentOperationV1::HookAdapter(request) => {
                crate::hook_adapter_op::evaluate_hook_adapter_request(&request)
            }
            ResidentOperationV1::HookArtifactCompose(request) => {
                crate::hook_artifact_compose_op::evaluate_hook_artifact_compose_request(&request)
            }
            ResidentOperationV1::HookArtifactFacts(request) => {
                crate::hook_artifact_facts_op::evaluate_hook_artifact_facts_request(&request)
            }
            ResidentOperationV1::InventoryItemClassification(request) => {
                crate::inventory_item_classification_op::evaluate_inventory_item_classification_request(
                    &request,
                )
            }
            ResidentOperationV1::InventorySnapshotDigest(request) => {
                crate::inventory_snapshot_digest_op::evaluate_inventory_snapshot_digest_request(
                    &request,
                )
            }
            ResidentOperationV1::InventorySourceEvidence(request) => {
                crate::inventory_source_evidence_op::evaluate_inventory_source_evidence_request(
                    &request,
                )
            }
            ResidentOperationV1::InventoryScanFindings(request) => {
                crate::inventory_scan_findings_op::evaluate_inventory_scan_findings_request(
                    &request,
                )
            }
            ResidentOperationV1::CodexHookIdentity(request) => {
                crate::codex_hook_identity_op::evaluate_codex_hook_identity_request(&request)
            }
            ResidentOperationV1::CodexHookFileIdentity(request) => {
                crate::codex_hook_file_identity_op::evaluate_codex_hook_file_identity_request(
                    &request,
                )
            }
            ResidentOperationV1::InventoryScanTargets(request) => {
                crate::inventory_scan_targets_op::evaluate_inventory_scan_targets_request(&request)
            }
            ResidentOperationV1::ArtifactContentHash(request) => {
                crate::artifact_content_hash_op::evaluate_artifact_content_hash_request(&request)
            }
            ResidentOperationV1::ConsumerArtifactCompose(request) => {
                crate::consumer_artifact_compose_op::evaluate_consumer_artifact_compose_request(
                    &request,
                )
            }
            ResidentOperationV1::ConsumerArtifactProject(request) => {
                crate::consumer_artifact_project_op::evaluate_consumer_artifact_project_request(
                    &request,
                )
            }
            ResidentOperationV1::LocalMcpGrantDecide(request) => {
                crate::local_mcp_grant_op::evaluate_local_mcp_grant_request(&request)
            }
            ResidentOperationV1::RequestContextBuild(request) => {
                crate::request_context_op::evaluate_request_context_request_with_store(
                    &request,
                    policy_store,
                )
            }
            ResidentOperationV1::SkillDirectoryIdentity(request) => {
                crate::skill_directory_identity_op::evaluate_skill_directory_identity_request(
                    &request,
                )
            }
            #[cfg(unix)]
            ResidentOperationV1::CodexBindingCapture(request) => {
                crate::binding_capture_op::evaluate_codex_binding_capture_request(&request)
            }
            ResidentOperationV1::ContributedMcpDecide(request) => {
                crate::contributed_mcp_decision_op::evaluate_with_store(
                    &request,
                    policy_store,
                )
            }
            ResidentOperationV1::McpToolPolicyDecide(request) => {
                crate::mcp_tool_policy_decide_op::evaluate_with_store(&request, policy_store)
            }
            ResidentOperationV1::McpToolCallIdentity(request) => {
                crate::mcp_tool_call_identity_op::evaluate_mcp_tool_call_identity_request(&request)
            }
            ResidentOperationV1::McpClassify(request) => {
                crate::mcp_classification_op::evaluate_mcp_classification_request(&request)
            }
            ResidentOperationV1::PackageAdvisoryIds(request) => {
                crate::package_authority_op::evaluate_package_advisory_ids(&request)
            }
            ResidentOperationV1::PackageApprovalHash(request) => {
                crate::package_approval_hash_op::evaluate_package_approval_hash(&request)
            }
            ResidentOperationV1::PackagePolicyResolve(request) => {
                crate::package_policy_resolve_op::evaluate_package_policy_resolve(&request)
            }
            ResidentOperationV1::PackageProtectFinalize(request) => {
                crate::package_protect_finalize_op::evaluate_package_protect_finalize(&request)
            }
            ResidentOperationV1::PackageEvaluationView(request) => {
                crate::package_evaluation_view_op::evaluate_package_evaluation_view(&request)
            }
            ResidentOperationV1::PackagePosture(request) => {
                crate::package_posture_op::evaluate_package_posture(&request)
            }
            ResidentOperationV1::PackageAuditProjection(request) => {
                crate::package_audit_projection_op::evaluate_package_audit_projection(&request)
            }
            ResidentOperationV1::WorkspaceInventory(request) => {
                crate::workspace_inventory_op::evaluate_workspace_inventory(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainedNodeExecute(request) => {
                crate::contained_op::evaluate_contained_node_execute(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainedTypescriptExecute(request) => {
                crate::contained_op::evaluate_contained_typescript_execute(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainedPackageScriptExecute(request) => {
                crate::contained_op::evaluate_contained_package_script_execute(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainedWorkspaceWriteExecute(request) => {
                crate::contained_op::evaluate_contained_workspace_write_execute(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainedExecute(request) => {
                crate::contained_op::evaluate_contained_execute(&request)
            }
            #[cfg(unix)]
            ResidentOperationV1::ContainmentHealthProbe(request) => {
                crate::contained_op::evaluate_containment_health_probe(&request)
            }
            ResidentOperationV1::ShimAdmin(request) => {
                crate::shim_op::evaluate_shim_admin(&request)
            }
            ResidentOperationV1::PackageContextBuild(request) => {
                crate::package_context_build_op::evaluate_package_context_build(&request)
            }
            ResidentOperationV1::McpStdioProbe(request) => {
                crate::mcp_probe_op::evaluate_mcp_stdio_probe(&request)
            }
            ResidentOperationV1::McpStdioCancel(request) => {
                crate::mcp_probe_op::cancel_mcp_stdio_probe(&request.request_id)
            }
            ResidentOperationV1::McpStdioSessionOpen(request) => {
                crate::mcp_stdio_session_op::session_open(&request)
            }
            ResidentOperationV1::McpStdioSessionSend(request) => {
                crate::mcp_stdio_session_op::session_send(&request)
            }
            ResidentOperationV1::McpStdioSessionRecv(request) => {
                crate::mcp_stdio_session_op::session_recv(&request)
            }
            ResidentOperationV1::McpStdioSessionClose(request) => {
                crate::mcp_stdio_session_op::session_close(&request)
            }
            ResidentOperationV1::McpRuntimeEvidence(request) => {
                crate::mcp_runtime_evidence_op::evaluate_mcp_runtime_evidence(&request)
            }
            ResidentOperationV1::RuntimeDetectorRun(request) => {
                crate::runtime_detector_run_op::evaluate_runtime_detector_run(&request)
            }
            ResidentOperationV1::RunnerAuthority(request) => {
                crate::runner_authority_op::evaluate_runner_authority(&request)
            }
            ResidentOperationV1::McpToolEvidence(request) => {
                crate::mcp_tool_evidence_op::evaluate_mcp_tool_evidence(&request)
            }
            ResidentOperationV1::PromptAnalyze(request) => {
                crate::prompt_analyze_op::evaluate_prompt_analyze(&request)
            }
            // Static catalog metadata only: no policy store, guard home or
            // effective-control state is read (ADR 0014).
            ResidentOperationV1::CatalogRead(request) => encode_response(
                &guard_command::catalog_read_model::evaluate_catalog_read(&request),
            ),
            ResidentOperationV1::CatalogReadV2(request) => encode_response(
                &guard_command::catalog_read_model::discovery::evaluate(&request),
            ),
            ResidentOperationV1::CatalogPrepareV1(request) => {
                encode_response(&guard_command::catalog_prepare::evaluate(request))
            }
            ResidentOperationV1::CatalogReadPreparedV1(request) => {
                encode_response(&guard_command::catalog_prepare::read(&request))
            }
            ResidentOperationV1::CloudCatalog(request) => encode_response(
                &guard_command::cloud_catalog::evaluate(&request),
            ),
            // Untrusted Cloud discovery bytes are validated and projected
            // here; the daemon adapter only moves bytes (no Python fallback).
            ResidentOperationV1::DiscoveryPlacementProject(request) => {
                crate::discovery_placement_op::evaluate_discovery_placement_project(&request)
            }
            // Untrusted portal release bytes are validated and projected here;
            // the daemon adapter only moves bytes (no Python fallback).
            ResidentOperationV1::ReleaseFeedProject(request) => {
                crate::release_feed_op::evaluate_release_feed_project(&request)
            }
            ResidentOperationV1::DataFlowAnalyze(request) => {
                crate::data_flow_analyze_op::evaluate_data_flow_analyze(&request)
            }
            ResidentOperationV1::ToolActionRequestIdentity(request) => {
                crate::tool_action_identity_op::evaluate_tool_action_request_identity(&request)
            }
            ResidentOperationV1::RuntimeArtifactIdentity(request) => {
                crate::runtime_artifact_identity_op::evaluate_runtime_artifact_identity(&request)
            }
            ResidentOperationV1::VerifiedReadDecision(request) => {
                crate::verified_read_decision_op::evaluate_verified_read_decision(&request)
            }
            ResidentOperationV1::InventoryUrlRedaction(request) => {
                crate::inventory_url_redaction_op::evaluate_inventory_url_redaction(&request)
            }
            ResidentOperationV1::VerifiedReadPlan(request) => {
                crate::verified_read_plan_op::evaluate_verified_read_plan(&request)
            }
            ResidentOperationV1::AibomReportSummaries(request) => {
                crate::aibom_report_summaries_op::evaluate_aibom_report_summaries(&request)
            }
            // Diagnostic correlation only: the lineage never authorizes an action.
            ResidentOperationV1::RetryLineageCapture(request) => {
                crate::retry_lineage_capture_op::evaluate_retry_lineage_capture(&request)
            }
            #[cfg(not(unix))]
            ResidentOperationV1::ContainedNodeExecute(_)
            | ResidentOperationV1::ContainedTypescriptExecute(_)
            | ResidentOperationV1::ContainedPackageScriptExecute(_)
            | ResidentOperationV1::ContainedWorkspaceWriteExecute(_)
            | ResidentOperationV1::ContainedExecute(_)
            | ResidentOperationV1::ContainmentHealthProbe(_) => {
                Err("native_operation_unavailable_on_this_platform".to_owned())
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

/// The Guard home an operation acts on, for operations that open per-home state.
fn operation_guard_home(operation: &ResidentOperationV1) -> Option<&str> {
    match operation {
        ResidentOperationV1::CloudCatalog(request) => {
            if request["action"] == "begin" || request["action"] == "reuse" {
                request["observation"]["guard_home"].as_str()
            } else {
                request["guard_home"].as_str()
            }
        }
        ResidentOperationV1::CatalogReadV2(request) => request.guard_home.to_str(),
        ResidentOperationV1::CatalogPrepareV1(request) => request.guard_home.to_str(),
        ResidentOperationV1::CatalogReadPreparedV1(request) => request.guard_home.to_str(),
        ResidentOperationV1::NativeBashPrepare(request) => Some(&request.capture.guard_home),
        ResidentOperationV1::NativeBashExecute(request) => Some(&request.capture.guard_home),
        ResidentOperationV1::NativeBashCancel(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashActivity(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashAck(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashReviewCheck(request) => Some(&request.guard_home),
        ResidentOperationV1::ArchiveAcquisition(request) => Some(&request.guard_home),
        ResidentOperationV1::DirectoryTrust(request) => Some(&request.guard_home),
        ResidentOperationV1::HookDirect(request) => Some(&request.guard_home),
        ResidentOperationV1::HookDirectEvidenceDrain(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayCommit(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayReady(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayClaim(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayServerReport(request) => Some(&request.guard_home),
        ResidentOperationV1::ApprovalReuseDiagnostic(request) => Some(&request.guard_home),
        ResidentOperationV1::ClaimApprovalReuseDecisions(request) => Some(&request.guard_home),
        ResidentOperationV1::GuardStore(request) => Some(&request.guard_home),
        ResidentOperationV1::HookEvidenceWriter(request) => Some(&request.guard_home),
        ResidentOperationV1::ApprovalGate(request) => Some(&request.guard_home),
        ResidentOperationV1::SupplyChainEval(request) => Some(&request.guard_home),
        ResidentOperationV1::ApplyStoredPackagePolicy(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAuthorityDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::CursorObserverProof(request) => Some(&request.guard_home),
        ResidentOperationV1::HookAuthorityState(request) => Some(&request.guard_home),
        ResidentOperationV1::ExtensionControlAuthority(request) => Some(&request.guard_home),
        ResidentOperationV1::CommandPackRecord(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAdvisoryIds(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageEvaluationCompose(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageReviewPlan(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageApprovalHash(request) => Some(&request.guard_home),
        ResidentOperationV1::PackagePolicyResolve(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageProtectFinalize(request) => Some(&request.guard_home),
        ResidentOperationV1::PackagePosture(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAuditProjection(request) => Some(&request.guard_home),
        ResidentOperationV1::WorkspaceInventory(request) => Some(&request.guard_home),
        ResidentOperationV1::PolicyDecisionLookup(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedNodeExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedTypescriptExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedPackageScriptExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedWorkspaceWriteExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainmentHealthProbe(request) => Some(&request.guard_home),
        ResidentOperationV1::ShimAdmin(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageContextBuild(request) => Some(&request.guard_home),
        ResidentOperationV1::McpStdioProbe(request) => Some(&request.guard_home),
        ResidentOperationV1::PromptAnalyze(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRuntimeEvidence(request) => Some(&request.guard_home),
        ResidentOperationV1::RuntimeDetectorRun(request) => Some(&request.guard_home),
        ResidentOperationV1::RunnerAuthority(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalCliGrantDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalCliHook(request) => Some(&request.guard_home),
        ResidentOperationV1::HookLocalCliRule(request) => Some(&request.guard_home),
        ResidentOperationV1::ConnectorSetupContext(request) => Some(&request.guard_home),
        ResidentOperationV1::McpToolEvidence(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalMcpGrantDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::ContributedMcpDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::RichCommandModel(request) => Some(&request.guard_home),
        ResidentOperationV1::RequestContextBuild(request) => Some(&request.guard_home),
        ResidentOperationV1::SkillDirectoryIdentity(request) => Some(&request.guard_home),
        #[cfg(unix)]
        ResidentOperationV1::CodexBindingCapture(request) => Some(&request.guard_home),
        ResidentOperationV1::ProtectRequest(request) => Some(&request.guard_home),
        ResidentOperationV1::CodexRequestResume(request) => Some(&request.guard_home),
        ResidentOperationV1::PolicyIntegrityRows(request) => request
            .generation
            .as_ref()
            .map(|generation| generation.guard_home.as_str()),
        _ => None,
    }
}

/// The store an operation opens, for operations that carry an explicit path.
fn operation_store_path(operation: &ResidentOperationV1) -> Option<&str> {
    match operation {
        ResidentOperationV1::NativeBashExecute(request) => Some(request.authorization.store_path()),
        ResidentOperationV1::NativeBashReviewCheck(request) => Some(&request.store_path),
        ResidentOperationV1::NativeBashAck(request) => Some(&request.store_path),
        ResidentOperationV1::ApprovalReuseDiagnostic(request) => Some(&request.store_path),
        ResidentOperationV1::ClaimApprovalReuseDecisions(request) => Some(&request.store_path),
        ResidentOperationV1::GuardStore(request) => Some(&request.store_path),
        ResidentOperationV1::SupplyChainEval(request) => Some(&request.store_path),
        ResidentOperationV1::ApplyStoredPackagePolicy(request) => Some(&request.store_path),
        ResidentOperationV1::PackageAuthorityDecide(request) => Some(&request.store_path),
        ResidentOperationV1::PackageAdvisoryIds(request) => Some(&request.store_path),
        ResidentOperationV1::PackageApprovalHash(request) => request.store_path.as_deref(),
        ResidentOperationV1::PackageAuditProjection(request) => match &request.query {
            guard_contracts::PackageAuditQueryV1::Receipt(query) => query.store_path.as_deref(),
            guard_contracts::PackageAuditQueryV1::Aliases(query) => Some(&query.store_path),
            guard_contracts::PackageAuditQueryV1::CloudPayload(query) => Some(&query.store_path),
            _ => None,
        },
        ResidentOperationV1::PolicyDecisionLookup(request) => Some(&request.store_path),
        ResidentOperationV1::LocalCliGrantDecide(request) => Some(&request.store_path),
        ResidentOperationV1::LocalCliHook(request) => Some(&request.store_path),
        ResidentOperationV1::HookLocalCliRule(request) => Some(&request.store_path),
        ResidentOperationV1::ConnectorSetupContext(request) => Some(&request.store_path),
        ResidentOperationV1::LocalMcpGrantDecide(request) => Some(&request.store_path),
        ResidentOperationV1::ContributedMcpDecide(request) => Some(&request.store_path),
        ResidentOperationV1::HookAuthorityState(request) => Some(&request.store_path),
        ResidentOperationV1::ExtensionControlAuthority(request) => Some(&request.store_path),
        ResidentOperationV1::CommandPackRecord(request) => Some(&request.store_path),
        ResidentOperationV1::ProtectRequest(request) => request.store_path.as_deref(),
        ResidentOperationV1::CodexRequestResume(request) => Some(&request.store_path),
        ResidentOperationV1::PolicyIntegrityRows(request) => request
            .generation
            .as_ref()
            .map(|generation| generation.store_path.as_str()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "catalog_read_op_tests.rs"]
mod catalog_read_op_tests;
