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
            ResidentOperationV1::CommandEffectDecide(request) => {
                crate::command_effect::evaluate_command_effect_request(&request)
            }
            ResidentOperationV1::ApprovalReuseDecide(request) => {
                crate::approval_reuse::evaluate_approval_reuse_request(&request)
            }
            ResidentOperationV1::ClaimApprovalReuseDecisions(request) => {
                crate::claim_approval_reuse_op::evaluate_claim_approval_reuse_request(&request)
            }
            ResidentOperationV1::ApprovalGate(request) => {
                crate::approval_gate_op::evaluate_approval_gate_request(&request)
            }
            ResidentOperationV1::PackageIntentParse(request) => {
                crate::package_authority_op::evaluate_package_intent_parse(&request)
            }
            ResidentOperationV1::SupplyChainEval(request) => {
                crate::package_authority_op::evaluate_supply_chain_eval(&request)
            }
            ResidentOperationV1::PackageAuthorityDecide(request) => {
                crate::package_authority_op::evaluate_package_authority_decide(&request)
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
            ResidentOperationV1::ContainedTestHook(request) => {
                crate::contained_op::evaluate_contained_test_hook(&request)
            }
            ResidentOperationV1::ShimAdmin(request) => {
                crate::shim_op::evaluate_shim_admin(&request)
            }
            ResidentOperationV1::McpStdioProbe(request) => {
                crate::mcp_probe_op::evaluate_mcp_stdio_probe(&request)
            }
            ResidentOperationV1::PromptAnalyze(request) => {
                crate::prompt_analyze_op::evaluate_prompt_analyze(&request)
            }
            #[cfg(not(unix))]
            ResidentOperationV1::ContainedNodeExecute(_)
            | ResidentOperationV1::ContainedTypescriptExecute(_)
            | ResidentOperationV1::ContainedPackageScriptExecute(_)
            | ResidentOperationV1::ContainedWorkspaceWriteExecute(_)
            | ResidentOperationV1::ContainedExecute(_)
            | ResidentOperationV1::ContainedTestHook(_) => {
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
