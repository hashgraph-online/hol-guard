//! Rust port of the issue/claim half of `runtime/github_workflow_authorization.py`
//! (:158-291) — the store-backed `issue_github_workflow_capability*` /
//! `claim_github_workflow_authorization` functions.
//!
//! The pure binding/context surface lives in
//! `guard_command::github_workflow_authorization`; these wrappers bridge it to
//! `workflow_capability_store`'s caller-owned `&Connection` substrate.
//! Error strings match Python `WorkflowCapabilityError` reasons verbatim.

use guard_command::effect_decision::{PositiveProof, ProofRequirement, ProofRoute};
use guard_command::github_workflow_authorization::GitHubWorkflowAuthorizationV1;
use guard_command::github_workflow_authorization::{
    build_github_workflow_binding, GitHubWorkflowBindingContext,
};
use guard_command::github_workflow_operations::GitHubWorkflowOperation;
use guard_contracts::{
    canonical_framed_payload, sign_workflow_capability, SignedWorkflowCapability,
    WorkflowCapabilityBinding, WorkflowCapabilityClaim, WorkflowCapabilityError,
    WORKFLOW_CAPABILITY_ALGORITHM, WORKFLOW_CAPABILITY_SCHEMA,
};
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::workflow_capability_store::{
    claim_workflow_capability, issue_workflow_capability, CapabilityStoreHooks,
};

#[allow(dead_code)]
type WfResult<T> = Result<T, WorkflowCapabilityError>;

/// `issue_github_workflow_capability` (:158) — build the binding from the
/// operation + ambient context, then delegate to the binding-level issue.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn issue_github_workflow_capability(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    operation: &GitHubWorkflowOperation,
    context: &GitHubWorkflowBindingContext,
    capability_id: &str,
    approval_provenance_id: &str,
    task_id: &str,
    nonce: &str,
    issuer_id: &str,
    subject_id: &str,
    issued_at: &str,
    not_before: &str,
    expires_at: &str,
    max_uses: i64,
    key: &[u8],
    key_id: &str,
    now: &str,
) -> WfResult<SignedWorkflowCapability> {
    issue_github_workflow_capability_binding(
        hooks,
        connection,
        build_github_workflow_binding(operation, context)
            .map_err(|e| WorkflowCapabilityError(e.0))?,
        capability_id,
        approval_provenance_id,
        task_id,
        nonce,
        issuer_id,
        subject_id,
        issued_at,
        not_before,
        expires_at,
        max_uses,
        key,
        key_id,
        now,
    )
}

/// `issue_github_workflow_capability_binding` (:194) — assemble the claim,
/// sign it with the host key, persist via the store substrate.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn issue_github_workflow_capability_binding(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    binding: WorkflowCapabilityBinding,
    capability_id: &str,
    approval_provenance_id: &str,
    task_id: &str,
    nonce: &str,
    issuer_id: &str,
    subject_id: &str,
    issued_at: &str,
    not_before: &str,
    expires_at: &str,
    max_uses: i64,
    key: &[u8],
    key_id: &str,
    now: &str,
) -> WfResult<SignedWorkflowCapability> {
    let claim = WorkflowCapabilityClaim {
        schema_version: WORKFLOW_CAPABILITY_SCHEMA.to_string(),
        algorithm: WORKFLOW_CAPABILITY_ALGORITHM.to_string(),
        capability_id: capability_id.to_string(),
        approval_provenance_id: approval_provenance_id.to_string(),
        task_id: task_id.to_string(),
        nonce: nonce.to_string(),
        issuer_id: issuer_id.to_string(),
        subject_id: subject_id.to_string(),
        binding,
        issued_at: issued_at.to_string(),
        not_before: not_before.to_string(),
        expires_at: expires_at.to_string(),
        max_uses,
    };
    // `sign_workflow_capability` runs `claim.validate()` internally (:760).
    let signed =
        sign_workflow_capability(claim, key, key_id).map_err(|e| WorkflowCapabilityError(e.0))?;
    issue_workflow_capability(hooks, connection, &signed, approval_provenance_id, now)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    Ok(signed)
}

/// `claim_github_workflow_authorization` (:230) — atomically claim the exact
/// capability, verify the persisted receipt binds back to the claim inputs,
/// then wrap the sealed evidence as `GitHubWorkflowAuthorizationV1`.
///
/// Python's `GitHubWorkflowAuthorization` keeps `_seal`/`_operation_identity`/
/// `_compatibility_action_class` private; the wire row is the faithful public
/// projection — `sealed: true` stands in for `_AUTHORIZATION_SEAL`.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn claim_github_workflow_authorization(
    hooks: &dyn CapabilityStoreHooks,
    connection: &Connection,
    capability_id: &str,
    operation: &GitHubWorkflowOperation,
    context: &GitHubWorkflowBindingContext,
    invocation_id: &str,
    subject_id: &str,
    task_id: &str,
    issuer_id: &str,
    approval_provenance_id: &str,
    now: &str,
) -> WfResult<GitHubWorkflowAuthorizationV1> {
    let binding = build_github_workflow_binding(operation, context)
        .map_err(|e| WorkflowCapabilityError(e.0))?;
    let receipt = claim_workflow_capability(
        hooks,
        connection,
        capability_id,
        invocation_id,
        &binding,
        subject_id,
        task_id,
        issuer_id,
        approval_provenance_id,
        now,
    )
    .map_err(|e| WorkflowCapabilityError(e.0))?;
    // `type(receipt) is not SignedWorkflowCapabilityReceipt` — the store only
    // ever returns that type; a wrong wire row would already have failed
    // `decode_signed_*`. Keep the structural assertion for parity.
    let claimed = &receipt.receipt;
    if claimed.binding != binding
        || claimed.capability_id != capability_id
        || claimed.invocation_id != invocation_id
        || claimed.task_id != task_id
        || claimed.approval_provenance_id != approval_provenance_id
    {
        return Err(WorkflowCapabilityError("github_workflow_receipt_mismatch"));
    }
    let receipt_sha256 = framed_sha256("github-workflow-receipt", &claimed.to_value())?;
    let binding_digest = framed_sha256(
        "github-workflow-claimed-binding",
        &serde_json::json!({
            "binding": binding.to_value(),
            "receipt_sha256": receipt_sha256,
        }),
    )?;
    Ok(GitHubWorkflowAuthorizationV1 {
        operation_identity: operation.command_identity.clone(),
        receipt_sha256,
        sealed: true,
        proof: PositiveProof {
            route: ProofRoute::WorkflowAuthorized,
            binding_digest,
            satisfied_requirements: vec![
                ProofRequirement::OperationAndTargets,
                ProofRequirement::RemoteResourceIdentity,
                ProofRequirement::RepositoryIdentity,
                ProofRequirement::WorkspaceIdentity,
                ProofRequirement::WorkingDirectoryIdentity,
                ProofRequirement::ExecutableIdentity,
                ProofRequirement::LaunchChain,
                ProofRequirement::ConfigurationIdentity,
                ProofRequirement::DependencyProvenance,
                ProofRequirement::ParserConfidence,
                ProofRequirement::ExpectedEffects,
                ProofRequirement::CapabilityConstraints,
            ],
            enforced: false,
        },
    })
}

/// `_framed_sha256` — sha256 of the canonical framed payload.
#[allow(dead_code)]
fn framed_sha256(purpose: &str, payload: &Value) -> WfResult<String> {
    let framed = canonical_framed_payload(purpose, payload)
        .map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))?;
    let mut hasher = Sha256::new();
    hasher.update(&framed);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
