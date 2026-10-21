//! Rust wire projection of `runtime/github_workflow_authorization.py`.
//!
//! The host issues/claims workflow capabilities in Python; the resident Rust
//! composition consumes only the evidence surface —
//! `github_workflow_authorization_evidence(authorization, command_identity)`
//! (:294). The wire row carries the sealed object's private fields; the
//! `sealed` flag reproduces the `_seal is not _AUTHORIZATION_SEAL` check so a
//! tampered host object can be marked unsealed on the wire.
//!
//! `len(receipt_sha256) != 64` (Python `len()` counts code points) is mirrored
//! with `chars().count()`.

use guard_contracts::{
    canonical_framed_payload, WorkflowCapabilityBinding, WorkflowCapabilityError,
    WorkflowCapabilityRuleBinding,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::effect_decision::PositiveProof;
use crate::github_capability_interaction::GITHUB_MAINTENANCE_ACTION_CLASS;
use crate::github_workflow_operations::GitHubWorkflowOperation;

type WfResult<T> = Result<T, WorkflowCapabilityError>;

/// `GitHubWorkflowAuthorization` wire row (:74-105): the four sealed
/// attributes plus a `sealed` flag standing in for the `_AUTHORIZATION_SEAL`
/// object-identity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GitHubWorkflowAuthorizationV1 {
    pub operation_identity: String,
    pub proof: PositiveProof,
    pub receipt_sha256: String,
    /// `true` iff the host object still carries the claim seal.
    pub sealed: bool,
}

/// `github_workflow_authorization_evidence` (:294). Returns
/// `(proof, action_class)` when the authorization binds `command_identity`.
pub fn github_workflow_authorization_evidence(
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    command_identity: &str,
) -> Option<(PositiveProof, &'static str)> {
    let authorization = authorization?;
    // `_seal is not _AUTHORIZATION_SEAL` → None.
    if !authorization.sealed {
        return None;
    }
    // `hmac.compare_digest(a, b)` — constant-time; equality is sufficient here
    // because Rust strings are already length-known and compare_digest degrades
    // to equality for str.
    if !hmac_compare_digest(&authorization.operation_identity, command_identity) {
        return None;
    }
    if authorization.receipt_sha256.chars().count() != 64 {
        return None;
    }
    Some((
        authorization.proof.clone(),
        *GITHUB_MAINTENANCE_ACTION_CLASS,
    ))
}

/// `hmac.compare_digest` for UTF-8 strings.
fn hmac_compare_digest(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
// ─── issue/claim binding surface (:120-155, :306-319) ─────────────────────

/// `_GITHUB_MAINTENANCE_EFFECT_ID` (:32).
pub const GITHUB_MAINTENANCE_EFFECT_ID: &str = "github.maintain-remote";
/// `_GITHUB_WORKFLOW_DECISION_ID` (:33).
pub const GITHUB_WORKFLOW_DECISION_ID: &str = "github.workflow-authorized";

/// `GitHubWorkflowBindingContext` (:54) — every ambient digest the claim
/// binds besides the operation itself.
#[derive(Debug, Clone, PartialEq)]
pub struct GitHubWorkflowBindingContext {
    pub repository_sha256: String,
    pub workspace_sha256: String,
    pub executable_sha256: String,
    pub cwd_sha256: String,
    pub environment_sha256: String,
    pub configuration_sha256: String,
    pub manifest_sha256: String,
    pub lockfile_sha256: String,
    pub sandbox_sha256: String,
    pub policy_id: String,
    pub policy_version: String,
    pub effect_id: String,
    pub effect_version: String,
    pub decision_id: String,
    pub decision_version: String,
    pub rules: Vec<WorkflowCapabilityRuleBinding>,
}

/// `github_repository_sha256` (:306). Strip+lower must be a no-op; the
/// lowercase `_REPOSITORY` (authorization :31 — stricter than the
/// operations parser regex) fullmatch gates owner/repo shape.
pub fn github_repository_sha256(repository: &str) -> WfResult<String> {
    let normalized = repository.trim().to_lowercase();
    let repository_ok = Regex::new(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
        .unwrap()
        .is_match(&normalized);
    if normalized != repository || !repository_ok {
        return Err(WorkflowCapabilityError(
            "invalid_github_workflow_repository",
        ));
    }
    framed_sha256("github-workflow-repository", &Value::String(normalized))
}

/// `build_github_workflow_binding` (:120). Validation ordering preserved:
/// context ids first, then repository digest compare, then launch digest.
/// Rust validates the assembled `WorkflowCapabilityBinding` at the end to
/// mirror the Python dataclass `__post_init__`.
pub fn build_github_workflow_binding(
    operation: &GitHubWorkflowOperation,
    context: &GitHubWorkflowBindingContext,
) -> WfResult<WorkflowCapabilityBinding> {
    validate_github_workflow_binding_context(context)?;
    let expected_repository_sha256 = github_repository_sha256(&operation.repository)?;
    if !hmac_compare_digest(&context.repository_sha256, &expected_repository_sha256) {
        return Err(WorkflowCapabilityError(
            "github_workflow_repository_mismatch",
        ));
    }
    let launch_sha256 = framed_sha256(
        "github-workflow-launch",
        &serde_json::json!({
            "command_identity": operation.command_identity,
            "configuration_sha256": context.configuration_sha256,
            "cwd_sha256": context.cwd_sha256,
            "environment_sha256": context.environment_sha256,
            "lockfile_sha256": context.lockfile_sha256,
            "manifest_sha256": context.manifest_sha256,
            "sandbox_sha256": context.sandbox_sha256,
        }),
    )?;
    let binding = WorkflowCapabilityBinding {
        operation_id: format!("github.{}.v1", operation.kind.as_str()),
        resource_type: operation.resource_type.clone(),
        resource_sha256: framed_sha256(
            "github-workflow-resource",
            &Value::String(operation.resource_id.clone()),
        )?,
        repository_sha256: context.repository_sha256.clone(),
        workspace_sha256: context.workspace_sha256.clone(),
        executable_sha256: context.executable_sha256.clone(),
        launch_sha256,
        policy_id: context.policy_id.clone(),
        policy_version: context.policy_version.clone(),
        effect_id: context.effect_id.clone(),
        effect_version: context.effect_version.clone(),
        decision_id: context.decision_id.clone(),
        decision_version: context.decision_version.clone(),
        rules: context.rules.clone(),
    };
    binding.validate()?;
    Ok(binding)
}

/// `_validate_github_workflow_binding_context` (:313).
fn validate_github_workflow_binding_context(
    context: &GitHubWorkflowBindingContext,
) -> WfResult<()> {
    if context.effect_id != GITHUB_MAINTENANCE_EFFECT_ID {
        return Err(WorkflowCapabilityError("github_workflow_effect_mismatch"));
    }
    if context.decision_id != GITHUB_WORKFLOW_DECISION_ID {
        return Err(WorkflowCapabilityError("github_workflow_decision_mismatch"));
    }
    if context.rules.len() != 1 || context.rules[0].rule_id != GITHUB_MAINTENANCE_EFFECT_ID {
        return Err(WorkflowCapabilityError("github_workflow_rule_mismatch"));
    }
    Ok(())
}

/// `_framed_sha256` (:322) — sha256 of the canonical framed payload.
/// `canonical_framed_payload` cannot fail on the well-formed values built
/// here (mirroring Python `json.dumps` of in-memory dicts), but a failure
/// is still surfaced rather than silently digested as empty.
fn framed_sha256(purpose: &str, payload: &Value) -> WfResult<String> {
    let framed = canonical_framed_payload(purpose, payload)
        .map_err(|_| WorkflowCapabilityError("capability_canonical_json_failed"))?;
    let mut hasher = Sha256::new();
    hasher.update(&framed);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
