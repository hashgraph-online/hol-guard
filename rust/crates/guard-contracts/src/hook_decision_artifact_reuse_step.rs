//! Wire types of the `HookDecide` `artifact_reuse_step` query: the artifact
//! hook's approval-reuse state machine.
//!
//! The transport gathers what the store and the lookups hold; the resident
//! answers a whole plan. A plan is a tree: each node is one effect the
//! transport runs, and a `claim` node names the plan that follows each of its
//! two outcomes, so the resident is not asked again between a claim and the
//! step that follows it. A saved approval is therefore never consumed and then
//! stranded behind a resident failure of its own follow-up.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SavedReuseQueryV1;

/// Advertised when the resident answers `artifact_reuse_step`; a resident that
/// predates it rejects the query, and the caller fails closed.
pub const HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE: &str = "hook-decision-artifact-reuse-step-v1";

/// What the artifact hook knows when it reaches approval reuse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReuseStepInputsV1 {
    /// The caller claims a saved approval on this pass.
    pub claim_saved_approval: bool,
    /// The composed action before any reuse is applied.
    pub current_action: Value,
    /// A matching remembered rule failed its integrity check.
    pub remembered_rule_rejected: bool,
    /// The saved decision the store holds for this request, if any.
    pub stored: Option<ReuseStoredDecisionV1>,
    pub lookup: ReuseLookupV1,
    /// Present when a trusted browser request resolved this exact request.
    pub trusted_override: Option<ReuseOverrideFactsV1>,
    /// Present on the pass that re-evaluates an already claimed approval.
    pub claimed: Option<ReuseClaimedFactsV1>,
}

/// The saved decision row, reduced to what reuse reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReuseStoredDecisionV1 {
    pub action: Value,
    pub artifact_hash: Value,
    pub source: Value,
    /// The request id of the approval the row records, when the row carries a
    /// complete approval authority. The workflow capability claim needs it.
    pub request_id: Option<String>,
}

/// The facts a tool request's saved-reuse lookup gathered, less the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReuseSavedFactsV1 {
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_artifact_hash: Value,
    pub integrity_failure: bool,
    pub stored_validation_reason: Option<String>,
    pub cursor_native_present: bool,
    pub cursor_validation_reason: Option<String>,
    pub diagnostic_reason: Option<String>,
    pub diagnostic_stored_hash: Value,
}

impl ReuseSavedFactsV1 {
    /// The `saved_reuse` query these facts make for `current_action`.
    pub fn query(&self, current_action: &Value) -> SavedReuseQueryV1 {
        SavedReuseQueryV1 {
            current_action: current_action.clone(),
            stored_present: self.stored_present,
            stored_action: self.stored_action.clone(),
            stored_artifact_hash: self.stored_artifact_hash.clone(),
            integrity_failure: self.integrity_failure,
            stored_validation_reason: self.stored_validation_reason.clone(),
            cursor_native_present: self.cursor_native_present,
            cursor_validation_reason: self.cursor_validation_reason.clone(),
            diagnostic_reason: self.diagnostic_reason.clone(),
            diagnostic_stored_hash: self.diagnostic_stored_hash.clone(),
        }
    }
}

/// Which request shape the reuse settles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReuseLookupV1 {
    /// A tool request: the lookups name what the store and the cursor row say.
    Tool {
        saved: Box<ReuseSavedFactsV1>,
        /// The workflow capability preflight found the request pending.
        workflow_preflight: bool,
    },
    /// A package request: its own evaluation already read the saved decision
    /// and recorded the outcome in its reasons.
    Package {
        reasons: Vec<Value>,
        evaluation_policy_action: Value,
    },
}

/// Token validation the trusted-request override depends on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReuseOverrideFactsV1 {
    pub token_validation_reason: Option<String>,
    pub stored_validation_reason: Option<String>,
}

/// Facts of the pass that re-evaluates a claimed approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReuseClaimedFactsV1 {
    pub claimed_hash: String,
    pub token_validation_reason: Option<String>,
    pub post_claim_refresh_failed: bool,
    pub workflow_capability_required: bool,
    pub workflow_authorization_claimed: bool,
    pub claimed_trusted_request_override: bool,
    pub claimed_package_approval_consumed: bool,
}

/// One node of the reuse plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum ArtifactReusePlanV1 {
    /// Claim the saved approval in the store; follow `on_claimed` when the
    /// claim wins and `on_failed` when it does not.
    Claim {
        on_claimed: Box<ArtifactReusePlanV1>,
        on_failed: Box<ArtifactReusePlanV1>,
    },
    /// Re-evaluate the request as the claimed approval's execution.
    Revalidate {
        trusted_request_override: bool,
        package_approval_consumed: bool,
        request_id: Option<String>,
    },
    /// Reuse is settled; the rest of the hook reads this.
    Settled {
        policy_action: String,
        approval_reuse_source: Option<String>,
        trusted_request_override_applied: bool,
        trusted_request_override_reason: Option<String>,
        /// Audit entries, in the order they were recorded.
        evidence: Vec<Value>,
        approval_reuse: Option<Value>,
        /// A package request's action moved, so its risk signals follow it.
        package_risk_refresh: bool,
    },
}
