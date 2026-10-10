//! `HookArtifactCompose` — wire contract for the resident hook-artifact
//! decision composition op.
//!
//! Python gathers evidence (policy config, store rows, scanner results) and the
//! resident decides: it composes the action lattice over the gathered inputs,
//! settles local grants, evaluates saved/claimed approval reuse, decides the
//! trusted-request override, and selects the decision copy. Every query is
//! pure: no IO, no SQLite. Python must send every field explicitly (nulls
//! included) so the request digest it binds matches the resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA: &str = "guard-hook-artifact-compose-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA: &str = "guard-hook-artifact-compose-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_COMPOSE_FEATURE: &str = "hook-artifact-compose-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: HookArtifactComposeQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookArtifactComposeQueryV1 {
    /// Current action composition, local-grant eligibility, and risk copy.
    PolicyStack(Box<PolicyStackQueryV1>),
    /// A matched local tool grant settles the current review as an allow.
    ToolGrantApply,
    /// Settle a local CLI grant result and the native floor.
    GrantSettle(GrantSettleQueryV1),
    /// Non-package saved-approval reuse composition.
    SavedReuse(Box<SavedReuseQueryV1>),
    /// A saved block selected for a package request.
    SavedBlockReuse {
        current_action: Value,
        policy_action: Value,
        stored_artifact_hash: Value,
    },
    /// The trusted-request override decision.
    TrustedOverride(Box<TrustedOverrideQueryV1>),
    /// Reuse composition after an atomic saved-approval claim.
    ClaimedReuse(Box<ClaimedReuseQueryV1>),
    /// Decision copy overlay for the composed action.
    DecisionCopy(Box<DecisionCopyQueryV1>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyStackQueryV1 {
    pub config_action: Value,
    pub approval_context_config_action: Value,
    /// Trusted CLI action; `null` means none was supplied.
    pub cli_action: Value,
    pub payload_action_present: bool,
    pub payload_action: Value,
    pub native_floor: Value,
    pub edge_floor: Value,
    pub current_action_override_present: bool,
    pub has_package: bool,
    pub package_policy_action: Value,
    pub has_data_flow: bool,
    pub data_flow_configured_action: Value,
    pub has_scanner: bool,
    pub scanner_action: Value,
    pub has_compound_findings: bool,
    pub artifact_risk_signals: Vec<String>,
    pub data_flow_reasons: Vec<String>,
    pub artifact_risk_summary: String,
    pub data_flow_summary: Option<String>,
    pub package_risk_signals: Vec<String>,
    pub package_risk_summary: Option<String>,
    pub scanner_risk_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantSettleQueryV1 {
    pub current_action: Value,
    pub policy_action: Value,
    pub approval_context_action: Value,
    pub granted_action: Value,
    pub native_floor: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SavedReuseQueryV1 {
    pub current_action: Value,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedOverrideQueryV1 {
    pub token_validation_reason: Option<String>,
    pub policy_action: Value,
    pub remembered_rule_rejected: bool,
    pub prior_reuse_reason_code: Option<String>,
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_source: Value,
    pub stored_validation_reason: Option<String>,
    /// `null` before the caller has attempted the claim.
    pub claim_succeeded: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PriorReuseV1 {
    pub action: Value,
    pub saved_action: Value,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimedReuseQueryV1 {
    pub claimed_hash: Value,
    pub token_validation_reason: Option<String>,
    pub post_claim_refresh_failed: bool,
    pub remembered_rule_rejected: bool,
    pub prior_reuse: Option<PriorReuseV1>,
    pub package_reuse_saved_action: Value,
    pub workflow_capability_required: bool,
    pub workflow_authorization_claimed: bool,
    pub policy_action: Value,
    pub current_policy_action: Value,
    pub claimed_trusted_request_override: bool,
    pub claimed_package_approval_consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyPackageV1 {
    pub reason_codes: Vec<String>,
    pub user_title: String,
    pub user_summary: String,
    pub user_harness_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyQueryV1 {
    pub policy_action: Value,
    pub package: Option<DecisionCopyPackageV1>,
    pub package_policy_action: Value,
    pub has_compound_findings: bool,
    pub compound_finding_count: Option<u64>,
    pub risk_summary: String,
    pub scanner_raised_to_block: bool,
    pub has_scanner_evidence: bool,
    pub scanner_primary_signal: Option<String>,
    pub base_user_body: Value,
    pub base_harness_message: Value,
    pub base_dashboard_primary_detail: Value,
    pub remembered_rule_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_hook_artifact_compose_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
