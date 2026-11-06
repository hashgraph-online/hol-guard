//! `PolicyComposition` -- the tail of the artifact hook's policy stack.
//!
//! The head of the stack (`policy_stack`) composes the current action from the
//! evidence Python gathered. Once saved approvals, the trusted-request
//! override and the claim have settled the verdict, two records are written
//! from it that outlive the hook: the `policy_composition` trace every consumer
//! of the decision reads, and the receipt's `approval_source`. The resident
//! writes both from the settled inputs, so no caller decides which source an
//! approval is recorded under.

use serde::{Deserialize, Serialize};

/// Capability advertised when the artifact hook's policy-stack tail is served:
/// `policy_stack` answers `local_eligibility_required`, the artifact facts
/// answer `skip_native_floor`, and the `policy_composition` query is known. A
/// runtime that predates any of them cannot answer the others' fields, so the
/// caller requires this feature for all three.
pub const HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE: &str = "hook-artifact-compose-policy-tail-v1";

/// What the artifact hook's evaluation settled, and the two facts about the
/// request that decide how it is recorded.
///
/// Every action is one source's answer as the resident returned it, or `null`
/// when that source said nothing. They are text rather than `GuardAction`
/// because the trace records the sources verbatim, including a saved action
/// this build does not recognize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCompositionQueryV1 {
    pub current_config_action: String,
    /// The artifact, publisher or harness override the config resolved.
    pub current_action_override: Option<String>,
    pub trusted_cli_action: Option<String>,
    pub untrusted_payload_action: Option<String>,
    pub package_policy_action: Option<String>,
    pub data_flow_action: Option<String>,
    pub scanner_action: Option<String>,
    /// The composed action before saved approvals were applied.
    pub current_composed_action: String,
    /// The saved decision's action, `null` when nothing is saved.
    pub saved_policy_action: Option<String>,
    /// The source named for this request's reuse evidence, if any.
    pub approval_reuse_source: Option<String>,
    pub trusted_request_override: bool,
    pub trusted_request_override_reason: Option<String>,
    /// The verdict the evaluation settled on.
    pub authoritative_action: String,
    /// Claude's own approval prompt was observed to approve this request.
    pub claude_native_approval_observed: bool,
    /// The hook payload carried a non-blank `user_override`.
    pub user_override_present: bool,
}
