//! `HookDecide` wire types for the artifact hook's final-action settle.
//!
//! Once the artifact hook has a verdict, a post-review step can still change
//! it: a Watch-mode record that executes the observed policy, a silent denial,
//! or a browser approval that resolved the review. `artifact_browser_outcome`
//! says whether such a browser outcome settles the hook, and
//! `artifact_finalize` says what the final action, the receipt and the
//! evidence become. The transport gathers the facts, applies the answer and
//! decides nothing itself.

use serde::{Deserialize, Serialize};

/// Advertised when the resident answers `artifact_finalize` and
/// `artifact_browser_outcome`; a resident that predates them rejects the
/// queries, so the transport demands the capability first.
pub const HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE: &str = "hook-decision-artifact-finalize-v1";

/// Facts the artifact hook's final-action settle depends on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFinalizeInputsV1 {
    /// The action the hook held before this settle.
    pub previous_action: String,
    /// The action being made final.
    pub policy_action: String,
    /// The policy Watch mode observed and did not execute.
    pub observed_policy_action: Option<String>,
    /// Who resolved the review; `browser` for an approval-center resolution.
    pub approval_source: Option<String>,
    /// The request the resolution answered, when the transport knows it.
    pub approval_request_id: Option<String>,
    /// The first queued approval request, for a terminal browser resolution
    /// that carries no request id of its own.
    pub queued_request_id: Option<String>,
    /// The action the review was raised with.
    pub initial_policy_action: String,
    pub receipt_approval_source: Option<String>,
    pub receipt_approval_request_id: Option<String>,
    pub receipt_user_override: Option<String>,
    /// The cloud reason code the previous decision carried, when it is a string.
    pub package_review_cloud_reason_code: Option<String>,
    /// The response carries a supply-chain evaluation.
    pub supply_chain_present: bool,
    /// That evaluation's own action, when it names one as a string.
    pub supply_chain_action: Option<String>,
}

/// The fields a post-review settle writes onto the policy composition and the
/// evidence entries that record it, in the order they are written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactEvidenceFieldsV1 {
    pub authoritative_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_policy_action: Option<String>,
}

/// Which evidence entries take the fields: those whose `source` matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactEvidencePatchV1 {
    pub source: String,
    pub fields: ArtifactEvidenceFieldsV1,
}

/// The evidence entry a browser resolution appends to the receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactResolutionEvidenceV1 {
    pub source: String,
    pub initial_action: String,
    pub authoritative_action: String,
    pub approval_request_id: Option<String>,
}

/// The receipt fields the settle fixes. The receipt is persisted as written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactReceiptFieldsV1 {
    pub policy_decision: String,
    pub approval_source: Option<String>,
    pub approval_request_id: Option<String>,
    pub user_override: Option<String>,
    /// Entries appended after the receipt's patched evidence.
    pub appended_evidence: Vec<ArtifactResolutionEvidenceV1>,
}

/// What a final-action settle makes of the hook's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactFinalizeV1 {
    /// The normalized final action.
    pub action: String,
    /// The normalized observed action, when Watch mode observed one.
    pub observed_action: Option<String>,
    /// The reason the decision-v2 record is built with.
    pub decision_reason: String,
    /// The cloud reason code the new decision keeps from the old one.
    pub cloud_reason_code: Option<String>,
    /// The action changed, so the risk summary and package copy are rewritten.
    pub refresh_copy: bool,
    /// Present when the package evaluation keeps the action it was observed with.
    pub observed_supply_chain_action: Option<String>,
    /// An unqualified terminal action would contradict the observed one.
    pub drop_terminal_action: bool,
    pub evidence_patch: ArtifactEvidencePatchV1,
    pub receipt: ArtifactReceiptFieldsV1,
}

/// A browser resolution's outcome, as the approval wait reported it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBrowserOutcomeInputsV1 {
    pub decision: String,
    pub event: String,
}

/// What a browser outcome does to the hook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactBrowserOutcomeV1 {
    /// The outcome makes a final action; the rest is empty when it does not.
    pub settle: bool,
    pub action: Option<String>,
    pub approval_source: Option<String>,
    /// The hook answers the harness with an empty allow itself.
    pub emit_native_allow: bool,
    /// The hook records its receipt and ends, with nothing left to render.
    pub finish_without_render: bool,
}
