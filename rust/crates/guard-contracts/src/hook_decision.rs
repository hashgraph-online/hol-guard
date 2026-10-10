//! `HookDecide` — wire contract for the resident generic-hook decision op.
//!
//! The Python hook transport gathers facts (payload fields, store lookups,
//! classifier verdicts) and renders host output. The resident owns every
//! decision in between: event-name and action normalization, composition of
//! configured/CLI/payload/edge/daemon inputs, the lookups it permits, the
//! final action after approval reuse and Watch mode, the receipt and activity
//! disposition, and the response directive. Every query is pure: no IO, no
//! SQLite. There is no Python evaluator, so a transport failure is "no
//! decision" and the caller must fail closed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const HOOK_DECISION_REQUEST_SCHEMA: &str = "guard-hook-decision-request.v1";
/// Schema discriminator for the result.
pub const HOOK_DECISION_RESULT_SCHEMA: &str = "guard-hook-decision-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_DECISION_FEATURE: &str = "hook-decision-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookDecisionRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: HookDecisionQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookDecisionQueryV1 {
    /// Compose the current action from configuration, hints and the edge floor.
    ComposeCurrent {
        inputs: Box<HookCompositionInputsV1>,
    },
    /// Derive the inputs of the approval-reuse re-evaluation after a claim.
    PostClaimReuse { inputs: PostClaimInputsV1 },
    /// Settle the final action, record dispositions and the response directive.
    Finalize {
        inputs: Box<HookCompositionInputsV1>,
        settled: Box<HookSettledInputsV1>,
    },
}

/// Facts the transport read from the hook payload and local configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookCompositionInputsV1 {
    /// The harness exactly as the CLI received it.
    pub harness: String,
    /// The adapter registry's canonical harness name.
    pub canonical_harness: String,
    /// The payload's `event`, `hook_event_name`, `hookEventName` and
    /// `hook_name` values, verbatim; the resident resolves the event itself.
    pub event_fields: Map<String, Value>,
    /// `str(payload["tool_name"])`; names the verified-benign classifier.
    pub tool_name_text: String,
    /// The configured override, else the configured default (untyped).
    pub configured_action: Value,
    pub has_configured_override: bool,
    pub has_narrow_override: bool,
    pub runtime_artifact_checked: bool,
    pub prompt_nonblank: bool,
    pub has_command_text: bool,
    /// Classifier verdicts the resident asked for; see `needs_facts`.
    #[serde(default)]
    pub facts: BTreeMap<String, bool>,
    /// The trusted CLI `--policy-action`, when given.
    #[serde(default)]
    pub cli_action: Option<Value>,
    /// Whether the payload carried a `policy_action` key (any value).
    #[serde(default)]
    pub has_payload_action: bool,
    #[serde(default)]
    pub payload_action: Value,
    #[serde(default)]
    pub native_edge: Option<HookNativeEdgeV1>,
    #[serde(default)]
    pub daemon_status: Value,
    #[serde(default)]
    pub fail_mode: Value,
    #[serde(default)]
    pub permission_decision_reason: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct HookNativeEdgeV1 {
    #[serde(default)]
    pub policy_action: Value,
    #[serde(default)]
    pub minimum_action: Value,
    #[serde(default)]
    pub decision: Value,
}

/// What the transport learned after the lookups the composition permitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookSettledInputsV1 {
    /// The composed action after the grant lookups the resident allowed.
    pub current_policy_action: String,
    pub tool_grant_applied: bool,
    /// `tool_identity_hash` and `capability` of the applied tool grant.
    #[serde(default)]
    pub tool_grant_identity: Option<Map<String, Value>>,
    /// The approval-reuse decision (already made by the resident).
    pub reuse_action: String,
    pub reuse_status: String,
    pub has_stored_decision: bool,
    pub has_ignored_integrity: bool,
    pub saved_decision_present: bool,
    #[serde(default)]
    pub stored_policy_action: Option<String>,
    /// Whether the reuse decision was re-evaluated after a one-shot claim.
    pub claimed_context: bool,
    pub asks_for_approval: bool,
    pub observe_mode: bool,
    pub has_approval_requests_list: bool,
    pub json_requested: bool,
    pub output_stream_present: bool,
    /// The payload already carried a string `artifact_id`.
    pub replay_artifact_id: bool,
    /// The payload already carried a string `policy_action`.
    pub payload_action_is_string: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PostClaimInputsV1 {
    pub current_policy_action: String,
    pub reuse_action: String,
    #[serde(default)]
    pub reuse_saved_action: Option<Value>,
    pub post_claim_refresh_failed: bool,
    pub context_changed: bool,
    pub has_ignored_integrity: bool,
    /// The claimed row no longer matches the authenticated saved row.
    pub claim_row_invalid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_hook_decision_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<HookDecisionPayloadV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookDecisionPayloadV1 {
    ComposeCurrent {
        /// The normalized hook event, resolved by the resident; classifiers the
        /// transport runs for a requested fact are scoped by it.
        event_name: Option<String>,
        /// Classifier facts still missing; resubmit with them when non-empty.
        needs_facts: Vec<String>,
        composition: Option<Box<HookCompositionV1>>,
    },
    PostClaimReuse {
        current_action: String,
        validation_reason: Option<String>,
    },
    Finalize(Box<HookFinalV1>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookCompositionV1 {
    /// The normalized hook event, if the payload named one.
    pub event_name: Option<String>,
    /// `event_name`, defaulting to `PreToolUse`.
    pub effective_event_name: String,
    pub composed_action: String,
    /// Whether the transport may look up local tool and CLI grants.
    pub grant_lookups_allowed: bool,
    /// Whether a trusted local tool eligibility is needed for this event.
    pub tool_eligibility_needed: bool,
    /// The action once a local tool grant is found.
    pub action_with_tool_grant: String,
    /// The action when no local tool grant applies.
    pub action_without_tool_grant: String,
    /// The reason to write back to the payload, if any.
    pub permission_decision_reason: Option<String>,
    pub daemon_failure_reason: Option<String>,
    pub token: HookTokenCompositionV1,
}

/// Composition values bound into the approval context token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookTokenCompositionV1 {
    pub current_config_action: String,
    pub daemon_hint_disposition: Option<String>,
    pub daemon_hint_reason_code: Option<String>,
    pub trusted_cli_action: Option<String>,
    pub untrusted_payload_action: Option<String>,
    pub untrusted_payload_action_disposition: Option<String>,
    pub untrusted_payload_action_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookFinalV1 {
    pub policy_action: String,
    pub observed_policy_action: Option<String>,
    pub effective_event_name: String,
    pub approval_reuse_source: Option<String>,
    pub policy_composition: Map<String, Value>,
    /// Audit entries that follow the transport's own evidence, in order.
    pub evidence_tail: Vec<Value>,
    pub silent_review: Option<HookSilentReviewV1>,
    pub record_receipt: bool,
    pub activity: HookActivityV1,
    pub directive: HookResponseDirectiveV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookSilentReviewV1 {
    /// The review-tier action that was converted to a block.
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookActivityV1 {
    /// `pre`, `post` or `none`.
    pub phase: String,
    pub reuse_status: String,
    pub prompted: bool,
}

/// What the transport renders. `route` is the first matching branch; the
/// remaining fields parameterize it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponseDirectiveV1 {
    /// `silent_exit`, `copilot`, `exit_block` or `render`.
    pub route: String,
    pub queue_observe_request: bool,
    pub queue_approval_request: bool,
    /// `default`, `grok`, `pi`, `zcode` or `devin`.
    pub emitter: String,
    /// `None` leaves the exit code to the host adapter (grok).
    pub exit_code: Option<i32>,
    /// For an exit block: write the stderr explanation only on a non-zero exit.
    pub stderr_only_on_nonzero_exit: bool,
    /// `always`, `with_approval_context` or `never`.
    pub codex_native_reason: String,
    pub include_remediation: bool,
    pub terminal_notice: bool,
    /// `none`, `claude_punctuated` or `codex_prompt`.
    pub system_message: String,
    pub try_json_document: bool,
    /// `native_response`, `post_tool_envelope` or `fallback_envelope`.
    pub after_json: String,
    /// `block` or `allow`.
    pub envelope_decision: String,
}
