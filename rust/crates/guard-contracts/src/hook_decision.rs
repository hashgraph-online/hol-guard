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

use crate::{CodexToolOutputFactsV1, NativeExtensionControlLayerV1};

/// Schema discriminator for the request.
pub const HOOK_DECISION_REQUEST_SCHEMA: &str = "guard-hook-decision-request.v1";
/// Schema discriminator for the result.
pub const HOOK_DECISION_RESULT_SCHEMA: &str = "guard-hook-decision-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_DECISION_FEATURE: &str = "hook-decision-v1";

/// Advertised separately because the composed post-claim request carries the
/// claimed approval's context token and expects the reuse decision back: a
/// resident that predates it would reject those fields as unknown after the
/// claim had already been consumed, so a caller asks for this first.
pub const HOOK_DECISION_POST_CLAIM_COMPOSE_FEATURE: &str = "hook-decision-post-claim-compose-v1";

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
    PostClaimReuse { inputs: Box<PostClaimInputsV1> },
    /// Settle the final action, record dispositions and the response directive.
    Finalize {
        inputs: Box<HookCompositionInputsV1>,
        settled: Box<HookSettledInputsV1>,
    },
    /// Settle a Copilot tool call: the final action and the effects to run.
    CopilotSettle { inputs: Box<CopilotSettleInputsV1> },
}

/// Facts for one Copilot `preToolUse` or `permissionRequest` call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CopilotSettleInputsV1 {
    /// `pre_tool_use` or `permission_request`.
    pub stage: String,
    /// The CLI harness is `copilot`. A pre-tool call relayed for another
    /// harness records its receipt and hands the call back to the pipeline.
    pub harness_is_copilot: bool,
    pub decision: CopilotToolDecisionV1,
    pub artifact: CopilotArtifactFactsV1,
    #[serde(default)]
    pub native_edge: Option<HookNativeEdgeV1>,
    /// Copilot's posture records only (Watch).
    pub recording_only: bool,
    /// Copilot's per-app posture override is `watch`.
    pub posture_watch: bool,
    /// Whether the acknowledged policy snapshot records only; supplied when
    /// the resident asks for it (`needs_facts`).
    #[serde(default)]
    pub acked_recording_only: Option<bool>,
    pub asks_for_approval: bool,
}

/// The resident's tool-call decision, echoed by the transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CopilotToolDecisionV1 {
    pub action: String,
    pub source: String,
    pub summary: String,
    pub signals: Vec<String>,
    #[serde(default)]
    pub normalization_reason_code: Option<String>,
    #[serde(default)]
    pub original_action: Option<String>,
    #[serde(default)]
    pub approval_reuse_status: Option<String>,
    #[serde(default)]
    pub approval_reuse_reason_code: Option<String>,
    #[serde(default)]
    pub current_action: Option<String>,
    #[serde(default)]
    pub saved_action: Option<String>,
}

/// The tool-call artifact as the approval queue and silent review store it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CopilotArtifactFactsV1 {
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_hash: String,
    pub artifact_type: String,
    pub source_scope: String,
    pub config_path: String,
    /// Sorted-key JSON of the tool arguments, else the artifact command.
    #[serde(default)]
    pub launch_target: Value,
    #[serde(default)]
    pub action_envelope_json: Value,
    pub canonical_harness: String,
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
    /// The raw tool call and caller facts the resident classifies itself.
    /// Absent means the transport could not observe them; every verdict that
    /// depends on them then fails closed (not benign).
    /// Omitted from the wire when absent, so the request digest the transport
    /// binds stays identical to the canonical form it sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_request: Option<HookNativeRequestV1>,
}

/// Raw tool call plus observed caller facts for resident-owned classifiers.
///
/// Python never recomputes these verdicts: it only forwards what the payload
/// and the host showed. `benign_native_file_read` and
/// `benign_tool_action` (`is_explicitly_benign_tool_action_request`) are both
/// computed from it; the composition reports the latter as `verified_benign`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookNativeRequestV1 {
    /// `payload["tool_name"]`, untyped as received.
    #[serde(default)]
    pub tool_name: Value,
    /// `payload["tool_input"]`, else `payload["arguments"]`, untyped.
    #[serde(default)]
    pub tool_input: Value,
    /// The runtime workspace directory, when known.
    #[serde(default)]
    pub cwd: Option<String>,
    /// The caller's home directory override, when given.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// Observed process cwd, home, account home, groups, bounded environment
    /// snapshot and `git` executable, as the tool-output op takes them.
    pub host: CodexToolOutputFactsV1,
    /// The extension-control snapshot active while the payload was handled.
    /// Absent means none was active, so no control can block a command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_snapshot: Option<HookControlSnapshotV1>,
}

/// Extension-control layers and authority health, as the runtime snapshot
/// carried them. An unknown health value makes the verdict not benign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookControlSnapshotV1 {
    pub health: String,
    pub layers: Vec<NativeExtensionControlLayerV1>,
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
    /// Whether the request's context moved since the claimed approval was
    /// saved, when the caller compared the two tokens itself. A caller that
    /// names both tokens below leaves this out and the resident compares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_changed: Option<bool>,
    /// The context token the claimed approval was stored under. Naming it asks
    /// the resident to compare the tokens and to compose what the re-evaluated
    /// claim means for reuse, so the caller makes one request instead of three.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_context_token: Option<Value>,
    /// The context token recomputed for this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_context_token: Option<Value>,
    /// The claimed row was approved locally in this session.
    ///
    /// Optional because the request digest binds the caller's own wire form:
    /// a caller that names the flag gets it back, one that leaves it out gets
    /// nothing back, and either shape re-serialises to what was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_local_approval: Option<bool>,
    /// The claimed row is a durable approval for this exact artifact, optional
    /// for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_exact_approval: Option<bool>,
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
        /// The reuse decision for the re-evaluated claim, present when the
        /// request named the claimed approval's context token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reuse: Option<Value>,
    },
    Finalize(Box<HookFinalV1>),
    CopilotSettle {
        /// Facts still missing; resubmit with them when non-empty.
        needs_facts: Vec<String>,
        plan: Option<Box<CopilotPlanV1>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CopilotPlanV1 {
    pub policy_action: String,
    pub approval_reuse: Option<Map<String, Value>>,
    /// The audit evidence every effect and response carries.
    pub scanner_evidence: Vec<Value>,
    /// Effects to run in order.
    pub effects: Vec<CopilotEffectV1>,
    /// `0` once the hook answered; `None` hands the call back to the pipeline.
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum CopilotEffectV1 {
    /// Store a review the agent sees only as a block.
    SilentReview {
        artifact: Map<String, Value>,
    },
    /// Record what Watch mode let through.
    ObserveQueue {
        executable_action: String,
        observed_policy_action: String,
        changed_fields: Vec<String>,
    },
    /// Write the tool-call receipt (`allow` or `block`).
    Receipt {
        verdict: String,
        decision_source: String,
        policy_action: String,
    },
    /// Record pre-hook command activity bound to the receipt just written.
    Activity {
        event: String,
        policy_action: String,
        prompted: bool,
        reuse_status: String,
    },
    Usage {
        policy_action: String,
    },
    /// Answer `preToolUse`.
    PretoolResponse {
        permission_decision: String,
        reason: String,
    },
    /// Answer `permissionRequest`.
    PermissionResponse {
        behavior: String,
        message: Option<String>,
        interrupt: Option<bool>,
    },
    /// Queue the approval, then deny with `deny_reason` and the review link.
    QueueApproval {
        evaluation_artifact: Map<String, Value>,
        response_payload: Map<String, Value>,
        deny_reason: String,
    },
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
    /// The resident's `is_explicitly_benign_tool_action_request` verdict for
    /// the native request; false when none was sent or it cannot be computed.
    #[serde(default)]
    pub verified_benign: bool,
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
