//! Answer a hook in the resident when the daemon would return the edge
//! verdict unchanged.
//!
//! The daemon path derives the workspace, checks daemon state the snapshot
//! does not carry, builds the edge envelope and, for most verdicts, returns the
//! edge's harness response verbatim. This operation repeats that path for the
//! shapes where the daemon adds nothing, in a workspace the current snapshot
//! settled, while the publisher's ACK still holds: a Codex or Claude Code
//! `PreToolUse` allow or terminal block, any `PreToolUse` verdict in Watch,
//! any reviewed `PostToolUse` of those harnesses, and a reviewed
//! `UserPromptSubmit` with its receipt, for Codex always and for Claude Code
//! in Watch, and a Cursor `PreToolUse` or `UserPromptSubmit` its hook client
//! renders as it would the daemon's answer.
//! The bounded bridge harnesses, Grok among them, are answered as Codex is.
//! The daemon never changes those responses. Every other request, and every
//! `PreToolUse` verdict the daemon turns into an approval or a repair link,
//! defers so the caller takes the daemon path, which is unchanged; a
//! reviewed `PreToolUse` outside Watch, Cursor's included, is answered from a
//! saved decision, an approve-once or the approval inbox where
//! `hook_direct_saved_decision.rs` reproduces the daemon. A Claude
//! Code or ZCode sandbox requirement outside Watch is routed to
//! contained execution as the daemon routes it, once the daemon has bound
//! its sink command, and defers without one. While custom extension
//! block rules exist, an allowed `PreToolUse` whose command launches a local
//! CLI reads that CLI's grant as the daemon does and, when the grant blocks
//! it, answers with the daemon's block; a launch or grant the daemon would
//! block as unverified still defers.
//!
//! The daemon also records evidence after it answers. An answer is returned
//! only once that evidence is queued for the daemon to drain.

use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use crate::policy_store::PolicySnapshotStore;
use edge::{direct_event, post_tool_answer, pre_tool_answer, prompt_answer, reviewed_edge};
use guard_contracts::{
    GuardExecutionEnvironmentV1, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(test, unix))]
use workspace::{expanduser, normalized_workspace, normpath};
use workspace::{settled_directory, workspace_candidate};

pub(crate) const HOOK_DIRECT_FEATURE: &str = "hook-direct-v1";
/// The resident accepts the sink command that routes a sandbox requirement.
pub(crate) const HOOK_DIRECT_CONTAINED_ROUTE_FEATURE: &str = "hook-direct-contained-route-v1";
/// Advertised once the resident answers a Claude PermissionRequest from the
/// session's notice, verified and marked seen with the bound integrity key.
pub(crate) const HOOK_DIRECT_PERMISSION_NOTICE_FEATURE: &str = "hook-direct-permission-notice-v1";
/// The resident answers a reviewed `PreToolUse` from a saved exact-action
/// decision when the binding carries what the daemon reads it with.
pub(crate) const HOOK_DIRECT_SAVED_DECISION_FEATURE: &str = "hook-direct-saved-decision-v1";
/// The resident takes the bound managed-policy view and answers an Oh My Pi
/// `PostToolUse` for which it requires no structured output mediation.
pub(crate) const HOOK_DIRECT_STRUCTURED_OUTPUT_FEATURE: &str = "hook-direct-structured-output-v1";
const HOOK_DIRECT_RESULT_SCHEMA: &str = "guard-hook-direct-result.v1";
/// The harnesses whose allow the daemon returns as the edge rendered it.
/// The bounded bridge harnesses after Cursor have no harness-specific step
/// on the daemon path for the hooks answered here; the `pi` module defers
/// the Oh My Pi steps the resident cannot repeat.
pub(crate) const DIRECT_HARNESSES: [&str; 14] = [
    "codex",
    CLAUDE_CODE,
    CURSOR,
    "copilot",
    "kimi",
    "devin",
    ZCODE,
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    GROK,
    "pi",
    "omp",
];
const TRANSITION_PROBE_FIELD: &str = "guard_transition_probe";
const EXECUTION_ENVIRONMENT_FIELD: &str = "guard_execution_environment";
const PAYLOAD_REFERENCE_FIELDS: [&str; 2] = ["guard_payload_ref", "guard_source_ref"];
const EVENT_NAME_FIELDS: [&str; 6] = [
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
];
const PRE_TOOL_USE: &str = "PreToolUse";
const POST_TOOL_USE: &str = "PostToolUse";
/// The denial the daemon adds a command-control repair link to.
const REPAIRABLE_BLOCK_REASON: &str = "native_command_control_authority_block";
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
const USER_PROMPT_EVENT_NAMES: [&str; 3] = ["prompt", "userpromptsubmit", "userpromptsubmitted"];
const CLAUDE_CODE: &str = "claude-code";
const CURSOR: &str = "cursor";
const ZCODE: &str = "zcode";
const GROK: &str = "grok";
const PRE_TOOL_EVENT_NAMES: [&str; 7] = [
    "pretool",
    "pretooluse",
    "pretoolcall",
    "beforeshellexecution",
    "beforereadfile",
    "beforewritefile",
    "beforemcpexecution",
];
const POST_TOOL_EVENT_NAMES: [&str; 7] = [
    "posttool",
    "posttooluse",
    "posttoolcall",
    "aftershellexecution",
    "afterreadfile",
    "afterwritefile",
    "aftermcpexecution",
];
/// The daemon's budget when the caller sends none, and its upper bound.
const DEFAULT_DEADLINE_BUDGET_MS: u64 = 750;
const MAX_DEADLINE_BUDGET_MS: u64 = 9_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectRequestV1 {
    pub(crate) harness: String,
    pub(crate) guard_home: String,
    /// The `home` query parameter; without one the daemon uses its own.
    #[serde(default)]
    pub(crate) home_dir: Option<String>,
    /// The `workspace` query parameter the daemon path would receive.
    #[serde(default)]
    pub(crate) workspace: Option<String>,
    #[serde(default)]
    pub(crate) deadline_budget_ms: Option<u64>,
    pub(crate) payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookDirectDefer {
    HarnessUnsupported,
    HarnessUnmanaged,
    EventUnsupported,
    PayloadUnsupported,
    TransitionProbe,
    WorkspaceMissing,
    WorkspaceInvalid,
    Lane(DirectLaneDefer),
    BindingIncomplete,
    HomeMismatch,
    LocalCliRules,
    PromptNotice,
    PermissionNotice,
    ExecutionEnvironmentInvalid,
    EvidenceUndrained,
    EvidenceFull,
    ContainedRouteFailed,
    EdgeFailed,
    NotAllow,
    SavedDecision,
    ReviewQueue,
    RuntimeSuperseded,
    StructuredMediation,
}

impl HookDirectDefer {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::HarnessUnsupported => "direct_hook_harness_unsupported",
            Self::HarnessUnmanaged => "direct_hook_harness_unmanaged",
            Self::EventUnsupported => "direct_hook_event_unsupported",
            Self::PayloadUnsupported => "direct_hook_payload_unsupported",
            Self::TransitionProbe => "direct_hook_transition_probe",
            Self::WorkspaceMissing => "direct_hook_workspace_missing",
            Self::WorkspaceInvalid => "direct_hook_workspace_invalid",
            Self::Lane(defer) => defer.code(),
            Self::BindingIncomplete => "direct_hook_binding_incomplete",
            Self::HomeMismatch => "direct_hook_home_mismatch",
            Self::LocalCliRules => "direct_hook_local_cli_rules",
            Self::PromptNotice => "direct_hook_prompt_notice",
            Self::PermissionNotice => "direct_hook_permission_notice",
            Self::ExecutionEnvironmentInvalid => "direct_hook_execution_environment_invalid",
            Self::EvidenceUndrained => "direct_hook_evidence_undrained",
            Self::EvidenceFull => "direct_hook_evidence_full",
            Self::ContainedRouteFailed => "direct_hook_contained_route_failed",
            Self::EdgeFailed => "direct_hook_edge_failed",
            Self::NotAllow => "direct_hook_not_allow",
            Self::SavedDecision => "direct_hook_saved_decision",
            Self::ReviewQueue => "direct_hook_review_queue",
            Self::RuntimeSuperseded => "direct_hook_runtime_superseded",
            Self::StructuredMediation => "direct_hook_structured_mediation",
        }
    }
}

pub(crate) fn evaluate(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match crate::hook_direct_counters::counted(request, policy_store, answer) {
        Ok(edge) => json!({
            "schema": HOOK_DIRECT_RESULT_SCHEMA,
            "outcome": "answer",
            "edge": edge,
        }),
        Err(defer) => json!({
            "schema": HOOK_DIRECT_RESULT_SCHEMA,
            "outcome": "defer",
            "reason": defer.code(),
        }),
    };
    serde_json::to_vec(&body).map_err(|_| "direct_hook_result_encoding_failed".to_owned())
}

/// Whether this resident still runs the executable on disk. Bridges reach a
/// resident by its executable path, so after an update replaces that file a
/// resident still running the old image must leave hooks to the daemon. Once
/// superseded it stays so, without hashing the new file on every hook.
pub(crate) fn runtime_current() -> bool {
    static SUPERSEDED: AtomicBool = AtomicBool::new(false);
    if SUPERSEDED.load(Ordering::Relaxed) {
        return false;
    }
    let current = crate::resident_state::runtime_digest()
        .is_ok_and(|digest| !crate::resident_state::runtime_superseded(&digest));
    if !current {
        SUPERSEDED.store(true, Ordering::Relaxed);
    }
    current
}

fn answer(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    if !DIRECT_HARNESSES.contains(&request.harness.as_str()) {
        return Err(HookDirectDefer::HarnessUnsupported);
    }
    if !runtime_current() {
        return Err(HookDirectDefer::RuntimeSuperseded);
    }
    let Value::Object(mut payload) = request.payload else {
        return Err(HookDirectDefer::PayloadUnsupported);
    };
    let Some(event) = direct_event(&payload)? else {
        return lifecycle::answer(
            &request.harness,
            &request.guard_home,
            &payload,
            policy_store,
        );
    };
    let pre_tool = event == PRE_TOOL_USE;
    let cursor_harness = request.harness == CURSOR;
    if payload.contains_key(TRANSITION_PROBE_FIELD) {
        // A probe carries a request identity only the daemon assigns.
        return Err(HookDirectDefer::TransitionProbe);
    }
    if PAYLOAD_REFERENCE_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    let structured_mediation = pi::structured_mediation(&request.harness, event);
    let source_ref_external_allowed = pi::source_ref_external_allowed(&request.harness);
    payload.remove("hook_env");
    // The daemon records the payload without `hook_env`, and with the
    // execution environment present even when the caller sent none.
    let mut evidence_payload = payload.clone();
    evidence_payload
        .entry(EXECUTION_ENVIRONMENT_FIELD)
        .or_insert(Value::Null);
    let execution_environment = match payload.remove(EXECUTION_ENVIRONMENT_FIELD) {
        None | Some(Value::Null) => None,
        Some(value @ Value::Object(_)) => Some(
            serde_json::from_value::<GuardExecutionEnvironmentV1>(value)
                .map_err(|_| HookDirectDefer::ExecutionEnvironmentInvalid)?,
        ),
        Some(_) => return Err(HookDirectDefer::ExecutionEnvironmentInvalid),
    };

    let request_home = match request.home_dir {
        Some(home_dir) => home_dir,
        None => policy_store
            .direct_lane_home_dir()
            .ok_or(HookDirectDefer::BindingIncomplete)?,
    };
    let candidate = workspace_candidate(&payload, request.workspace.as_deref(), &request_home)?
        .ok_or(HookDirectDefer::WorkspaceMissing)?;
    let workspace = settled_directory(&candidate)?;
    let (snapshot, binding) = policy_store
        .admit_direct_hook_or_subdirectory(&workspace)
        .map_err(HookDirectDefer::Lane)?;
    if structured_mediation
        && !pi::structured_output_unrequired(
            &request.harness,
            binding.structured_output_config.as_ref(),
        )
    {
        return Err(HookDirectDefer::StructuredMediation);
    }

    let home_dir = binding
        .home_dir
        .as_deref()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    if home_dir != request_home {
        return Err(HookDirectDefer::HomeMismatch);
    }
    // The daemon checks custom block rules against an allowed `PreToolUse`.
    let mut custom_rules = binding
        .local_cli_block_rules
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // The binding is only as fresh as its last publish, while the daemon reads
    // the rules and the managed installs from the store before every hook.
    // A change saved since then lives only in the store, so read it there
    // too. An unreadable store counts as holding rules, as a failed daemon
    // probe does.
    let store =
        crate::local_store_read::hook_store_probe(Path::new(&request.guard_home), &request.harness)
            .map_err(|_| HookDirectDefer::LocalCliRules)?;
    if store.harness_unmanaged {
        // The daemon passes such a hook through and leaves the harness its
        // own permission flow; a direct answer would replace that flow.
        return Err(HookDirectDefer::HarnessUnmanaged);
    }
    custom_rules |= store.local_cli_block_rules;
    let postures = binding
        .harness_postures
        .as_ref()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // A per-harness override wins over the snapshot mode in both directions.
    let recording_only = match postures.get(&request.harness) {
        Some(posture) => posture == "watch",
        None => snapshot.mode == "observe",
    };
    // Outside Watch the daemon may add Guard's notice to a Claude Code
    // prompt response.
    let prompt_notice =
        event == USER_PROMPT_SUBMIT && !recording_only && request.harness == CLAUDE_CODE;
    if binding.evidence_drain != Some(true) {
        return Err(HookDirectDefer::EvidenceUndrained);
    }

    // Only a `PreToolUse` under custom rules reads its payload after the edge.
    let rule_payload = (pre_tool && custom_rules).then(|| payload.clone());
    // Claude Code and ZCode apply `updatedInput`, so the daemon routes their
    // sandbox requirements to contained execution with the sink command it
    // binds.
    let contained = pre_tool && (request.harness == CLAUDE_CODE || request.harness == ZCODE);
    let sink_command = binding.contained_sink_command.clone().filter(|_| contained);
    let guard_home = request.guard_home.clone();
    // Without custom rules, the daemon reads a reviewed `PreToolUse` against
    // the exact-action decisions the user saved.
    let saved_payload = (pre_tool && !custom_rules && !recording_only).then(|| payload.clone());
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: None,
        harness: request.harness.clone(),
        event: event.to_owned(),
        raw_payload: Value::Object(payload),
        deadline_budget_ms: Some(
            request
                .deadline_budget_ms
                .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
                .clamp(1, MAX_DEADLINE_BUDGET_MS),
        ),
        policy_generation: snapshot.generation,
        policy_snapshot: json!({
            "generation": snapshot.generation,
            "policy_digest": snapshot.policy_digest,
            "runtime_identity": snapshot.runtime_identity,
        }),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(workspace.clone()),
            home_dir: request_home.clone(),
            guard_home: request.guard_home,
            source_ref_external_allowed,
            execution_environment,
        },
        recording_only,
    };
    let edge = crate::edge::evaluate_envelope_with_store(envelope, policy_store)
        .map_err(|_| HookDirectDefer::EdgeFailed)?;
    // Removed again unless the answer that runs it is returned.
    let mut snapshot = None;
    let mut answered = match event {
        // Watch never pauses or repairs a call: the daemon records the
        // edge's non-blocking response for every verdict, as the drain does.
        PRE_TOOL_USE if recording_only && !cursor_harness => reviewed_edge(&edge, PRE_TOOL_USE)?,
        PRE_TOOL_USE => match (
            if cursor_harness {
                cursor::answer(&edge, recording_only)
            } else {
                pre_tool_answer(&edge, contained && sink_command.is_none())
            },
            saved_payload.as_ref(),
        ) {
            // The daemon returns a saved decision's response as is.
            (Err(HookDirectDefer::NotAllow), Some(payload)) => {
                let context = saved_decision::Context {
                    harness: &request.harness,
                    payload,
                    recorded_payload: &evidence_payload,
                    workspace: &workspace,
                    home_dir: &request_home,
                    guard_home: &guard_home,
                    binding: &binding,
                };
                saved_decision::answer(&edge, &context)?
            }
            (passed, _) => {
                let mut answered = passed?;
                if let Some(command) = sink_command.as_deref() {
                    let target = contained::SinkTarget {
                        command,
                        harness: &request.harness,
                        guard_home: &guard_home,
                        home_dir: &request_home,
                        workspace: &workspace,
                    };
                    if let Some((routed, written)) =
                        contained::route(&answered["harness_response"], &evidence_payload, &target)?
                    {
                        answered["harness_response"] = routed;
                        snapshot = Some(written);
                    }
                }
                answered
            }
        },
        POST_TOOL_USE => post_tool_answer(&edge)?,
        _ => prompt_answer(&edge, prompt_notice)?,
    };
    let rule_check = local_cli::RuleCheck {
        payload: rule_payload.as_ref(),
        harness: &request.harness,
        workspace: &workspace,
        home_dir: &request_home,
        guard_home: &guard_home,
        recording_only,
        own_shape: cursor_harness,
    };
    // The daemon's custom block replaces the edge response before it routes
    // a sandbox requirement, so a block also drops any routed snapshot.
    if let Some(blocked) = local_cli::custom_rule_response(&answered, &rule_check)
        .map_err(|()| HookDirectDefer::LocalCliRules)?
    {
        answered["harness_response"] = blocked;
        snapshot = None;
    }
    let evidence = json!({
        "event": event,
        "harness": request.harness,
        "workspace": workspace,
        "home_dir": request_home,
        "payload": Value::Object(evidence_payload),
        "receipt": answered.get("receipt").cloned().unwrap_or(Value::Null),
        "harness_response": answered["harness_response"].clone(),
    });
    if !policy_store.direct_evidence().offer(evidence) {
        return Err(HookDirectDefer::EvidenceFull);
    }
    if let Some(snapshot) = snapshot {
        snapshot.keep();
    }
    Ok(answered)
}

#[path = "hook_direct_claude_permission_text.rs"]
mod claude_permission_text;
#[path = "hook_direct_claude_prompt_text.rs"]
mod claude_prompt_text;
#[path = "hook_direct_contained.rs"]
pub(crate) mod contained;
#[path = "hook_direct_cursor.rs"]
mod cursor;
#[path = "hook_direct_edge.rs"]
mod edge;
#[path = "hook_direct_lifecycle.rs"]
mod lifecycle;
#[path = "hook_direct_local_cli.rs"]
mod local_cli;
#[path = "hook_direct_pi.rs"]
mod pi;
#[path = "hook_direct_saved_decision.rs"]
mod saved_decision;
#[path = "hook_direct_workspace.rs"]
mod workspace;

#[cfg(all(test, unix))]
#[path = "hook_direct_tests.rs"]
mod tests;
