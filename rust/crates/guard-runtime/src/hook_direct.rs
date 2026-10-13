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
//! in Watch, and a Cursor `PreToolUse` its hook client runs as an allow. The
//! daemon never changes those responses. Every other request,
//! and every `PreToolUse` verdict the daemon turns into an approval or a
//! repair link, defers so the caller takes the daemon path, which is
//! unchanged. A Claude Code sandbox requirement outside Watch is routed to
//! contained execution as the daemon routes it, once the daemon has bound
//! its sink command, and defers without one. While custom extension
//! block rules exist, an allowed `PreToolUse` whose command launches a local
//! CLI, or whose launch cannot be derived, also defers so the daemon reads
//! that CLI's grant.
//!
//! The daemon also records evidence after it answers. An answer is returned
//! only once that evidence is queued for the daemon to drain.

use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    GuardExecutionEnvironmentV1, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(test, unix))]
use workspace::{expanduser, normalized_workspace, normpath};
use workspace::{python_strip, settled_directory, workspace_candidate};

pub(crate) const HOOK_DIRECT_FEATURE: &str = "hook-direct-v1";
/// The resident accepts the sink command that routes a sandbox requirement.
pub(crate) const HOOK_DIRECT_CONTAINED_ROUTE_FEATURE: &str = "hook-direct-contained-route-v1";
const HOOK_DIRECT_RESULT_SCHEMA: &str = "guard-hook-direct-result.v1";
/// The harnesses whose allow the daemon returns as the edge rendered it.
const DIRECT_HARNESSES: [&str; 3] = ["codex", CLAUDE_CODE, CURSOR];
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
enum HookDirectDefer {
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
    ExecutionEnvironmentInvalid,
    EvidenceUndrained,
    EvidenceFull,
    ContainedRouteFailed,
    EdgeFailed,
    NotAllow,
    RuntimeSuperseded,
}

impl HookDirectDefer {
    fn code(self) -> &'static str {
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
            Self::ExecutionEnvironmentInvalid => "direct_hook_execution_environment_invalid",
            Self::EvidenceUndrained => "direct_hook_evidence_undrained",
            Self::EvidenceFull => "direct_hook_evidence_full",
            Self::ContainedRouteFailed => "direct_hook_contained_route_failed",
            Self::EdgeFailed => "direct_hook_edge_failed",
            Self::NotAllow => "direct_hook_not_allow",
            Self::RuntimeSuperseded => "direct_hook_runtime_superseded",
        }
    }
}

pub(crate) fn evaluate(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match answer(request, policy_store) {
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
fn runtime_current() -> bool {
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
    let event = direct_event(&payload)?.ok_or(HookDirectDefer::EventUnsupported)?;
    let pre_tool = event == PRE_TOOL_USE;
    let cursor_harness = request.harness == CURSOR;
    if cursor_harness && !pre_tool {
        return Err(HookDirectDefer::EventUnsupported);
    }
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
        .admit_direct_hook(&workspace)
        .map_err(HookDirectDefer::Lane)?;

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
    // Claude Code applies `updatedInput`, so the daemon routes its sandbox
    // requirements to contained execution with the sink command it binds.
    let contained = pre_tool && request.harness == CLAUDE_CODE;
    let sink_command = binding.contained_sink_command.clone().filter(|_| contained);
    let guard_home = request.guard_home.clone();
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
            source_ref_external_allowed: false,
            execution_environment,
        },
        recording_only,
    };
    let edge = crate::edge::evaluate_envelope_with_store(envelope, policy_store)
        .map_err(|_| HookDirectDefer::EdgeFailed)?;
    // Removed again unless the answer that runs it is returned.
    let mut snapshot = None;
    let answered = match event {
        PRE_TOOL_USE if cursor_harness => cursor::answer(&edge, recording_only)?,
        // Watch never pauses or repairs a call: the daemon records the
        // edge's non-blocking response for every verdict, as the drain does.
        PRE_TOOL_USE if recording_only => reviewed_edge(&edge, PRE_TOOL_USE)?,
        PRE_TOOL_USE => {
            let mut answered = pre_tool_answer(&edge, contained && sink_command.is_none())?;
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
        POST_TOOL_USE => post_tool_answer(&edge)?,
        _ => prompt_answer(&edge, prompt_notice)?,
    };
    if local_cli::defers_for_custom_rule(
        &answered,
        rule_payload.as_ref(),
        &workspace,
        &request_home,
    ) {
        return Err(HookDirectDefer::LocalCliRules);
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

/// The edge result for `event`, when it carries the result and harness
/// response the daemon reads.
fn reviewed_edge(edge: &[u8], event: &str) -> Result<Value, HookDirectDefer> {
    let parsed: Value = serde_json::from_slice(edge).map_err(|_| HookDirectDefer::EdgeFailed)?;
    if parsed.get("event_name").and_then(Value::as_str) != Some(event)
        || !parsed.get("result").is_some_and(Value::is_object)
        || !parsed.get("harness_response").is_some_and(Value::is_object)
    {
        return Err(HookDirectDefer::EdgeFailed);
    }
    Ok(parsed)
}

/// The edge result to return as is, when the daemon would pass it through
/// unchanged:
///
/// - an allow, with an allow or warn floor. The daemon asks for approval
///   only on review and require-reapproval floors, so a warn is recorded and
///   run like an allow.
/// - a terminal block or sandbox requirement. The daemon only adds a repair
///   link to a command-control authority block and routes a Claude Code
///   sandbox requirement to contained execution, which defers here with
///   `contained` and is otherwise routed by the caller; any other denial keeps
///   the edge's harness response. A saved approval never lowers a terminal
///   action, and the daemon checks custom block rules only against an allow.
fn pre_tool_answer(edge: &[u8], contained: bool) -> Result<Value, HookDirectDefer> {
    let parsed = reviewed_edge(edge, PRE_TOOL_USE)?;
    let result = parsed.get("result");
    let field = |name: &str| {
        result
            .and_then(|result| result.get(name))
            .and_then(Value::as_str)
    };
    let passed_through = match (field("decision"), field("minimum_action")) {
        (Some("allow"), Some("allow" | "warn")) => true,
        (Some("deny" | "block"), Some("block")) => {
            field("reason_code") != Some(REPAIRABLE_BLOCK_REASON)
        }
        (Some("deny" | "block"), Some("sandbox-required")) => !contained,
        _ => false,
    };
    if !passed_through {
        return Err(HookDirectDefer::NotAllow);
    }
    Ok(parsed)
}

/// The edge result to return as is: the daemon passes every reviewed
/// `PostToolUse` of these harnesses through unchanged.
fn post_tool_answer(edge: &[u8]) -> Result<Value, HookDirectDefer> {
    reviewed_edge(edge, POST_TOOL_USE)
}

/// The edge result to return as is: the daemon passes a reviewed
/// `UserPromptSubmit` through once it accepts the receipt, and answers one
/// without a receipt as unavailable. With `notice`, the daemon adds Guard's
/// Claude Code notice for exactly these actions and leaves any other
/// response untouched.
fn prompt_answer(edge: &[u8], notice: bool) -> Result<Value, HookDirectDefer> {
    let parsed = reviewed_edge(edge, USER_PROMPT_SUBMIT)?;
    if !parsed.get("receipt").is_some_and(Value::is_object) {
        return Err(HookDirectDefer::EdgeFailed);
    }
    let action = parsed
        .get("result")
        .and_then(|result| result.get("minimum_action"))
        .and_then(Value::as_str);
    if notice
        && matches!(
            action,
            Some("require-reapproval" | "block" | "sandbox-required")
        )
    {
        return Err(HookDirectDefer::PromptNotice);
    }
    Ok(parsed)
}

/// The daemon's event name rule: the first non-blank name field decides, and
/// a payload without one is a `PreToolUse`. Only the two tool events and a
/// prompt can be answered here.
fn direct_event(payload: &Map<String, Value>) -> Result<Option<&'static str>, HookDirectDefer> {
    for field in EVENT_NAME_FIELDS {
        let Some(value) = payload.get(field).and_then(Value::as_str) else {
            continue;
        };
        let Some(stripped) = python_strip(value)? else {
            continue;
        };
        let compact: String = stripped
            .chars()
            .filter(|character| !matches!(character, '_' | '-'))
            .collect();
        if !compact.is_ascii() {
            return Ok(None);
        }
        let compact = compact.to_ascii_lowercase();
        return Ok(if PRE_TOOL_EVENT_NAMES.contains(&compact.as_str()) {
            Some(PRE_TOOL_USE)
        } else if POST_TOOL_EVENT_NAMES.contains(&compact.as_str()) {
            Some(POST_TOOL_USE)
        } else if USER_PROMPT_EVENT_NAMES.contains(&compact.as_str()) {
            Some(USER_PROMPT_SUBMIT)
        } else {
            None
        });
    }
    Ok(Some(PRE_TOOL_USE))
}

#[path = "hook_direct_contained.rs"]
mod contained;
#[path = "hook_direct_cursor.rs"]
mod cursor;
#[path = "hook_direct_local_cli.rs"]
mod local_cli;
#[path = "hook_direct_workspace.rs"]
mod workspace;

#[cfg(all(test, unix))]
#[path = "hook_direct_tests.rs"]
mod tests;
