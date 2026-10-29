//! The ratified emergency-safe profile, enforced in the resident.
//!
//! When the daemon cannot answer a hook the bridge pauses the call. A pause
//! is the right default, but it also stops the handful of read-only Guard
//! commands an operator needs in order to see why the daemon is down. The
//! profile in `docs/guard/contracts/rust-emergency-safe-profile.v1.json`
//! names those commands exactly, and this module is the only place a hook
//! may continue on their account.
//!
//! The resident is the only process that can prove the profile's four
//! identity requirements, which is why enforcement lives here rather than in
//! the one-shot bridge. `PolicySnapshotStore::current_snapshot` admits a
//! snapshot only after `validate_v3` has checked it against the resident's
//! pinned runtime identity (`package_version_match`), its pinned rule digest
//! (`rule_digest_match`), the publisher's verifier key and generation floor
//! (`authenticated_daemon_generation`), and the snapshot's own expiry
//! (`policy_snapshot_current`). `require_guard_home` pins the home those
//! proofs were made under. A one-shot bridge holds none of that: its
//! `BridgeConfig` carries a Guard home and a timeout, and the resident state
//! on disk carries no rule digest and no snapshot at all.
//!
//! Everything about the match is exact. Only a `PreToolUse` of a bounded
//! bridge harness is considered, only a shell tool call whose input carries
//! nothing but a command and its description or timeout, and only a command
//! whose tokens equal one operation's `exact_argv`. The profile's global
//! prohibitions include `uncertain_parse`, so any shell metacharacter, any
//! unexpected field and any tokenizing doubt pauses instead. Of the four
//! ratified operations only the two `guard_internal_read_only` reads are
//! here: `guard_daemon_repair` requires a local confirmation and
//! `git_status_metadata` a workspace binding, and neither gate exists yet,
//! so both stay paused.
//!
//! The continue is not a verdict. It is the same no-decision response the
//! bridge already writes for a hook that does not pause when Guard is
//! unavailable (`bounded_hook_bridge_render::failure_payload`), so the
//! harness proceeds without Guard having reviewed anything. The call is
//! still recorded: the evidence is queued for the daemon to drain, and a
//! hook whose record would not be kept pauses instead, whether because the
//! queue cannot take it or because the bound daemon does not drain it.

use serde_json::{json, Map, Value};

use super::{HookDirectDefer, PRE_TOOL_USE};
use crate::codex_hook_bridge_direct::BOUNDED_DIRECT_HARNESSES;
use crate::policy_store::PolicySnapshotStore;
use std::path::Path;

/// What the harness is told, and the reason the evidence carries.
const CONTINUE_REASON: &str = "HOL Guard is unavailable; this read-only Guard command is allowed by the emergency-safe profile.";
/// The reason code the queued evidence carries.
const REASON_CODE: &str = "native_emergency_safe_profile";

/// A `guard_internal_read_only` operation of the ratified profile. Keep this
/// table and the contract identical; `hook_direct_emergency_safe_tests.rs`
/// reads the contract and fails when they drift.
struct SafeOperation {
    id: &'static str,
    argv: &'static [&'static str],
}

const SAFE_OPERATIONS: [SafeOperation; 2] = [
    SafeOperation {
        id: "guard_runtime_status",
        argv: &["hol-guard", "runtime", "status", "--json"],
    },
    SafeOperation {
        id: "guard_native_doctor",
        argv: &["hol-guard", "doctor", "--native", "--json"],
    },
];

/// The only `tool_input` fields an emergency-safe call may carry. A command
/// arriving with anything else is not the shape this profile was ratified
/// against, so it pauses.
const TOOL_INPUT_FIELDS: [&str; 3] = ["command", "description", "timeout"];

/// The answer for a hook the bridge asks about only after the daemon failed.
///
/// `Ok` is a continue; every `Err` pauses the call, which is what the bridge
/// would have done without this module.
pub(super) fn answer(
    harness: &str,
    guard_home: &str,
    home_dir: &str,
    workspace: &str,
    pre_tool: bool,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    if !pre_tool {
        return Err(HookDirectDefer::EmergencySafeProfile);
    }
    if !BOUNDED_DIRECT_HARNESSES.contains(&harness) {
        return Err(HookDirectDefer::HarnessUnsupported);
    }
    // Both proofs are the resident's own: the home it serves, and a snapshot
    // admitted against its pinned identity, rule digest, generation floor and
    // expiry.
    policy_store
        .require_guard_home(guard_home)
        .map_err(|_| HookDirectDefer::HomeMismatch)?;
    policy_store
        .current_snapshot()
        .map_err(|_| HookDirectDefer::EmergencySafeProfile)?;
    // The ordinary direct lane answers nothing the bound daemon will not
    // collect, and a continue here is recorded the same way. A daemon that
    // does not drain the direct queue, an older one for instance, would
    // leave this call in it unrecorded, so the hook pauses as the lane does.
    if !policy_store.direct_lane_evidence_drain() {
        return Err(HookDirectDefer::EvidenceUndrained);
    }
    let operation = command_text(payload)
        .and_then(matching_operation)
        .ok_or(HookDirectDefer::EmergencySafeProfile)?;
    let response = continue_response(harness);
    let evidence = evidence_record(harness, home_dir, workspace, payload, operation, &response);
    if !crate::edge_receipt::offer_direct(
        policy_store.direct_evidence(),
        Path::new(guard_home),
        evidence,
    ) {
        return Err(HookDirectDefer::EvidenceFull);
    }
    Ok(json!({
        "event_name": PRE_TOOL_USE,
        "harness_response": response,
        "emergency_safe_operation": operation,
    }))
}

/// The record the daemon drains, in the shape `record_direct_hook_evidence`
/// requires of a direct answer: an event and a harness it knows, the payload,
/// and a workspace and home it reads as text. The record carries no receipt,
/// because nothing reviewed this call, so the drain records the command
/// activity alone and cites no decision.
fn evidence_record(
    harness: &str,
    home_dir: &str,
    workspace: &str,
    payload: &Map<String, Value>,
    operation: &str,
    response: &Value,
) -> Value {
    json!({
        "event": PRE_TOOL_USE,
        "harness": harness,
        "workspace": workspace,
        "home_dir": home_dir,
        "payload": Value::Object(payload.clone()),
        "receipt": Value::Null,
        "harness_response": response.clone(),
        "emergency_safe_operation": operation,
        "reason_code": REASON_CODE,
    })
}

/// The command of a shell tool call whose input carries nothing unexpected.
fn command_text(payload: &Map<String, Value>) -> Option<&str> {
    let tool_name = field(payload, "tool_name", "toolName")?.as_str()?;
    if !guard_command::package_intent_parser::shell_tool_name(tool_name) {
        return None;
    }
    let tool_input = field(payload, "tool_input", "toolInput")?.as_object()?;
    if tool_input
        .keys()
        .any(|key| !TOOL_INPUT_FIELDS.contains(&key.as_str()))
    {
        return None;
    }
    tool_input.get("command")?.as_str()
}

fn field<'a>(payload: &'a Map<String, Value>, snake: &str, camel: &str) -> Option<&'a Value> {
    payload.get(snake).or_else(|| payload.get(camel))
}

/// The profile operation `command` is, when its tokens are exactly one
/// operation's `exact_argv`.
fn matching_operation(command: &str) -> Option<&'static str> {
    let tokens = tokens(command)?;
    SAFE_OPERATIONS
        .iter()
        .find(|operation| operation.argv == tokens.as_slice())
        .map(|operation| operation.id)
}

/// The command's tokens, for a command that holds nothing but the characters
/// the ratified argv spell it with. A shell metacharacter, a tab, a repeated
/// or edge space, or any non-ASCII character makes the parse uncertain, which
/// the profile prohibits outright.
fn tokens(command: &str) -> Option<Vec<&str>> {
    if command.is_empty() || !command.chars().all(spelled_exactly) {
        return None;
    }
    let tokens: Vec<&str> = command.split(' ').collect();
    if tokens.iter().any(|token| token.is_empty()) {
        return None;
    }
    Some(tokens)
}

fn spelled_exactly(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/' | '=' | ' ')
}

/// The no-decision response the bridge writes for a hook that does not pause
/// when Guard is unavailable, in `failure_payload`'s own per-harness shapes.
fn continue_response(harness: &str) -> Value {
    match harness {
        "copilot" => json!({ "permissionDecision": "allow" }),
        "openclaw" | "hermes" => json!({ "decision": "allow", "reason": CONTINUE_REASON }),
        _ => json!({
            "continue": true,
            "systemMessage": CONTINUE_REASON,
            "hookSpecificOutput": { "hookEventName": PRE_TOOL_USE },
        }),
    }
}

#[cfg(test)]
#[path = "hook_direct_emergency_safe_tests.rs"]
mod tests;
