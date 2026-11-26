//! The daemon's fixed hook replies: the fail-safe envelope each harness
//! reads, and the reasons a refusal carries.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::hook_scheduler;
#[cfg(test)]
pub(super) use crate::hook_fail_closed_envelopes::fill;
pub(super) use crate::hook_fail_closed_envelopes::{envelope, event_kind, ENVELOPES};

/// The reason and code a library step's `fail_safe` carries.
pub(super) fn refusal(refused: &Value) -> Option<(&str, &str)> {
    Some((
        refused.get("reason")?.as_str()?,
        refused.get("reason_code")?.as_str()?,
    ))
}

pub(super) fn prepare_refusal(
    harness: &str,
    event: &str,
    refused: &Value,
    payload: &Map<String, Value>,
) -> Option<Value> {
    let (fallback, code) = refusal(refused)?;
    if let Some(allowed) = claude_recovery(harness, event, code, payload) {
        return Some(allowed);
    }
    let reason = refused
        .get("policy_failure")
        .and_then(Value::as_object)
        .filter(|_| code == "native_policy_not_ready")
        .map(crate::hook_policy_admission_op::daemon_reason);
    Some(fail_safe(
        harness,
        event,
        reason.as_deref().unwrap_or(fallback),
        code,
    ))
}

/// The answer that lets a Claude Code recovery command run when the daemon
/// could not reach a verdict. Codex gets the same list in its hook bridge
/// (`codex_hook_bridge_recovery`); without it a Claude Code session whose
/// daemon cannot publish policy is refused every tool call, including the
/// `hol-guard daemon repair` the refusal asks for, until a person runs it in
/// a terminal. Only a word-for-word recovery or diagnostic command qualifies;
/// a real verdict, any other command and any other harness keep the refusal.
fn claude_recovery(
    harness: &str,
    event: &str,
    code: &str,
    payload: &Map<String, Value>,
) -> Option<Value> {
    use crate::codex_hook_bridge::recovery;
    if harness != "claude-code" || event != "PreToolUse" || !recovery::is_no_verdict(code) {
        return None;
    }
    let data = serde_json::to_string(payload).ok()?;
    recovery::is_recovery_call(&data).then(|| {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "HOL Guard could not finish preparing its policy, so it did not review this call. It runs because it only reads or repairs Guard's own state; every other action stays blocked until Guard answers.",
            },
        })
    })
}

/// Whether a `native_policy_not_ready` refusal only means the policy wait
/// used up the hook's own deadline: no time is left and the publisher reports
/// no error. Under a burst the barrier waits in the admitted slot, so a hook
/// that queued behind others can run out of time while the next ACK is a
/// moment away. That is deadline exhaustion, and naming it so keeps the
/// "policy not ready" reason for a publisher that actually failed. The
/// verdict is the same deny either way.
pub(super) fn policy_wait_outlived_deadline(refused: &Value, remaining_seconds: f64) -> bool {
    if remaining_seconds > 0.0
        || refusal(refused).map(|(_, code)| code) != Some("native_policy_not_ready")
    {
        return false;
    }
    refused
        .get("policy_failure")
        .and_then(|failure| failure.get("last_error"))
        .and_then(Value::as_str)
        .is_none_or(|code| code.trim().is_empty())
}

/// The message a capacity refusal carries. A retry usually succeeds once a
/// cold start or a burst has passed; one that keeps failing points at a
/// daemon that needs repair, so each message names the command for that.
///
/// The command names the refusing daemon's Guard home whenever it is not
/// known to be `<home_dir>/.hol-guard`, quoted for the shell: a bare
/// `hol-guard repair` would repair the default install and leave this one
/// refusing. An unknown home directory cannot prove the home is the default,
/// so it names the home too.
pub(super) fn capacity_reason(code: &str, guard_home: &Path, home_dir: &str) -> String {
    let command = if !home_dir.is_empty() && Path::new(home_dir).join(".hol-guard") == guard_home {
        "hol-guard repair".to_owned()
    } else {
        format!(
            "hol-guard repair --guard-home {}",
            crate::mcp_proxy_shlex::quote(&guard_home.to_string_lossy())
        )
    };
    let cause = if code == hook_scheduler::DEADLINE_EXHAUSTED {
        "HOL Guard could not complete local review within the hook deadline."
    } else {
        "HOL Guard is safely queueing the maximum local review workload."
    };
    format!("{cause} Retry this action; if it keeps failing, run `{command}`.")
}

/// The harness's answer when the hook worker could not review the hook:
/// `fail_closed_response` with `native_hook_worker_unavailable`. Tool,
/// permission and prompt events get a constant deny in the harness envelope;
/// other events a constant payload that carries no verdict.
pub(super) fn fail_safe(harness: &str, event: &str, reason: &str, code: &str) -> Value {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let kind = event_kind(&contract, event);
    let reason = if kind == "prompt" {
        contract["defaults"]["prompt_reason"]
            .as_str()
            .unwrap_or(reason)
    } else {
        reason
    };
    envelope(
        &kind,
        harness,
        &[
            ("$reason", reason),
            ("$reason_code", code),
            ("$event_name", event),
        ],
    )
}
