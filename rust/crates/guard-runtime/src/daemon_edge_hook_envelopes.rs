//! The daemon's fixed hook replies: the fail-safe envelope each harness
//! reads, and the reasons a refusal carries.

use std::path::Path;

use serde_json::Value;

use super::hook_scheduler;
pub(super) use crate::hook_fail_closed_envelopes::{envelope, event_kind, fill, ENVELOPES};

/// The reason and code a library step's `fail_safe` carries.
pub(super) fn refusal(refused: &Value) -> Option<(&str, &str)> {
    Some((
        refused.get("reason")?.as_str()?,
        refused.get("reason_code")?.as_str()?,
    ))
}

pub(super) fn prepare_refusal(harness: &str, event: &str, refused: &Value) -> Option<Value> {
    let (fallback, code) = refusal(refused)?;
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
