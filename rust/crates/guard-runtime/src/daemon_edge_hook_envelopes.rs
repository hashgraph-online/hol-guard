//! The daemon's fixed hook replies: the fail-safe envelope each harness
//! reads, and the reasons a refusal carries.

use std::path::Path;

use serde_json::{json, Value};

use super::hook_scheduler;

/// The daemon's fixed hook replies, declared once for every harness.
pub(super) const ENVELOPES: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);

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

/// `_envelope`: the contract's reply of `kind` for the harness, else its
/// default, with the placeholders filled.
pub(super) fn envelope(kind: &str, harness: &str, values: &[(&str, &str)]) -> Value {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let table = &contract["envelopes"][kind];
    let harness = harness.trim().to_lowercase().replace('_', "-");
    let template = table
        .get(harness.as_str())
        .or_else(|| table.get("*"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    fill(template, values)
}

/// `_event_kind`: the envelope family an event name belongs to.
pub(super) fn event_kind(contract: &Value, event: &str) -> String {
    let compact: String = event
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect();
    if let Some(kind) = contract["events"]
        .get(compact.as_str())
        .and_then(Value::as_str)
    {
        return kind.to_owned();
    }
    contract["event_prefixes"]
        .as_object()
        .into_iter()
        .flatten()
        .find(|(prefix, _)| compact.starts_with(prefix.as_str()))
        .and_then(|(_, kind)| kind.as_str())
        .unwrap_or("lifecycle")
        .to_owned()
}

/// The envelope with its whole-string placeholders filled.
pub(super) fn fill(template: Value, values: &[(&str, &str)]) -> Value {
    match template {
        Value::String(text) => values
            .iter()
            .find(|(placeholder, _)| *placeholder == text)
            .map_or(Value::String(text), |(_, value)| json!(value)),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, fill(value, values)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| fill(item, values)).collect())
        }
        other => other,
    }
}
