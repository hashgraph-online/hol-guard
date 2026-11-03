//! `runner_authority` kind `hook_approval_wait`: whether a Grok or Muse
//! `PreToolUse` review waits for its approval inside the hook, and how the
//! answer is rewritten once that wait settles (`wait_for_grok_live_approval`,
//! `apply_grok_pretool_approval_wait`, `grok_resume_metadata_from_guard_payload`
//! and `apply_muse_pretool_approval_wait` before they moved here).
//!
//! Python keeps the store: it marks the Grok operations waiting, waits on the
//! requests this names and applies the edits this returns. A value that only
//! matters by its type crosses as a stand-in that keeps its truthiness.
//! serde_json does not keep object order, so edits come back as ordered
//! `[key, value]` pairs.

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::py_strip;

const WAITABLE_ACTIONS: [&str; 2] = ["review", "require-reapproval"];
/// `GROK_APPROVAL_WAIT_MAX_SECONDS`: below Grok's 85-second internal bound.
const GROK_WAIT_MAX_SECONDS: i64 = 80;
const SINGLE_ID_KEYS: [&str; 3] = [
    "primary_approval_request_id",
    "approval_request_id",
    "guardApprovalRequestId",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Harness {
    Grok,
    Muse,
}

impl Harness {
    fn label(self) -> &'static str {
        match self {
            Self::Grok => "Grok",
            Self::Muse => "Muse",
        }
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let harness = match map.get("harness").and_then(Value::as_str) {
        Some("grok") => Harness::Grok,
        Some("muse") => Harness::Muse,
        _ => return Err(ERR_INVALID),
    };
    match map.get("op").and_then(Value::as_str) {
        Some("plan") if map.len() == 6 => plan(map, harness),
        Some("settle") if map.len() == 5 => settle(map, harness),
        Some("rewrite") if map.len() == 3 => rewrite(map, harness),
        Some("resume_metadata") if harness == Harness::Grok && map.len() == 3 => {
            resume_metadata(map)
        }
        _ => Err(ERR_INVALID),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, &'static str> {
    map.get(key).and_then(Value::as_object).ok_or(ERR_INVALID)
}

/// `_optional_string`: a string with its whitespace stripped, unless empty.
fn stripped(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|text| !text.is_empty())
}

/// The requests a review waits on, or none when it does not wait: only a
/// `PreToolUse` review or reapproval waits, and never for zero seconds.
/// Grok caps the wait below its own hook deadline.
fn plan(map: &Map<String, Value>, harness: Harness) -> KindResult {
    let event = text(map, "event")?;
    let action = text(map, "policy_action")?;
    let timeout = map
        .get("timeout")
        .and_then(Value::as_i64)
        .ok_or(ERR_INVALID)?;
    let response = object(map, "response")?;
    let seconds = match harness {
        Harness::Grok => timeout.clamp(0, GROK_WAIT_MAX_SECONDS),
        Harness::Muse => timeout,
    };
    let compact = event.replace(['_', '-'], "").to_lowercase();
    let waits = compact == "pretooluse" && WAITABLE_ACTIONS.contains(&action) && seconds > 0;
    let ids = match harness {
        _ if !waits => Vec::new(),
        Harness::Grok => grok_request_ids(response),
        Harness::Muse => muse_request_ids(response),
    };
    let seconds = if ids.is_empty() { 0 } else { seconds };
    Ok(json!({ "request_ids": ids, "seconds": seconds }))
}

/// `_approval_request_ids`: every queued request object's id, else the first
/// single id the answer names.
fn grok_request_ids(response: &Map<String, Value>) -> Vec<String> {
    let queued: Vec<String> = response
        .get("approval_requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|item| stripped(item.get("request_id")))
        .map(str::to_owned)
        .collect();
    if !queued.is_empty() {
        return queued;
    }
    SINGLE_ID_KEYS
        .iter()
        .find_map(|key| stripped(response.get(*key)))
        .map(|id| vec![id.to_owned()])
        .unwrap_or_default()
}

/// Muse's `approval_request_ids`: the single ids, then each queued request's
/// `request_id` (or its `id` when that is falsy) or the bare string, once each.
fn muse_request_ids(response: &Map<String, Value>) -> Vec<String> {
    let singles = SINGLE_ID_KEYS.iter().map(|key| response.get(*key));
    let queued = response
        .get("approval_requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| match item.as_object() {
            Some(item) => match item.get("request_id") {
                Some(id) if py_truthy(id) => Some(id),
                _ => item.get("id"),
            },
            None => Some(item),
        });
    let mut ids: Vec<String> = Vec::new();
    for id in singles.chain(queued).filter_map(stripped) {
        if !ids.iter().any(|seen| seen == id) {
            ids.push(id.to_owned());
        }
    }
    ids
}

/// The decision a finished wait reached and the fields the answer carries
/// for it. Only a resolved wait whose every resolution is an explicit allow
/// resumes the call; anything else resolved keeps it blocked.
fn settle(map: &Map<String, Value>, harness: Harness) -> KindResult {
    let resolved = py_truthy(map.get("resolved").ok_or(ERR_INVALID)?);
    let rows = map
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let request_id = text(map, "request_id")?;
    let label = harness.label();
    if !resolved {
        let hint = format!(
            "Approval is still pending in HOL Guard. Approve it, and {label} will resume this exact tool call."
        );
        return Ok(json!({ "decision": null, "fields": [["review_hint", hint]] }));
    }
    let actions: Vec<Option<&Value>> = rows
        .iter()
        .filter_map(Value::as_object)
        .map(|row| row.get("action"))
        .collect();
    let allowed = !actions.is_empty()
        && actions
            .iter()
            .all(|action| action.and_then(Value::as_str) == Some("allow"));
    if !allowed {
        let hint = format!("HOL Guard kept this {label} action blocked.");
        return Ok(json!({ "decision": "block", "fields": [["review_hint", hint]] }));
    }
    let hint = format!("Approval received in HOL Guard. {label} is resuming this action.");
    Ok(json!({
        "decision": "allow",
        "fields": [["browser_resolution_request_id", request_id], ["review_hint", hint]],
    }))
}

/// The edits that turn a waited review into an allow or a deny. A Grok allow
/// spells `permissionDecision: "allow"`; Muse rejects a bare allow, so its
/// allow drops the decision instead.
fn rewrite(map: &Map<String, Value>, harness: Harness) -> KindResult {
    match text(map, "decision")? {
        "allow" => {
            let (hook_set, hook_drop) = match harness {
                Harness::Grok => (
                    json!([["permissionDecision", "allow"]]),
                    json!(["permissionDecisionReason"]),
                ),
                Harness::Muse => (
                    json!([]),
                    json!(["permissionDecision", "permissionDecisionReason"]),
                ),
            };
            Ok(json!({
                "set": [["decision", "allow"], ["policy_action", "allow"]],
                "drop": ["reason"],
                "hook_set": hook_set,
                "hook_drop": hook_drop,
            }))
        }
        "block" => Ok(json!({
            "set": [["decision", "deny"], ["policy_action", "block"]],
            "drop": [],
            "hook_set": [["permissionDecision", "deny"]],
            "hook_drop": [],
        })),
        _ => Err(ERR_INVALID),
    }
}

/// `grok_resume_metadata_from_guard_payload`: where Grok polls for the
/// queued request and where the user approves it.
fn resume_metadata(map: &Map<String, Value>) -> KindResult {
    let payload = object(map, "payload")?;
    let request_id = stripped(payload.get("primary_approval_request_id"))
        .map(str::to_owned)
        .or_else(|| grok_request_ids(payload).into_iter().next());
    let approval_url = stripped(payload.get("primary_approval_url"))
        .or_else(|| stripped(payload.get("approval_url")));
    let center_url = stripped(payload.get("approval_center_url"));
    let mut fields = Vec::new();
    if let Some(id) = request_id {
        let poll_path = format!("/v1/requests/{id}");
        fields.push(json!(["approval_request_id", id]));
        fields.push(json!(["resume_poll_path", poll_path]));
    }
    if let Some(url) = approval_url {
        fields.push(json!(["approval_url", url]));
    }
    if let Some(url) = center_url {
        fields.push(json!(["approval_center_url", url]));
    }
    Ok(json!({ "fields": fields }))
}

#[cfg(test)]
#[path = "hook_approval_wait_tests.rs"]
mod tests;
