//! The harness answers of the bounded hook bridge: `_event_name` from
//! `bounded_cli_hook_envelope.py`, `_daemon_response_to_native` from
//! `bounded_cli_hook_daemon.py` and `failure_payload` from
//! `bounded_cli_hook_failure.py`, for the harnesses the native bridge serves.
//!
//! Each function renders what the Python one renders, byte for byte. None
//! of them decides a verdict: the daemon's answer is reshaped for the
//! harness, and a failure is the fixed fail-closed payload.

use guard_contracts::GuardAction;

use crate::blocked_request_mode::is_unlinked_connector_setup_reason;
use crate::bounded_hook_bridge_hermes::hermes_bridge_response;
use crate::claude_hook_bridge_render::py_strip;
use crate::hook_env_stamp::{backslash_surrogates, dumps, set_member};
use crate::pyjson::PyVal;

/// The harnesses whose Python bridge the native bridge answers for. Grok
/// runs its own generated client, which `bounded_hook_bridge_grok` answers.
pub(crate) const NATIVE_HARNESSES: [&str; 8] = [
    "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode",
];

pub(crate) const FAILURE_REASON: &str =
    "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal.";
const PROMPT_UNAVAILABLE_REASON: &str = "HOL Guard could not complete native prompt review safely.";
const PROMPT_UNAVAILABLE_REASON_CODE: &str = "native_prompt_unavailable";
const AUTHORITY_BLOCK_REASON_MARKER: &str = "native command extension policy";
const AUTHORITY_BLOCK_REMEDIATION: &str = " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor.";

const EVENT_NAME_KEYS: [&str; 6] = [
    "hook_event_name",
    "hookEventName",
    "event",
    "eventName",
    "hook_name",
    "hookName",
];
const EVENT_ALIASES: [(&str, &str); 10] = [
    ("permissionrequest", "PermissionRequest"),
    ("permissionrequestv2", "PermissionRequest"),
    ("pretooluse", "PreToolUse"),
    ("pretoolcall", "PreToolUse"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("userpromptsubmitted", "UserPromptSubmit"),
    ("posttooluse", "PostToolUse"),
    ("sessionstart", "SessionStart"),
    ("notification", "Notification"),
    ("stop", "Stop"),
];
const LIFECYCLE_COMPACT_EVENTS: [&str; 13] = [
    "sessionstart",
    "sessionend",
    "subagentstart",
    "subagentstop",
    "stop",
    "notification",
    "taskstart",
    "taskerror",
    "sessionshutdown",
    "permissiondenied",
    "userpromptsubmit",
    "userpromptsubmitted",
    "subagentend",
];
const REVIEW_CANNOT_FINISH_REASON_CODES: [&str; 24] = [
    "native_policy_not_ready",
    "native_hook_event_unavailable",
    "native_pre_tool_unavailable",
    "native_post_tool_unavailable",
    "native_overloaded",
    "native_hook_worker_unavailable",
    "native_hook_worker_unavailable_before_compatibility",
    "native_hook_worker_unsupported",
    "native_hook_worker_exception",
    "native_hook_compatibility_disabled",
    "native_hook_edge_invalid_response",
    "native_hook_edge_unavailable",
    "python_hook_oracle_unavailable",
    "python_oracle_exception",
    "watch_recording_only",
    "daemon_hook_queue_capacity",
    "daemon_hook_deadline_exhausted",
    "daemon_hook_process_deadline_exhausted",
    "daemon_hook_process_not_ready",
    "daemon_hook_process_failed",
    "daemon_hook_process_invalid_request",
    "daemon_hook_process_guard_home_mismatch",
    "daemon_worker_exception",
    "harness_not_managed",
];
const COPIED_APPROVAL_KEYS: [&str; 8] = [
    "reason_code",
    "approval_url",
    "approval_request_id",
    "primary_approval_request_id",
    "primary_approval_url",
    "guardApprovalRequestId",
    "guardApprovalUrl",
    "approval_requests",
];
const RESTRICTIVE: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];
const DECISIONS: [&str; 4] = ["allow", "ask", "deny", "block"];

/// `event_name.replace("_", "").replace("-", "").lower()`.
fn compact(event_name: &str) -> String {
    event_name
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect::<String>()
        .to_lowercase()
}

/// `_compact_hook_event_name`: the same, after `strip()`.
fn compact_stripped(event_name: &str) -> String {
    compact(py_strip(event_name))
}

/// `_canonical_event_token`.
pub(crate) fn canonical_event_token(value: &str) -> Option<String> {
    let stripped = py_strip(value);
    if stripped.is_empty() {
        return None;
    }
    let normalized = compact(stripped);
    Some(
        EVENT_ALIASES
            .iter()
            .find(|(alias, _)| *alias == normalized)
            .map_or_else(|| stripped.to_owned(), |(_, name)| (*name).to_owned()),
    )
}

/// `_event_name(input_text)`, given the text and its parsed object.
pub(crate) fn event_name(text: &str, payload: &PyVal) -> String {
    for key in EVENT_NAME_KEYS {
        if let Some(PyVal::Str(value)) = payload.get(key) {
            if let Some(named) = canonical_event_token(value) {
                return named;
            }
        }
    }
    for key in EVENT_NAME_KEYS {
        let token = format!("\"{key}\"");
        let Some(start) = text.find(&token) else {
            continue;
        };
        let after_key = start + token.len();
        let Some(colon) = text[after_key..].find(':').map(|at| after_key + at) else {
            continue;
        };
        let Some(quote) = text[colon + 1..].find('"').map(|at| colon + 1 + at) else {
            continue;
        };
        let Some(end) = text[quote + 1..].find('"').map(|at| quote + 1 + at) else {
            continue;
        };
        if let Some(named) = canonical_event_token(&text[quote + 1..end]) {
            return named;
        }
    }
    "PreToolUse".to_owned()
}

fn is_guard_action(value: &str) -> bool {
    GuardAction::from_canonical(value).is_some()
}

/// `hook_event_pauses_when_unavailable`.
fn event_pauses_when_unavailable(event_name: &str) -> bool {
    let compact = compact_stripped(event_name);
    if compact == "userpromptsubmit" || compact == "userpromptsubmitted" {
        return true;
    }
    if LIFECYCLE_COMPACT_EVENTS.contains(&compact.as_str()) {
        return false;
    }
    !(compact == "posttooluse" || compact == "posttool" || compact.starts_with("after"))
}

fn is_permission_event(event_name: &str) -> bool {
    matches!(
        compact_stripped(event_name).as_str(),
        "permissionrequest" | "permissionrequestv2" | "copilotpermissionrequest"
    )
}

fn str_dict(entries: Vec<(&str, PyVal)>) -> PyVal {
    PyVal::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn text(value: &str) -> PyVal {
    PyVal::Str(value.to_owned())
}

/// `failure_payload(harness=..., event_name=..., reason=...)` for a native
/// harness: the payload and the exit code.
pub(crate) fn failure_payload(harness: &str, event_name: &str, reason: &str) -> (PyVal, i32) {
    if !event_pauses_when_unavailable(event_name) {
        let payload = match harness {
            "copilot" => str_dict(vec![("permissionDecision", text("allow"))]),
            "openclaw" | "hermes" => {
                str_dict(vec![("decision", text("allow")), ("reason", text(reason))])
            }
            _ => str_dict(vec![
                ("continue", PyVal::Bool(true)),
                ("systemMessage", text(reason)),
                (
                    "hookSpecificOutput",
                    str_dict(vec![("hookEventName", text(event_name))]),
                ),
            ]),
        };
        return (payload, 0);
    }
    let prompt = matches!(
        compact_stripped(event_name).as_str(),
        "userpromptsubmit" | "userpromptsubmitted"
    );
    if prompt {
        let payload = if harness == "copilot" {
            str_dict(vec![
                ("behavior", text("deny")),
                ("message", text(PROMPT_UNAVAILABLE_REASON)),
                ("interrupt", PyVal::Bool(false)),
                ("policy_action", text("block")),
                ("reason_code", text(PROMPT_UNAVAILABLE_REASON_CODE)),
            ])
        } else {
            str_dict(vec![
                ("decision", text("block")),
                ("reason", text(PROMPT_UNAVAILABLE_REASON)),
                ("systemMessage", text(PROMPT_UNAVAILABLE_REASON)),
                ("policy_action", text("block")),
                ("reason_code", text(PROMPT_UNAVAILABLE_REASON_CODE)),
                (
                    "hookSpecificOutput",
                    str_dict(vec![("hookEventName", text("UserPromptSubmit"))]),
                ),
            ])
        };
        return (payload, 0);
    }
    if harness == "copilot" {
        let payload = if is_permission_event(event_name) {
            str_dict(vec![
                ("behavior", text("deny")),
                ("message", text(reason)),
                ("interrupt", PyVal::Bool(false)),
            ])
        } else {
            str_dict(vec![
                ("permissionDecision", text("deny")),
                ("permissionDecisionReason", text(reason)),
            ])
        };
        return (payload, 0);
    }
    if harness == "openclaw" {
        return (
            str_dict(vec![("decision", text("deny")), ("reason", text(reason))]),
            0,
        );
    }
    if harness == "hermes" {
        return (
            str_dict(vec![("decision", text("block")), ("reason", text(reason))]),
            2,
        );
    }
    if is_permission_event(event_name) {
        return (
            str_dict(vec![
                ("continue", PyVal::Bool(false)),
                ("stopReason", text(reason)),
                ("systemMessage", text(reason)),
            ]),
            0,
        );
    }
    (
        str_dict(vec![(
            "hookSpecificOutput",
            str_dict(vec![
                ("hookEventName", text(event_name)),
                ("permissionDecision", text("deny")),
                ("permissionDecisionReason", text(reason)),
            ]),
        )]),
        2,
    )
}

/// `_emit_failure` output: compact JSON and a newline, plus the exit code.
/// `unmap` writes a mapped lone surrogate back as its `\udXXX` escape.
pub(crate) fn failure_output(harness: &str, event_name: &str, unmap: bool) -> (String, i32) {
    failure_output_for(harness, event_name, FAILURE_REASON, unmap)
}

/// `_emit_failure(..., reason=reason)` output.
pub(crate) fn failure_output_for(
    harness: &str,
    event_name: &str,
    reason: &str,
    unmap: bool,
) -> (String, i32) {
    let (payload, code) = failure_payload(harness, event_name, reason);
    let mut rendered = String::new();
    dumps(&payload, true, unmap, &mut rendered);
    rendered.push('\n');
    (rendered, code)
}

/// `zcode_authority_block_reason`.
fn zcode_authority_block_reason(reason: &str) -> String {
    if reason.contains(AUTHORITY_BLOCK_REASON_MARKER)
        && !reason.contains("hol-guard command controls")
    {
        format!("{reason}{AUTHORITY_BLOCK_REMEDIATION}")
    } else {
        reason.to_owned()
    }
}

/// `zcode_hook_process_exit(policy_action=..., event_name=...) == 2`.
fn zcode_exit_blocks(policy_action: &str, event_name: &str) -> bool {
    let event_name = if event_name.is_empty() {
        "PreToolUse"
    } else {
        event_name
    };
    if compact(event_name) == "pretooluse"
        && matches!(policy_action, "review" | "require-reapproval")
    {
        return false;
    }
    RESTRICTIVE.contains(&policy_action)
}

/// `_should_exit_block`.
fn should_exit_block(harness: &str, event_name: &str, policy_action: &str) -> bool {
    let compact = compact(event_name);
    let blocking = matches!(
        compact.as_str(),
        "pretooluse" | "userpromptsubmit" | "pretoolcall"
    ) || (harness == "devin" && compact == "permissionrequest");
    if !matches!(harness, "kimi" | "zcode" | "devin") || !blocking {
        return false;
    }
    if harness == "zcode" {
        return zcode_exit_blocks(policy_action, event_name);
    }
    RESTRICTIVE.contains(&policy_action)
}

/// A recognized decision: `value.strip().lower()` within the four words.
fn decision_word(value: Option<&PyVal>) -> Option<String> {
    let lowered = py_strip(value?.as_str()?).to_lowercase();
    DECISIONS.contains(&lowered.as_str()).then_some(lowered)
}

fn has_key(entries: &[(String, PyVal)], key: &str) -> bool {
    entries.iter().any(|(name, _)| name == key)
}

pub(crate) fn member<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `_consistent_native_response`: the aligned response and the policy
/// action that decides the exit code.
fn consistent_native_response(
    daemon_response: &[(String, PyVal)],
    harness: &str,
    event_name: &str,
) -> (Vec<(String, PyVal)>, String) {
    let mut response = daemon_response.to_vec();
    let compact_event = compact(event_name);
    let gating = matches!(
        compact_event.as_str(),
        "permissionrequest" | "pretoolcall" | "pretooluse" | "userpromptsubmit"
    );
    let mut policy_action = member(&response, "policy_action")
        .and_then(PyVal::as_str)
        .map(py_strip)
        .filter(|action| is_guard_action(action))
        .map(str::to_owned);
    if gating && has_key(&response, "policy_action") && policy_action.is_none() {
        policy_action = Some("block".to_owned());
        set_member(&mut response, "policy_action", text("block"));
    }
    let restrictive = policy_action
        .as_deref()
        .is_some_and(|action| RESTRICTIVE.contains(&action));
    let mut top = decision_word(member(&response, "decision"));
    if gating && has_key(&response, "decision") && top.is_none() {
        top = Some("deny".to_owned());
        set_member(&mut response, "decision", text("deny"));
    }
    let mut hook_specific = match member(&response, "hookSpecificOutput") {
        Some(PyVal::Dict(entries)) => Some(entries.clone()),
        _ => None,
    };
    let mut nested = hook_specific
        .as_ref()
        .and_then(|entries| decision_word(member(entries, "permissionDecision")));
    if let Some(entries) = hook_specific.as_mut() {
        if gating && has_key(entries, "permissionDecision") && nested.is_none() {
            nested = Some("deny".to_owned());
            set_member(entries, "permissionDecision", text("deny"));
        }
    }

    if restrictive && compact_event == "userpromptsubmit" && top.is_none() {
        top = Some("block".to_owned());
        set_member(&mut response, "decision", text("block"));
    } else if restrictive
        && matches!(
            compact_event.as_str(),
            "permissionrequest" | "pretoolcall" | "pretooluse"
        )
    {
        if hook_specific.is_none() && has_key(&response, "hookSpecificOutput") {
            hook_specific = Some(vec![("hookEventName".to_owned(), text(event_name))]);
        }
        if let Some(entries) = hook_specific.as_mut() {
            if nested.is_none() {
                let word = if policy_action.as_deref() == Some("block") {
                    "deny"
                } else {
                    "ask"
                };
                nested = Some(word.to_owned());
                set_member(entries, "permissionDecision", text(word));
            }
        }
        if harness == "openclaw" && top.is_none() {
            top = Some("deny".to_owned());
            set_member(&mut response, "decision", text("deny"));
        }
    }

    let decisions: Vec<&str> = [top.as_deref(), nested.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let has_deny = decisions
        .iter()
        .any(|decision| matches!(*decision, "deny" | "block"));
    let has_ask = decisions.contains(&"ask");
    let permissive = matches!(policy_action.as_deref(), Some("allow" | "warn"));
    if permissive && has_deny {
        policy_action = Some("block".to_owned());
        set_member(&mut response, "policy_action", text("block"));
    } else if permissive && has_ask {
        policy_action = Some("review".to_owned());
        set_member(&mut response, "policy_action", text("review"));
    }

    let action = policy_action.as_deref();
    let top_word = |top: &str| if top == "block" { "block" } else { "deny" };
    if action == Some("block") || (action.is_none() && has_deny) {
        if let Some(top) = top.as_deref() {
            set_member(&mut response, "decision", text(top_word(top)));
        }
        if let (Some(_), Some(entries)) = (nested.as_ref(), hook_specific.as_mut()) {
            set_member(entries, "permissionDecision", text("deny"));
        }
    } else if matches!(
        action,
        Some("review" | "require-reapproval" | "sandbox-required")
    ) || (action.is_none() && has_ask)
    {
        if let Some(top) = top.as_deref() {
            set_member(&mut response, "decision", text(top_word(top)));
        }
        if let (Some("allow"), Some(entries)) = (nested.as_deref(), hook_specific.as_mut()) {
            set_member(entries, "permissionDecision", text("ask"));
        }
    } else if matches!(action, Some("allow" | "warn")) {
        if top.is_some() {
            set_member(&mut response, "decision", text("allow"));
        }
        if let (Some(_), Some(entries)) = (nested.as_ref(), hook_specific.as_mut()) {
            set_member(entries, "permissionDecision", text("allow"));
        }
    }

    if let Some(entries) = hook_specific {
        set_member(&mut response, "hookSpecificOutput", PyVal::Dict(entries));
    }
    let exit_action = match policy_action {
        Some(action) => action,
        None if has_deny => "block".to_owned(),
        None if has_ask => "review".to_owned(),
        None => "allow".to_owned(),
    };
    (response, exit_action)
}

/// `str(value)` for the scalar types; `None` for a list or an object,
/// whose Python `repr` the native bridge does not reproduce.
fn python_str(value: &PyVal) -> Option<String> {
    match value {
        PyVal::Int(digits) if digits == "-0" => Some("0".to_owned()),
        other => other.scalar_text(),
    }
}

/// Python truthiness; JSON `-0` parses to the falsy integer zero.
fn py_truthy(value: &PyVal) -> bool {
    !matches!(value, PyVal::Int(digits) if digits == "-0") && value.truthy()
}

/// `str(response.get(first) or response.get(second) or "")`.
fn first_truthy_text(response: &[(String, PyVal)], keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| member(response, key))
        .find(|value| py_truthy(value))
        .map_or_else(|| Some(String::new()), python_str)
}

/// `_policy_action_from_daemon`.
fn policy_action_from_daemon(response: &[(String, PyVal)], event_name: &str) -> String {
    if let Some(action) = member(response, "policy_action")
        .and_then(PyVal::as_str)
        .map(py_strip)
        .filter(|action| is_guard_action(action))
    {
        return action.to_owned();
    }
    // A list or object never names a known reason code.
    let reason_code = first_truthy_text(response, &["reason_code"]).unwrap_or_default();
    let continues = REVIEW_CANNOT_FINISH_REASON_CODES.contains(&py_strip(&reason_code));
    if !event_pauses_when_unavailable(event_name) && continues {
        "warn".to_owned()
    } else {
        "block".to_owned()
    }
}

fn native_permission_decision(harness: &str, policy_action: &str) -> Option<&'static str> {
    match policy_action {
        "allow" | "warn" => Some("allow"),
        "sandbox-required" if harness == "zcode" => Some("deny"),
        "review" | "require-reapproval" | "sandbox-required" => Some("ask"),
        "block" => Some("deny"),
        _ => None,
    }
}

/// What the bridge writes for one daemon answer.
#[derive(Debug, PartialEq)]
pub(crate) struct Rendered {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
}

/// `unmap` writes a mapped lone surrogate back as Python does: its
/// `\udXXX` escape in the JSON, and in stderr as `backslashreplace` writes it.
pub(crate) fn rendered(
    payload: &[(String, PyVal)],
    stderr: String,
    exit_code: i32,
    unmap: bool,
) -> Rendered {
    let mut stdout = String::new();
    dumps(&PyVal::Dict(payload.to_vec()), true, unmap, &mut stdout);
    let stderr = if unmap {
        backslash_surrogates(&stderr)
    } else {
        stderr
    };
    Rendered {
        stdout,
        stderr,
        exit_code,
    }
}

/// `_daemon_response_to_native` for a native harness. `None` when the
/// answer carries a value Python would render through `repr`.
pub(crate) fn daemon_response_to_native(
    daemon_response: &[(String, PyVal)],
    harness: &str,
    event_name: &str,
    unmap: bool,
) -> Option<Rendered> {
    if harness == "hermes" {
        return Some(hermes_bridge_response(daemon_response, unmap));
    }
    let event_name = canonical_event_token(event_name).unwrap_or_else(|| event_name.to_owned());
    let event_name = event_name.as_str();
    if has_key(daemon_response, "hookSpecificOutput") || has_key(daemon_response, "decision") {
        let (mut response, action) =
            consistent_native_response(daemon_response, harness, event_name);
        let blocks = should_exit_block(harness, event_name, &action);
        let mut stderr = String::new();
        if blocks && matches!(harness, "kimi" | "devin" | "zcode") {
            let mut reason = match member(&response, "reason") {
                Some(PyVal::Str(reason)) if !reason.is_empty() => Some(reason.clone()),
                _ => None,
            };
            if reason.is_none() {
                if let Some(PyVal::Dict(hook_specific)) = member(&response, "hookSpecificOutput") {
                    reason = match member(hook_specific, "permissionDecisionReason") {
                        Some(PyVal::Str(reason)) if !reason.is_empty() => Some(reason.clone()),
                        _ => None,
                    };
                }
            }
            let reason =
                reason.unwrap_or_else(|| format!("HOL Guard blocked this action ({action})"));
            stderr = if harness == "zcode" {
                zcode_authority_block_reason(&reason)
            } else {
                reason
            };
        }
        if blocks && harness == "devin" {
            set_member(&mut response, "decision", text("block"));
            if !member(&response, "reason").is_some_and(py_truthy) {
                set_member(&mut response, "reason", text(&stderr));
            }
        }
        return Some(rendered(
            &response,
            stderr,
            if blocks { 2 } else { 0 },
            unmap,
        ));
    }

    let action = policy_action_from_daemon(daemon_response, event_name);
    let reason = first_truthy_text(daemon_response, &["reason", "permission_decision_reason"])?;
    let default_reason = format!("HOL Guard blocked this action ({action})");
    let mut payload: Vec<(String, PyVal)> = Vec::new();
    if event_name == "UserPromptSubmit" {
        if RESTRICTIVE.contains(&action.as_str()) {
            payload.push(("decision".to_owned(), text("block")));
            let shown = if reason.is_empty() {
                &default_reason
            } else {
                &reason
            };
            payload.push(("reason".to_owned(), text(shown)));
        }
    } else {
        let decision = native_permission_decision(harness, &action);
        let mut hook_specific = vec![("hookEventName".to_owned(), text(event_name))];
        if let Some(decision) = decision {
            hook_specific.push(("permissionDecision".to_owned(), text(decision)));
            if decision != "allow" || reason.to_lowercase().contains("unreachable") {
                let shown = if reason.is_empty() {
                    format!("HOL Guard {action} this action")
                } else {
                    reason.clone()
                };
                hook_specific.push(("permissionDecisionReason".to_owned(), text(&shown)));
            }
        }
        payload.push(("hookSpecificOutput".to_owned(), PyVal::Dict(hook_specific)));
        if let (Some(decision), "openclaw") = (decision, harness) {
            let word = if decision == "allow" { "allow" } else { "deny" };
            payload.push(("decision".to_owned(), text(word)));
            payload.push(("policy_action".to_owned(), text(&action)));
            if decision != "allow" && !reason.is_empty() {
                payload.push(("reason".to_owned(), text(&reason)));
            }
            // A default-mode connector setup reason carries no approval link.
            let unlinked = is_unlinked_connector_setup_reason(&reason);
            for key in COPIED_APPROVAL_KEYS {
                match member(daemon_response, key) {
                    None | Some(PyVal::Null) => {}
                    Some(_) if unlinked && key != "reason_code" => {}
                    Some(value) => set_member(&mut payload, key, value.clone()),
                }
            }
        }
    }

    let blocks = should_exit_block(harness, event_name, &action);
    if blocks && harness == "devin" {
        set_member(&mut payload, "decision", text("block"));
        if !member(&payload, "reason").is_some_and(py_truthy) {
            let shown = if reason.is_empty() {
                &default_reason
            } else {
                &reason
            };
            set_member(&mut payload, "reason", text(shown));
        }
    }
    let stderr = if blocks && harness == "zcode" {
        zcode_authority_block_reason(if reason.is_empty() {
            &default_reason
        } else {
            &reason
        })
    } else if blocks && matches!(harness, "kimi" | "devin") {
        reason
    } else {
        String::new()
    };
    Some(rendered(
        &payload,
        stderr,
        if blocks { 2 } else { 0 },
        unmap,
    ))
}
