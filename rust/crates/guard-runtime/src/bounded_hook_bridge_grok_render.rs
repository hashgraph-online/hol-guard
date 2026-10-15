//! The Grok answers of the bounded hook bridge: the pure steps of the
//! generated Grok hook script (`bounded_cli_hook_script_template.py`
//! rendered for `grok`), byte for byte.
//!
//! The script is the oracle. Its event names, daemon answer rendering,
//! fail-closed payloads, approval request ids, decision rewrite and the
//! `approval_wait_timeout_seconds` lookup are reproduced here. None of them
//! decides a verdict: the daemon's answer is reshaped for Grok, a failure is
//! the script's fixed fail-closed payload, and an approval wait only applies
//! the resolution the daemon reports for the request it opened.

use crate::bounded_hook_bridge_render::{member, FAILURE_REASON};
use crate::claude_hook_bridge_render::py_strip;
use crate::hook_env_stamp::{dumps, set_member};
use crate::pyjson::{self, PyVal};

const DEFAULT_EVENT: &str = "PreToolUse";
const PROMPT_REASON: &str = "HOL Guard could not complete native prompt review safely.";
const EVENT_NAME_KEYS: [&str; 6] = [
    "hook_event_name",
    "hookEventName",
    "event",
    "eventName",
    "hook_name",
    "hookName",
];
const EVENT_ALIASES: [(&str, &str); 7] = [
    ("permissionrequest", "PermissionRequest"),
    ("permissionrequestv2", "PermissionRequest"),
    ("pretooluse", "PreToolUse"),
    ("pretoolcall", "PreToolUse"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("userpromptsubmitted", "UserPromptSubmit"),
    ("posttooluse", "PostToolUse"),
];
const OBSERVE_EVENTS: [&str; 6] = [
    "sessionstart",
    "sessionend",
    "subagentstart",
    "subagentstop",
    "posttooluse",
    "permissiondenied",
];
const OTHER_LIFECYCLE_EVENTS: [&str; 7] = [
    "stop",
    "notification",
    "taskstart",
    "taskerror",
    "sessionshutdown",
    "userpromptsubmitted",
    "subagentend",
];
const PROMPT_EVENTS: [&str; 2] = ["userpromptsubmit", "userpromptsubmitted"];
const BLOCKING_EVENTS: [&str; 3] = ["pretooluse", "userpromptsubmit", "pretoolcall"];
const RESTRICTIVE_ACTIONS: [&str; 4] =
    ["review", "require-reapproval", "sandbox-required", "block"];
const APPROVAL_KEYS: [&str; 8] = [
    "reason_code",
    "approval_url",
    "approval_request_id",
    "primary_approval_request_id",
    "primary_approval_url",
    "guardApprovalRequestId",
    "guardApprovalUrl",
    "approval_requests",
];
const REQUEST_ID_KEYS: [&str; 3] = [
    "primary_approval_request_id",
    "approval_request_id",
    "guardApprovalRequestId",
];
/// The decisions an approval wait still resolves.
pub(crate) const WAITING_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// `_compact`.
pub(crate) fn compact(event_name: &str) -> String {
    event_name.replace(['_', '-'], "").to_lowercase()
}

/// `_json_object`: a JSON object as Python's `json.loads` reads it, or
/// `None` when the text is not one or holds a lone surrogate escape.
pub(crate) fn json_object(text: &str) -> Option<Vec<(String, PyVal)>> {
    let parsed = pyjson::parse_mapping_lone_surrogates(text).ok()?;
    match parsed.value {
        PyVal::Dict(entries) if !parsed.mapped => Some(entries),
        _ => None,
    }
}

/// Every string event label of the hook, as written.
fn event_labels(payload: &[(String, PyVal)]) -> impl Iterator<Item = &str> {
    EVENT_NAME_KEYS
        .iter()
        .filter_map(|key| member(payload, key).and_then(PyVal::as_str))
}

/// The labels are plain ASCII, so `_compact` and `str.strip` read them
/// exactly as Python does.
pub(crate) fn event_labels_are_ascii(payload: &[(String, PyVal)]) -> bool {
    event_labels(payload).all(|label| label.is_ascii())
}

/// `_event_name` for a parsed hook object.
pub(crate) fn event_name(payload: &[(String, PyVal)]) -> String {
    let Some(label) = event_labels(payload).next() else {
        return DEFAULT_EVENT.to_owned();
    };
    let stripped = py_strip(label);
    let compacted = compact(stripped);
    if let Some((_, alias)) = EVENT_ALIASES.iter().find(|(name, _)| *name == compacted) {
        return (*alias).to_owned();
    }
    if stripped.is_empty() {
        DEFAULT_EVENT.to_owned()
    } else {
        stripped.to_owned()
    }
}

/// `_event_name(input_text)`: the hook's event, or `PreToolUse` when the
/// text is not a JSON object.
pub(crate) fn event_name_of_text(text: &str) -> String {
    let source = if text.is_empty() { "{}" } else { text };
    json_object(source).map_or_else(|| DEFAULT_EVENT.to_owned(), |payload| event_name(&payload))
}

/// `_grok_pretool_event_conflict`.
pub(crate) fn pretool_event_conflict(payload: &[(String, PyVal)]) -> bool {
    let mut events: Vec<String> = Vec::new();
    for label in event_labels(payload) {
        let mut compacted = compact(py_strip(label));
        if compacted == "pretoolcall" {
            compacted = "pretooluse".to_owned();
        }
        if !events.contains(&compacted) {
            events.push(compacted);
        }
    }
    events.iter().any(|event| event == "pretooluse") && events.len() > 1
}

pub(crate) fn is_observe_event(event_name: &str) -> bool {
    OBSERVE_EVENTS.contains(&compact(event_name).as_str())
}

/// `_pauses_when_unavailable`.
fn pauses_when_unavailable(event_name: &str) -> bool {
    let compacted = compact(event_name);
    if PROMPT_EVENTS.contains(&compacted.as_str()) {
        return true;
    }
    if OBSERVE_EVENTS.contains(&compacted.as_str())
        || OTHER_LIFECYCLE_EVENTS.contains(&compacted.as_str())
        || compacted.starts_with("after")
    {
        return false;
    }
    !matches!(compacted.as_str(), "posttooluse" | "posttool")
}

fn text(value: &str) -> PyVal {
    PyVal::Str(value.to_owned())
}

/// `json.dumps(payload, ensure_ascii=True, separators=(",", ":"))`.
pub(crate) fn dump_object(payload: &[(String, PyVal)]) -> String {
    let mut out = String::new();
    dumps(&PyVal::Dict(payload.to_vec()), true, false, &mut out);
    out
}

/// `_failure_payload(event_name, reason)` for Grok.
fn failure_payload(event_name: &str, reason: &str) -> Vec<(String, PyVal)> {
    let compacted = compact(event_name);
    if OBSERVE_EVENTS.contains(&compacted.as_str()) {
        return Vec::new();
    }
    if PROMPT_EVENTS.contains(&compacted.as_str()) {
        return vec![
            ("decision".to_owned(), text("block")),
            ("reason".to_owned(), text(PROMPT_REASON)),
            ("systemMessage".to_owned(), text(PROMPT_REASON)),
            (
                "hookSpecificOutput".to_owned(),
                PyVal::Dict(vec![("hookEventName".to_owned(), text("UserPromptSubmit"))]),
            ),
        ];
    }
    let decision = if pauses_when_unavailable(event_name) {
        "deny"
    } else {
        "allow"
    };
    vec![
        ("decision".to_owned(), text(decision)),
        ("reason".to_owned(), text(reason)),
    ]
}

/// What `_fail(input_text)` writes to stdout; Grok's failure always exits 0.
/// The caller has already ruled out a PreToolUse label conflict.
pub(crate) fn failure_stdout(input_text: &str) -> String {
    failure_stdout_for(input_text, FAILURE_REASON)
}

/// What `_fail(input_text, reason=reason)` writes to stdout.
pub(crate) fn failure_stdout_for(input_text: &str, reason: &str) -> String {
    let mut stdout = dump_object(&failure_payload(&event_name_of_text(input_text), reason));
    stdout.push('\n');
    stdout
}

/// `str(value or default)`, or `None` when Python would render a container
/// through `repr`.
fn py_str_or(value: Option<&PyVal>, default: &str) -> Option<String> {
    match value {
        Some(value) if value.truthy() => value.scalar_text(),
        _ => Some(default.to_owned()),
    }
}

/// `_permission_decision`.
fn permission_decision(policy_action: &str) -> Option<&'static str> {
    match policy_action {
        "allow" | "warn" => Some("allow"),
        "review" | "require-reapproval" | "sandbox-required" => Some("ask"),
        "block" => Some("deny"),
        _ => None,
    }
}

/// `_should_exit_block` for Grok.
fn should_exit_block(event_name: &str, policy_action: &str) -> bool {
    BLOCKING_EVENTS.contains(&compact(event_name).as_str())
        && RESTRICTIVE_ACTIONS.contains(&policy_action)
}

/// `_to_native(daemon_response, event_name)` for Grok: the payload Grok
/// reads and the exit code. `None` when Python would render a value through
/// `repr`; the caller fails closed instead.
pub(crate) fn to_native(
    response: &[(String, PyVal)],
    event_name: &str,
) -> Option<(Vec<(String, PyVal)>, i32)> {
    let compacted = compact(event_name);
    if response.is_empty()
        && (OBSERVE_EVENTS.contains(&compacted.as_str())
            || PROMPT_EVENTS.contains(&compacted.as_str()))
    {
        return Some((Vec::new(), 0));
    }
    if member(response, "hookSpecificOutput").is_some() || member(response, "decision").is_some() {
        let policy = py_str_or(member(response, "policy_action"), "block")?;
        let exit_code = if should_exit_block(event_name, &policy) {
            2
        } else {
            0
        };
        return Some((response.to_vec(), exit_code));
    }
    let policy_action = py_str_or(member(response, "policy_action"), "block")?;
    let reason_value = member(response, "reason")
        .filter(|value| value.truthy())
        .or_else(|| member(response, "permission_decision_reason"));
    let reason = py_str_or(reason_value, "")?;
    let mut payload: Vec<(String, PyVal)> = Vec::new();
    if event_name == "UserPromptSubmit" {
        if RESTRICTIVE_ACTIONS.contains(&policy_action.as_str()) {
            let shown = if reason.is_empty() {
                format!("HOL Guard blocked this action ({policy_action})")
            } else {
                reason.clone()
            };
            payload.push(("decision".to_owned(), text("block")));
            payload.push(("reason".to_owned(), PyVal::Str(shown)));
        }
    } else {
        let decision = permission_decision(&policy_action);
        let mut hook_specific = vec![("hookEventName".to_owned(), text(event_name))];
        if let Some(decision) = decision {
            hook_specific.push(("permissionDecision".to_owned(), text(decision)));
            if decision != "allow" || reason.to_lowercase().contains("unreachable") {
                let shown = if reason.is_empty() {
                    format!("HOL Guard {policy_action} this action")
                } else {
                    reason.clone()
                };
                hook_specific.push(("permissionDecisionReason".to_owned(), PyVal::Str(shown)));
            }
        }
        payload.push(("hookSpecificOutput".to_owned(), PyVal::Dict(hook_specific)));
        if let Some(decision) = decision {
            let flat = if decision == "allow" { "allow" } else { "deny" };
            payload.push(("decision".to_owned(), text(flat)));
            payload.push((
                "policy_action".to_owned(),
                PyVal::Str(policy_action.clone()),
            ));
            if decision != "allow" && !reason.is_empty() {
                payload.push(("reason".to_owned(), PyVal::Str(reason.clone())));
            }
            for key in APPROVAL_KEYS {
                match member(response, key) {
                    None | Some(PyVal::Null) => {}
                    Some(value) => set_member(&mut payload, key, value.clone()),
                }
            }
        }
    }
    let exit_code = if should_exit_block(event_name, &policy_action) {
        2
    } else {
        0
    };
    Some((payload, exit_code))
}

/// `_approval_request_ids`.
pub(crate) fn approval_request_ids(payload: &[(String, PyVal)]) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(PyVal::List(queued)) = member(payload, "approval_requests") {
        for item in queued {
            if let Some(PyVal::Str(request_id)) = item.get("request_id") {
                let request_id = py_strip(request_id);
                if !request_id.is_empty() {
                    ids.push(request_id.to_owned());
                }
            }
        }
    }
    if !ids.is_empty() {
        return ids;
    }
    for key in REQUEST_ID_KEYS {
        if let Some(PyVal::Str(request_id)) = member(payload, key) {
            let request_id = py_strip(request_id);
            if !request_id.is_empty() {
                return vec![request_id.to_owned()];
            }
        }
    }
    Vec::new()
}

/// `_rewrite_grok_decision`.
pub(crate) fn rewrite_decision(payload: &[(String, PyVal)], allowed: bool) -> Vec<(String, PyVal)> {
    let mut updated = payload.to_vec();
    set_member(
        &mut updated,
        "decision",
        text(if allowed { "allow" } else { "deny" }),
    );
    set_member(
        &mut updated,
        "policy_action",
        text(if allowed { "allow" } else { "block" }),
    );
    if allowed {
        updated.retain(|(key, _)| key != "reason");
    }
    let hook_specific = match member(&updated, "hookSpecificOutput") {
        Some(PyVal::Dict(hook_specific)) => Some(hook_specific.clone()),
        _ => None,
    };
    if let Some(mut rewritten) = hook_specific {
        set_member(
            &mut rewritten,
            "permissionDecision",
            text(if allowed { "allow" } else { "deny" }),
        );
        if allowed {
            rewritten.retain(|(key, _)| key != "permissionDecisionReason");
        }
        set_member(&mut updated, "hookSpecificOutput", PyVal::Dict(rewritten));
    }
    updated
}

/// `str.splitlines()`.
fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let breaks = matches!(
            character,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        lines.push(&text[start..index]);
        start = index + character.len_utf8();
        if character == '\r' {
            if let Some((next, '\n')) = chars.peek().copied() {
                chars.next();
                start = next + 1;
            }
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `_toml_scalar(raw, key)`.
pub(crate) fn toml_scalar<'a>(raw: &'a str, key: &str) -> &'a str {
    for line in py_splitlines(raw) {
        let stripped = py_strip(line.split('#').next().unwrap_or_default());
        let Some((left, right)) = stripped.split_once('=') else {
            continue;
        };
        if py_strip(left) != key {
            continue;
        }
        return py_strip(right).trim_matches('"').trim_matches('\'');
    }
    ""
}

/// `float(token)` for ASCII text. `None` for text `float` rejects, and for
/// any non-ASCII text, which is read as no override.
pub(crate) fn py_float(token: &str) -> Option<f64> {
    let token = py_strip(token);
    if !token.is_ascii() {
        return None;
    }
    let bytes = token.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'_' {
            continue;
        }
        let digit_before = index > 0 && bytes[index - 1].is_ascii_digit();
        let digit_after = bytes.get(index + 1).is_some_and(u8::is_ascii_digit);
        if !digit_before || !digit_after {
            return None;
        }
    }
    let plain = token.replace('_', "");
    if plain.is_empty() {
        return None;
    }
    plain.parse::<f64>().ok()
}

/// `_approval_wait_seconds()` given the `config.toml` text, when it could be
/// read, and `TIMEOUT_SECONDS`. A non-ASCII override waits not at all.
pub(crate) fn approval_wait_seconds(config: Option<&str>, timeout_seconds: f64) -> f64 {
    let mut configured = timeout_seconds;
    if let Some(raw) = config {
        let token = toml_scalar(raw, "approval_wait_timeout_seconds");
        if !py_strip(token).is_ascii() {
            return 0.0;
        }
        if let Some(parsed) = py_float(token) {
            if parsed >= 0.0 {
                configured = parsed;
            }
        }
    }
    let ceiling = (timeout_seconds * 0.4).min(80.0);
    let floor = if configured < 0.0 { 0.0 } else { configured };
    if ceiling < floor {
        ceiling
    } else {
        floor
    }
}

/// `urllib.parse.quote(text, safe="")`.
pub(crate) fn quote_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(all(test, unix))]
#[path = "bounded_hook_bridge_grok_render_tests.rs"]
mod tests;
