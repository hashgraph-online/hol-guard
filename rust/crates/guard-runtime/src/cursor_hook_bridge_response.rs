//! The Cursor client's own answer for a resident's harness response.
//!
//! This reproduces `_emit_cursor_response` and `_cursor_reason` for the
//! allows, denials and reviews a resident answers, byte for byte as the
//! client's `print(json.dumps(response))` writes them. `_cursor_reason`
//! rewrites a review link through `live_approval_review_url`, which signs a
//! loopback link with the daemon auth token; the bridge signs it the same
//! way.
//!
//! A lone surrogate escape CPython's `json.loads` keeps is read as the
//! character [`pyjson::parse_mapping_lone_surrogates`] maps it onto and
//! written back as the `\udXXX` escape `json.dumps` writes.
//!
//! It also holds the client's fixed answers for a hook it cannot read or
//! review: `_cursor_unavailable_response` and
//! `_exit_unparseable_cursor_input`.

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue, PyJsonError};
use guard_contracts::write_json_string;

use crate::claude_hook_bridge_render::py_strip;
use crate::daemon_policy_authority::load_guard_daemon_auth_token;
use crate::hook_env_stamp::{dumps, json_string};
use crate::native_review_link::{live_review_url, OPEN_GUARD};
use crate::pyjson;

/// `print(json.dumps({"permission": "allow"}))`.
pub(crate) const ALLOW_STDOUT: &str = "{\"permission\": \"allow\"}\n";
/// The client's `after*` observers, stripped and lowercased.
pub(crate) const AFTER_EVENTS: [&str; 2] = ["aftershellexecution", "aftermcpexecution"];
/// The client's answer to an `after*` observer: `print("{}")`.
pub(crate) const AFTER_STDOUT: &str = "{}\n";
/// `_cursor_unavailable_response`'s denial.
pub(crate) const UNAVAILABLE_STDOUT: &str = "{\"permission\": \"deny\", \"user_message\": \"HOL Guard could not complete the native hook decision safely.\"}\n";
/// `cursor_unparseable_input_permission`'s denial, which the client also
/// prints itself when it cannot import Guard.
pub(crate) const UNPARSEABLE_STDOUT: &str = "{\"permission\": \"deny\", \"user_message\": \"Guard could not process this hook request safely. Retry or repair Guard from a terminal.\"}\n";
/// `_cursor_reason` when the response names no reason and no review link.
const DEFAULT_BLOCK_REASON: &str = "HOL Guard blocked this Cursor action.";
/// `_cursor_reason`'s lead when the response names a link but no reason.
const NEEDS_APPROVAL: &str = "HOL Guard needs approval for this Cursor action.";
const REVIEW_URL_KEYS: [&str; 3] = ["primary_approval_url", "approval_url", "guardApprovalUrl"];
const REASON_KEYS: [&str; 7] = [
    "reason",
    "stopReason",
    "systemMessage",
    "review_hint",
    "risk_summary",
    "why_now",
    "risk_headline",
];
const DECISION_REASON_KEYS: [&str; 4] = [
    "harness_message",
    "retry_instruction",
    "user_body",
    "user_title",
];

/// `json.loads(text)` as the bridge reads it, and whether the text held a
/// lone surrogate escape, which the value holds as its mapped character.
/// `None` when the port cannot read the text alike, or when a lone
/// surrogate sits beside a genuine character of the mapped range and the
/// two could no longer be told apart.
pub(crate) fn python_document(text: &str) -> Option<(OValue, bool)> {
    read_python_document(text).ok()
}

/// [`python_document`], telling text CPython refuses
/// ([`PyJsonError::Decode`]) from text it reads that the port cannot
/// ([`PyJsonError::Unsupported`]).
pub(crate) fn read_python_document(text: &str) -> Result<(OValue, bool), PyJsonError> {
    match parse_python_json(text) {
        Ok(value) => return Ok((value, false)),
        Err(PyJsonError::Decode) => return Err(PyJsonError::Decode),
        Err(PyJsonError::Unsupported) => {}
    }
    let unsupported = PyJsonError::Unsupported;
    let parsed = pyjson::parse_mapping_lone_surrogates(text).map_err(|_| unsupported)?;
    if !parsed.mapped || parsed.collision {
        return Err(PyJsonError::Unsupported);
    }
    let mut literal = String::new();
    dumps(&parsed.value, false, false, &mut literal);
    parse_python_json(&literal)
        .map(|value| (value, true))
        .map_err(|_| PyJsonError::Unsupported)
}

/// `text`, compact `ensure_ascii` JSON of a value read by
/// [`python_document`], with each mapped character written back as the
/// lone `\udXXX` escape `json.dumps` writes for the surrogate.
pub(crate) fn unmapped_json(text: &str) -> Option<String> {
    let value = pyjson::parse(text).ok()?;
    let mut out = String::new();
    dumps(&value, true, true, &mut out);
    Some(out)
}

/// `value.strip()` for a non-blank string value.
fn stripped(value: Option<&OValue>) -> Option<&str> {
    let text = py_strip(value?.as_str()?);
    (!text.is_empty()).then_some(text)
}

/// `_cursor_review_url`: the first link the response names.
fn review_url(response: &OMap) -> Option<&str> {
    if let Some(url) = REVIEW_URL_KEYS
        .iter()
        .find_map(|key| stripped(response.get(key)))
    {
        return Some(url);
    }
    response
        .get("approval_requests")
        .and_then(OValue::as_list)?
        .iter()
        .find_map(|item| stripped(item.as_map()?.get("approval_url")))
}

#[cfg(test)]
thread_local! {
    /// The session clock a test fixes, in place of the system clock.
    pub(crate) static FIXED_NOW: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

/// The current UTC time in microseconds since the epoch.
fn now_micros() -> Option<i64> {
    #[cfg(test)]
    if let Some(now) = FIXED_NOW.with(std::cell::Cell::get) {
        return Some(now);
    }
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_micros()).ok()
}

/// `_cursor_reason`, with a loopback review link signed as
/// `live_approval_review_url` signs it from `guard_home`'s daemon auth
/// token. A link this bridge does not reproduce is shown unsigned, unless
/// the client would sign it: then `None`, and the bridge does not answer.
fn reason(response: &OMap, guard_home: &Path) -> Option<String> {
    let hook_output = response.get("hookSpecificOutput").and_then(OValue::as_map);
    let decision = response.get("decision_v2_json").and_then(OValue::as_map);
    let reason = REASON_KEYS
        .iter()
        .map(|key| response.get(key))
        .chain(hook_output.map(|output| output.get("permissionDecisionReason")))
        .chain(
            DECISION_REASON_KEYS
                .iter()
                .filter_map(|key| decision.map(|decision| decision.get(key))),
        )
        .find_map(stripped);
    let Some(review_url) = review_url(response) else {
        return Some(reason.unwrap_or(DEFAULT_BLOCK_REASON).to_owned());
    };
    let token = load_guard_daemon_auth_token(guard_home);
    let live_url = match now_micros() {
        Some(now) => live_review_url(review_url, token.as_deref(), now)?,
        None => review_url.to_owned(),
    };
    let suffix = format!("{OPEN_GUARD} {live_url}.");
    Some(match reason {
        None => format!("{NEEDS_APPROVAL} {suffix}"),
        Some(reason) if live_url != review_url && reason.contains(review_url) => {
            reason.replacen(review_url, &live_url, 1)
        }
        Some(reason) if reason.contains(&live_url) => reason.to_owned(),
        Some(reason) => format!("{reason} {suffix}"),
    })
}

/// `print(json.dumps(response))` for the client's string-valued answer,
/// with mapped surrogates written back when `unmap` is set.
fn printed(fields: &[(&str, &str)], unmap: bool) -> String {
    let mut out = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(name, &mut out);
        out.extend_from_slice(b": ");
        if unmap {
            out.extend_from_slice(json_string(value, true, true).as_bytes());
        } else {
            write_json_string(value, &mut out);
        }
    }
    out.extend_from_slice(b"}\n");
    String::from_utf8(out).expect("ensure_ascii output is ASCII")
}

/// The client's stdout and exit code for `response`, the harness response
/// the daemon would return for a hook the client names `event`, with
/// `guard_home` its `GUARD_HOME` and `unmap` whether `response` held a lone
/// surrogate, or `None` when the bridge cannot reproduce
/// the client's answer. This is `_emit_cursor_response` with
/// `_cursor_permission`: a review asks, which `beforeReadFile` and
/// `preToolUse` turn into a denial.
pub(crate) fn rendered(
    event: &str,
    response: &OMap,
    guard_home: &Path,
    unmap: bool,
) -> Option<(String, i32)> {
    let permission = match response.get_str("policy_action")? {
        "allow" | "warn" => return Some((ALLOW_STDOUT.to_owned(), 0)),
        "block" | "sandbox-required" => "deny",
        "review" | "require-reapproval" => "ask",
        _ => return None,
    };
    let reason = reason(response, guard_home)?;
    let event = py_strip(event).to_lowercase();
    if event == "beforereadfile" {
        let fields = [("permission", "deny"), ("user_message", reason.as_str())];
        return Some((printed(&fields, unmap), 2));
    }
    let permission = if event == "pretooluse" {
        "deny"
    } else {
        permission
    };
    let fields = [
        ("permission", permission),
        ("user_message", reason.as_str()),
        ("agent_message", reason.as_str()),
    ];
    Some((
        printed(&fields, unmap),
        if permission == "deny" { 2 } else { 0 },
    ))
}

/// The client's `strip().lower().replace("_", "").replace("-", "")` check
/// for an `after*` observer.
fn compact_after_event(event: &str) -> bool {
    let compact: String = py_strip(event)
        .to_lowercase()
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .collect();
    AFTER_EVENTS.contains(&compact.as_str())
}

/// `_cursor_unavailable_response` for a hook the client names `event`: its
/// stdout and exit code.
pub(crate) fn unavailable_output(event: &str) -> (&'static str, i32) {
    if compact_after_event(event) {
        return (AFTER_STDOUT, 0);
    }
    (UNAVAILABLE_STDOUT, 2)
}

/// `_exit_unparseable_cursor_input` for a hook the client names `event`
/// from its argv and reads by `deadline`: its stdout and exit code. The
/// client prints the same answer whether or not it can import Guard.
pub(crate) fn unparseable_output(event: &str, deadline: Instant) -> (&'static str, i32) {
    if Instant::now() >= deadline {
        return unavailable_output(event);
    }
    if compact_after_event(event) {
        return (AFTER_STDOUT, 0);
    }
    (UNPARSEABLE_STDOUT, 2)
}
