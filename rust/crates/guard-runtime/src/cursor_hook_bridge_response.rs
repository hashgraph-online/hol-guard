//! The Cursor client's own answer for a resident's harness response.
//!
//! This reproduces `_emit_cursor_response` and `_cursor_reason` for the
//! allows, denials and reviews a resident answers, byte for byte as the
//! client's `print(json.dumps(response))` writes them. `_cursor_reason`
//! rewrites a review link through `live_approval_review_url`, which signs a
//! loopback link with the daemon auth token only when the client's
//! interpreter can import Guard; a response whose link the client may sign
//! is left to the client.

use std::path::Path;

use guard_command::hook_adapter_value::{OMap, OValue};
use guard_contracts::write_json_string;

use crate::claude_hook_bridge_render::py_strip;
use crate::native_review_link::{review_url_stays_unsigned, OPEN_GUARD};

/// `print(json.dumps({"permission": "allow"}))`.
pub(crate) const ALLOW_STDOUT: &str = "{\"permission\": \"allow\"}\n";
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

/// `_cursor_reason`, or `None` when the client would show a link it signs
/// with Guard's Python only if its interpreter can import it.
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
    // `live_approval_review_url` then hands the link back unchanged.
    if !review_url_stays_unsigned(review_url, guard_home) {
        return None;
    }
    let suffix = format!("{OPEN_GUARD} {review_url}.");
    Some(match reason {
        None => format!("{NEEDS_APPROVAL} {suffix}"),
        Some(reason) if reason.contains(review_url) => reason.to_owned(),
        Some(reason) => format!("{reason} {suffix}"),
    })
}

/// `print(json.dumps(response))` for the client's string-valued answer.
fn printed(fields: &[(&str, &str)]) -> String {
    let mut out = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(name, &mut out);
        out.extend_from_slice(b": ");
        write_json_string(value, &mut out);
    }
    out.extend_from_slice(b"}\n");
    String::from_utf8(out).expect("ensure_ascii output is ASCII")
}

/// The client's stdout and exit code for `response`, the harness response
/// the daemon would return for a hook the client names `event`, with
/// `guard_home` its `GUARD_HOME`, or `None` when the bridge cannot reproduce
/// the client's answer. This is `_emit_cursor_response` with
/// `_cursor_permission`: a review asks, which `beforeReadFile` and
/// `preToolUse` turn into a denial.
pub(crate) fn rendered(event: &str, response: &OMap, guard_home: &Path) -> Option<(String, i32)> {
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
        return Some((printed(&fields), 2));
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
    Some((printed(&fields), if permission == "deny" { 2 } else { 0 }))
}
