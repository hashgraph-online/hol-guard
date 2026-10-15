//! The edge results the resident returns as the daemon would, and the
//! daemon's rule for which event a hook is.

use super::workspace::python_strip;
use super::{
    claude_prompt_text, HookDirectDefer, EVENT_NAME_FIELDS, POST_TOOL_EVENT_NAMES, POST_TOOL_USE,
    PRE_TOOL_EVENT_NAMES, PRE_TOOL_USE, REPAIRABLE_BLOCK_REASON, USER_PROMPT_EVENT_NAMES,
    USER_PROMPT_SUBMIT,
};
use serde_json::{Map, Value};

/// The edge result for `event`, when it carries the result and harness
/// response the daemon reads.
pub(super) fn reviewed_edge(edge: &[u8], event: &str) -> Result<Value, HookDirectDefer> {
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
pub(super) fn pre_tool_answer(edge: &[u8], contained: bool) -> Result<Value, HookDirectDefer> {
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
pub(super) fn post_tool_answer(edge: &[u8]) -> Result<Value, HookDirectDefer> {
    reviewed_edge(edge, POST_TOOL_USE)
}

/// The edge result the daemon returns: it passes a reviewed
/// `UserPromptSubmit` through once it accepts the receipt, and answers one
/// without a receipt as unavailable. With `notice`, it adds Guard's Claude
/// Code notice to the response; only these actions carry one.
pub(super) fn prompt_answer(edge: &[u8], notice: bool) -> Result<Value, HookDirectDefer> {
    let mut parsed = reviewed_edge(edge, USER_PROMPT_SUBMIT)?;
    if !parsed.get("receipt").is_some_and(Value::is_object) {
        return Err(HookDirectDefer::EdgeFailed);
    }
    let result = parsed.get("result").cloned().unwrap_or(Value::Null);
    let action = result.get("minimum_action").and_then(Value::as_str);
    if notice
        && matches!(
            action,
            Some("require-reapproval" | "block" | "sandbox-required")
        )
    {
        let response = parsed
            .get_mut("harness_response")
            .ok_or(HookDirectDefer::PromptNotice)?;
        claude_prompt_text::brand(response, &result)?;
    }
    Ok(parsed)
}

/// The daemon's event name rule: the first non-blank name field decides, and
/// a payload without one is a `PreToolUse`. Only the two tool events and a
/// prompt can be answered here.
pub(super) fn direct_event(
    payload: &Map<String, Value>,
) -> Result<Option<&'static str>, HookDirectDefer> {
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
