//! Codex hook event naming and response shaping for the native Codex hook
//! bridge: ports of `runtime_hook_event_name`,
//! `hook_event_is_permission_request`, `_fail_closed` and
//! `codex_hook_response`. Nothing here decides a verdict; it only keeps the
//! daemon's answer inside Codex's strict hook output schemas.

use crate::claude_hook_bridge_render::py_strip;
use crate::hook_env_stamp::{json_string, set_member};
use crate::pyjson::PyVal;

pub(crate) const PRE_TOOL_USE: &str = "PreToolUse";
pub(crate) const POST_TOOL_USE: &str = "PostToolUse";
pub(crate) const FAIL_CLOSED_REASON: &str = "HOL Guard could not authenticate the local daemon. \
Run `hol-guard daemon repair` from a terminal, then retry.";

const EVENT_KEYS: [&str; 6] = [
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
];
const PRE_TOOL_NAMES: [&str; 7] = [
    "pretool",
    "pretooluse",
    "pretoolcall",
    "beforeshellexecution",
    "beforereadfile",
    "beforewritefile",
    "beforemcpexecution",
];
const POST_TOOL_NAMES: [&str; 7] = [
    "posttool",
    "posttooluse",
    "posttoolcall",
    "aftershellexecution",
    "afterreadfile",
    "afterwritefile",
    "aftermcpexecution",
];
const PERMISSION_NAMES: [&str; 2] = ["permissionrequest", "permissionrequestv2"];
const PROMPT_NAMES: [&str; 3] = ["prompt", "userpromptsubmit", "userpromptsubmitted"];
const UNIVERSAL_KEYS: [&str; 4] = ["continue", "stopReason", "suppressOutput", "systemMessage"];
const POST_TOOL_OUTPUT_KEYS: [&str; 3] =
    ["hookEventName", "additionalContext", "updatedMCPToolOutput"];

/// `raw.lower().replace("_", "").replace("-", "")`.
fn compact(raw: &str) -> String {
    raw.to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect()
}

/// `runtime_hook_event_name(payload)` for a parsed hook object.
pub(crate) fn runtime_hook_event_name(payload: &[(String, PyVal)]) -> String {
    for key in EVENT_KEYS {
        let Some((_, PyVal::Str(value))) = payload.iter().find(|(name, _)| name == key) else {
            continue;
        };
        let raw = py_strip(value);
        if raw.is_empty() {
            continue;
        }
        let compact = compact(raw);
        let compact = compact.as_str();
        return if PRE_TOOL_NAMES.contains(&compact) {
            PRE_TOOL_USE.to_owned()
        } else if POST_TOOL_NAMES.contains(&compact) {
            POST_TOOL_USE.to_owned()
        } else if PERMISSION_NAMES.contains(&compact) {
            "PermissionRequest".to_owned()
        } else if PROMPT_NAMES.contains(&compact) {
            "UserPromptSubmit".to_owned()
        } else {
            raw.to_owned()
        };
    }
    PRE_TOOL_USE.to_owned()
}

/// `hook_event_is_permission_request(event_name)`.
pub(crate) fn is_permission_request(event_name: &str) -> bool {
    matches!(
        compact(py_strip(event_name)).as_str(),
        "permissionrequest" | "permissionrequestv2" | "copilotpermissionrequest"
    )
}

/// `json.dumps(_fail_closed(event_name), separators=(",", ":"))`.
pub(crate) fn fail_closed(event_name: &str) -> String {
    let reason = json_string(FAIL_CLOSED_REASON, true, false);
    if is_permission_request(event_name) {
        format!(
            "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PermissionRequest\",\
\"decision\":{{\"behavior\":\"deny\",\"message\":{reason}}}}}}}"
        )
    } else if event_name == PRE_TOOL_USE {
        format!(
            "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\
\"permissionDecision\":\"deny\",\"permissionDecisionReason\":{reason}}}}}"
        )
    } else {
        format!("{{\"continue\":true,\"systemMessage\":{reason}}}")
    }
}

/// The PreToolUse `hookSpecificOutput` Codex accepts, from the daemon's.
fn cleaned_pre_tool_output(
    hook_output: &PyVal,
    response: &[(String, PyVal)],
    filtered: &mut Vec<(String, PyVal)>,
) -> PyVal {
    let mut cleaned = vec![(
        "hookEventName".to_owned(),
        PyVal::Str(PRE_TOOL_USE.to_owned()),
    )];
    let PyVal::Dict(_) = hook_output else {
        return PyVal::Dict(cleaned);
    };
    let policy_action = response
        .iter()
        .find(|(key, _)| key == "policy_action")
        .map(|(_, value)| value);
    let mut normalized = match hook_output.get("permissionDecision") {
        Some(PyVal::Str(decision)) => py_strip(decision).to_lowercase(),
        _ => String::new(),
    };
    if matches!(policy_action, Some(PyVal::Str(action)) if action == "deny") {
        normalized = "deny".to_owned();
    }
    let reason = hook_output.get("permissionDecisionReason");
    match normalized.as_str() {
        "deny" | "ask" => {
            cleaned.push((
                "permissionDecision".to_owned(),
                PyVal::Str(normalized.clone()),
            ));
            if let Some(PyVal::Str(text)) = reason {
                if !text.is_empty() {
                    cleaned.push((
                        "permissionDecisionReason".to_owned(),
                        PyVal::Str(text.clone()),
                    ));
                }
            }
        }
        "allow" => match hook_output.get("updatedInput") {
            Some(updated @ PyVal::Dict(_)) => {
                cleaned.push((
                    "permissionDecision".to_owned(),
                    PyVal::Str("allow".to_owned()),
                ));
                cleaned.push(("updatedInput".to_owned(), updated.clone()));
            }
            _ => {
                let warned = matches!(policy_action, Some(PyVal::Str(action)) if action == "warn");
                let has_message = filtered
                    .iter()
                    .find(|(key, _)| key == "systemMessage")
                    .is_some_and(|(_, value)| value.truthy());
                if let Some(PyVal::Str(text)) = reason {
                    if warned && !py_strip(text).is_empty() && !has_message {
                        set_member(filtered, "systemMessage", PyVal::Str(text.clone()));
                    }
                }
            }
        },
        _ => {}
    }
    PyVal::Dict(cleaned)
}

/// `codex_hook_response(response, event_name=event_name)`.
pub(crate) fn codex_hook_response(response: &[(String, PyVal)], event_name: &str) -> PyVal {
    let post_tool = event_name == POST_TOOL_USE;
    let allowed = |key: &str| {
        UNIVERSAL_KEYS.contains(&key)
            || key == "hookSpecificOutput"
            || (post_tool && (key == "decision" || key == "reason"))
    };
    let mut filtered: Vec<(String, PyVal)> = response
        .iter()
        .filter(|(key, _)| allowed(key))
        .cloned()
        .collect();
    let hook_output = filtered
        .iter()
        .position(|(key, _)| key == "hookSpecificOutput");
    if post_tool {
        if let Some(index) = hook_output {
            match &filtered[index].1 {
                PyVal::Dict(entries) => {
                    let kept = entries
                        .iter()
                        .filter(|(key, _)| POST_TOOL_OUTPUT_KEYS.contains(&key.as_str()))
                        .cloned()
                        .collect();
                    filtered[index].1 = PyVal::Dict(kept);
                }
                _ => {
                    filtered.remove(index);
                }
            }
        }
        return PyVal::Dict(filtered);
    }
    if event_name == PRE_TOOL_USE {
        if let Some(index) = hook_output {
            let original = filtered[index].1.clone();
            let cleaned = cleaned_pre_tool_output(&original, response, &mut filtered);
            filtered[index].1 = cleaned;
        }
    }
    PyVal::Dict(filtered)
}

#[cfg(all(test, unix))]
#[path = "codex_hook_response_tests.rs"]
mod tests;
