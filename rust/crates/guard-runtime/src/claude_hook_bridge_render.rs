//! Hook responses the native Claude hook bridge writes itself: the deny,
//! degraded and control-plane shapes from `claude_daemon_hook_bridge.py`, and
//! the check that a daemon or fallback response is a decision Claude Code
//! will honor for the hook event.
//!
//! The bridge never weakens a decision here. Where CPython would have raised
//! out of these helpers (an integer past its digit limit while reading the
//! event name), the bridge reads the event from the text prefix instead and
//! still denies.

use crate::hook_env_stamp::json_string;
use crate::pyjson::{
    self, float_repr, in_surrogate_plane, JsonFailure, PyVal, SURROGATE_PLANE_BASE,
};

const DEGRADED_DAEMON_MESSAGE_PREFIX: &str = "HOL Guard could not complete native review (";
const DEGRADED_DAEMON_MESSAGE_SUFFIX: &str = ") and denied this action.";
const RISKY_PROMPT_SYSTEM_MESSAGE: &str = "HOL Guard intercepted this prompt because it asks Claude to access local secrets. If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt.";
const RISKY_PROMPT_ADDITIONAL_CONTEXT: &str = "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval question to protect you.";
const RISKY_PROMPT_TOKENS: [&str; 4] = [".env", "secret", "api key", "token"];
const PERMISSION_PASSTHROUGH_KEY: &str = "guard_permission_passthrough";
const DEFAULT_EVENT: &str = "PreToolUse";
const EVENT_PREFIX_CHARS: usize = 4096;
/// Stands in for `str()` of a truthy non-string event value. Only exact
/// event names and the `Permission` prefix change a response, and no
/// `str()` of a JSON number, boolean, list or object has either.
const NON_STRING_EVENT: &str = "\u{0}non-string-event";

/// `_event_name(data)`, with whether a mapped lone surrogate in the name
/// must be written back as its `\udXXX` escape.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct HookEvent {
    pub(crate) name: String,
    unmap: bool,
}

impl HookEvent {
    pub(crate) fn named(name: &str) -> Self {
        HookEvent {
            name: name.to_owned(),
            unmap: false,
        }
    }

    pub(crate) fn is_permission(&self) -> bool {
        self.name.starts_with("Permission")
    }

    fn json(&self) -> String {
        json_string(&self.name, true, self.unmap)
    }
}

/// CPython `str.strip()` with no argument.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

fn parse_object(data: &str) -> Option<(Vec<(String, PyVal)>, bool)> {
    let source = if data.is_empty() { "{}" } else { data };
    let parsed = pyjson::parse_mapping_lone_surrogates(source).ok()?;
    let unmap = parsed.mapped && !parsed.collision;
    match parsed.value {
        PyVal::Dict(entries) => Some((entries, unmap)),
        _ => None,
    }
}

fn member<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value)
}

pub(crate) fn event_name(data: &str) -> HookEvent {
    if let Some((entries, unmap)) = parse_object(data) {
        let chosen = [
            member(&entries, "hook_event_name"),
            member(&entries, "event"),
        ]
        .into_iter()
        .flatten()
        .find(|value| value.truthy());
        return match chosen {
            None => HookEvent::named(DEFAULT_EVENT),
            Some(PyVal::Str(name)) => {
                let ambiguous = !unmap && name.chars().any(in_surrogate_plane);
                if ambiguous && pyjson::parse_mapping_lone_surrogates(data).is_ok_and(|p| p.mapped)
                {
                    HookEvent::named(DEFAULT_EVENT)
                } else {
                    HookEvent {
                        name: name.clone(),
                        unmap,
                    }
                }
            }
            Some(_) => HookEvent::named(NON_STRING_EVENT),
        };
    }
    let prefix: Vec<char> = data.chars().take(EVENT_PREFIX_CHARS).collect();
    for key in ["hook_event_name", "event"] {
        let needle: Vec<char> = format!("\"{key}\"").chars().collect();
        let Some(start) = find(&prefix, &needle, 0, prefix.len()) else {
            continue;
        };
        let Some(colon) = find(&prefix, &[':'], start, start + 64) else {
            continue;
        };
        let Some(quote) = find(&prefix, &['"'], colon + 1, colon + 80) else {
            continue;
        };
        if let Some(end) = find(&prefix, &['"'], quote + 1, quote + 80) {
            let name: String = prefix[quote + 1..end].iter().collect();
            return HookEvent::named(if name.is_empty() {
                DEFAULT_EVENT
            } else {
                &name
            });
        }
    }
    HookEvent::named(DEFAULT_EVENT)
}

/// `str.find(needle, start, end)` over characters.
fn find(haystack: &[char], needle: &[char], start: usize, end: usize) -> Option<usize> {
    let end = end.min(haystack.len());
    if start > end || needle.len() > end - start {
        return None;
    }
    (start..=end - needle.len()).find(|&index| haystack[index..index + needle.len()] == *needle)
}

/// `str(prompt or "")` for `_prompt_text`; nested strings follow `repr()`
/// closely enough for the secret-token check.
fn prompt_text(data: &str) -> String {
    let Some((entries, _)) = parse_object(data) else {
        return String::new();
    };
    let prompt = member(&entries, "prompt").or_else(|| member(&entries, "user_prompt"));
    match prompt {
        Some(value) if value.truthy() => py_str(value),
        _ => String::new(),
    }
}

fn py_str(value: &PyVal) -> String {
    match value {
        PyVal::Str(text) => text.clone(),
        other => py_repr(other),
    }
}

fn py_repr(value: &PyVal) -> String {
    match value {
        PyVal::Null => "None".to_owned(),
        PyVal::Bool(true) => "True".to_owned(),
        PyVal::Bool(false) => "False".to_owned(),
        PyVal::Int(digits) => digits.clone(),
        PyVal::Float(number) => float_repr(*number),
        PyVal::Str(text) => py_repr_str(text),
        PyVal::List(items) => {
            let parts: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        PyVal::Dict(entries) => {
            let parts: Vec<String> = entries
                .iter()
                .map(|(key, item)| format!("{}: {}", py_repr_str(key), py_repr(item)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (0x7f..=0xa0).contains(&(c as u32)) || c == '\u{ad}' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if in_surrogate_plane(c) => {
                out.push_str(&format!(
                    "\\u{:04x}",
                    c as u32 - SURROGATE_PLANE_BASE + 0xd800
                ));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn degraded_prompt(data: &str) -> String {
    let prompt = prompt_text(data).to_lowercase();
    if RISKY_PROMPT_TOKENS
        .iter()
        .any(|token| prompt.contains(token))
    {
        return format!(
            "{{\"systemMessage\":{},\"hookSpecificOutput\":{{\"hookEventName\":\"UserPromptSubmit\",\"additionalContext\":{}}}}}",
            json_string(RISKY_PROMPT_SYSTEM_MESSAGE, true, false),
            json_string(RISKY_PROMPT_ADDITIONAL_CONTEXT, true, false),
        );
    }
    "{\"hookSpecificOutput\":{\"hookEventName\":\"UserPromptSubmit\"}}".to_owned()
}

pub(crate) fn limit_denied(kind: &str, event: &HookEvent) -> String {
    deny_event(
        event,
        &format!("HOL Guard blocked this action because {kind} exceeded the safe size limit."),
    )
}

pub(crate) fn deny_event(event: &HookEvent, message: &str) -> String {
    let message = json_string(message, true, false);
    if event.is_permission() {
        return format!(
            "{{\"systemMessage\":{message},\"hookSpecificOutput\":{{\"hookEventName\":{},\"decision\":{{\"behavior\":\"deny\",\"message\":{message}}}}}}}",
            event.json(),
        );
    }
    if matches!(
        event.name.as_str(),
        "UserPromptSubmit" | "PostToolUse" | "Stop"
    ) {
        return format!(
            "{{\"decision\":\"block\",\"reason\":{message},\"hookSpecificOutput\":{{\"hookEventName\":{}}}}}",
            event.json(),
        );
    }
    format!(
        "{{\"systemMessage\":{message},\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":{message}}}}}"
    )
}

pub(crate) fn degraded(reason: &str, data: &str) -> String {
    let event = event_name(data);
    if event.name == "UserPromptSubmit" {
        return degraded_prompt(data);
    }
    if event.name == DEFAULT_EVENT || event.is_permission() {
        let message =
            format!("{DEGRADED_DAEMON_MESSAGE_PREFIX}{reason}{DEGRADED_DAEMON_MESSAGE_SUFFIX}");
        return deny_event(&event, &message);
    }
    "{}".to_owned()
}

pub(crate) fn control_plane_failure(reason: &str, data: &str) -> String {
    let message =
        format!("HOL Guard denied the action because daemon authentication failed: {reason}");
    let event = event_name(data);
    if event.is_permission() || event.name == DEFAULT_EVENT {
        return deny_event(&event, &message);
    }
    format!(
        "{{\"continue\":true,\"stopReason\":{}}}",
        json_string(&message, true, false)
    )
}

pub(crate) fn should_suppress_output(data: &str, response_body: &str) -> bool {
    event_name(data).name == "UserPromptSubmit" && matches!(py_strip(response_body), "" | "{}")
}

/// `_valid_hook_json_or_degraded`. `Err` carries the failure CPython's
/// `json.loads` would raise on the response instead of `JSONDecodeError`.
pub(crate) fn valid_hook_json_or_degraded(
    output: &str,
    reason: &str,
    data: &str,
) -> Result<String, JsonFailure> {
    let trimmed = py_strip(output);
    if trimmed.is_empty() {
        return Ok(degraded(reason, data));
    }
    let decoded = match pyjson::parse_mapping_lone_surrogates(trimmed) {
        Ok(parsed) => parsed.value,
        Err(JsonFailure::Syntax) => return Ok(degraded(reason, data)),
        Err(failure) => return Err(failure),
    };
    let PyVal::Dict(entries) = decoded else {
        return Ok(degraded(reason, data));
    };
    let event = event_name(data);
    let hook_output = member(&entries, "hookSpecificOutput").and_then(PyVal::as_dict);
    let names_event = |output: &[(String, PyVal)]| {
        member(output, "hookEventName").and_then(PyVal::as_str) == Some(event.name.as_str())
    };
    if event.name == DEFAULT_EVENT {
        let decided = hook_output.is_some_and(|output| {
            names_event(output)
                && matches!(
                    member(output, "permissionDecision").and_then(PyVal::as_str),
                    Some("allow" | "ask" | "deny")
                )
        });
        if !decided {
            return Ok(degraded(reason, data));
        }
    } else if event.is_permission() {
        let passthrough = member(&entries, PERMISSION_PASSTHROUGH_KEY) == Some(&PyVal::Bool(true))
            && hook_output
                .is_some_and(|output| names_event(output) && member(output, "decision").is_none());
        if passthrough {
            return Ok(trimmed.to_owned());
        }
        let decided = hook_output.is_some_and(|output| {
            names_event(output)
                && member(output, "decision")
                    .and_then(PyVal::as_dict)
                    .and_then(|decision| member(decision, "behavior"))
                    .and_then(PyVal::as_str)
                    .is_some_and(|behavior| matches!(behavior, "allow" | "deny"))
        });
        if !decided {
            return Ok(degraded(reason, data));
        }
    }
    Ok(trimmed.to_owned())
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_render_tests.rs"]
mod tests;
