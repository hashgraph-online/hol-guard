//! How the Cline hook worker reads Guard's decision: which object in its
//! stdout is the decision, whether it blocks, whether it explicitly allows,
//! and the reason it gives.

use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};

use crate::claude_hook_bridge_render::py_strip;
use crate::daemon_lifecycle_text::py_splitlines;

const DEFAULT_REASON: &str = "HOL Guard blocked this action.";
const REASON_KEYS: [&str; 6] = [
    "reason",
    "stopReason",
    "review_hint",
    "systemMessage",
    "message",
    "error",
];
const DENY_WORDS: [&str; 3] = ["deny", "block", "ask"];
const RESTRICTIVE_ACTIONS: [&str; 4] =
    ["review", "require-reapproval", "sandbox-required", "block"];
const ALLOW_ACTIONS: [&str; 2] = ["allow", "warn"];

/// The decision object in Guard's stdout: the whole stripped text, else the
/// last line that is one.
pub(super) fn parse_output(text: &str) -> Option<OMap> {
    let text = py_strip(text);
    let lines: Vec<&str> = py_splitlines(text)
        .into_iter()
        .map(py_strip)
        .filter(|line| !line.is_empty())
        .collect();
    std::iter::once(text)
        .chain(lines.into_iter().rev())
        .filter(|candidate| candidate.starts_with('{'))
        .find_map(|candidate| match parse_python_json(candidate) {
            Ok(OValue::Map(map)) => Some(map),
            _ => None,
        })
}

fn lower(value: Option<&OValue>) -> Option<String> {
    value?.as_str().map(str::to_lowercase)
}

fn word_in(value: Option<&OValue>, words: &[&str]) -> bool {
    lower(value).is_some_and(|word| words.contains(&word.as_str()))
}

pub(super) fn blocked(decision: &OMap) -> bool {
    if decision.get("blocked") == Some(&OValue::Bool(true))
        || decision.get("continue") == Some(&OValue::Bool(false))
        || word_in(decision.get("decision"), &DENY_WORDS)
        || ["policy_action", "policyAction"]
            .iter()
            .any(|key| word_in(decision.get(key), &RESTRICTIVE_ACTIONS))
    {
        return true;
    }
    let Some(specific) = decision.get("hookSpecificOutput").and_then(OValue::as_map) else {
        return false;
    };
    word_in(specific.get("permissionDecision"), &DENY_WORDS)
        || word_in(
            specific
                .get("decision")
                .and_then(OValue::as_map)
                .and_then(|nested| nested.get("behavior")),
            &DENY_WORDS,
        )
}

/// The decision says "allow" in a shape this worker reads, and no present
/// field says anything else. A tier it cannot place is no permission.
pub(super) fn explicitly_allows(decision: &OMap) -> bool {
    if blocked(decision) {
        return false;
    }
    if decision
        .get("decision")
        .is_some_and(|value| value.as_str().is_none())
    {
        return false;
    }
    let verdict = lower(decision.get("decision"));
    let mut actions = Vec::new();
    for key in ["policy_action", "policyAction"] {
        let Some(value) = decision.get(key) else {
            continue;
        };
        let Some(action) = value.as_str() else {
            return false;
        };
        actions.push(action.to_lowercase());
    }
    if actions
        .iter()
        .any(|action| !ALLOW_ACTIONS.contains(&action.as_str()))
    {
        return false;
    }
    let specific = decision.get("hookSpecificOutput").and_then(OValue::as_map);
    let permission = specific.and_then(|specific| lower(specific.get("permissionDecision")));
    let behavior = specific
        .and_then(|specific| specific.get("decision"))
        .and_then(OValue::as_map)
        .and_then(|nested| lower(nested.get("behavior")));
    let allow = |word: &Option<String>| word.as_deref() == Some("allow");
    let other = |word: &Option<String>| word.as_deref().is_some_and(|word| word != "allow");
    if other(&verdict) || other(&permission) || other(&behavior) {
        return false;
    }
    allow(&verdict) || !actions.is_empty() || allow(&permission) || allow(&behavior)
}

/// The stripped reason the decision gives, or the default.
pub(super) fn reason(decision: &OMap) -> &str {
    fn stripped(value: Option<&OValue>) -> Option<&str> {
        value
            .and_then(OValue::as_str)
            .map(py_strip)
            .filter(|text| !text.is_empty())
    }
    if let Some(text) = REASON_KEYS
        .iter()
        .find_map(|key| stripped(decision.get(key)))
    {
        return text;
    }
    let Some(specific) = decision.get("hookSpecificOutput").and_then(OValue::as_map) else {
        return DEFAULT_REASON;
    };
    if let Some(text) = ["permissionDecisionReason", "additionalContext"]
        .iter()
        .find_map(|key| stripped(specific.get(key)))
    {
        return text;
    }
    // A nested message is used as written, even when it strips to nothing.
    specific
        .get("decision")
        .and_then(OValue::as_map)
        .and_then(|nested| nested.get("message"))
        .and_then(OValue::as_str)
        .map_or(DEFAULT_REASON, py_strip)
}
