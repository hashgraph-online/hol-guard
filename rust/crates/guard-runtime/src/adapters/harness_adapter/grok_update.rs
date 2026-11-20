//! `hooks_current`: whether the two Grok hook files `hol-guard update` finds
//! already hold what an install would write now.
//!
//! The pretool hook must keep its timeout and name the command an install
//! would render; the prompt hook file must still carry every observe hook
//! entry. Python rewrites the install when this answers `false`.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::grok::{
    hook_cli_args, hooks_dir, observe_hook, HOOK_INTERNAL_TIMEOUT_SECONDS, PRETOOL_FILE,
    PROMPT_FILE,
};
use super::{hook_config, Ctx, Failure, Spec, Step};
use crate::grok_user_config::GROK_PRETOOL_HOOK_TIMEOUT_SECONDS;
use crate::pyjson::{self, JsonFailure, PyVal};

const UNREADABLE: &str = "Grok hook file is not readable JSON";

/// A hook file's JSON. `None` where Python's `OSError` or `JSONDecodeError`
/// answered "not current"; text that is not UTF-8 is the `ValueError` Python
/// let through.
fn read_json(ctx: &Ctx, path: &Path) -> Step<Option<PyVal>> {
    let Ok(bytes) = fs::read(ctx.absolute(path)) else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        Failure::Refusal(crate::claude_hook_bridge_auth::utf8_error_message(
            &bytes, error,
        ))
    })?;
    match pyjson::parse(text) {
        Ok(value) => Ok(Some(value)),
        Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(Failure::Refusal(UNREADABLE.to_owned())),
    }
}

/// `_pretool_entry`: the first `PreToolUse` handler, or its group when the
/// group names no handlers.
fn pretool_entry(payload: &PyVal) -> Option<&PyVal> {
    let hooks = payload.get("hooks")?;
    if !matches!(hooks, PyVal::Dict(_)) {
        return None;
    }
    let first = hooks.get("PreToolUse")?.as_list()?.first()?;
    if !matches!(first, PyVal::Dict(_)) {
        return None;
    }
    match first
        .get("hooks")
        .and_then(PyVal::as_list)
        .and_then(<[PyVal]>::first)
    {
        Some(inner @ PyVal::Dict(_)) => Some(inner),
        _ => Some(first),
    }
}

/// `actual == expected` for the scalar kinds an observe hook carries, as
/// Python compares them (`True == 1`, `15.0 == 15`).
fn py_equal(actual: &PyVal, expected: &PyVal) -> bool {
    match (actual, expected) {
        (PyVal::Str(actual), PyVal::Str(expected)) => actual == expected,
        (PyVal::Int(actual), PyVal::Int(expected)) => actual == expected,
        (PyVal::Bool(flag), PyVal::Int(digits)) => digits == if *flag { "1" } else { "0" },
        (PyVal::Float(number), PyVal::Int(digits)) => {
            digits.parse::<f64>().is_ok_and(|value| value == *number)
        }
        _ => false,
    }
}

/// Whether one group has no matcher and holds a handler with every field of
/// `wanted`.
fn group_current(group: &PyVal, wanted: &[(String, PyVal)]) -> bool {
    matches!(group, PyVal::Dict(_))
        && !group.get("matcher").is_some_and(PyVal::truthy)
        && group
            .get("hooks")
            .and_then(PyVal::as_list)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    matches!(hook, PyVal::Dict(_))
                        && wanted.iter().all(|(key, value)| {
                            hook.get(key).is_some_and(|got| py_equal(got, value))
                        })
                })
            })
}

/// `_prompt_hook_entries_are_current`: every event the observe hooks name
/// still has a matcher-less group holding the expected handler. Other
/// groups, handlers and events are the user's and stay.
fn prompt_entries_current(payload: &PyVal, expected: &PyVal) -> bool {
    let Some(hooks @ PyVal::Dict(_)) = payload.get("hooks") else {
        return false;
    };
    let Some(expected_hooks) = expected.get("hooks").and_then(PyVal::as_dict) else {
        return false;
    };
    expected_hooks.iter().all(|(event, required)| {
        let wanted = required
            .as_list()
            .and_then(<[PyVal]>::first)
            .and_then(|group| group.get("hooks"))
            .and_then(PyVal::as_list)
            .and_then(<[PyVal]>::first)
            .and_then(PyVal::as_dict);
        match (hooks.get(event).and_then(PyVal::as_list), wanted) {
            (Some(groups), Some(wanted)) => groups.iter().any(|group| group_current(group, wanted)),
            _ => false,
        }
    })
}

fn current(flag: bool) -> Step<Value> {
    Ok(json!({ "current": flag }))
}

/// `_grok_hooks_are_current`.
pub(super) fn hooks_current(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let hooks = hooks_dir(ctx);
    let pretool_path = hooks.join(PRETOOL_FILE);
    if !ctx.absolute(&pretool_path).is_file() {
        return current(false);
    }
    let Some(pretool) = read_json(ctx, &pretool_path)? else {
        return current(false);
    };
    let entry = pretool_entry(&pretool);
    let timeout_current = matches!(
        entry.and_then(|entry| entry.get("timeout")),
        Some(PyVal::Int(digits)) if *digits == GROK_PRETOOL_HOOK_TIMEOUT_SECONDS.to_string()
    );
    if !timeout_current {
        return current(false);
    }
    let command = entry
        .and_then(|entry| entry.get("command"))
        .and_then(PyVal::as_str)
        .unwrap_or("");
    let Some(prompt) = read_json(ctx, &hooks.join(PROMPT_FILE))? else {
        return current(false);
    };
    if !prompt_entries_current(&prompt, &observe_hook(command)) {
        return current(false);
    }
    let argv = hook_config::hook_argv(
        ctx,
        spec.harness,
        &hook_cli_args(ctx, spec.harness),
        HOOK_INTERNAL_TIMEOUT_SECONDS,
    )?;
    let mut fields = Map::new();
    fields.insert("hook_argv".to_owned(), json!(argv));
    let candidates = super::grok_install::hook_candidates(ctx, &fields)?;
    let expected = candidates
        .get("hook_command")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    current(command == expected)
}
