//! Oh My Pi PreToolUse proofs that need the raw tool input: delegation and
//! bookkeeping tools, names-only listings, bounded `grep` scopes, and the
//! literal-only `eval` bridge. Every proof is gated on harness `omp`,
//! `PreToolUse`, and an exact tool name; anything else falls through to the
//! ordinary generic review path.

#[path = "generic_omp_eval.rs"]
mod eval;

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use crate::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{Map, Value};
use std::time::Instant;

pub(super) struct OmpContext<'a> {
    pub(super) harness: &'a str,
    pub(super) event: &'a str,
    pub(super) controls: Option<&'a CompiledNativeCommandControls>,
    pub(super) deadline: Option<Instant>,
    pub(super) path: super::super::PathContext<'a>,
    pub(super) execution_environment: Option<&'a guard_contracts::GuardExecutionEnvironmentV1>,
}

/// `Some` only when a bounded proof applies; `None` keeps the normal path.
pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if context.event != "PreToolUse"
        || context.harness != "omp"
        || signals.sensitive_target
        || signals.command.is_some()
        || signals.package_present
        || !signals.url_values.is_empty()
    {
        return None;
    }
    let tool = signals.tool_name.as_deref()?;
    match tool {
        "task" | "wait" | "todo" | "todo_write" => {
            // Delegated work runs through its own guarded tool calls. A
            // path-bearing input is not a delegation envelope.
            signals
                .path_values
                .is_empty()
                .then(|| delegation_result(tool, context))
        }
        "eval" => eval::evaluate(payload, signals, context),
        "glob" | "find" | "ls" => listing(payload, signals, context),
        "grep" => grep_scope(payload, signals, context),
        _ => None,
    }
}

fn delegation_result(tool: &str, context: &OmpContext<'_>) -> PreToolResultV1 {
    let (action_type, operation) = match tool {
        "task" => (PreToolActionTypeV1::Harness, PreToolOperationV1::Start),
        "wait" => (PreToolActionTypeV1::Harness, PreToolOperationV1::Read),
        _ => (PreToolActionTypeV1::Harness, PreToolOperationV1::Set),
    };
    generic_result(
        generic_action(context.harness, context.event, action_type, operation, true, false),
        "allow",
        "native_omp_agent_task",
        "The Rust authority allowed this Oh My Pi task, wait, or todo control call; any tool a delegated task runs is guarded independently.",
    )
}

/// The one tool input object. Alternate spellings must agree with it.
pub(super) fn strict_tool_input(payload: &Value) -> Option<&Map<String, Value>> {
    let root = payload.as_object()?;
    let input = root.get("tool_input")?.as_object()?;
    for alias in super::extract::EMBEDDED_ARGUMENT_KEYS {
        if alias == "tool_input" {
            continue;
        }
        if root
            .get(alias)
            .is_some_and(|value| value.as_object() != Some(input))
        {
            return None;
        }
    }
    Some(input)
}

/// Optional `path` string. `Some(None)` is an absent path (workspace root).
fn input_path<'a>(
    input: &'a Map<String, Value>,
    signals: &GenericSignals,
) -> Option<Option<&'a str>> {
    let path = match input.get("path") {
        None => None,
        Some(Value::String(path)) if !path.is_empty() => Some(path.as_str()),
        Some(_) => return None,
    };
    let expected: Vec<&str> = path.into_iter().collect();
    (signals.path_values.len() == expected.len()
        && signals.path_values.iter().map(String::as_str).eq(expected))
    .then_some(path)
}

/// A pattern or glob can never leave the target directory.
fn contained_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with(['/', '~', '\\'])
        && !value.contains(['\0', '\n', '\r', '$', '`'])
        && !value.split(['/', '\\']).any(|part| part == "..")
        && value.as_bytes().get(1) != Some(&b':')
}

/// Scalar keys carry no path or command; strings are limited to `string_keys`.
fn scalar_keys(input: &Map<String, Value>, string_keys: &[&str]) -> bool {
    input.iter().all(|(key, value)| match value {
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(_) => string_keys.contains(&key.as_str()),
        _ => false,
    })
}

fn directory_allow(context: &OmpContext<'_>, code: &str, reason: &str) -> PreToolResultV1 {
    generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::FileRead,
            PreToolOperationV1::Read,
            true,
            false,
        ),
        "allow",
        code,
        reason,
    )
}

fn listing(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !scalar_keys(input, &["path", "pattern"]) {
        return None;
    }
    if let Some(pattern) = input.get("pattern") {
        if !contained_selector(pattern.as_str()?) {
            return None;
        }
    }
    let target = input_path(input, signals)?.unwrap_or(".");
    super::super::safe_reads::bounded_omp_directory_read_target(
        target,
        context.path.home_dir,
        context.path.cwd,
    )
    .then(|| {
        directory_allow(
            context,
            "native_omp_directory_listing",
            "The Rust authority proved this names-only listing targets a verified ordinary directory.",
        )
    })
}

fn grep_scope(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !scalar_keys(input, &["path", "pattern", "glob", "type"]) {
        return None;
    }
    let pattern = input.get("pattern")?.as_str()?;
    if pattern.is_empty() || pattern.len() > 4096 {
        return None;
    }
    for key in ["glob", "type"] {
        if let Some(value) = input.get(key) {
            if !contained_selector(value.as_str()?) {
                return None;
            }
        }
    }
    let target = input_path(input, signals)?.unwrap_or(".");
    // A single file is proven by the ordinary bounded file-read path.
    super::super::search_scope::unfiltered_directory_scope_proven(
        target,
        context.path.home_dir,
        context.path.cwd,
    )
    .then(|| {
        directory_allow(
            context,
            "native_bounded_search_scope",
            "The Rust authority proved this directory search cannot reach a sensitive file.",
        )
    })
}

/// `skill://<name>[/<relative.md>]` names a skill the host resolves from its
/// own registered skill roots; the name is a bounded token, never a path.
fn skill_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("skill://") else {
        return false;
    };
    let token = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    rest.len() <= 512 && rest.split('/').all(token)
}

/// Reason code for host-held reference selectors, `None` for real paths.
pub(super) fn host_reference_reason(value: &str) -> Option<&'static str> {
    if artifact_reference(value) {
        Some("native_omp_artifact_read")
    } else if skill_reference(value) {
        Some("native_omp_skill_read")
    } else {
        None
    }
}

/// `artifact://<digits>` names an Oh My Pi session artifact, never a path.
fn artifact_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("artifact://") else {
        return false;
    };
    let (id, range) = match rest.split_once(':') {
        Some((id, range)) => (id, Some(range)),
        None => (rest, None),
    };
    !id.is_empty()
        && id.len() <= 9
        && id.bytes().all(|byte| byte.is_ascii_digit())
        && range.is_none_or(|range| {
            range.split_once('-').is_some_and(|(start, end)| {
                [start, end].iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 9
                        && part.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
        })
}
