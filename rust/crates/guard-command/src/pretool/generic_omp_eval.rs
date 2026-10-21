//! Literal-only parser for Oh My Pi's `eval` bridge.
//!
//! OMP's Codex-style code mode routes tool calls through one JavaScript
//! program, so the host hook sees only an opaque `eval`. This module accepts
//! a deliberately tiny language: statements built from `tool.read`,
//! `tool.grep`, `tool.glob` and `tool.bash` calls whose arguments are object
//! literals of scalar literals, or the SDK's `await read(literal_path)` helper,
//! plus `display`/`log`, `const`/`let` bindings,
//! `Promise.all`, `JSON.stringify`, `.text` and `.length`. Every extracted call is then
//! evaluated as the equivalent standalone tool, through the same entry point
//! a direct call takes, so a bridged `bash` call's `cwd` is resolved exactly
//! as the direct `bash` tool's; any non-allow reviews the
//! whole program, except a bridged `bash` call that would run under Guard
//! containment on its own, since the bridge re-hooks it. Everything else,
//! including comments, templates with interpolation, operators, other identifiers and other languages, is
//! rejected rather than interpreted. A `py` program may only be whole lines of
//! the Python prelude's `read(literal_path)`, optionally inside `print` or
//! `display`.

use super::{strict_tool_input, OmpContext};
use crate::pretool::generic::extract::GenericSignals;
use crate::pretool::generic::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{json, Map, Value};

#[path = "generic_omp_eval_browser.rs"]
mod browser;
#[path = "generic_omp_eval_parser.rs"]
mod parser;
#[path = "generic_omp_eval_pure.rs"]
mod pure;
#[path = "generic_omp_eval_tokens.rs"]
mod tokens;
use parser::{parse_program, parse_python, Call, Lit};

/// Map one literal call onto the equivalent standalone tool payload.
fn standalone_payload(call: &Call, context: &OmpContext<'_>) -> Option<Value> {
    let mut input = Map::new();
    for (key, lit) in &call.args {
        let allowed_string = match call.tool.as_str() {
            "read" => &["path"][..],
            "grep" => &["pattern", "path", "glob", "type"][..],
            "glob" => &["pattern", "path"][..],
            // The shell inherits the workspace; only an explicit `.` matches.
            _ => &["command", "cwd"][..],
        };
        match lit {
            // OMP's session-tool wrapper accepts a literal intent label.
            Lit::Str(text) if key == "i" => {
                input.insert(key.clone(), Value::String(text.clone()));
            }
            Lit::Str(text) if allowed_string.contains(&key.as_str()) => {
                if call.sdk_read_helper && text.contains(':') {
                    let path = std::path::Path::new(text);
                    let candidate = if path.is_absolute() {
                        path.to_path_buf()
                    } else {
                        std::path::Path::new(context.path.cwd?).join(path)
                    };
                    // A colon can be a literal filename, but the SDK never
                    // strips read selectors. Prove that the exact file exists.
                    if !candidate.is_file() {
                        return None;
                    }
                }
                if call.tool == "bash" && key == "cwd" {
                    // `.` is the session directory everywhere. Oh My Pi's
                    // bridge hands any other `cwd` to the same `bash` tool,
                    // whose standalone proof resolves it; other harnesses
                    // have no such argument to model.
                    if text == "." {
                        continue;
                    }
                    if context.harness != "omp" {
                        return None;
                    }
                }
                input.insert(key.clone(), Value::String(text.clone()));
            }
            Lit::Str(_) => return None,
            // Only modeled options on read-only tools survive; the shell and
            // unknown options are reviewed rather than silently dropped.
            Lit::Scalar(value) if super::modeled_scalar(&call.tool, key, value) => {
                input.insert(key.clone(), value.clone());
            }
            Lit::Scalar(_) => return None,
        }
    }
    let required = match call.tool.as_str() {
        "read" => "path",
        "grep" => "pattern",
        "bash" => "command",
        _ => "",
    };
    if !required.is_empty() && !input.contains_key(required) {
        return None;
    }
    Some(json!({"tool_name": call.tool, "tool_input": Value::Object(input)}))
}

/// A JavaScript eval that only drives OMP's isolated browser against
/// loopback pages. URLs in such a program are checked by the parser, so this
/// runs before the generic URL bail-out.
pub(super) fn evaluate_browser(
    payload: &Value,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    let modeled = input.iter().all(|(key, value)| match key.as_str() {
        "code" | "language" => value.is_string(),
        "title" => value.is_string() || value.is_null(),
        "reset" => value.is_boolean() || value.is_null(),
        "timeout" => value.is_number() || value.is_null(),
        _ => false,
    });
    if !modeled
        || input.get("language")?.as_str()? != "js"
        || !browser::loopback_browser_program(input.get("code")?.as_str()?, context.path.home_dir)
    {
        return None;
    }
    Some(generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::Harness,
            PreToolOperationV1::Read,
            true,
            false,
        ),
        "allow",
        "native_omp_eval_loopback_browser",
        "The Rust authority read this eval program and found only isolated-browser reads and interactions on loopback pages and GET requests to loopback URLs, with page functions that run inside the page: no files, processes, modules or other hosts.",
    ))
}

pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if !signals.path_values.is_empty() {
        return None;
    }
    let input = strict_tool_input(payload)?;
    let language = input.get("language")?.as_str()?;
    if !matches!(language, "js" | "py")
        || !input.iter().all(|(key, value)| match key.as_str() {
            "code" | "language" => value.is_string(),
            // Codex-style code mode sends `null` for an optional field the
            // model left unset; it means the default, like an absent key.
            "title" => value.is_string() || value.is_null(),
            "reset" => value.is_boolean() || value.is_null(),
            "timeout" => value.is_number() || value.is_null(),
            _ => false,
        })
    {
        return None;
    }
    let code = input.get("code")?.as_str()?;
    let calls = if language == "py" {
        match parse_python(code) {
            Some(calls) => calls,
            None if pure::pure_python(code) => {
                return Some(generic_result(
                    generic_action(
                        context.harness,
                        context.event,
                        PreToolActionTypeV1::Harness,
                        PreToolOperationV1::Read,
                        true,
                        false,
                    ),
                    "allow",
                    "native_omp_eval_pure_compute",
                    "The Rust authority read this eval program and found only in-memory computation: no files, processes, network or environment.",
                ));
            }
            None => return None,
        }
    } else {
        parse_program(code)?
    };
    let mut ran_shell = false;
    for call in &calls {
        let inner = standalone_payload(call, context)?;
        ran_shell |= call.tool == "bash";
        // The entry point a direct call takes, so the bridged call gets the
        // same `cwd` resolution and compound re-judging as that call.
        let result = crate::pretool::generic::evaluate_pre_tool_envelope_with_execution_context(
            context.harness,
            context.event,
            &inner,
            context.controls,
            context.deadline,
            context.path,
            context.execution_environment,
        );
        if result.action.sensitive_target
            || (result.minimum_action != "allow" && !contained_bash(call, &result))
        {
            return None;
        }
    }
    let (action_type, operation) = if ran_shell {
        (PreToolActionTypeV1::Command, PreToolOperationV1::Execute)
    } else {
        (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read)
    };
    Some(generic_result(
        generic_action(context.harness, context.event, action_type, operation, true, false),
        "allow",
        "native_omp_eval_bounded_tools",
        "The Rust authority parsed this eval as literal Oh My Pi tool calls and proved each one allowed, or contained, on its own.",
    ))
}

/// Whether a bridged `bash` call needs only the containment its standalone
/// form would get. OMP wraps every tool the eval bridge reaches in its
/// extension gate, so the bridged call raises its own `tool_call` hook and
/// Guard contains it, or refuses to start it, exactly as when the agent
/// calls `bash` directly. Anything that would be reviewed standalone, or a
/// verdict with no containment profile, keeps the whole program reviewed.
fn contained_bash(call: &Call, result: &PreToolResultV1) -> bool {
    call.tool == "bash"
        && result.minimum_action == "sandbox-required"
        && result.policy_action == "sandbox-required"
        && crate::hook_responses::contained_execution_profile(&result.reason_code).is_some()
}
