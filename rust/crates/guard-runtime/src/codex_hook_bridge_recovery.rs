//! The one way past a Guard daemon that cannot answer: the commands that
//! repair it.
//!
//! The hook tells an agent to run `hol-guard daemon repair`, and the same
//! hook would stop that command, because a hook with no daemon answer denies
//! every tool call. The agent could neither read the state of the daemon nor
//! mend it. This module lets exactly the documented recovery and diagnostic
//! commands through when, and only when, the daemon gave no verdict at all:
//! it was unreachable, or it reported that it could not finish a review.
//!
//! What it never does is decide for the daemon. A daemon that answered with a
//! policy verdict keeps it, a command that is not word-for-word one of the
//! listed forms stays denied, and a call that asks Codex to leave its sandbox
//! is not a recovery command.

use serde_json::Value;

use super::{Prepared, Route, PRE_TOOL_USE};
use crate::codex_hook_response::codex_hook_response;
use crate::hook_env_stamp::dumps;
use crate::pyjson::PyVal;

/// Codex names its shell tool `exec_command` and carries the text in `cmd`;
/// other harnesses name it `Bash` and carry it in `command`.
const SHELL_TOOLS: [&str; 4] = ["Bash", "bash", "exec_command", "functions.exec_command"];
const GUARD_PROGRAM: &str = "hol-guard";

/// The only keys a recovery call may carry. Anything else could change what
/// runs: Codex's `exec_command` takes a model-supplied `shell` path and a
/// `login` flag, so a call that names one is not a recovery call.
const ALLOWED_INPUT_KEYS: [&str; 11] = [
    "command",
    "cmd",
    "workdir",
    "description",
    "timeout",
    "timeout_ms",
    "yield_time_ms",
    "max_output_tokens",
    "justification",
    "sandbox_permissions",
    "with_escalated_permissions",
];

/// The argument lists, after `hol-guard`, that read Guard's own state or
/// restart its daemon. Each one is read-only or repairs only Guard's own
/// runtime; none takes a path, a program or a home to act on.
const RECOVERY_ARGUMENTS: [&[&str]; 9] = [
    &["--version"],
    &["doctor"],
    &["doctor", "--json"],
    &["daemon", "status"],
    &["daemon", "status", "--json"],
    &["daemon", "repair"],
    &["daemon", "repair", "--json"],
    &["daemon", "recovery", "inspect"],
    &["daemon", "recovery", "inspect", "--json"],
];

/// Reason codes that say the daemon never reached a verdict, rather than
/// deciding against the call.
const NO_VERDICT_REASON_CODES: [&str; 22] = [
    "native_policy_not_ready",
    "native_policy_update_in_progress",
    "native_hook_event_unavailable",
    "native_pre_tool_unavailable",
    "native_overloaded",
    "native_hook_worker_unavailable",
    "native_hook_worker_unavailable_before_compatibility",
    "native_hook_worker_exception",
    "native_hook_edge_invalid_response",
    "native_hook_edge_unavailable",
    "native_command_extension_evaluation_failed",
    "native_command_extension_evaluation_timed_out",
    "daemon_hook_queue_capacity",
    "daemon_hook_deadline_exhausted",
    "daemon_hook_process_deadline_exhausted",
    "daemon_hook_process_not_ready",
    "daemon_hook_process_failed",
    "daemon_hook_process_guard_home_mismatch",
    "daemon_worker_exception",
    "native_approval_authority_busy",
    // Taking the authority lock failed; the authority itself was not judged.
    "native_approval_authority_lock_failed",
    "native_approval_authority_directory_lock_failed",
];

/// Whether `code` says the daemon could not decide, as opposed to refusing.
/// Integrity and provenance findings (a mismatch, a rollback, an invalid or
/// missing authority) are verdicts, so they are not listed.
pub(crate) fn is_no_verdict(code: &str) -> bool {
    NO_VERDICT_REASON_CODES.contains(&code)
}

/// The characters a recovery command may hold. Nothing here lets a shell
/// start a second command, expand a variable, redirect, glob or quote.
fn is_plain_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Whether `command` is, word for word, one of the recovery commands.
pub(super) fn is_recovery_command(command: &str) -> bool {
    let words: Vec<&str> = command.split(' ').collect();
    // Doubled, leading or trailing spaces, tabs and newlines are not the
    // documented spelling.
    if words.iter().any(|word| !is_plain_word(word)) {
        return false;
    }
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    *program == GUARD_PROGRAM && RECOVERY_ARGUMENTS.contains(&arguments)
}

/// Whether the hook is a shell call that runs only a recovery command inside
/// Codex's own sandbox policy. The event is checked by the caller against the
/// bridge's normalized event name.
pub(crate) fn is_recovery_call(data: &str) -> bool {
    let Ok(payload) = serde_json::from_str::<Value>(data) else {
        return false;
    };
    let tool = ["tool_name", "toolName"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str));
    if !tool.is_some_and(|tool| SHELL_TOOLS.contains(&tool)) {
        return false;
    }
    let Some(input) = ["tool_input", "toolInput"]
        .iter()
        .find_map(|key| payload.get(*key))
        .and_then(Value::as_object)
    else {
        return false;
    };
    if input
        .keys()
        .any(|key| !ALLOWED_INPUT_KEYS.contains(&key.as_str()))
    {
        return false;
    }
    // A call that asks to run outside the sandbox is not a recovery step.
    let escalated = input
        .get("sandbox_permissions")
        .and_then(Value::as_str)
        .is_some_and(|value| value != "use_default")
        || input.get("with_escalated_permissions") == Some(&Value::Bool(true));
    if escalated {
        return false;
    }
    // Exactly one spelling of the command: a call that carries both keys
    // could show the reviewer one text and run the other.
    let text = match (input.get("command"), input.get("cmd")) {
        (Some(command), None) => command,
        (None, Some(cmd)) => cmd,
        _ => return false,
    };
    text.as_str().is_some_and(is_recovery_command)
}

/// The answer that lets a recovery command run, saying why Guard did not
/// review it.
fn allow_recovery() -> String {
    let allow = PyVal::Dict(vec![(
        "permissionDecision".to_owned(),
        PyVal::Str("allow".to_owned()),
    )]);
    let response = vec![
        ("hookSpecificOutput".to_owned(), allow),
        (
            "systemMessage".to_owned(),
            PyVal::Str(
                "HOL Guard could not reach its daemon, so it did not review this call. It runs \
because it only reads or repairs Guard's own state; every other action stays blocked until the \
daemon answers."
                    .to_owned(),
            ),
        ),
    ];
    let mut text = String::new();
    dumps(
        &codex_hook_response(&response, PRE_TOOL_USE),
        true,
        false,
        &mut text,
    );
    text
}

/// The route for a hook the daemon gave no verdict on: the recovery answer
/// for a recovery command, `None` for anything else.
pub(super) fn bootstrap_route(prepared: &Prepared) -> Option<Route> {
    (prepared.event_name == PRE_TOOL_USE && is_recovery_call(&prepared.data))
        .then(|| Route::Respond(allow_recovery()))
}

/// The route for a daemon answer that says it could not decide, when the hook
/// is a recovery command. Any other answer is left to `route_response`.
pub(super) fn bootstrap_for_answer(prepared: &Prepared, answer: &str) -> Option<Route> {
    let parsed: Value = serde_json::from_str(answer).ok()?;
    let code = parsed.get("reason_code")?.as_str()?;
    if !is_no_verdict(code) {
        return None;
    }
    bootstrap_route(prepared)
}
