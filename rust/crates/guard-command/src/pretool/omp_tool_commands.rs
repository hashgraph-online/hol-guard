//! Oh My Pi tool commands.
//!
//! Oh My Pi 19 mounts its less common built-in tools (`github`, `lsp`,
//! `ast_grep` and the rest of [`MOUNTED_BUILTINS`]) as commands inside its own
//! `bash` tool, on by default through its `tools.commands` setting. Its
//! in-process shell runs such a command by calling the tool, and that call goes
//! through the same extension wrapper as a top-level call, so Guard's own
//! `tool_call` hook reviews the tool and its arguments before it runs.
//!
//! The outer `bash` call names a program no PATH entry holds, so the generic
//! rule reviews it, and on macOS and Linux the workspace sandbox then takes it.
//! The sandbox runs a real shell, which has no such command: the call fails
//! with "command not found" (exit 127) and the agent loses the tool.
//!
//! [`settle`] lets that one shape through: the whole command is a single plain
//! invocation of a mounted built-in, nothing on PATH answers to the name, and
//! the line holds no pipe, list, substitution, expansion or glob. A file
//! redirect is split off before this runs and judged by the redirect floors
//! like any other command's output file.
//! The shell then either dispatches the reviewed tool call or reports that the
//! command does not exist; there is no program for it to start. Oh My Pi's
//! special commands (`resolve`, `reject`, `propose`, `report_issue`) are left
//! out because they are not wrapped, so no tool hook sees them.
//!
//! A name the shell answers to itself is left out for the same reason, and the
//! absence from PATH cannot find it: a builtin never reaches PATH, so the
//! check passes for every one of them while the shell still runs its own.
//! Oh My Pi 19 mounts `export`, which is a POSIX special builtin, so the
//! mounted set is screened against [`shell_names::shell_name`] rather than
//! trusted as written.

use guard_contracts::{GuardExecutionEnvironmentV1, PreToolActionTypeV1, PreToolResultV1};
use serde_json::Value;
use std::path::Path;

/// Oh My Pi 19 built-in tools that load on demand (not essential and not
/// pinned top-level), so the command transport mounts them in `bash`.
pub(crate) const MOUNTED_BUILTINS: [&str; 14] = [
    "ast_edit",
    "ast_grep",
    "checkpoint",
    "debug",
    "github",
    "goal",
    "lsp",
    "memory_edit",
    "recall",
    "reflect",
    "retain",
    "rewind",
    "security_scan",
    "think",
];

pub(crate) const REASON: &str = "native_omp_tool_command";

pub(super) fn settle(
    result: &mut PreToolResultV1,
    model: Option<&crate::CanonicalCommandV1>,
    harness: &str,
    event: &str,
    payload: &Value,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) {
    if !matches!(harness, "omp" | "oh-my-pi")
        || event != "PreToolUse"
        || payload.get("tool_name").and_then(Value::as_str) != Some("bash")
        || result.minimum_action != "review"
        || result.reason_code != "native_command_review_required"
        || result.action.action_type != PreToolActionTypeV1::Command
        || result.action.sensitive_target
    {
        return;
    }
    let (Some(model), Some(environment)) = (model, execution_environment) else {
        return;
    };
    // Whatever line this pass sees must itself be plain words, not only the
    // parser's model of it.
    let raw = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str);
    if !raw.is_some_and(plain_words) {
        return;
    }
    let Some(name) = mounted_invocation(model) else {
        return;
    };
    if !absent_from_path(name, &environment.path) {
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = REASON.into();
    result.reason = format!(
        "Oh My Pi runs `{name}` as its built-in tool, which Guard reviews as a tool call; no program by that name is on PATH."
    );
}

/// The mounted built-in a whole command invokes, when it is one plain word
/// list: a single segment, no wrapper, environment prefix or PATH override,
/// and nothing the shell would expand or redirect.
fn mounted_invocation(model: &crate::CanonicalCommandV1) -> Option<&'static str> {
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return None;
    }
    let [segment] = model.segments.as_slice() else {
        return None;
    };
    if segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || !plain_words(&segment.text)
        || !plain_words(&model.normalized_text)
    {
        return None;
    }
    let executable = segment.executable.as_deref()?;
    // A shell dispatches its own builtin before it looks for a program, so
    // the tool hook never sees the call and PATH never holds the name. Only a
    // mounted tool the shell has no answer for can be read as a tool call.
    if super::shell_names::shell_name(executable) {
        return None;
    }
    MOUNTED_BUILTINS
        .iter()
        .copied()
        .find(|name| *name == executable)
}

/// Whether `text` is only words: single-quoted text is literal, and outside
/// single quotes no character the shell treats as an operator, redirect,
/// expansion, substitution, glob or escape appears. Double quotes are allowed
/// only around text that holds none of `$`, `` ` `` and `\`.
fn plain_words(text: &str) -> bool {
    let mut single = false;
    let mut double = false;
    for character in text.chars() {
        if single {
            single = character != '\'';
            continue;
        }
        match character {
            '\'' if !double => single = true,
            '"' => double = !double,
            '$' | '`' | '\\' | '\n' | '\r' => return false,
            '<' | '>' | '|' | '&' | ';' | '(' | ')' | '*' | '?' | '[' | ']' | '{' | '}' | '~'
            | '#' | '!'
                if !double =>
            {
                return false
            }
            _ => {}
        }
    }
    !single && !double
}

/// Whether no PATH entry holds anything named `name` (or, on Windows, `name`
/// with an executable extension). A relative or empty entry is searched from
/// the working directory, which the command could populate, and an entry that
/// cannot be read proves nothing, so either refuses.
fn absent_from_path(name: &str, search_path: &str) -> bool {
    let (separator, suffixes): (char, &[&str]) = if cfg!(windows) {
        (';', &["", ".exe", ".com", ".cmd", ".bat", ".ps1"])
    } else {
        (':', &[""])
    };
    if search_path.is_empty() {
        return false;
    }
    search_path.split(separator).all(|entry| {
        let directory = Path::new(entry);
        directory.is_absolute()
            && suffixes.iter().all(|suffix| {
                matches!(
                    std::fs::symlink_metadata(directory.join(format!("{name}{suffix}"))),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                )
            })
    })
}
