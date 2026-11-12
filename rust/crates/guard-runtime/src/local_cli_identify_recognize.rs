//! `local_cli_recognize` — the one CLI a pasted command or tool path names.
//!
//! The operator pastes a command, or a path to a script or binary. Each
//! candidate spelling (the paste itself, then the resolved file launched the
//! way its suffix implies) either names an unlisted CLI or says why it cannot
//! be one: a common shell tool, Guard itself, a built-in extension, or a
//! compound command.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use guard_command::command_model::parse_shell_command;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    executable_name, identify, is_interpreter_name, is_reserved_tool_name, owned_executables,
    python_suffix, shlex_quote, Outcome, Request, DEADLINE_EXCEEDED, MAX_BUDGET_MS,
};
use crate::context_digest_local_cli::python_whitespace;
use crate::custom_extension_suggestion::common_tool_reject_message;
use crate::grok_executable_paths::strip_verbatim;

const ERR_INVALID: &str = "native_runner_authority_invalid";
const SCRIPT_LAUNCHERS: [(&str, &str); 6] = [
    (".py", "python3"),
    (".js", "node"),
    (".mjs", "node"),
    (".cjs", "node"),
    (".ts", "tsx"),
    (".rb", "ruby"),
];
const MISSING_MESSAGE: &str = "Paste a command or a path to the tool.";
const UNRECOGNIZED_MESSAGE: &str = "Guard could not turn that into one tool. Paste a single \
                                    command, not a pipeline, and include the script or binary path.";
const COMPOUND_MESSAGE: &str =
    "Paste only the tool itself. Wrappers, pipes, and chained commands are not covered.";
const RESERVED_MESSAGE: &str = "Guard itself is not added as a custom extension.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    command_text: String,
    cwd: String,
    home_dir: String,
    user_home: String,
    env: BTreeMap<String, String>,
    budget_ms: u64,
    #[serde(default)]
    answer: Answer,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum Answer {
    #[default]
    Recognition,
    Candidates,
}

pub(crate) fn dispatch(args: &Value) -> Result<Value, &'static str> {
    if !args.is_object() {
        return Err(ERR_INVALID);
    }
    let args = Args::deserialize(args).map_err(|_| ERR_INVALID)?;
    match args.answer {
        Answer::Candidates => Ok(json!({
            "candidates": candidates(&args.command_text, &args.cwd, &args.home_dir),
        })),
        Answer::Recognition => recognize(&args),
    }
}

fn refusal(code: &str, message: &str) -> Value {
    json!({ "identity": null, "error_code": code, "message": message })
}

/// `recognize_operator_cli`: the identity, or the reason there is none.
fn recognize(args: &Args) -> Outcome<Value> {
    let stripped = args.command_text.trim_matches(python_whitespace);
    if stripped.is_empty() {
        return Ok(refusal("missing_command", MISSING_MESSAGE));
    }
    let deadline = Instant::now() + Duration::from_millis(args.budget_ms.min(MAX_BUDGET_MS));
    let owned = owned_executables()?;
    let mut last = ("unrecognized_command", UNRECOGNIZED_MESSAGE);
    for candidate in candidates(stripped, &args.cwd, &args.home_dir) {
        let found = identify(&Request {
            command_text: &candidate,
            cwd: &args.cwd,
            home_dir: Some(&args.home_dir),
            user_home: &args.user_home,
            compound: false,
            env: &args.env,
            budget_ms: remaining_ms(deadline)?,
        })?;
        if let Some(identity) = found.into_iter().next() {
            let identity = serde_json::to_value(identity).map_err(|_| ERR_INVALID)?;
            return Ok(json!({ "identity": identity, "error_code": "", "message": "" }));
        }
        if let Some(exe) = first_executable_name(&candidate, &args.cwd, &args.home_dir) {
            if let Some(message) = common_tool_reject_message(&exe) {
                return Ok(refusal("common_shell_utility", &message));
            }
            if is_reserved_tool_name(&exe) {
                return Ok(refusal("reserved_tool", RESERVED_MESSAGE));
            }
            if owned.contains(&exe) && !is_interpreter_name(&exe) {
                let message = format!("{exe} is already a built-in Guard extension.");
                return Ok(refusal("already_built_in", &message));
            }
        }
        if candidate.contains("&&") || candidate.contains('|') {
            last = ("compound_command", COMPOUND_MESSAGE);
        }
    }
    Ok(refusal(last.0, last.1))
}

/// The paste with `~/` expanded, then the file it names launched the way its
/// suffix implies. `~user` spellings are left as typed.
fn candidates(command_text: &str, cwd: &str, home_dir: &str) -> Vec<String> {
    let expanded = command_text.replace("~/", &format!("{home_dir}/"));
    let mut found = vec![expanded.clone()];
    if let Some(file) = resolved_file(&expanded, cwd) {
        let quoted = shlex_quote(&file);
        let suffix = python_suffix(&file).to_lowercase();
        let candidate = match SCRIPT_LAUNCHERS.iter().find(|(known, _)| *known == suffix) {
            Some((_, launcher)) => format!("{launcher} {quoted}"),
            None => quoted,
        };
        if candidate != expanded {
            found.push(candidate);
        }
    }
    found
}

fn resolved_file(expanded: &str, cwd: &str) -> Option<String> {
    let path = PathBuf::from(expanded);
    let path = if path.is_absolute() {
        path
    } else {
        Path::new(cwd).join(path)
    };
    let resolved = strip_verbatim(std::fs::canonicalize(path).ok()?);
    resolved
        .is_file()
        .then(|| resolved.to_string_lossy().into_owned())
}

fn first_executable_name(candidate: &str, cwd: &str, home_dir: &str) -> Option<String> {
    let model = parse_shell_command(
        candidate,
        Some(Path::new(cwd)),
        Some(Path::new(home_dir)),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    executable_name(model.segments.first()?.executable.as_deref())
}

fn remaining_ms(deadline: Instant) -> Outcome<u64> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .map_or(0, |left| {
            u64::try_from(left.as_millis()).unwrap_or(u64::MAX)
        });
    if left == 0 {
        return Err(DEADLINE_EXCEEDED);
    }
    Ok(left)
}

#[cfg(test)]
#[path = "local_cli_identify_recognize_tests.rs"]
mod tests;
