//! Receipts for chains that run part of the command outside the sandbox.
//!
//! The command crate splits two shapes around a step Guard runs directly: the
//! Git steps that follow contained checks, and a `git worktree add` whose
//! checkout the checks then run in. The sink runs the first itself: the
//! checks contained, then the Git steps on the host once the resident proves
//! them again. The second stays with `guard execute-contained-test`, which
//! re-proves the checkout; the native sink must never take it.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use super::*;

/// The reason a chain carries whose trailing Git steps run after the
/// contained checks. It must match the command crate's text exactly.
pub(crate) const PUBLISH_REASON: &str = concat!(
    "HOL Guard runs the checks in this command in a protected workspace sandbox ",
    "(no network, no home access, no PTY or Docker socket), then runs the Git ",
    "steps that follow directly, outside the sandbox, once it proves them again. ",
    "Every program the checks start, including children of an interpreter, runs ",
    "contained and can write only the workspace, $TMPDIR and a private ",
    "scratch $HOME.",
);
const STEPS_UNPROVEN: &str =
    "Guard could not prove the Git steps again after the checks ran; they did not run.";
/// The variables that would point a host Git at another repository than the
/// one its directory holds.
const GIT_LOCATION: [&str; 7] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
];

/// Whether a receipt's `reason` names a chain whose host step this sink
/// cannot run.
pub(crate) fn host_split(reason: Option<&Value>) -> bool {
    reason.and_then(Value::as_str) == Some(guard_command::pretool::CONTAINED_WORKTREE_ADD_REASON)
}

/// Whether a receipt's `reason` names a chain whose Git steps follow the
/// contained checks.
pub(super) fn publishes(reason: Option<&Value>) -> bool {
    reason.and_then(Value::as_str) == Some(PUBLISH_REASON)
}

/// The checks `command` runs before `&& suffix`, as the command crate split
/// it.
pub(super) fn checks<'a>(command: &'a str, suffix: &str) -> Option<&'a str> {
    if suffix.is_empty() {
        return None;
    }
    let head = command.trim().strip_suffix(suffix)?.trim_end();
    let checks = head.strip_suffix("&&")?.trim_end();
    (!checks.is_empty()).then_some(checks)
}

/// Run the Git steps after the contained checks, once the resident proves
/// them again on their own: the checks may have changed the repository, so
/// the verdict taken before they ran is not trusted for the steps. They run
/// outside the sandbox because a push needs the network and the user's own
/// credentials.
pub(super) fn run_publish_steps(
    payload: &Map<String, Value>,
    suffix: &str,
    workspace: &Path,
    authority: &Authority<'_>,
    signals: &process::Signals,
) -> Outcome<i32> {
    let mut tool_input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| Failure::invalid("Invalid workspace sandbox request."))?;
    tool_input.insert("command".to_owned(), Value::String(suffix.to_owned()));
    let mut asked = payload.clone();
    asked.insert("tool_input".to_owned(), Value::Object(tool_input));
    let proven = authority.authorize(&asked).is_some_and(|response| {
        let text = |name: &str| response.get(name).and_then(Value::as_str);
        text("decision") == Some("allow")
            && text("policy_action") == Some("allow")
            && response.get("observe_mode") != Some(&Value::Bool(true))
    });
    if !proven {
        return Err(Failure::invalid(STEPS_UNPROVEN));
    }
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    run_host(
        suffix,
        &GIT_LOCATION,
        &outside_search_path(&search_path, workspace),
        workspace,
        signals,
        RUN_TIMEOUT_SECONDS,
    )
}

/// Run `script` with `/bin/sh` on the host, in `cwd`, in its own session:
/// without the `removed` variables, with `search_path` as `PATH`, and with
/// the sink's own output. Its exit code.
fn run_host(
    script: &str,
    removed: &[&str],
    search_path: &OsStr,
    cwd: &Path,
    signals: &process::Signals,
    timeout_seconds: u64,
) -> Outcome<i32> {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let launcher = std::env::current_exe().map_err(|error| host_not_started(&error))?;
    let mut command = Command::new(launcher);
    command.args([LAUNCH_COMMAND, process::HOST_STEP]);
    run_launched(
        command,
        script,
        removed,
        search_path,
        cwd,
        signals,
        timeout_seconds,
    )
}

/// `run_host` through `launcher`, which runs the arguments it is given.
fn run_launched(
    mut launcher: Command,
    script: &str,
    removed: &[&str],
    search_path: &OsStr,
    cwd: &Path,
    signals: &process::Signals,
    timeout_seconds: u64,
) -> Outcome<i32> {
    launcher
        .args(["/bin/sh", "-c", script])
        .env("PATH", search_path)
        .current_dir(cwd)
        .stdin(Stdio::null());
    for name in removed {
        launcher.env_remove(name);
    }
    let (status, timed_out) = process::run_tracked(&mut launcher, signals, timeout_seconds, false)
        .map_err(|error| host_not_started(&error))?;
    if timed_out {
        return Err(Failure::with_exit(
            "pytest_restricted_timeout",
            format!("The Git steps exceeded the {timeout_seconds}-second execution deadline."),
            124,
        ));
    }
    Ok(status.map_or(1, process::exit_code))
}

fn host_not_started(error: &std::io::Error) -> Failure {
    Failure::new(
        SANDBOX_UNAVAILABLE,
        format!("The Git steps could not start; they did not run: {error}"),
    )
}

/// `search_path` without relative entries or entries inside `workspace`:
/// the checks could plant a `git` or `gh` in either, and a host step would
/// run it unsandboxed.
fn outside_search_path(search_path: &OsStr, workspace: &Path) -> OsString {
    let root = resolved(workspace);
    let kept: Vec<PathBuf> = std::env::split_paths(search_path)
        .filter(|entry| entry.is_absolute() && !resolved(entry).starts_with(&root))
        .collect();
    std::env::join_paths(kept).unwrap_or_default()
}

/// An absolute path with its links followed as far as it exists and the
/// rest joined as written, as `Path.resolve()` answers.
fn resolved(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if let Ok(real) = resolved.canonicalize() {
                    resolved = real;
                }
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    resolved
}

#[cfg(test)]
#[path = "contained_workspace_sink_split_tests.rs"]
mod tests;
