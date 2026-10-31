//! Receipts for chains that run part of the command outside the sandbox.
//!
//! The command crate splits two shapes around a step Guard runs directly: the
//! Git steps that follow contained checks, and a `git worktree add` whose
//! checkout the checks then run in. The sink runs the first itself: the
//! checks contained, then the Git steps on the host once the resident proves
//! them again. The second runs the add on the host first (`worktree`).

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
/// Reason codes that say the runtime never reached a decision, rather than
/// deciding against the steps.
const AUTHORITY_UNAVAILABLE: [&str; 4] = [
    "native_hook_render_unavailable",
    "native_hook_worker_exception",
    "native_hook_worker_unavailable",
    "native_pre_tool_unavailable",
];
const SETTLE_ATTEMPTS: usize = 3;
const SETTLE_PAUSE: Duration = Duration::from_millis(750);
/// An ask that took longer than this already waited out the resident's
/// readiness window; asking again would only delay the same answer.
const SETTLE_RETRY_WITHIN: Duration = Duration::from_secs(5);
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

/// Whether a receipt's `reason` names a `git worktree add` chain.
pub(super) fn host_split(reason: Option<&Value>) -> bool {
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
    let answer = settled(|| authority.authorize(&asked), std::thread::sleep);
    if !answer.as_ref().is_some_and(proven) {
        return Err(Failure::invalid(STEPS_UNPROVEN));
    }
    run_on_host(suffix, "The Git steps", workspace, &[], signals)
}

/// Whether the resident's answer lets a command run as it stands.
pub(super) fn proven(response: &Map<String, Value>) -> bool {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    text("decision") == Some("allow")
        && text("policy_action") == Some("allow")
        && response.get("observe_mode") != Some(&Value::Bool(true))
}

/// Run `script` on the host from `workspace`, with a search path that
/// leaves out `workspace` and every `excluded` directory: either could hold
/// a `git` or `gh` the contained work or a new checkout planted. `label`
/// names the step when it fails.
pub(super) fn run_on_host(
    script: &str,
    label: &str,
    workspace: &Path,
    excluded: &[&Path],
    signals: &process::Signals,
) -> Outcome<i32> {
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    let mut roots = vec![workspace];
    roots.extend_from_slice(excluded);
    run_host(
        script,
        label,
        &GIT_LOCATION,
        &outside_search_path(&search_path, &roots),
        workspace,
        signals,
        RUN_TIMEOUT_SECONDS,
    )
}

/// The resident's answer from `authorize`, asked again while it cannot
/// answer. The checks already ran, so a resident that is restarting for a
/// moment would otherwise cancel the steps they were run for. A decision is
/// deterministic and arrives on the first ask; only a missing answer is
/// asked again, and only while asking stays quick.
pub(super) fn settled(
    mut authorize: impl FnMut() -> Option<Map<String, Value>>,
    pause: impl Fn(Duration),
) -> Option<Map<String, Value>> {
    let mut started = Instant::now();
    let mut response = authorize();
    for _ in 1..SETTLE_ATTEMPTS {
        let unavailable = response.as_ref().is_none_or(|response| {
            response
                .get("reason_code")
                .and_then(Value::as_str)
                .is_some_and(|code| AUTHORITY_UNAVAILABLE.contains(&code))
        });
        if !unavailable || started.elapsed() > SETTLE_RETRY_WITHIN {
            break;
        }
        pause(SETTLE_PAUSE);
        started = Instant::now();
        response = authorize();
    }
    response
}

/// Run `script` with `/bin/sh` on the host, in `cwd`, in its own session:
/// without the `removed` variables, with `search_path` as `PATH`, and with
/// the sink's own output. Its exit code.
fn run_host(
    script: &str,
    label: &str,
    removed: &[&str],
    search_path: &OsStr,
    cwd: &Path,
    signals: &process::Signals,
    timeout_seconds: u64,
) -> Outcome<i32> {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let launcher = std::env::current_exe().map_err(|error| host_not_started(label, &error))?;
    let mut command = Command::new(launcher);
    command.args([LAUNCH_COMMAND, process::HOST_STEP]);
    run_launched(
        command,
        script,
        label,
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
    label: &str,
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
        .map_err(|error| host_not_started(label, &error))?;
    if timed_out {
        return Err(Failure::with_exit(
            "pytest_restricted_timeout",
            format!("{label} exceeded the {timeout_seconds}-second execution deadline."),
            124,
        ));
    }
    Ok(status.map_or(1, process::exit_code))
}

fn host_not_started(label: &str, error: &std::io::Error) -> Failure {
    Failure::new(
        SANDBOX_UNAVAILABLE,
        format!("{label} could not start: {error}"),
    )
}

/// `search_path` without relative entries or entries inside any of `roots`:
/// the checks could plant a `git` or `gh` in either, and a host step would
/// run it unsandboxed.
fn outside_search_path(search_path: &OsStr, roots: &[&Path]) -> OsString {
    let roots: Vec<PathBuf> = roots.iter().map(|root| resolved(root)).collect();
    let kept: Vec<PathBuf> = std::env::split_paths(search_path)
        .filter(|entry| {
            let entry_root = resolved(entry);
            entry.is_absolute() && !roots.iter().any(|root| entry_root.starts_with(root))
        })
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
