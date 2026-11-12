//! A Codex turn that already runs inside Codex's own sandbox.
//!
//! Codex's `workspace-write` and `read-only` sandboxes run each shell call
//! under a macOS Seatbelt profile. Guard's contained sink cannot start in
//! there: the profile refuses its connection to the resident socket, and
//! macOS refuses to apply a second Seatbelt profile inside the first. The
//! rewrite would fail every time, so a call in a turn whose sandbox
//! confines it at least as tightly as the profile Guard requires runs in
//! Codex's sandbox instead: a read-only turn for any profile, a
//! workspace-write turn with no extra writable roots that also keeps `/tmp`
//! and `$TMPDIR` read-only for the workspace profile, and never with
//! network. Codex lets a workspace-write call write both temporary
//! directories unless its config excludes them; Guard's workspace profile
//! does not.
//!
//! A project's own pytest is the one read-only profile a workspace-write
//! turn also runs, temporary directories shared or not. Codex's default
//! sandbox lets the agent write the workspace and both temporary
//! directories with any shell command, so a test run that can write the
//! same places reaches nothing the turn could not already reach, while the
//! sandbox still keeps it off the network and out of the home directory and
//! the folders beside the workspace. Every other read-only profile keeps
//! Guard's answer in a workspace-write turn.
//!
//! The turn's sandbox is not proof that this one call runs in it: Codex
//! starts a call outside it when the user approves an escalation, when an
//! exec-policy rule trusts the command, or when it retries a call without
//! the sandbox, and the hook sees none of that. A call that asks for an
//! escalation keeps Guard's own answer. Any other call is rewritten to
//! start with `codex-sandbox-check`, which asks the kernel about the
//! process the shell actually runs in, and the shell runs the original
//! command only when the check passes. The check asks about a fixed set of
//! directories, not every path below them, so a writable root the user
//! adds deeper inside one of them is caught only by the turn's recorded
//! `writable_roots`.
//!
//! The hook payload does not say which sandbox the turn uses, so the turn's
//! `turn_context` record is read from the session transcript Codex names
//! in `transcript_path`, matched by `turn_id`. Codex keeps that file under
//! its own home, which its sandbox does not let the agent write.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::{first, resolved_workspace, routed_response, shell_join, text, Contained};
use crate::codex_sandbox_check::{
    CHECK_COMMAND, PYTEST_PROFILE, REFUSED, SHARED_TMP_CHECK, WORKSPACE_PROFILE,
};
use crate::pyjson::{PyVal, SurrogateMapped};

const REASON: &str = "native_contained_by_codex_sandbox";
/// How much of the transcript's end is read for the turn's context. Codex
/// writes `turn_context` at the start of each turn, so a turn longer than
/// this is treated as unknown and keeps Guard's own answer.
const TAIL_BYTES: u64 = 8 * 1024 * 1024;

/// The sandbox a Codex turn runs its shell calls in.
#[derive(Debug, PartialEq)]
pub(super) enum Turn {
    /// No sandbox, or none Guard can confirm.
    Unknown,
    /// Codex's read-only sandbox, with no network.
    ReadOnly,
    /// Codex's workspace-write sandbox with no extra writable roots, the
    /// shared temporary directories excluded, and no network.
    WorkspaceWrite,
    /// Codex's default workspace-write sandbox: no extra writable roots and
    /// no network, but `/tmp` and `$TMPDIR` writable.
    SharedTmp,
    /// A Codex sandbox that is wider than the workspace: it reaches the
    /// network or writes outside the workspace, `/tmp` and `$TMPDIR`
    /// included.
    Wider,
}

impl Turn {
    /// The profile `codex-sandbox-check` must confirm before a call that
    /// Guard requires to run under `profile` runs in this sandbox, or `None`
    /// when this sandbox does not hold that profile.
    pub(super) fn check_profile<'a>(&self, profile: Option<&'a str>) -> Option<&'a str> {
        match (self, profile?) {
            (Self::ReadOnly, profile) => Some(profile),
            (Self::WorkspaceWrite, WORKSPACE_PROFILE | PYTEST_PROFILE) => Some(WORKSPACE_PROFILE),
            (Self::SharedTmp, PYTEST_PROFILE) => Some(SHARED_TMP_CHECK),
            _ => None,
        }
    }
}

/// The sandbox of the turn this hook call belongs to. Only macOS is known
/// to refuse a nested sandbox; elsewhere Guard's rewrite stands.
pub(super) fn launching_turn(payload: &PyVal) -> Turn {
    if !cfg!(target_os = "macos") {
        return Turn::Unknown;
    }
    turn(payload)
}

/// The sandbox the payload's transcript records for its turn.
pub(super) fn turn(payload: &PyVal) -> Turn {
    let (Some(transcript), Some(turn_id)) = (
        text(payload, "transcript_path"),
        text(payload, "turn_id").filter(|turn_id| !turn_id.is_empty()),
    ) else {
        return Turn::Unknown;
    };
    if escalated(payload) {
        return Turn::Unknown;
    }
    let Some(tail) = transcript_tail(Path::new(transcript)) else {
        return Turn::Unknown;
    };
    tail.lines()
        .rev()
        .filter(|line| line.contains("turn_context") && line.contains(turn_id))
        .find_map(|line| turn_policy(line, turn_id))
        .unwrap_or(Turn::Unknown)
}

/// A call that asks Codex to run it outside the sandbox. It keeps Guard's
/// own answer, whatever the check would say: the check only asks about the
/// directories it names, so an escalation that widens writes elsewhere
/// would not show in its answer.
fn escalated(payload: &PyVal) -> bool {
    let Some(input) = first(payload, &["tool_input", "toolInput"]) else {
        return false;
    };
    let permissions = text(input, "sandbox_permissions");
    permissions.is_some_and(|value| value != "use_default")
        || input.get("with_escalated_permissions") == Some(&PyVal::Bool(true))
}

/// The last `TAIL_BYTES` of a regular, non-symlinked transcript file,
/// starting at a whole line.
fn transcript_tail(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let start = metadata.len().saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    if start > 0 {
        let newline = bytes.iter().position(|byte| *byte == b'\n')?;
        bytes.drain(..=newline);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The sandbox of one transcript line, when it is the `turn_context` of
/// `turn_id`.
fn turn_policy(line: &str, turn_id: &str) -> Option<Turn> {
    let record: serde_json::Value = serde_json::from_str(line).ok()?;
    if record.get("type")?.as_str()? != "turn_context" {
        return None;
    }
    let context = record.get("payload")?;
    if context.get("turn_id")?.as_str()? != turn_id {
        return None;
    }
    let Some(policy) = context.get("sandbox_policy") else {
        return Some(Turn::Unknown);
    };
    let network = policy.get("network_access");
    let networked = network.is_some_and(|value| value != &serde_json::Value::Bool(false));
    let roots = policy.get("writable_roots");
    let extra_roots =
        roots.is_some_and(|roots| roots.as_array().is_none_or(|roots| !roots.is_empty()));
    let excluded = |key: &str| policy.get(key) == Some(&serde_json::Value::Bool(true));
    let shared_tmp = !(excluded("exclude_slash_tmp") && excluded("exclude_tmpdir_env_var"));
    match policy.get("type").and_then(serde_json::Value::as_str) {
        Some("read-only" | "workspace-write") if networked || extra_roots => Some(Turn::Wider),
        Some("read-only") => Some(Turn::ReadOnly),
        Some("workspace-write") if shared_tmp => Some(Turn::SharedTmp),
        Some("workspace-write") => Some(Turn::WorkspaceWrite),
        _ => Some(Turn::Unknown),
    }
}

/// The allow that runs the `original` call in Codex's sandbox behind
/// `codex-sandbox-check`, or the denial when the check cannot be named.
pub(super) fn checked(
    original: &PyVal,
    payload: &SurrogateMapped,
    profile: Option<&str>,
) -> Contained {
    let check = check_line(original, &payload.value, profile);
    match check {
        Some((check, command)) => {
            let command = format!("{check} || exit {REFUSED}\n{command}");
            Contained::Routed(routed_response(original, &command, REASON), payload.mapped)
        }
        None => Contained::Unchanged,
    }
}

/// The check's command line, and the original command it guards.
fn check_line<'a>(
    original: &'a PyVal,
    payload: &PyVal,
    profile: Option<&str>,
) -> Option<(String, &'a str)> {
    let command = original.get("command")?.as_str()?;
    let workspace = resolved_workspace(first(payload, &["cwd", "workspace"])?.as_str()?)?;
    let executable = std::env::current_exe().ok()?;
    executable.is_file().then_some(())?;
    let check = [
        executable.to_str()?,
        CHECK_COMMAND,
        "--profile",
        profile?,
        "--workspace",
        workspace.as_str(),
    ];
    let check = shell_join(&check.map(str::to_owned))?;
    Some((check, command))
}

#[cfg(test)]
#[path = "codex_hook_bridge_contain_sandbox_tests.rs"]
mod tests;
