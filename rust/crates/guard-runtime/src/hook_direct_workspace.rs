//! The daemon's workspace rules for a hook, repeated where the resident
//! answers it directly. Wherever the daemon would take a path this cannot
//! reproduce exactly, the hook defers.

use super::HookDirectDefer;
use crate::guard_paths::{self, PathError};
use serde_json::{Map, Value};
use std::path::Path;

/// The daemon's workspace choice: an `exec_command` workdir, then the payload
/// `cwd`, then the `workspace` query parameter. A `cwd` or query naming a
/// temporary root is skipped and the next one decides, as in the daemon. A
/// present workdir the daemon cannot use rejects its workspace instead, which
/// leaves the daemon without one, so that defers.
pub(super) fn workspace_candidate(
    payload: &Map<String, Value>,
    workspace_query: Option<&str>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    if let Some(workdir) = exec_command_workdir(payload, home_dir)? {
        return Ok(Some(workdir));
    }
    if let Some(cwd) = normalized_workspace(payload.get("cwd").and_then(Value::as_str), home_dir)? {
        return Ok(Some(cwd));
    }
    normalized_workspace(workspace_query, home_dir)
}

fn exec_command_workdir(
    payload: &Map<String, Value>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !python_strip(tool_name)?.is_some_and(|name| name.eq_ignore_ascii_case("exec_command")) {
        return Ok(None);
    }
    let Some(workdir) = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|tool_input| tool_input.get("workdir"))
    else {
        return Ok(None);
    };
    // A workdir that is present but unusable rejects the daemon's workspace.
    let workdir = workdir.as_str().ok_or(HookDirectDefer::WorkspaceInvalid)?;
    let stripped = python_strip(workdir)?.ok_or(HookDirectDefer::WorkspaceInvalid)?;
    if is_null_sentinel(stripped) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let candidate = normpath(&expanduser(stripped, home_dir)?)?;
    if is_temporary_root(&candidate)? {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(Some(candidate))
}

pub(super) fn normalized_workspace(
    value: Option<&str>,
    home_dir: &str,
) -> Result<Option<String>, HookDirectDefer> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(stripped) = python_strip(value)? else {
        return Ok(None);
    };
    if is_null_sentinel(stripped) {
        return Ok(None);
    }
    let mut candidate = expanduser(stripped, home_dir)?;
    // Callers still send `<dir>/None` as the "no workspace" sentinel. This is
    // `os.path.dirname`, which keeps a head made only of separators. It splits
    // on a backslash as well where `ntpath` does, so a Windows caller sending
    // `C:\proj\None` drops the same component the daemon drops.
    if candidate == "None" {
        return Ok(None);
    }
    if let Some(head) = candidate
        .strip_suffix("None")
        .filter(|head| head.ends_with(guard_paths::is_separator))
    {
        let trimmed = head.trim_end_matches(guard_paths::is_separator);
        candidate = if trimmed.is_empty() { head } else { trimmed }.to_owned();
    }
    let candidate = normpath(&candidate)?;
    // The daemon skips a temporary root, so the next candidate decides.
    if is_temporary_root(&candidate)? {
        return Ok(None);
    }
    Ok(Some(candidate))
}

fn is_null_sentinel(value: &str) -> bool {
    value.eq_ignore_ascii_case("none") || value.eq_ignore_ascii_case("null")
}

/// The shared path helpers, reported as a hook that defers rather than a
/// path the caller can retry.
fn deferred(_error: PathError) -> HookDirectDefer {
    HookDirectDefer::WorkspaceInvalid
}

pub(super) fn python_strip(value: &str) -> Result<Option<&str>, HookDirectDefer> {
    guard_paths::python_strip(value).map_err(deferred)
}

pub(super) fn expanduser(value: &str, home_dir: &str) -> Result<String, HookDirectDefer> {
    guard_paths::expanduser(value, home_dir).map_err(deferred)
}

pub(super) fn normpath(value: &str) -> Result<String, HookDirectDefer> {
    guard_paths::normpath(value).map_err(deferred)
}

fn is_temporary_root(candidate: &str) -> Result<bool, HookDirectDefer> {
    guard_paths::is_temporary_root(candidate).map_err(deferred)
}

/// The realpath the daemon validates, which is what the publisher settled.
pub(super) fn settled_directory(candidate: &str) -> Result<String, HookDirectDefer> {
    let resolved = std::fs::canonicalize(Path::new(candidate))
        .map_err(|_| HookDirectDefer::WorkspaceInvalid)?;
    if !resolved.is_dir() {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| HookDirectDefer::WorkspaceInvalid)
}

#[cfg(all(test, unix))]
#[path = "hook_direct_workspace_tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "hook_direct_workspace_windows_tests.rs"]
mod windows_tests;
