//! The daemon's workspace rules for a hook, repeated where the resident
//! answers it directly. Wherever the daemon would take a path this cannot
//! reproduce exactly, the hook defers.

use super::HookDirectDefer;
use serde_json::{Map, Value};
use std::path::Path;

/// The daemon's workspace choice: an `exec_command` workdir, then the payload
/// `cwd`, then the `workspace` query parameter. Where the daemon would skip a
/// temporary root and fall through, this defers instead.
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
    if is_temporary_root(&candidate) {
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
    // `os.path.dirname`, which keeps a head made only of slashes.
    if candidate == "None" {
        return Ok(None);
    }
    if let Some(head) = candidate
        .strip_suffix("None")
        .filter(|head| head.ends_with('/'))
    {
        let trimmed = head.trim_end_matches('/');
        candidate = if trimmed.is_empty() { head } else { trimmed }.to_owned();
    }
    let candidate = normpath(&candidate)?;
    if is_temporary_root(&candidate) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(Some(candidate))
}

/// Python's `str.strip()`, or a defer for the separators it strips and Rust
/// does not. `None` when nothing is left.
pub(super) fn python_strip(value: &str) -> Result<Option<&str>, HookDirectDefer> {
    if value
        .chars()
        .any(|character| ('\u{1c}'..='\u{1f}').contains(&character))
    {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let stripped = value.trim();
    Ok((!stripped.is_empty()).then_some(stripped))
}

fn is_null_sentinel(value: &str) -> bool {
    value.eq_ignore_ascii_case("none") || value.eq_ignore_ascii_case("null")
}

/// `os.path.expanduser` for the daemon's own home; another user's home defers.
pub(super) fn expanduser(value: &str, home_dir: &str) -> Result<String, HookDirectDefer> {
    if value == "~" {
        return Ok(home_dir.to_owned());
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(format!("{}/{rest}", home_dir.trim_end_matches('/')));
    }
    if value.starts_with('~') {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(value.to_owned())
}

/// Lexical `os.path.normpath` for absolute POSIX paths. Relative paths and the
/// implementation-defined `//` prefix defer.
pub(super) fn normpath(value: &str) -> Result<String, HookDirectDefer> {
    if !value.starts_with('/') || (value.starts_with("//") && !value.starts_with("///")) {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// Whether `candidate` resolves to a temporary directory root the daemon
/// refuses as a workspace. This covers at least the daemon's roots.
fn is_temporary_root(candidate: &str) -> bool {
    let Ok(resolved) = std::fs::canonicalize(candidate) else {
        return false;
    };
    let mut roots = vec![std::env::temp_dir()];
    roots.extend(
        ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"]
            .iter()
            .map(std::path::PathBuf::from),
    );
    if roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| root == resolved)
    {
        return true;
    }
    // The per-user Darwin root, `/private/var/folders/<xx>/<id>/T`.
    let components: Vec<_> = resolved.components().collect();
    components.len() == 7
        && resolved.starts_with("/private/var/folders")
        && resolved.file_name().is_some_and(|name| name == "T")
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
