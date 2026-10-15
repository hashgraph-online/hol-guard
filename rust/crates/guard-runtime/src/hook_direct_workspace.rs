//! The daemon's workspace rules for a hook, repeated where the resident
//! answers it directly. Wherever the daemon would take a path this cannot
//! reproduce exactly, the hook defers.

use super::HookDirectDefer;
use serde_json::{Map, Value};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

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
    // The daemon skips a temporary root, so the next candidate decides.
    if is_temporary_root(&candidate)? {
        return Ok(None);
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

/// Symlinks followed before a resolution defers: a cycle, which Python
/// reports as `OSError`, is not told apart from a long chain here.
const MAX_SYMLINKS: usize = 256;

/// Whether the daemon skips `candidate` as a temporary directory root:
/// `trusted_temporary_root_for_path` and the realpath comparison after it.
/// The daemon's own `tempfile.gettempdir()` is not visible here, so a verdict
/// that only this process's temporary directory decides defers.
fn is_temporary_root(candidate: &str) -> Result<bool, HookDirectDefer> {
    // Python raises `ValueError` for an embedded NUL instead of skipping.
    if candidate.contains('\0') {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let candidate = Path::new(candidate);
    let fixed = fixed_temporary_roots();
    let verdict = temporary_root_verdict(candidate, &fixed)?;
    let own = std::env::temp_dir();
    let own = normpath(own.to_str().ok_or(HookDirectDefer::WorkspaceInvalid)?)?;
    let mut roots = vec![PathBuf::from(own)];
    roots.extend(fixed);
    if temporary_root_verdict(candidate, &roots)? != verdict {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    Ok(verdict)
}

/// The roots Python adds after `tempfile.gettempdir()`, in its order.
fn fixed_temporary_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
    if cfg!(target_os = "macos") {
        roots.extend([
            PathBuf::from("/private/tmp"),
            PathBuf::from("/private/var/tmp"),
        ]);
    }
    roots
}

fn temporary_root_verdict(candidate: &Path, roots: &[PathBuf]) -> Result<bool, HookDirectDefer> {
    if !lexically_temporary(candidate, roots)? {
        return Ok(false);
    }
    let Some(resolved) = python_realpath(candidate)? else {
        return Ok(false);
    };
    // The first root holding the candidate decides, as in Python.
    for root in roots {
        let Some(resolved_root) = python_realpath(root)? else {
            continue;
        };
        if resolved.starts_with(&resolved_root) {
            return Ok(resolved == resolved_root);
        }
    }
    let Some(root) = darwin_user_temporary_root(&resolved)? else {
        return Ok(false);
    };
    Ok(root == resolved && owned_by_current_user(&root))
}

/// `_is_lexically_temporary_path`. A normalized absolute path has no `..`.
fn lexically_temporary(candidate: &Path, roots: &[PathBuf]) -> Result<bool, HookDirectDefer> {
    if !candidate.is_absolute() {
        return Ok(false);
    }
    if roots
        .iter()
        .any(|root| root.is_absolute() && candidate.starts_with(root))
    {
        return Ok(true);
    }
    Ok(darwin_user_temporary_root(candidate)?.is_some())
}

/// `os.path.realpath(path, strict=True)` for an absolute path, `None` where
/// Python raises `OSError`. Links are followed by their stored text, as
/// Python does, never by the platform `realpath`, which may also fold case.
fn python_realpath(path: &Path) -> Result<Option<PathBuf>, HookDirectDefer> {
    if !path.is_absolute() {
        return Err(HookDirectDefer::WorkspaceInvalid);
    }
    let mut resolved = PathBuf::from("/");
    let mut pending = Vec::new();
    push_components(&mut pending, path);
    let mut links = 0;
    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(part);
        let Ok(metadata) = std::fs::symlink_metadata(&next) else {
            return Ok(None);
        };
        if !metadata.file_type().is_symlink() {
            resolved = next;
            continue;
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(HookDirectDefer::WorkspaceInvalid);
        }
        let Ok(target) = std::fs::read_link(next) else {
            return Ok(None);
        };
        if target.is_absolute() {
            resolved = PathBuf::from("/");
        }
        push_components(&mut pending, &target);
    }
    Ok(Some(resolved))
}

/// Queues the components of `path` so that the first one pops first.
fn push_components(pending: &mut Vec<OsString>, path: &Path) {
    let parts: Vec<OsString> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    pending.extend(parts.into_iter().rev());
}

/// `_darwin_user_temporary_root`: `/var/folders/<xx>/<id>/T`, with or
/// without `/private`, when that root is a directory.
#[cfg(target_os = "macos")]
fn darwin_user_temporary_root(path: &Path) -> Result<Option<PathBuf>, HookDirectDefer> {
    let parts: Vec<&std::ffi::OsStr> = path.components().map(|part| part.as_os_str()).collect();
    for prefix in [
        &["/", "var", "folders"][..],
        &["/", "private", "var", "folders"][..],
    ] {
        let length = prefix.len();
        if parts.len() < length + 3
            || !parts
                .iter()
                .zip(prefix)
                .all(|(part, expected)| *part == *expected)
        {
            continue;
        }
        // Python counts code points; other bytes defer.
        let bucket = parts[length]
            .to_str()
            .ok_or(HookDirectDefer::WorkspaceInvalid)?;
        if bucket.chars().count() != 2 || parts[length + 2] != "T" {
            continue;
        }
        let root: PathBuf = parts[..length + 3].iter().collect();
        return Ok(root.is_dir().then_some(root));
    }
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_temporary_root(_path: &Path) -> Result<Option<PathBuf>, HookDirectDefer> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn owned_by_current_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.uid() == nix::unistd::getuid().as_raw())
}

#[cfg(not(target_os = "macos"))]
fn owned_by_current_user(_path: &Path) -> bool {
    false
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
