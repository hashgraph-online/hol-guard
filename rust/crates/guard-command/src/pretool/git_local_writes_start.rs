//! A new branch at a named start point.
//!
//! `git checkout -b NAME START` and `git switch -c NAME START` carry local
//! changes over or refuse, and the branch they leave keeps both histories
//! reachable. What they can lose is an ignored file: Git overwrites one
//! without asking when the start point tracks a file at the same path. The
//! proof lists the paths the start point adds over `HEAD` and requires that
//! none of them, nor any directory above them, exists in the working tree as
//! anything Git could replace.

use super::super::git_session_probe::Probe;
use std::fs;
use std::path::Path;

/// Paths the proof checks before it gives up and keeps the review.
const MAX_ADDED_PATHS: usize = 20_000;

/// The start point of `checkout -b NAME START` or `switch -c NAME START`.
pub(super) fn start_point(arguments: &[String]) -> Option<&str> {
    let [command, flag, name, start] = arguments else {
        return None;
    };
    let branch = [command.clone(), flag.clone(), name.clone()];
    (matches!(command.as_str(), "checkout" | "switch")
        && super::super::workspace_contained::keeping_arguments(&branch)
        && reference(start))
    .then_some(start.as_str())
}

/// A ref name or remote-tracking ref, never an option or a revision
/// expression.
pub(super) fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.starts_with(['-', '/', '.'])
        && !value.ends_with(['/', '.'])
        && !value.ends_with(".lock")
        && !value.contains("..")
        && !value.contains("/.")
        && !value.contains("//")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

/// Whether moving the working tree from `HEAD` to `start` replaces nothing
/// Git does not track.
pub(super) fn replaces_nothing(probe: &Probe, start: &str) -> bool {
    let commit = format!("{start}^{{commit}}");
    if probe
        .text(&[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &commit,
        ])
        .is_none()
    {
        return false;
    }
    let Some(top) = probe.text(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Ok(top) = fs::canonicalize(top) else {
        return false;
    };
    let Some(added) = probe.output(&[
        "--no-pager",
        "diff",
        "--no-relative",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "-z",
        "--diff-filter=A",
        "HEAD",
        &commit,
        "--",
    ]) else {
        return false;
    };
    let paths: Vec<&[u8]> = added
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    paths.len() <= MAX_ADDED_PATHS
        && paths.iter().all(|path| {
            std::str::from_utf8(path).is_ok_and(|path| absent_below(&top, Path::new(path)))
        })
}

/// `path` does not exist below `top`, and each directory above it that does
/// exist is a real directory.
fn absent_below(top: &Path, path: &Path) -> bool {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return false;
    }
    let mut current = top.to_path_buf();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
            Ok(metadata) if components.peek().is_some() && metadata.is_dir() => {}
            Ok(_) => return false,
        }
    }
    false
}
