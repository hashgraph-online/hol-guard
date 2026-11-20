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

/// The commit a checkout moves the working tree to: the start point of
/// `checkout -b NAME START` or `switch -c NAME START`, or the branch or commit
/// a plain `checkout`/`switch` moves to. The proof below is the same either
/// way, because Git refuses rather than overwrite a tracked or untracked file
/// and replaces only an ignored one silently.
pub(super) fn start_point(arguments: &[String]) -> Option<Target> {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        [command, flag, name, start] if matches!(*command, "checkout" | "switch") => {
            let branch = [command.to_string(), flag.to_string(), name.to_string()];
            (super::super::workspace_contained::keeping_arguments(&branch) && reference(start))
                .then(|| Target::revision(start))
        }
        // `--detach` alone leaves `HEAD` where it is, detached.
        [command, "--detach"] if matches!(*command, "checkout" | "switch") => {
            Some(Target::revision("HEAD"))
        }
        [command, "--detach", target] if matches!(*command, "checkout" | "switch") => {
            moved_to(target).map(Target::detaching)
        }
        [command, target] if matches!(*command, "checkout" | "switch") => moved_to(target),
        _ => None,
    }
}

/// The commit a one-word `checkout`/`switch` names. `-` is the branch Git
/// left last, which it spells `@{-1}`. A pathspec reaches here too, and the
/// proof refuses it: it names no commit.
fn moved_to(target: &str) -> Option<Target> {
    match target {
        "-" => Some(Target::revision("@{-1}")),
        value if reference(value) => Some(Target::branch(value)),
        _ => None,
    }
}

/// A revision a checkout moves to, and the order Git resolves its name in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Target {
    name: String,
    /// A plain `git checkout NAME` or `git switch NAME` checks out the local
    /// branch of that name; a tag or any other ref spelled the same way wins
    /// only when no such branch exists. Every other form here — a start point
    /// for a new branch, a detaching checkout, a rebase upstream — resolves by
    /// Git's usual revision order, where a tag comes before a branch. Reading
    /// the wrong one would prove a commit the checkout never moves to.
    branch: bool,
}

impl Target {
    pub(super) fn revision(name: &str) -> Self {
        Self {
            name: name.to_string(),
            branch: false,
        }
    }

    fn branch(name: &str) -> Self {
        Self {
            name: name.to_string(),
            branch: true,
        }
    }

    /// A detaching checkout names a commit, never the branch at that name.
    fn detaching(mut self) -> Self {
        self.branch = false;
        self
    }

    /// The revision the proof reads: the local branch Git will check out when
    /// the repository holds one, and the name as written otherwise.
    fn commit(&self, probe: &Probe) -> Option<String> {
        if self.branch {
            let branch = format!("refs/heads/{}^{{commit}}", self.name);
            if verified(probe, &branch) {
                return Some(branch);
            }
        }
        let commit = format!("{}^{{commit}}", self.name);
        verified(probe, &commit).then_some(commit)
    }
}

/// Whether `revision` names a commit this repository holds.
fn verified(probe: &Probe, revision: &str) -> bool {
    probe
        .text(&[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            revision,
        ])
        .is_some()
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
pub(super) fn replaces_nothing(probe: &Probe, start: &Target) -> bool {
    let Some(commit) = start.commit(probe) else {
        return false;
    };
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

#[cfg(test)]
#[path = "git_local_writes_start_tests.rs"]
mod tests;
