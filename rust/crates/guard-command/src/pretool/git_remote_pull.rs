//! `git pull` from `origin`: the proven `origin` refresh, then a fast-forward
//! of the current branch or a merge of the fetched branch into it. Both
//! rewrite the working tree, so the proof also needs everything a merge or
//! checkout could start to be absent: no rebase, signature check, fsmonitor,
//! moved worktree or filter driver other than the user's own Git LFS install,
//! an `origin` upstream when Git picks it, and no `post-merge` or
//! `post-index-change` hook. A pull that may merge also writes a merge commit,
//! so it additionally needs `merge_inert` and none of `MERGE_HOOKS`.

use super::config::GitConfig;
use super::Probe;

/// Every hook a merge or cherry-pick can run, including the commit it writes
/// and the automatic garbage collection after it.
pub(in crate::pretool) const MERGE_HOOKS: &[&str] = &[
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-merge",
    "post-rewrite",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
];
const FAST_FORWARD_HOOKS: &[&str] = &["post-merge", "post-index-change"];

/// The shape of a proven pull.
#[derive(Clone, Copy)]
pub(super) struct Pull {
    /// Git picks the upstream: no remote is named.
    pub(super) upstream: bool,
    /// Without `--ff-only`, Git may write a merge commit.
    pub(super) merge: bool,
}

/// The shape of the arguments after `pull`: `--ff-only` or a merge, either
/// with no remote, where Git picks the upstream, or with `origin [branch]`.
/// `--rebase` and every other option keep the review.
pub(super) fn shaped(rest: &[String]) -> Option<Pull> {
    let mut fast_forward = false;
    let mut fetch = Vec::new();
    for argument in rest {
        match argument.as_str() {
            // `--ff`, `--no-ff` and `--ff-only` set one option; the last wins.
            "--ff-only" => fast_forward = true,
            "--ff" | "--no-ff" => fast_forward = false,
            "-q" | "--quiet" | "--no-edit" | "--no-rebase" => {}
            _ => fetch.push(argument.clone()),
        }
    }
    let merge = !fast_forward;
    if fetch.is_empty() {
        return Some(Pull {
            upstream: true,
            merge,
        });
    }
    // More than one branch would ask for an octopus merge.
    (fetch
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .count()
        <= 2
        && crate::command_compatibility::git_fetch_origin_shaped(&fetch))
    .then_some(Pull {
        upstream: false,
        merge,
    })
}

/// Whether nothing the fast-forward or merge runs after the fetch can start
/// a program or write outside the checkout.
pub(super) fn pull_inert(
    effective: &GitConfig,
    repository: &GitConfig,
    pull: Pull,
    probe: &Probe,
) -> bool {
    let routed = effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("filter.") && (!standard_lfs(key, values) || repository.contains_key(key)))
            // The user's own `gpg.*` names a program that only a signature
            // check (`*.verifysignatures` below) or commit signing (refused by
            // `merge_inert`) starts. A repository's choice stays routed.
            || (key.starts_with("gpg.") && repository.contains_key(key))
            || key.starts_with("hook.")
            || key == "core.worktree"
            || (key == "core.fsmonitor" && enabled)
            || (key.ends_with(".verifysignatures") && enabled)
            || ((key == "pull.rebase" || key.starts_with("branch.") && key.ends_with(".rebase"))
                && enabled)
            || (pull.upstream
                && key.starts_with("branch.")
                && key.ends_with(".remote")
                && values.iter().any(|value| value.trim() != "origin"))
    });
    let hooks = if pull.merge {
        MERGE_HOOKS
    } else {
        FAST_FORWARD_HOOKS
    };
    !routed
        && !repository_lfs_program(repository)
        && (!pull.merge || merge_inert(effective, repository))
        && probe.hooks_inert(hooks.iter().copied())
}

/// Whether a merge, and the commit it may write, can start no program the
/// fast-forward checks above leave open: no merge driver, no strategy or
/// merge option chosen by configuration (a strategy name runs
/// `git-merge-<name>` from `PATH`), no commit signing or signature check, and
/// no editor the repository picks. Git opens an editor for a merge message
/// only on a terminal and without `--no-edit`; the user's own editor setting
/// is their choice, but a repository must not choose one for them.
pub(in crate::pretool) fn merge_inert(effective: &GitConfig, repository: &GitConfig) -> bool {
    !effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("merge.") && (key.ends_with(".driver") || key.ends_with(".recursive")))
            // Merging a signed tag checks its signature with `gpg.program`.
            || (key.starts_with("gpg.") && repository.contains_key(key))
            || matches!(key.as_str(), "pull.twohead" | "pull.octopus")
            || (key.starts_with("branch.") && key.ends_with(".mergeoptions"))
            || (matches!(key.as_str(), "commit.gpgsign" | "merge.verifysignatures") && enabled)
    }) && !repository
        .keys()
        .any(|key| matches!(key.as_str(), "core.editor" | "sequence.editor"))
}

/// The filter `git lfs install` writes to the user's own configuration. A
/// repository cannot set it, and it names the installed `git-lfs` program.
pub(in crate::pretool) fn standard_lfs(key: &str, values: &[String]) -> bool {
    let expected = match key {
        "filter.lfs.clean" => "git-lfs clean -- %f",
        "filter.lfs.smudge" => "git-lfs smudge -- %f",
        "filter.lfs.process" => "git-lfs filter-process",
        "filter.lfs.required" => "true",
        _ => return false,
    };
    values.iter().all(|value| value.trim() == expected)
}

/// Git LFS also starts programs named by `lfs.extension.<name>.*`,
/// `lfs.customtransfer.<name>.path` and `lfs.standalonetransferagent`. A
/// repository can set those while leaving the user's filter alone.
pub(in crate::pretool) fn repository_lfs_program(repository: &GitConfig) -> bool {
    repository.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key.starts_with("lfs.")
            && (key.starts_with("lfs.extension.")
                || key.starts_with("lfs.customtransfer.")
                || key.ends_with(".standalonetransferagent"))
    })
}

pub(in crate::pretool) fn disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "false" | "no" | "off" | "0"
    )
}
