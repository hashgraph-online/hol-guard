//! `git pull --ff-only`: the proven `origin` refresh, then a fast-forward of
//! the current branch. The fast-forward rewrites the working tree, so the
//! proof also needs everything a merge or checkout could start to be absent:
//! no rebase, signature check, fsmonitor, moved worktree or filter driver
//! other than the user's own Git LFS install, an `origin` upstream when Git
//! picks it, and no `post-merge` or `post-index-change` hook.

use super::config::GitConfig;
use super::Probe;

/// For the arguments after `pull`: `Some(true)` for `--ff-only` alone, where
/// Git picks the upstream, `Some(false)` for `--ff-only origin [branch]`.
pub(super) fn shaped(rest: &[String]) -> Option<bool> {
    let mut fast_forward = false;
    let mut fetch = Vec::new();
    for argument in rest {
        match argument.as_str() {
            "--ff-only" if !fast_forward => fast_forward = true,
            "-q" | "--quiet" => {}
            _ => fetch.push(argument.clone()),
        }
    }
    if !fast_forward {
        return None;
    }
    if fetch.is_empty() {
        return Some(true);
    }
    // More than one branch would ask for an octopus merge.
    (fetch
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .count()
        <= 2
        && crate::command_compatibility::git_fetch_origin_shaped(&fetch))
    .then_some(false)
}

/// Whether nothing the fast-forward runs after the fetch can start a program
/// or write outside the checkout.
pub(super) fn fast_forward_inert(
    effective: &GitConfig,
    repository: &GitConfig,
    upstream: bool,
    probe: &Probe,
) -> bool {
    let routed = effective.iter().any(|(key, values)| {
        let enabled = values.iter().any(|value| !disabled(value));
        (key.starts_with("filter.") && (!standard_lfs(key, values) || repository.contains_key(key)))
            || key.starts_with("gpg.")
            || key.starts_with("hook.")
            || key == "core.worktree"
            || (key == "core.fsmonitor" && enabled)
            || (key.ends_with(".verifysignatures") && enabled)
            || ((key == "pull.rebase" || key.starts_with("branch.") && key.ends_with(".rebase"))
                && enabled)
            || (upstream
                && key.starts_with("branch.")
                && key.ends_with(".remote")
                && values.iter().any(|value| value.trim() != "origin"))
    });
    !routed
        && !repository_lfs_program(repository)
        && probe.hooks_inert(["post-merge", "post-index-change"])
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
