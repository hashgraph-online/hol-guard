//! The argument forms of the local Git writes `git_local_writes` proves:
//! `add`, a non-forced `rm`, `commit` with its message on the command line
//! and a non-forced `branch` rename, plus the `stash list` read beside them.

use super::super::git_remote_config::GitConfig;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

/// Options `allowed` accepts, then pathspecs, with `--` ending the options.
fn pathspecs(rest: &[&str], allowed: impl Fn(&str) -> bool) -> bool {
    let mut options = true;
    rest.iter().all(|word| {
        if options && *word == "--" {
            options = false;
            true
        } else if options && word.starts_with('-') {
            allowed(word)
        } else {
            !word.is_empty()
        }
    })
}

pub(super) fn add(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-A" | "--all"
                | "-u"
                | "--update"
                | "-v"
                | "--verbose"
                | "-n"
                | "--dry-run"
                | "-N"
                | "--intent-to-add"
                | "--ignore-errors"
        )
    })
}

pub(super) fn rm(rest: &[&str]) -> bool {
    pathspecs(rest, |option| {
        matches!(
            option,
            "-q" | "--quiet" | "-r" | "--cached" | "-n" | "--dry-run" | "--ignore-unmatch"
        )
    })
}

/// A commit whose message is on the command line, so no editor starts.
pub(super) fn commit(rest: &[&str]) -> bool {
    let (mut message, mut amend, mut no_edit) = (false, false, false);
    let mut options = true;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if !options || !word.starts_with('-') {
            if word.is_empty() {
                return false;
            }
            continue;
        }
        match *word {
            "--" => options = false,
            "-m" | "--message" | "-am" => {
                if words.next().is_none() {
                    return false;
                }
                message = true;
            }
            value if value.starts_with("--message=") => message = true,
            value if value.len() > 2 && value.starts_with("-m") => message = true,
            "-q" | "--quiet" | "-a" | "--all" | "-s" | "--signoff" | "-n" | "--no-verify"
            | "--allow-empty" | "--no-gpg-sign" => {}
            "--amend" => amend = true,
            "--no-edit" => no_edit = true,
            _ => return false,
        }
    }
    message || (amend && no_edit)
}

/// `branch -m NEW` or `branch -m OLD NEW`, options first. A rename moves the
/// ref with its reflog and refuses an existing target, so nothing becomes
/// unreachable. `-M`, `--force`, a copy and every other option are refused.
pub(super) fn branch_rename(rest: &[&str]) -> bool {
    let mut moved = false;
    let mut names = Vec::new();
    for word in rest {
        match *word {
            "-m" | "--move" if !moved && names.is_empty() => moved = true,
            "-q" | "--quiet" if names.is_empty() => {}
            name if super::super::worktree_add::valid_branch_name(name) => names.push(name),
            _ => return false,
        }
    }
    moved && matches!(names.len(), 1 | 2)
}

/// `stash list` with at most a count limit. Git runs it as `git log -g
/// refs/stash`; other log options can ask for patches whose diff drivers the
/// proof below does not clear.
pub(super) fn stash_list(rest: &[&str]) -> bool {
    match rest {
        [] => true,
        ["-n" | "--max-count", value] => count(value),
        [flag] => flag
            .strip_prefix("--max-count=")
            .or_else(|| flag.strip_prefix('-').filter(|_| !flag.starts_with("--")))
            .is_some_and(count),
        _ => false,
    }
}

fn count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `stash apply` or `stash pop` with `-q`, `--index` and at most one entry
/// (`stash@{N}` or `N`). Git refuses to apply an entry over a modified file,
/// and `pop` keeps the entry when the apply conflicts.
pub(super) fn stash_restore(rest: &[&str]) -> bool {
    let mut entries = 0;
    rest.iter().all(|option| match *option {
        "-q" | "--quiet" | "--index" => true,
        entry if stash_entry(entry) => {
            entries += 1;
            entries == 1
        }
        _ => false,
    })
}

fn stash_entry(value: &str) -> bool {
    let index = value
        .strip_prefix("stash@{")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(value);
    !index.is_empty() && index.len() <= 4 && index.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether the `git stash` at `index` starts no program its hooks do not
/// cover. Stash pages only under its own `pager.stash` setting. `list` runs
/// `git log -g refs/stash`, held to the configuration proof of that log
/// read; `apply` and `pop` merge the entry, which may run a configured merge
/// driver, and then run `git status`, held to the proof of that read.
pub(super) fn stash_free(
    effective: &GitConfig,
    model: &CanonicalCommandV1,
    index: usize,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let original = &model.segments[index];
    let stripped = super::super::segment_proof::without_stderr_merge(original);
    let segment = stripped.as_ref().unwrap_or(original);
    let stdout_piped = super::super::git_helper_context::stdout_piped(model, index);
    let free = |arguments: &[&str]| {
        let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
        super::super::git_config::execution_free(
            "git",
            &arguments,
            context,
            deadline,
            execution_environment,
            stdout_piped,
        ) == Some(true)
    };
    let pager_off = |value: &String| {
        value.is_empty() || value == "cat" || super::super::git_remote_ops::pull::disabled(value)
    };
    let merge_driver = effective.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key.starts_with("merge.") && key.ends_with(".driver")
    });
    (stdout_piped
        || effective
            .get("pager.stash")
            .is_none_or(|values| values.iter().all(pager_off)))
        && match segment.arguments.get(1).map(String::as_str) {
            Some("list") => free(&["log", "-g", "--first-parent", "refs/stash"]),
            Some("apply" | "pop") => !merge_driver && free(&["status"]),
            _ => true,
        }
}

/// Whether the configuration defines an alias named like a Git step's
/// subcommand. Git ignores an alias that shadows a builtin; the proof does
/// not rely on that.
pub(super) fn aliased(effective: &GitConfig, model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .iter()
        .filter(|segment| segment.executable.as_deref() == Some("git"))
        .filter_map(|segment| segment.arguments.first())
        .any(|name| effective.contains_key(&format!("alias.{}", name.to_ascii_lowercase())))
}

/// The branch `git switch -c <name>` or `git checkout -b <name>` creates at
/// the checked-out commit. A start point is not one of these forms.
pub(super) fn created_branch(original: &CommandSegmentV1) -> Option<&str> {
    match original.arguments.as_slice() {
        [command, flag, name]
            if matches!(
                (command.as_str(), flag.as_str()),
                ("switch", "-c" | "--create") | ("checkout", "-b")
            ) =>
        {
            Some(name.as_str())
        }
        _ => None,
    }
}

/// Whether a write other than a branch creation may change the checked-out
/// branch: any `checkout`, `switch` or `branch` form.
pub(super) fn moves_head(original: &CommandSegmentV1) -> bool {
    original
        .arguments
        .first()
        .is_none_or(|command| matches!(command.as_str(), "checkout" | "switch" | "branch"))
}
