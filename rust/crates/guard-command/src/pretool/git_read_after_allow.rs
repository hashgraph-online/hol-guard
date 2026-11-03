//! Git reads that follow steps the user allowed.
//!
//! The Git extension has no permission for reads such as `git rev-parse HEAD`,
//! `git merge-base` or `git branch --show-current`: Guard proves them on its
//! own. That proof holds for a read that runs first, or after steps that are
//! themselves proven. After a step the user allowed (`git push`, `git checkout
//! main`), the benign proof no longer carries a read that takes any argument,
//! so `git push && git rev-parse HEAD` lost the Allow its push was given.
//!
//! A read that only looks up refs and objects in the current repository does
//! not depend on anything such a step changes. It names no file, runs in the
//! same directory, and the Git floor still probes the configuration it runs
//! under. This module counts it as covered when the steps before it are.
//!
//! The same holds for a Docker listing Guard proves on its own (`docker ps`,
//! `docker images`, `docker logs`): none of them reads a project file, so a
//! Git step before it cannot change what it does.
//!
//! Two things an allowed step could still change reach a later read: Git's
//! configuration, which a `git config` write rewrites outright, and a tracked
//! file a configuration include names, which a checkout or reset can replace.
//! The first ends the run here, since only steps on [`CONFIG_STABLE_STEPS`]
//! carry it. The second needs a probe of the repository, which the Git floor
//! runs when it asks whether the Allow settles its order check, through
//! [`allow_settles_read_order`].

use super::PathContext;
use crate::CanonicalCommandV1;
use std::collections::BTreeSet;

/// Reads that look up refs, commits or objects and never the working tree.
/// Each is one the Git floor probes (`git_config::execution_free`), so the
/// pager, diff driver or textconv setting it would run is still checked where
/// it runs. Status, diff, grep and the index listings are not here: their
/// proof reads the tree's attributes and index, which an allowed checkout or
/// pull changes.
const REF_READS: &[&str] = &[
    "rev-parse",
    "rev-list",
    "merge-base",
    "show-ref",
    "for-each-ref",
    "branch",
    "describe",
    "cat-file",
    "tag",
    "log",
    "show",
    "shortlog",
    "reflog",
];

/// Git operations that write no configuration a later read obeys. Some record
/// an upstream (`push -u`, `checkout --track`, `branch -u`), and those
/// `branch.*` keys name no program. Only a step whose first argument is one of
/// these carries a read, so a leading `-C` that points the step at another
/// repository ends the run.
const CONFIG_STABLE_STEPS: &[&str] = &[
    "add", "branch", "checkout", "commit", "fetch", "merge", "pull", "push", "reset", "restore",
    "stash", "switch", "tag",
];

/// Git operations that rewrite no tracked file. Any other step the Git floor
/// leaves unsettled may replace a file a configuration include names.
const TREE_PRESERVING_STEPS: &[&str] = &["add", "branch", "commit", "fetch", "push", "tag"];

/// `git worktree` actions that write no file at a new path. Removing a linked
/// worktree deletes files, which can drop configuration but never adds a
/// program to it; `add` and `move` write where an absolute include may point.
const TREE_PRESERVING_WORKTREE_ACTIONS: &[&str] = &["list", "lock", "prune", "remove", "unlock"];

/// The Git ref reads and Docker listings in `model` that the steps before
/// them leave covered.
///
/// `benign` holds the segments the native benign proof covers and `covered`
/// every segment covered so far, by that proof, an enabled permission or a
/// GitHub grant. A read qualifies when it is proven safe on its own, takes no
/// leading Git option (so `-C` and `--git-dir` cannot route it elsewhere), and
/// every earlier step is covered and either benign or a Git step on
/// [`CONFIG_STABLE_STEPS`]. Any other step, such as an allowed `ln` or `git
/// config`, could repoint the directory the read runs in or the program it
/// starts, so it ends the run.
pub(crate) fn git_reads_after_allowed_steps(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    benign: &BTreeSet<usize>,
    covered: &BTreeSet<usize>,
) -> Vec<usize> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return Vec::new();
    }
    let Some(cwd) = read_directory(model, context) else {
        return Vec::new();
    };
    let proof_context = PathContext {
        creates_nothing: super::search::command_creates_nothing(model),
        cwd: cwd.as_deref().or(context.cwd),
        ..context
    };
    let mut added = Vec::new();
    for (index, segment) in model.segments.iter().enumerate() {
        let git = git_segment(segment);
        if covered.contains(&index) {
            if benign.contains(&index)
                || (git && leading_operation_in(segment, CONFIG_STABLE_STEPS))
            {
                continue;
            }
            break;
        }
        let read = if git {
            ref_read(model, segment, proof_context)
        } else {
            docker_listing(model, segment, proof_context)
        };
        if !read {
            break;
        }
        added.push(index);
    }
    added
}

/// Whether the user's Allow may settle the Git floor's order check for
/// `steps`, the earlier steps it could not prove leave a later read's
/// configuration as Guard read it. A step that may rewrite tracked files
/// settles it only when no configuration include reaches the work tree, so no
/// file it checks out becomes configuration the read obeys. Such a step with a
/// leading option may act on another repository, whose files an absolute
/// include could name, so it never settles. Steps outside Git keep the Allow's
/// judgment.
pub(crate) fn allow_settles_read_order(
    model: &CanonicalCommandV1,
    steps: &[usize],
    context: PathContext<'_>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let mut first = None;
    for &index in steps {
        let Some(segment) = model.segments.get(index) else {
            return false;
        };
        if !git_segment(segment) || preserves_tree(&segment.arguments) {
            continue;
        }
        if segment
            .arguments
            .first()
            .is_none_or(|argument| argument.starts_with('-'))
        {
            return false;
        }
        first = Some(first.map_or(index, |current: usize| current.min(index)));
    }
    let Some(first) = first else {
        return true;
    };
    // The directory the floor probed its reads in.
    let destination = super::segment_proof::git_read_cwd_compound_context(model, context);
    let read_context = PathContext {
        cwd: destination.as_deref().or(context.cwd),
        ..context
    };
    (first + 1..model.segments.len()).all(|index| {
        // `... | xargs git log` runs its read as the child.
        let child = super::fanout_reads::git_xargs_child(model, index);
        let later = child.as_ref().unwrap_or(&model.segments[index]);
        !git_segment(later)
            || super::git_remote_ops::work_tree_outside_configuration(
                later,
                read_context,
                deadline,
                execution_environment,
            )
    })
}

/// The directory a `cd` chain leaves the reads in: `Some(None)` when the
/// command has no `cd` and runs where it was reported, `None` when a `cd`
/// cannot be followed.
fn read_directory(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<Option<String>> {
    let cwd = super::segment_proof::verified_cwd_compound_context(model, context);
    if cwd.is_none()
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    Some(cwd)
}

/// Whether a Git step, wherever its global options route it, rewrites no
/// tracked file. A global option the shared Git parser does not know leaves
/// the subcommand unknown, so the step does not qualify.
fn preserves_tree(arguments: &[String]) -> bool {
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return false;
    };
    match arguments.get(index).map(String::as_str) {
        Some("worktree") => arguments
            .get(index + 1)
            .is_some_and(|action| TREE_PRESERVING_WORKTREE_ACTIONS.contains(&action.as_str())),
        Some(operation) => TREE_PRESERVING_STEPS.contains(&operation),
        None => false,
    }
}

/// Whether the segment's first argument, with no global option before it, is
/// one of `operations`.
fn leading_operation_in(segment: &crate::CommandSegmentV1, operations: &[&str]) -> bool {
    segment
        .arguments
        .first()
        .is_some_and(|operation| operations.contains(&operation.as_str()))
}

fn git_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|executable| super::executable_basename(executable) == "git")
}

/// A Docker listing the Docker proof admits. That proof also admits `docker
/// start`, which runs a container whose bind mount may hold the files an
/// allowed checkout just changed, so a start never qualifies here.
fn docker_listing(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    !super::docker_start::start_shaped(&words)
        && super::docker_reads::proven_segment(model, segment, context)
}

fn ref_read(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let stripped = super::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some((operation, rest)) = segment.arguments.split_first() else {
        return false;
    };
    !segment.path_overridden
        && segment.wrapper_chain.is_empty()
        && segment
            .environment_names
            .iter()
            .all(|name| crate::command_compatibility::inert_git_environment_name(name))
        && REF_READS.contains(&operation.as_str())
        && !super::git_history_reads::cleans_working_tree(operation, rest)
        // The Git floor probes each of these reads, so the proof may lean on
        // that probe for the helper context, as the floor's own order check
        // does.
        && super::segment_proof::exact_safe_segment_with_context(model, segment, true, context)
}

#[cfg(test)]
mod tests {
    use super::{preserves_tree, REF_READS};

    #[test]
    fn working_tree_reads_are_not_ref_reads() {
        for operation in ["status", "diff", "grep", "ls-files", "blame", "check-attr"] {
            assert!(!REF_READS.contains(&operation), "{operation}");
        }
    }

    fn words(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_step_routed_by_global_options_keeps_its_own_subcommand() {
        for command in [
            "push",
            "-C repo worktree remove wt",
            "-c a.b=c branch -D pr",
        ] {
            assert!(preserves_tree(&words(command)), "{command}");
        }
        // `--attr-source` takes a value, so `push` here is that value and the
        // step is a checkout.
        for command in [
            "checkout main",
            "--attr-source push checkout main",
            "--attr-source=push checkout main",
            "-C repo worktree add wt",
        ] {
            assert!(!preserves_tree(&words(command)), "{command}");
        }
    }
}
