//! Git steps that leave what runs after them as Guard read it.
//!
//! A step the user allowed can still replace the program, the configuration
//! or the tracked file a later step starts under. The predicates here answer
//! which Git verbs cannot: they rewrite no tracked file, write no
//! configuration a later read obeys, or write nothing at all. The read proof
//! in [`super`] uses them to decide how far an Allow carries, and the
//! extension-wide coverage walk uses them to decide where it stops.

use super::git_output_target::{names_an_output_file, points_output_at_a_protected_file};
use super::git_read_after_allow::{git_segment, CONFIG_STABLE_STEPS, REF_READS};

/// Git operations that rewrite no tracked file. Any other step the Git floor
/// leaves unsettled may replace a file a configuration include names.
const TREE_PRESERVING_STEPS: &[&str] = &["add", "branch", "commit", "fetch", "push", "tag"];

/// Git verbs that write nothing a later step could read: no tracked file, no
/// configuration, no new path at all. A step on this list leaves the program,
/// the configuration and the bind-mounted file a later step starts exactly as
/// Guard read them, so coverage that reads a whole extension as allowed walks
/// past it. `diff` is left out on purpose: `git diff --output=<file>` writes
/// wherever it is pointed, and so can replace a later step's program.
const WRITES_NOTHING_STEPS: &[&str] = &[
    "blame",
    "cat-file",
    "check-attr",
    "check-ref-format",
    "describe",
    "for-each-ref",
    "grep",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge-base",
    "name-rev",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-branch",
    "show-ref",
    "status",
    "var",
    "whatchanged",
];

/// Git's diff plumbing, which compares trees, the index and the working tree
/// and prints the result. Like `git diff`, each takes `--output=<file>` and
/// writes wherever it points, so a step qualifies only when it names no
/// output at all; without one it prints and writes nothing, the way
/// `git whatchanged` and `git log` do. Users reach for `git diff-tree` where
/// Git 2.53 refuses `git whatchanged`, so leaving these out stopped a full
/// Git Allow partway through the same read.
const DIFF_PLUMBING_STEPS: &[&str] = &["diff-files", "diff-index", "diff-tree"];

/// `git worktree` actions that write no file at a new path. Removing a linked
/// worktree deletes files, which can drop configuration but never adds a
/// program to it; `add` and `move` write where an absolute include may point.
const TREE_PRESERVING_WORKTREE_ACTIONS: &[&str] = &["list", "lock", "prune", "remove", "unlock"];

/// Whether a Git step, wherever its global options route it, writes no
/// configuration a later read obeys: a step that records only `branch.*` keys
/// ([`CONFIG_STABLE_STEPS`]) or writes nothing at all
/// ([`WRITES_NOTHING_STEPS`]). Every other subcommand is refused, `config`
/// among them, and so is one the shared Git parser cannot resolve — an alias
/// runs whatever the configuration names it, which is the program this check
/// exists to keep out.
pub(super) fn preserves_configuration(arguments: &[String]) -> bool {
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return false;
    };
    match arguments
        .get(index)
        .map(|word| crate::command_compatibility::canonical_git_subcommand(word))
    {
        // `git worktree add` writes a configuration of its own; the actions
        // that only list or retire a checkout leave this one's alone.
        Some("worktree") => arguments
            .get(index + 1)
            .is_some_and(|action| TREE_PRESERVING_WORKTREE_ACTIONS.contains(&action.as_str())),
        Some(operation) => {
            CONFIG_STABLE_STEPS.contains(&operation)
                || WRITES_NOTHING_STEPS.contains(&operation)
                || REF_READS.contains(&operation)
        }
        None => false,
    }
}

/// Whether a Git step, wherever its global options route it, rewrites no
/// tracked file. A global option the shared Git parser does not know leaves
/// the subcommand unknown, so the step does not qualify.
pub(super) fn preserves_tree(arguments: &[String]) -> bool {
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return false;
    };
    match arguments
        .get(index)
        .map(|word| crate::command_compatibility::canonical_git_subcommand(word))
    {
        Some("worktree") => arguments
            .get(index + 1)
            .is_some_and(|action| TREE_PRESERVING_WORKTREE_ACTIONS.contains(&action.as_str())),
        Some(operation) => TREE_PRESERVING_STEPS.contains(&operation),
        None => false,
    }
}

/// Whether `segment` leaves what a later step runs as Guard read it.
///
/// A Git step that rewrites tracked files can replace the program, the
/// configuration or the bind-mounted file a later step starts, so coverage
/// that reads a whole extension as allowed stops at it. Only a Git step whose
/// verb rewrites nothing is answered here; every other program -- `ln`, `cp`,
/// `mv`, `tee`, `gh pr checkout` -- can replace the same files without Guard
/// modelling how, so it ends the walk unless the caller already proved that
/// segment benign.
pub(crate) fn step_preserves_later_programs(segment: &crate::CommandSegmentV1) -> bool {
    let arguments = &segment.arguments;
    git_segment(segment)
        && !points_output_at_a_protected_file(arguments)
        && (preserves_tree(arguments) || writes_nothing(arguments))
}

/// Whether `segment` is a Git step that writes its output over a file a later
/// step runs under.
///
/// An extension-wide Allow answers for Git's own work, and packaging a tree
/// into a file the workspace names -- `git archive -o snapshot.tar HEAD` --
/// is part of that work. Pointing the same output at `.git/config`, a hook,
/// or a path that leaves the workspace is not: it rewrites what the next Git
/// step runs, so that step keeps the review it had.
pub(crate) fn git_step_overwrites_what_runs_next(segment: &crate::CommandSegmentV1) -> bool {
    git_segment(segment) && points_output_at_a_protected_file(&segment.arguments)
}

/// Whether a Git step, wherever its global options route it, writes nothing a
/// later step reads. A global option the shared Git parser does not know
/// leaves the subcommand unknown, so the step does not qualify.
pub(super) fn writes_nothing(arguments: &[String]) -> bool {
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return false;
    };
    arguments.get(index).is_some_and(|operation| {
        WRITES_NOTHING_STEPS.contains(&operation.as_str())
            || (DIFF_PLUMBING_STEPS.contains(&operation.as_str())
                && !names_an_output_file(&arguments[index + 1..]))
    })
}
