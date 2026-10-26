//! A Git subcommand group that only reports keeps a literal redirect literal.
use super::tests::{controls, decision};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// A workspace file written beside `git worktree list` or `git stash list`
/// reached an evaluation failure and blocked outright, with no approval left
/// to give it: the group word alone counted as a Git command that lays down a
/// working tree, so the literal redirect was read as one a link could
/// retarget. The reporting operations write no tree, so these chains stay
/// reviewable the way the same write beside `git branch -v` already did.
#[test]
fn a_reporting_worktree_or_stash_step_beside_a_write_is_not_an_evaluation_failure() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "echo hi > docs/a.md && git worktree list",
        "echo hi > docs/a.md && git worktree list --porcelain",
        "echo hi > docs/a.md && git worktree prune",
        "echo hi > docs/a.md && git stash list",
        "mkdir -p docs && cat > docs/a.md <<'EOF'\n# Branch audit\nEOF\ngit worktree list",
        "mkdir -p docs && cat > docs/a.md <<'EOF'\n# Branch audit\nEOF\ngit worktree remove --force ../audit-wt && git worktree list && git add docs/a.md && git commit -q -m x",
    ] {
        let (action, reason) = decision(&controls, command);
        assert_ne!(reason, FAILED, "{command}");
        assert_ne!(action, "block", "{command}");
    }
}

/// An operation that does lay down a working tree keeps the failure: the
/// redirect's literal path is no longer proof of the file it opens, and a
/// group whose operation is missing or unknown stays counted as a tree write.
#[test]
fn a_worktree_or_stash_operation_that_writes_a_tree_keeps_the_failure() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "echo hi > docs/a.md && git worktree add ../audit-wt",
        "echo hi > docs/a.md && git worktree move ../audit-wt ../audit-moved",
        "echo hi > docs/a.md && git worktree",
        "echo hi > docs/a.md && git stash pop",
        "echo hi > docs/a.md && git stash",
        "echo hi > docs/a.md && git checkout main",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// `--ext-diff` runs the program `diff.external` names, so a reporting
/// operation carrying it can still leave a link a later redirect writes
/// through. Narrowing the group words must not hand that option a literal
/// redirect, on `git stash show` or on any other Git command.
#[test]
fn an_external_diff_helper_keeps_the_failure_whatever_the_operation_reports() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "echo hi > docs/a.md && git stash show --ext-diff",
        "echo hi > docs/a.md && git stash show --ext-diff stash@{0}",
        "echo hi > docs/a.md && git diff --ext-diff",
        "echo hi > docs/a.md && git log -p --ext-diff",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
