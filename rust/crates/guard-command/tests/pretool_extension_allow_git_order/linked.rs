//! A refresh routed with `-C` into a linked worktree, the review checkout an
//! agent keeps beside its work, and the read after it in that worktree.

use super::{checkout, decide, every_permission, git, shell_path};
use fixture::FixtureCleanup;
use std::path::PathBuf;

use crate::git_helper_fixture as fixture;

/// The project with a linked worktree checked out inside it, the way an agent
/// keeps a review checkout next to its work, and an `origin/main` to refresh
/// it onto.
fn linked_review_checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let (root, cleanup) = checkout(label, false);
    let project = root.join("project");
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "second"]);
    git(
        &root,
        &project,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    git(
        &root,
        &project,
        &["worktree", "add", "--quiet", "--detach", "review-wt"],
    );
    (root, cleanup)
}

/// The same refresh routed into a linked worktree. Guard proved the route
/// against the checkout the session started in, whose top level is never the
/// worktree the read runs in, so the read after the refresh always waited for
/// review even though every step worked in that one worktree.
#[test]
fn a_ref_read_after_a_refresh_routed_into_a_linked_worktree_runs_without_review() {
    let (root, _cleanup) = linked_review_checkout("routed-linked");
    let worktree = shell_path(&root.join("project").join("review-wt"));
    let controls = every_permission("enabled");
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in [
            "git -C review-wt checkout -B refresh --no-track origin/main \
             && git -C review-wt rev-parse --short HEAD && git -C review-wt status --short"
                .to_owned(),
            "git -C review-wt checkout -B refresh origin/main && git -C review-wt rev-parse --short HEAD"
                .to_owned(),
            format!(
                "git -C {worktree} checkout -B refresh origin/main \
                 && git -C {worktree} rev-parse --abbrev-ref HEAD"
            ),
        ] {
            let result = decide(&root, harness, &command, &controls);
            if result.decision != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {} {}",
                    result.decision, result.reason_code, result.reason
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Proving the route where the read runs is what lets that proof refuse it:
/// a configuration include that names a file inside the linked worktree makes
/// whatever the refresh checks out there configuration the read obeys.
#[test]
fn a_ref_read_routed_into_a_linked_worktree_that_includes_its_own_files_still_waits() {
    let (root, _cleanup) = linked_review_checkout("routed-linked-include");
    let worktree = root.join("project").join("review-wt");
    let include = shell_path(&worktree.join("team.gitconfig"));
    git(&root, &worktree, &["config", "include.path", &include]);
    let controls = every_permission("enabled");
    for command in [
        "git -C review-wt checkout -B refresh origin/main && git -C review-wt rev-parse --short HEAD",
        "git -C review-wt checkout -B refresh origin/main && git -C review-wt status --short",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
