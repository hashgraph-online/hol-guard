#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

#[test]
fn commit_walks_are_proven_reads() {
    let session = session("rev-list");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            "git rev-list --left-right --count main...origin/main",
            "git rev-list --count HEAD",
            "git rev-list --count origin/main..HEAD",
            "git rev-list -n 5 --first-parent HEAD",
            "git rev-list --max-count=1 HEAD",
            "git status --short && git rev-list --count main..HEAD",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            "git rev-list --objects HEAD",
            "git rev-list --stdin",
            "git rev-list --output=commits.txt HEAD",
            "git rev-list --filter=blob:none --objects HEAD",
            "git rev-list --missing=print HEAD",
            // `%G?` verifies signatures through the configured `gpg.program`.
            "git rev-list --pretty=format:%G? HEAD",
            "git rev-list --count HEAD -- tracked.txt",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    // A configured pager runs a program, so the probe keeps the review.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.rev-list", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git rev-list --count HEAD", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}
