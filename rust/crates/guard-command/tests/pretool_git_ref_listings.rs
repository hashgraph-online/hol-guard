#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

#[test]
fn reference_listings_are_proven_reads() {
    let session = session("ref-listings");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            "git show-ref --heads",
            "git show-ref | grep main",
            "git show-ref --verify --quiet refs/heads/main && echo present",
            "git for-each-ref --format='%(refname)' refs/remotes | grep main",
            "git for-each-ref --sort=-committerdate --count=5 --format '%(refname:short)' refs/heads",
            "git status --short && git show-ref --tags",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            "git show-ref --exclude-existing",
            "git for-each-ref --stdin",
            "git show-ref --remotes",
            // `%(signature)` runs the configured `gpg.program`.
            "git for-each-ref --format='%(signature:grade)' refs/tags",
            "git for-each-ref --format '%(refname) %(signature)' refs/heads",
            "git for-each-ref --sort signature:signer refs/tags",
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
        &["config", "pager.show-ref", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git show-ref --heads", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}
