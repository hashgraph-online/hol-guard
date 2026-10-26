#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

/// Leave one stash entry behind and a clean worktree, the state an agent
/// finds when it asks what it set aside.
fn stash_one(home: &std::path::Path, repository: &std::path::Path) {
    std::fs::write(repository.join("tracked.txt"), "fixture\nwip\n").unwrap();
    git(home, repository, &["stash", "push", "-m", "wip notes"]);
}

#[test]
fn printing_stash_forms_are_proven_reads() {
    let session = session("stash-reads");
    for cwd in [&session.primary, &session.worktree] {
        stash_one(&session.home, cwd);
        for command in [
            "git stash list",
            "git stash list -n 3",
            "git stash list --max-count=3",
            "git stash list -3",
            "git stash list | head -3",
            "git stash show",
            "git stash show -p stash@{0}",
            "git stash show --stat 0",
            "git stash show --name-only stash@{0} | head",
            "git stash list | head -3 && git status --porcelain | wc -l",
            "git stash list | head -3 && git stash show -p stash@{0}",
            // A listing has to leave the reads after it provable too.
            "git stash list && git status --short && git log --oneline -3",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // The read grammar admits a listing and a `show` of one entry,
            // and nothing else: a spelling that moves work is judged by the
            // rules that already cover it, never as a read.
            "git stash show --ext-diff stash@{0}",
            "git stash show --textconv stash@{0}",
            "git stash show stash@{0} stash@{1}",
            "git stash show --unknown-option",
            // A listing that asks for patches runs the diff drivers the
            // read proof did not clear.
            "git stash list --patch",
            "git stash list --unknown-option",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn a_configured_stash_pager_keeps_the_review() {
    let session = session("stash-pager");
    stash_one(&session.home, &session.primary);
    let result = session.evaluate_at("git stash list", &session.primary);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    // A listing is `git log -g refs/stash`, so both pager keys run a program.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.stash", "./synthetic-never-execute"],
    );
    for command in [
        "git stash list",
        "git stash show -p stash@{0}",
        // Beside another Git read that needs the helper probe, the stash
        // read has to be probed too, not waved through with its neighbor.
        "git log -1 && git stash list",
        "git status --short && git stash list",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn an_external_diff_driver_keeps_the_show_reviewed() {
    let session = session("stash-diff-driver");
    stash_one(&session.home, &session.primary);
    git(
        &session.home,
        &session.primary,
        &["config", "diff.external", "./synthetic-never-execute"],
    );
    for command in [
        "git stash show -p stash@{0}",
        "git log -1 && git stash show -p stash@{0}",
        "git status --short && git stash show -p stash@{0}",
        "cd . && git stash show -p stash@{0}",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
