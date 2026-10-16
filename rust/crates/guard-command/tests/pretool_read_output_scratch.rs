#![cfg(unix)]

use crate::pretool_git_session_ops::session;

#[test]
fn git_reads_saved_to_a_scratch_file_are_allowed_in_a_checkout() {
    let session = session("read-output-scratch");
    for checkout in [&session.primary, &session.worktree] {
        std::fs::create_dir_all(checkout.join(".tmp")).unwrap();
        for command in [
            "git log --oneline -5 > .tmp/log.txt",
            "git status --short > .tmp/status.txt 2>&1",
            "git log -1 --format=%H >> .tmp/head.txt",
            "git log --oneline -5 > .tmp/log.txt; wc -l .tmp/log.txt",
        ] {
            let result = session.evaluate_at(command, checkout);
            assert_eq!(
                result.minimum_action,
                "allow",
                "{} {command}: {}",
                checkout.display(),
                result.reason_code
            );
        }
    }
}

#[test]
fn git_reads_saved_into_repository_internals_stay_reviewed() {
    let session = session("read-output-internals");
    for checkout in [&session.primary, &session.worktree] {
        for command in [
            "git log -1 > .git/hooks/pre-commit",
            "git log -1 > .git/config",
            "git log -1 > .git",
            "git log -1 > .gitattributes",
            "git log -1 > .tmp/../.git/config",
        ] {
            let result = session.evaluate_at(command, checkout);
            assert_ne!(
                result.minimum_action,
                "allow",
                "{} {command}: {}",
                checkout.display(),
                result.reason_code
            );
        }
    }
}
