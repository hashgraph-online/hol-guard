//! A checkout that turns every hook off with `core.hooksPath = /dev/null`.
#![cfg(unix)]

use crate::pretool_git_session_ops::session;

const WRITE: &str = "native_exact_safe_git_local_write";

/// Git cannot make a hook path below the null device absolute, so the proof
/// asks for it as Git spells it. Staging and committing there raise no review,
/// while Git's own write proof still refuses an inline override or a hook
/// directory below the device's name.
#[test]
fn null_hook_directory_keeps_local_writes_quiet() {
    let session = session("null-hooks");
    std::fs::write(session.worktree.join("notes.md"), "notes\n").unwrap();
    let quiet = |command: &str| session.quiet_at(command, &session.worktree, WRITE);
    let proven = |command: &str| {
        let result = session.evaluate_at(command, &session.worktree);
        result.minimum_action == "allow" && result.reason_code == WRITE
    };
    session.config(&["core.hooksPath", "/dev/null"]);
    for command in [
        "git add notes.md",
        "git add -A && git commit -m 'docs: add notes'",
    ] {
        quiet(command).unwrap();
    }
    assert!(!proven("git -c core.hooksPath=/tmp/hooks commit -m x"));
    session.config(&["core.hooksPath", "/dev/null/hooks"]);
    assert!(quiet("git add notes.md").is_err());
    assert!(!proven("git add notes.md"));
}
