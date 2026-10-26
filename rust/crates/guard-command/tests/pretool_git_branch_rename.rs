#![cfg(unix)]

use crate::pretool_git_session_ops::{executable_hook, session};

const WRITE: &str = "native_exact_safe_git_local_write";

#[test]
fn branch_rename_in_a_linked_worktree_is_quiet_only_without_force_or_programs() {
    let session = session("rename");
    let at_tree = |command: &str| session.evaluate_at(command, &session.worktree);
    let allowed = |command: &str| {
        let result = at_tree(command);
        (result.minimum_action == "allow" && result.reason_code == WRITE)
            .then_some(())
            .ok_or(format!("{command}: {}", result.reason_code))
    };
    let reviewed = |command: &str| {
        let result = at_tree(command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    };
    for command in [
        "git branch -m main",
        "git branch -m old new",
        "git branch --move feat/renamed",
        "git branch -q -m fix/report-lane feat/renamed",
    ] {
        allowed(command).unwrap();
    }
    for command in [
        "git branch -M main",
        "git branch -c a b",
        "git branch -C a b",
        "git branch --copy a b",
        "git branch -m --force main",
        "git branch -m -f main",
        "git branch -m",
        "git branch -m a b c",
        "git branch -m ../escape",
        "git branch -m main -q",
        "git -c core.hooksPath=x branch -m main",
    ] {
        reviewed(command);
    }
    session.config(&["hook.reference-transaction.command", "id"]);
    reviewed("git branch -m main");
    session.config(&["--unset-all", "hook.reference-transaction.command"]);
    // A rename updates refs, so it answers for the reference-transaction hook.
    executable_hook(&session.primary.join(".git/hooks/reference-transaction"));
    reviewed("git branch -m main");
}
