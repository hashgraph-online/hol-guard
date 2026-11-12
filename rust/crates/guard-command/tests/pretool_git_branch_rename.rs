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

#[test]
fn branch_creation_at_a_start_point_is_quiet_only_in_the_plain_form() {
    let session = session("create");
    let at_tree = |command: &str| session.evaluate_at(command, &session.worktree);
    let allowed = |command: &str| {
        let result = at_tree(command);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", WRITE),
            "{command}"
        );
    };
    // Each of these is refused by the creation form, so none of them reaches
    // the local-write proof. Some route to the workspace sandbox instead,
    // which carries a floor of its own, so what is claimed here is the proof
    // the command is admitted to, not the floor that follows from it.
    let reviewed = |command: &str| {
        let result = at_tree(command);
        assert_ne!(result.reason_code, WRITE, "{command}");
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    };
    let contained = |command: &str| {
        let result = at_tree(command);
        assert_eq!(
            result.reason_code, "native_workspace_containment_required",
            "{command}"
        );
    };
    // Creating a branch writes one new ref. It leaves `HEAD` and every file
    // in the checkout alone, and Git refuses a name that is already taken.
    for command in [
        "git branch fix/report HEAD",
        "git branch fix/report main",
        "git branch fix/report origin/main",
        "git branch fix/report refs/heads/main",
        "git branch -q fix/report origin/main",
    ] {
        allowed(command);
    }
    for command in [
        "git branch -f fix/report origin/main",
        "git branch --force fix/report origin/main",
        "git branch -t fix/report origin/main",
        "git branch --track fix/report origin/main",
        "git branch -u origin/main",
        "git branch --set-upstream-to=origin/main fix/report",
        "git branch -d fix/report",
        "git branch -D fix/report",
        "git branch fix/report origin/main extra",
        "git branch fix/report ../escape",
        "git branch fix/report main -q",
        "git branch ../escape main",
        "git -c core.hooksPath=x branch fix/report main",
    ] {
        reviewed(command);
    }
    // A creation with one positional, and one that asks for no upstream, name
    // no `branch.NAME.*` key the workspace sandbox would have to refuse, so
    // they keep the containment route they already had and never reach the
    // local-write proof.
    for command in [
        "git branch fix/report",
        "git branch --no-track fix/report origin/main",
    ] {
        contained(command);
    }
    // Creation updates a ref, so it answers for the reference-transaction hook.
    executable_hook(&session.primary.join(".git/hooks/reference-transaction"));
    reviewed("git branch fix/report main");
}
