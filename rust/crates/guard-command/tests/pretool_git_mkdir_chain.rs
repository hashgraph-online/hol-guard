#![cfg(unix)]

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_contracts::PreToolResultV1;
use serde_json::json;

fn bash(session: &Session, command: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.primary.to_str(),
    )
}

#[test]
fn proven_git_commands_may_share_a_chain_with_mkdir() {
    let session = session("git-mkdir-chain");
    let ledger = session.home.join("ledger");
    let ledger = ledger.to_str().unwrap();
    for command in [
        format!("git fetch origin main && mkdir -p {ledger}"),
        format!("mkdir -p {ledger} && git fetch origin main"),
        "git status --short && mkdir -p notes".to_owned(),
    ] {
        let result = bash(&session, &command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn mkdir_beside_git_keeps_its_own_screening() {
    let session = session("git-mkdir-screen");
    std::fs::write(session.primary.join("plan.md"), "plan\n").unwrap();
    for command in [
        "git fetch origin main && mkdir -p .git/hooks",
        "git fetch origin main && mkdir -p ~/.ssh/keys",
        "git fetch origin main && mkdir -p /opt/guard-fixture",
        "git clean -fdx && mkdir -p notes",
        "git status --short && mkdir -p notes && cp plan.md notes/",
    ] {
        let result = bash(&session, command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// `mkdir` targets are screened before the chain runs, so a Git command that
/// writes the work tree could first check out a tracked link such as
/// `notes -> ~/.ssh` that `mkdir -p notes/keys` would then follow.
#[test]
fn work_tree_updating_git_keeps_mkdir_in_review() {
    let session = session("git-mkdir-worktree");
    let checkout = session.home.join("app-portal-next");
    let checkout = checkout.to_str().unwrap();
    for command in [
        "git pull --ff-only && mkdir -p notes/keys".to_owned(),
        "git pull origin main && mkdir -p notes".to_owned(),
        format!("git worktree add -b fix/next {checkout} origin/main && mkdir -p notes"),
        format!(
            "git fetch origin main && git worktree add -b fix/next {checkout} origin/main \
             && mkdir -p {checkout}/notes"
        ),
        "git checkout origin/main && mkdir -p notes".to_owned(),
        "git switch -c next origin/main && mkdir -p notes".to_owned(),
        "git reset --hard origin/main && mkdir -p notes".to_owned(),
        "git merge --ff-only origin/main && mkdir -p notes".to_owned(),
        "git rebase origin/main && mkdir -p notes".to_owned(),
        "git stash pop && mkdir -p notes".to_owned(),
        "git restore . && mkdir -p notes".to_owned(),
        "git -C . pull && mkdir -p notes".to_owned(),
    ] {
        let result = bash(&session, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
