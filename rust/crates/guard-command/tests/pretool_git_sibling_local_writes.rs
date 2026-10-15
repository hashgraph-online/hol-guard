#![cfg(unix)]

//! Local Git writes beside the working repository: `git -C <sibling>` is
//! judged as `cd <sibling> && git ...`, stash entries come back with `apply`
//! or `pop`, commit identity variables steer no program, and a proven write
//! may precede a read after `;`. Anything that could run a program, change
//! configuration or discard work stays reviewed.

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::{Path, PathBuf};

fn repository(session: &Session, directory: &Path) {
    std::fs::create_dir_all(directory).unwrap();
    git(&session.home, directory, &["init", "--quiet", "-b", "main"]);
    git(
        &session.home,
        directory,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &session.home,
        directory,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(directory.join("README.md"), "fixture\n").unwrap();
    git(&session.home, directory, &["add", "README.md"]);
    git(
        &session.home,
        directory,
        &["commit", "--quiet", "-m", "fixture"],
    );
}

/// The session plus `org/service-api`, a sibling repository of the cwd.
fn sibling(label: &str) -> (Session, PathBuf) {
    let session = session(label);
    let service = session.org.join("service-api");
    repository(&session, &service);
    (session, service)
}

fn allowed(session: &Session, command: &str) -> bool {
    session
        .evaluate_at(command, &session.primary)
        .minimum_action
        == "allow"
}

/// The command runs without a prompt: allowed, or run in the workspace
/// sandbox, which takes a plain write in a main checkout before the local
/// write proof does.
fn assert_quiet(session: &Session, command: &str) {
    let result = session.evaluate_at(command, &session.primary);
    assert!(
        matches!(result.minimum_action.as_str(), "allow" | "sandbox-required"),
        "{command}: {} {}",
        result.minimum_action,
        result.reason_code
    );
}

fn assert_allowed(session: &Session, command: &str) {
    let result = session.evaluate_at(command, &session.primary);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

fn assert_reviewed(session: &Session, command: &str) {
    let result = session.evaluate_at(command, &session.primary);
    assert_ne!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

#[test]
fn sibling_writes_behind_git_c_match_the_cd_form() {
    let (session, service) = sibling("sibling-c");
    let sib = service.display();
    for command in [
        format!("git -C {sib} add README.md"),
        format!("git -C {sib} commit -m \"fix: correct epoch anchors\" -m \"Body line.\""),
        format!(
            "git -C {sib} commit --amend --no-edit 2>&1 | tail -1; \
             git -C {sib} log --format='%h %an <%ae>' -1"
        ),
        format!(
            "git -C {sib} stash pop 2>&1 | tail -2; \
             git -C {sib} log --format='%h %an <%ae> %s' -3"
        ),
        format!("git -C {sib} add README.md && git -C {sib} commit -m x"),
    ] {
        assert_allowed(&session, &command);
    }
    for command in [
        format!("cd {sib} && git commit -m x"),
        format!("cd {sib} && git commit --amend --no-edit 2>&1 | tail -1; git log -1"),
    ] {
        assert_quiet(&session, &command);
    }
    let hidden = session.home.join(".cache/service-api");
    repository(&session, &hidden);
    let org = session.org.display();
    for command in [
        "git -C / commit -m x".to_owned(),
        // Not a repository, and a repository below a hidden directory.
        format!("git -C {org} commit -m x"),
        format!("git -C {} commit -m x", hidden.display()),
        format!("git -C {sib}/missing commit -m x"),
        // Two directories, or a Git step without `-C`.
        format!("git -C {sib} add README.md && git -C {org}/app-portal commit -m x"),
        format!("git -C {sib} add README.md && git commit -m x"),
        format!("cd {sib} && git -C {sib} commit -m x"),
        // Steps other than Git run from the shell's directory.
        format!("git -C {sib} commit -m x && rm -rf build"),
        format!("git -C {sib} commit -m x && git -C {sib} push origin main"),
        format!("git -C {sib} -c core.hooksPath=/tmp/hooks commit -m x"),
        format!("git -C {sib} config core.fsmonitor x; git -C {sib} status"),
        format!("git -C {sib} stash drop"),
        // After `;` a step may run in either directory.
        format!("cd {sib} && git commit -m x; rm -rf build"),
        format!("cd {sib} && git commit -m x; git push origin main"),
    ] {
        assert_reviewed(&session, &command);
    }
    git(
        &session.home,
        &service,
        &["config", "core.fsmonitor", "/tmp/monitor"],
    );
    assert_reviewed(&session, &format!("git -C {sib} commit -m x"));
    assert_reviewed(&session, &format!("cd {sib} && git commit -m x"));
}

#[test]
fn stash_restores_and_identity_variables_are_local_writes() {
    let (session, _) = sibling("stash-env");
    for command in [
        "git stash list",
        "git stash list -n 5",
        "git stash apply",
        "git stash apply --index",
        "git stash pop -q 0",
        "git stash pop",
        "git stash pop 2>&1 | tail -2; git log --oneline -3",
        "GIT_AUTHOR_NAME=dev GIT_AUTHOR_EMAIL=dev@example.com git commit -m \"fix: x\"",
        "GIT_COMMITTER_NAME=dev GIT_COMMITTER_DATE=2026-01-01T00:00:00 git commit --amend --no-edit",
    ] {
        assert_allowed(&session, command);
    }
    for command in [
        "git stash drop",
        "git stash clear",
        "git stash apply stash@{0} stash@{1}",
        "git stash list -p",
        "git stash show -p",
        "git config core.pager 'sh -c id'; git log",
        "git -c core.pager='sh -c id' log",
        "git -c core.pager='sh -c id' stash list",
        "git remote add x https://example.com/x.git; git log",
        "git branch -u origin/main; git log",
        "git commit -m x; git config core.pager id",
        "GIT_CONFIG_GLOBAL=x git log",
        "GIT_PAGER=x git log",
        "GIT_PAGER=x git commit -m x",
        "GIT_DIR=x git commit -m x",
        "GIT_EDITOR=x git commit --amend --no-edit",
        "GIT_EXEC_PATH=x git stash pop",
    ] {
        assert_reviewed(&session, command);
    }
    for (key, value, command) in [
        ("pager.stash", "sh -c id", "git stash list"),
        ("pager.log", "sh -c id", "git stash list"),
        ("pager.status", "sh -c id", "git stash pop"),
        ("merge.custom.driver", "sh -c id", "git stash apply"),
        // A plain commit in this main checkout takes the workspace sandbox;
        // the identity prefix leaves it to the local write proof.
        (
            "alias.commit",
            "!sh -c id",
            "GIT_AUTHOR_NAME=dev git commit -m x",
        ),
        (
            "core.fsmonitor",
            "/tmp/monitor",
            "git stash pop; git log -1",
        ),
    ] {
        assert!(allowed(&session, command), "{command}");
        session.config(&[key, value]);
        assert_reviewed(&session, command);
        session.config(&["--unset-all", key]);
    }
}

#[test]
fn stash_listing_composes_with_worktree_listing() {
    let (session, _) = sibling("stash-worktrees");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    assert_allowed(
        &session,
        &format!("cd {primary} && git stash list | head -3 && git worktree list | grep -c fix"),
    );
    assert_allowed(
        &session,
        &format!(
            "cd {primary} && git status --short && git stash list && git worktree list --porcelain"
        ),
    );
    for command in [
        format!("cd {primary} && git stash list && git worktree list -z"),
        format!("cd {primary} && git stash list && git worktree remove --force {worktree}"),
    ] {
        assert_reviewed(&session, &command);
    }
}

#[test]
fn stash_listing_keeps_its_proof_beside_fallbacks_and_github_reads() {
    let (session, service) = sibling("stash-fallback");
    let primary = session.primary.display();
    let sib = service.display();
    for command in [
        format!(
            r#"cd {primary} && git status --short | head -4 && git stash list | head -3 && git worktree list | grep -c "fix" || echo "no fix worktrees remain" && gh pr list --repo example-org/app-portal --state open --json number,title --jq '.[] | "\(.number) \(.title)"' | head -4"#
        ),
        format!("cd {sib} && git stash list | head -3 || echo none"),
        "git stash list | head -3 && gh pr list --repo example-org/app-portal --json number"
            .to_owned(),
    ] {
        assert_allowed(&session, &command);
    }
    // After `||` a step may run in either directory, so only reads proven in
    // both may follow it.
    for command in [
        format!("cd {sib} && git stash list || git stash pop"),
        format!("cd {sib} && git stash list || echo none && git commit -m x"),
        format!("cd {sib} && git stash list || git push origin main"),
        format!("cd {sib} && git stash list || gh pr merge 1 --repo example-org/app-portal"),
        format!("cd {sib} && git stash list || cat ~/.ssh/id_rsa"),
    ] {
        assert_reviewed(&session, &command);
    }
}
