#![cfg(unix)]
//! `git worktree add <path> <name>` for a branch that exists only on one
//! remote creates `<name>` tracking that remote branch. Agents do this to check
//! out a fetched branch, so it runs without review when the remote branch's
//! tree is as inert as any other checkout. A name no remote has makes Git stop
//! before writing anything, so that runs without review too.

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn git(repository: &Path, arguments: &[&str]) -> std::process::Output {
    let home = repository.parent().unwrap();
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}");
    output
}

/// `root/repository` with an `origin` whose `feat/remote-only` branch was
/// fetched but never checked out.
fn repository(label: &str) -> (PathBuf, FixtureCleanup) {
    let root_directory = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = std::fs::canonicalize(root_directory).unwrap().join(format!(
        "guard-worktree-remote-branch-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let repository = root.join("repository");
    std::fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "--quiet", "-b", "main"]);
    git(&repository, &["config", "user.name", "Guard Fixture"]);
    git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(
        &repository,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/app-portal.git",
        ],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&repository, &["add", "tracked.txt"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &repository,
        &["update-ref", "refs/remotes/origin/feat/remote-only", "HEAD"],
    );
    (repository, FixtureCleanup(root))
}

fn decide(repository: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        repository.parent().unwrap().to_str(),
        repository.to_str(),
    )
}

fn add_command(repository: &Path, name: &str) -> (PathBuf, String) {
    let destination = repository.parent().unwrap().join("remote-child");
    let command = format!("git worktree add {} {name}", destination.display());
    (destination, command)
}

#[test]
fn a_branch_only_one_remote_has_is_checked_out_without_review() {
    let (repository, _cleanup) = repository("unique");
    let (destination, command) = add_command(&repository, "feat/remote-only");
    let result = decide(&repository, &command);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    assert_eq!(result.reason_code, "native_exact_safe_worktree_add");

    // Git does what the proof modelled: a new local branch tracking origin.
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            destination.to_str().unwrap(),
            "feat/remote-only",
        ],
    );
    let upstream = git(
        &destination,
        &["rev-parse", "--abbrev-ref", "feat/remote-only@{upstream}"],
    );
    assert_eq!(upstream.stdout, b"origin/feat/remote-only\n");
}

#[test]
fn a_branch_no_remote_has_fails_without_review() {
    let (repository, _cleanup) = repository("missing");
    let (destination, command) = add_command(&repository, "feat/nowhere");
    let result = decide(&repository, &command);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);

    // Git refuses the name before it writes anything.
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", repository.parent().unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "worktree",
            "add",
            destination.to_str().unwrap(),
            "feat/nowhere",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!destination.exists());
}

#[test]
fn a_branch_two_remotes_have_still_waits_for_review() {
    let (repository, _cleanup) = repository("ambiguous");
    git(
        &repository,
        &[
            "remote",
            "add",
            "upstream",
            "https://example.invalid/upstream.git",
        ],
    );
    git(
        &repository,
        &[
            "update-ref",
            "refs/remotes/upstream/feat/remote-only",
            "HEAD",
        ],
    );
    let (_, command) = add_command(&repository, "feat/remote-only");
    assert_ne!(decide(&repository, &command).minimum_action, "allow");
}

#[test]
fn a_remote_with_a_custom_fetch_mapping_still_waits_for_review() {
    let (repository, _cleanup) = repository("refspec");
    git(
        &repository,
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/mirror/*",
        ],
    );
    git(
        &repository,
        &["update-ref", "refs/remotes/mirror/feat/remote-only", "HEAD"],
    );
    let (_, command) = add_command(&repository, "feat/remote-only");
    assert_ne!(decide(&repository, &command).minimum_action, "allow");
}

#[test]
fn a_post_checkout_hook_still_waits_for_review() {
    let (repository, _cleanup) = repository("hook");
    let hook = repository.join(".git/hooks/post-checkout");
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (_, command) = add_command(&repository, "feat/remote-only");
    assert_ne!(decide(&repository, &command).minimum_action, "allow");
}
