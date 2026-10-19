#![cfg(unix)]

//! A long-lived repository keeps a `branch.<name>` section for every branch a
//! worktree was ever created on. The `worktree add` proof still judges every
//! entry of a listing that large, so a program-running setting at its end, or
//! an executable `post-checkout` hook, keeps the review.

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Well past the 64 KiB the proof used to stop reading at.
const TRACKED_BRANCHES: usize = 3_000;

fn git(repository: &Path, arguments: &[&str]) {
    let home = repository.parent().unwrap();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

fn evaluate(repository: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    let home = repository.parent().unwrap();
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        repository.to_str(),
    )
}

fn fixture_root() -> PathBuf {
    let base = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    std::fs::canonicalize(base).unwrap().join(format!(
        "guard-git-worktree-large-config-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn append_config(repository: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(repository.join(".git/config"))
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

#[test]
fn worktree_add_is_proven_in_a_repository_with_many_tracked_branches() {
    let root = fixture_root();
    let _cleanup = FixtureCleanup(root.clone());
    let repository = root.join("app-portal");
    std::fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "--quiet", "--initial-branch=main"]);
    git(&repository, &["config", "user.name", "Guard Fixture"]);
    git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("README.md"), "# app-portal\n").unwrap();
    git(&repository, &["add", "README.md"]);
    git(&repository, &["commit", "--quiet", "-m", "base"]);
    git(&repository, &["branch", "feature/report-fix"]);
    git(
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let sections: String = (0..TRACKED_BRANCHES)
        .map(|index| {
            format!(
                "[branch \"fix/report-window-{index:05}\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
            )
        })
        .collect();
    append_config(&repository, &sections);
    assert!(
        std::fs::metadata(repository.join(".git/config"))
            .unwrap()
            .len()
            > 128 * 1024
    );

    let existing = format!(
        "git -C {} worktree add {} feature/report-fix",
        repository.display(),
        root.join("app-portal-report-fix").display()
    );
    let result = evaluate(&repository, &existing);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);

    let fresh = format!(
        "git -C {} worktree add {} -b feature/report-followup origin/main",
        repository.display(),
        root.join("app-portal-followup").display()
    );
    let result = evaluate(&repository, &fresh);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);

    // A program-running setting after every branch section is still read.
    let tripwire = root.join("fsmonitor-tripwire");
    append_config(
        &repository,
        &format!("[core]\n\tfsmonitor = {}\n", tripwire.display()),
    );
    let result = evaluate(&repository, &fresh);
    assert_ne!(result.minimum_action, "allow", "{fresh}");
    git(&repository, &["config", "--unset", "core.fsmonitor"]);
    assert_eq!(evaluate(&repository, &fresh).minimum_action, "allow");

    // An executable post-checkout hook would run in the new checkout.
    let hook = repository.join(".git/hooks/post-checkout");
    std::fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", tripwire.display())).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = evaluate(&repository, &existing);
    assert_ne!(result.minimum_action, "allow", "{existing}");
    assert!(!tripwire.exists());
}
