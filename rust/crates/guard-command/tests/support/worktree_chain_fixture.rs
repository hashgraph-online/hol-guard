//! A worktree-chain fixture: `org/app` below a fresh home, and the
//! allow/review assertions the chain proof's tests make against it.
#![cfg(unix)]

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn evaluate(home: &Path, cwd: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

pub fn directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

pub fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

/// `org/app` below a fresh home, with a remote-tracking `origin/main`, a
/// sibling repository and a symlink beside it that leads out of `org` into a
/// directory every user can write, where no checkout is admitted.
pub fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let organization = home.join("org");
    let repository = organization.join("app");
    for path in [&root, &home, &organization, &repository] {
        directory(path);
    }
    git(
        &home,
        &repository,
        &["init", "--quiet", "--initial-branch=main"],
    );
    git(
        &home,
        &repository,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &home,
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&home, &repository, &["add", "tracked.txt"]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let sibling = organization.join("service");
    directory(&sibling);
    git(&home, &sibling, &["init", "--quiet"]);
    directory(&root.join("elsewhere"));
    std::fs::set_permissions(
        root.join("elsewhere"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("elsewhere"), organization.join("link")).unwrap();
    (cleanup, home, repository)
}

pub fn assert_allowed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

pub fn assert_reviewed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}

/// The verdict for `command`, for a shell whose search path carries `extra`
/// ahead of the host's own entries.
pub fn evaluate_on_search_path(
    home: &Path,
    cwd: &Path,
    extra: &Path,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let host = std::env::var("PATH").unwrap();
    let path = format!("{}:{host}", extra.display());
    fixture::evaluate_on_path(
        ("omp", "PreToolUse"),
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        (Some(&fixture::github_controls("enabled")), None),
        (home.to_str(), cwd.to_str(), true),
        path,
    )
}

/// As [`assert_allowed`], on a search path that carries `extra`.
pub fn assert_allowed_on_search_path(home: &Path, cwd: &Path, extra: &Path, command: &str) {
    let result = evaluate_on_search_path(home, cwd, extra, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

/// As [`assert_reviewed`], on a search path that carries `extra`.
pub fn assert_reviewed_on_search_path(home: &Path, cwd: &Path, extra: &Path, command: &str) {
    let result = evaluate_on_search_path(home, cwd, extra, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}
