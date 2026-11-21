#![cfg(unix)]

//! `git worktree add <path> <ref> && ln -s <dir> <path>/<sub>/<name>`: a
//! dependency directory shared with the checkout the same command creates.

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn evaluate(home: &Path, cwd: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
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

fn directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

/// `org/app` below a fresh home: a tracked `dashboard` directory holding a
/// tracked `vendor` directory and `index.js`, a tracked link `linked ->
/// dashboard`, and ignored `node_modules` directories installed at the root
/// and in `dashboard`. A directory outside the repository stands beside it.
fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-link-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = home.join("org/app");
    for path in [&root, &home, &repository] {
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
    directory(&repository.join("dashboard/vendor"));
    std::fs::write(repository.join("dashboard/index.js"), "\n").unwrap();
    std::fs::write(repository.join("dashboard/vendor/keep.txt"), "\n").unwrap();
    std::fs::write(repository.join(".gitignore"), "node_modules/\n").unwrap();
    std::os::unix::fs::symlink("dashboard", repository.join("linked")).unwrap();
    git(&home, &repository, &["add", "."]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    directory(&repository.join("node_modules/vitest"));
    directory(&repository.join("dashboard/node_modules/vite"));
    directory(&home.join("org/outside/node_modules"));
    (cleanup, home, repository)
}

fn assert_allowed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

fn assert_reviewed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}

/// Links into a tracked directory of the new checkout, or its root, under a
/// name the checked-out commit does not track.
#[test]
fn links_into_the_new_worktree_are_allowed() {
    let (_cleanup, home, repository) = repository("allowed");
    let app = repository.display();
    let checkout = home.join("org/app-x");
    let checkout = checkout.display();
    for command in [
        format!("git worktree add {checkout} -b br-x origin/main 2>&1 | tail -1 && ln -s {app}/dashboard/node_modules {checkout}/dashboard/node_modules"),
        format!("git worktree add ../app-x -b br-x origin/main && ln -s {app}/node_modules ../app-x/node_modules"),
        "git worktree add ../app-x -b br-x origin/main && ln -s ../../app/dashboard/node_modules ../app-x/dashboard/node_modules".to_owned(),
        format!("git worktree add ../app-x origin/main && ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/dashboard/node_modules ../app-x/dashboard/node_modules"),
        format!("git worktree add -b br-x ../app-x origin/main && ln -s {app}/node_modules ../app-x/node_modules && git -C ../app-x status --short"),
    ] {
        assert_allowed(&home, &repository, &command);
    }
}

/// A link through a tracked link, onto a tracked name, into a directory the
/// commit does not track, outside the checkout, to a directory of another
/// repository, twice to one path, or after a separator that does not wait
/// for the add keeps its review.
#[test]
fn other_links_after_a_worktree_add_stay_reviewed() {
    let (_cleanup, home, repository) = repository("reviewed");
    let app = repository.display();
    let add = "git worktree add -b br-x ../app-x origin/main";
    for tail in [
        format!("&& ln -s {app}/node_modules ../app-x/linked/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/vendor"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/index.js"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/INDEX.JS"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/missing/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/.cache"),
        format!("&& ln -s {app}/dashboard/node_modules ../elsewhere/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x"),
        "&& ln -s ../../outside/node_modules ../app-x/dashboard/node_modules".to_owned(),
        format!("&& ln -s {app}/.git ../app-x/dashboard/node_modules"),
        format!("&& ln -sf {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/node_modules {}/node_modules", home.join("org/app-x").display()),
        format!("; ln -s {app}/node_modules ../app-x/node_modules"),
        format!("|| ln -s {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && touch ../app-x/node_modules/x"),
    ] {
        assert_reviewed(&home, &repository, &format!("{add} {tail}"));
    }
}

/// A listing through a link the same command just made reads the directory
/// the link points at, which exists now, so it is screened there:
/// `ls -d <checkout>/node_modules/.bin/vitest` confirms the shared launcher.
/// Any other name in the new checkout is not there yet, and a listing before
/// the link, a recursive one or another read through it keeps its review.
#[test]
fn a_listing_through_the_new_link_is_allowed() {
    let (_cleanup, home, repository) = repository("listing");
    let shims = repository.join("node_modules/.bin");
    directory(&shims);
    std::os::unix::fs::symlink("../vitest", shims.join("vitest")).unwrap();
    let app = repository.display();
    let checkout = home.join("org/app-x");
    let checkout = checkout.display();
    let add = format!("git worktree add {checkout} -b br-x origin/main 2>&1 | tail -1");
    let link = format!("ln -s {app}/node_modules {checkout}/node_modules");
    for tail in [
        format!("ls -d {checkout}/node_modules/.bin/vitest"),
        format!("ls -la {checkout}/node_modules/.bin"),
        format!("ls {checkout}/node_modules"),
        "ls -d ../app-x/node_modules/.bin/vitest".to_owned(),
    ] {
        assert_allowed(&home, &repository, &format!("{add} && {link} && {tail}"));
    }
    for tail in [
        format!("ls -R {checkout}/node_modules"),
        format!("ls -d {checkout}/dashboard/.cache"),
        format!("ls -d {checkout}/node_modules/.bin/vitest {checkout}/.git"),
        format!("cat {checkout}/node_modules/.bin/vitest"),
        format!("ls -d {checkout}/node_modules/.bin/vitest > {checkout}/listing.txt"),
    ] {
        assert_reviewed(&home, &repository, &format!("{add} && {link} && {tail}"));
    }
    assert_reviewed(
        &home,
        &repository,
        &format!("{add} && ls -d {checkout}/node_modules/.bin/vitest && {link}"),
    );
}

/// The commit is read whole whatever directory the command runs in: from a
/// subdirectory, a tracked link or directory at the checkout root is still
/// seen as taken.
#[test]
fn a_link_from_a_subdirectory_still_sees_every_tracked_name() {
    let (_cleanup, home, repository) = repository("subdirectory");
    let app = repository.display();
    let cwd = repository.join("dashboard");
    let add = "git worktree add -b br-x ../../app-x origin/main";
    assert_allowed(
        &home,
        &cwd,
        &format!("{add} && ln -s {app}/node_modules ../../app-x/node_modules"),
    );
    for tail in [
        format!("&& ln -s {app}/node_modules ../../app-x/linked"),
        format!("&& ln -s {app}/node_modules ../../app-x/dashboard"),
        format!("&& ln -s {app}/node_modules ../../app-x/.gitignore"),
    ] {
        assert_reviewed(&home, &cwd, &format!("{add} {tail}"));
    }
}

/// A commit can track `dashboard/` beside `Dashboard/node_modules`, a link
/// out of the checkout. A case-insensitive filesystem checks both out into
/// one directory, where `ln` would write through that link, so a folder name
/// another tracked entry shares under a different case is not a proven
/// parent. The colliding entries are written straight to the index, so the
/// fixture builds on either kind of filesystem.
#[test]
fn a_folder_sharing_its_name_under_another_case_takes_no_link() {
    let (_cleanup, home, repository) = repository("case-collision");
    let app = repository.display();
    let blob = git_output(&home, &repository, &["hash-object", "-w", ".gitignore"]);
    for (mode, path) in [
        ("120000", "Dashboard/node_modules"),
        ("100644", "web/index.js"),
        ("100644", "WEB.md"),
    ] {
        git(
            &home,
            &repository,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("{mode},{blob},{path}"),
            ],
        );
    }
    git(&home, &repository, &["commit", "--quiet", "-m", "collide"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    let add = "git worktree add -b br-x ../app-x origin/main";
    for tail in [
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/Dashboard/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/web.md"),
    ] {
        assert_reviewed(&home, &repository, &format!("{add} {tail}"));
    }
    // A folder no other entry collides with still takes the link.
    assert_allowed(
        &home,
        &repository,
        &format!("{add} && ln -s {app}/node_modules ../app-x/web/node_modules"),
    );
}

fn git_output(home: &Path, repository: &Path, arguments: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
