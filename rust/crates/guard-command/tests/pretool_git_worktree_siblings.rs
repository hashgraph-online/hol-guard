#![cfg(unix)]

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

fn directory(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
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

/// A checkout outside home may get a sibling worktree below the shared
/// temporary directory, but only where no other user could have placed or
/// redirected a directory on the way. Directly in the sticky root, only a
/// leaf that does not exist yet is admitted.
#[test]
fn worktree_add_admits_fresh_temporary_siblings_only() {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-siblings-{unique}"));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let organization = root.join("org");
    let repository = organization.join("app");
    for path in [&root, &home, &organization, &repository] {
        directory(path, 0o755);
    }
    git(&home, &repository, &["init", "--quiet"]);
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

    // `git lfs install` writes this filter to the user's configuration.
    std::fs::write(
        home.join(".gitconfig"),
        "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n",
    )
    .unwrap();
    for (index, destination) in [
        organization.join("app-next").display().to_string(),
        "../app-relative".to_owned(),
        organization.join("missing/next").display().to_string(),
        format!("/tmp/guard-worktree-direct-{unique}"),
    ]
    .iter()
    .enumerate()
    {
        let command = format!("git worktree add {destination} -b sibling-{index} HEAD");
        let result = evaluate(&home, &repository, &command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
        if index == 2 {
            git(
                &home,
                &repository,
                &[
                    "worktree",
                    "add",
                    "--quiet",
                    destination,
                    "-b",
                    "sibling-2",
                    "HEAD",
                ],
            );
            assert!(organization.join("missing/next/tracked.txt").is_file());
        }
    }

    directory(&root.join("shared"), 0o777);
    directory(&root.join("group"), 0o775);
    directory(&root.join(".hidden"), 0o755);
    directory(&organization.join("existing"), 0o755);
    directory(&organization.join(".github"), 0o755);
    directory(&home.join("Library/LaunchAgents"), 0o755);
    let redirected = link(&organization, "redirected", &root.join("shared"));
    for destination in [
        root.join("shared/next"),
        root.join("group/next"),
        root.join(".hidden/next"),
        organization.join(".next"),
        organization.join("existing"),
        organization.join(".github/workflows"),
        root.join("shared/missing/next"),
        root.join("group/missing/next"),
        root.join(".hidden/missing/next"),
        organization.join(".git/missing/next"),
        organization.join(".github/workflows/missing/next"),
        redirected.join("missing/next"),
        std::path::PathBuf::from(format!("/tmp/guard-uncreated-{unique}/parent/next")),
        // An autostart location stays reviewed below an owned temporary root.
        home.join("Library/LaunchAgents/next"),
        // Directly in the shared root, a directory that already exists.
        root.clone(),
    ] {
        let command = format!("git worktree add {} -b refused HEAD", destination.display());
        let result = evaluate(&home, &repository, &command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

fn link(directory: &Path, name: &str, target: &Path) -> std::path::PathBuf {
    let path = directory.join(name);
    std::os::unix::fs::symlink(target, &path).unwrap();
    path
}

/// A destination reached through a symlink, as `/tmp` is on macOS, is
/// judged where the link leads, exactly as if that path had been spelled.
/// A link into an autostart, workflow or credential directory, or out to a
/// directory others can write, keeps review, as does a link another user
/// could swap before Git runs.
#[test]
fn worktree_add_judges_a_symlinked_parent_where_it_leads() {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-symlinked-{unique}"));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let organization = root.join("org");
    let repository = organization.join("app");
    for path in [&root, &home, &organization, &repository] {
        directory(path, 0o755);
    }
    git(&home, &repository, &["init", "--quiet"]);
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

    let alias = link(&root, "alias", &organization);
    let nested = link(&root, "nested", &root);
    for (index, destination) in [alias.join("app-aliased"), nested.join("org/app-nested")]
        .iter()
        .enumerate()
    {
        let command = format!(
            "git worktree add {} -b aliased-{index} HEAD",
            destination.display()
        );
        let result = evaluate(&home, &repository, &command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }

    directory(&home.join("Library/LaunchAgents"), 0o755);
    directory(&home.join(".ssh"), 0o700);
    directory(&repository.join(".github"), 0o755);
    directory(&root.join("shared"), 0o777);
    directory(&root.join("swappable"), 0o777);
    let swappable = link(&root.join("swappable"), "org", &organization);
    for destination in [
        link(&root, "launch", &home.join("Library/LaunchAgents")).join("next"),
        link(&repository, "scratch", &home.join(".ssh")).join("next"),
        link(&root, "github", &repository.join(".github")).join("workflows"),
        link(&root, "shared-alias", &root.join("shared")).join("next"),
        link(&root, "system", Path::new("/usr")).join("next"),
        // The link leads to `org`, but another user could replace it.
        swappable.join("next"),
    ] {
        let command = format!("git worktree add {} -b refused HEAD", destination.display());
        let result = evaluate(&home, &repository, &command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

/// The repository may not set a filter or name an LFS program of its own.
#[test]
fn worktree_add_keeps_repository_filters_reviewed() {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-filters-{unique}"));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = home.join("org/app");
    for path in [&root, &home, &repository] {
        directory(path, 0o755);
    }
    git(&home, &repository, &["init", "--quiet"]);
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
    for (index, (key, value)) in [
        ("filter.lfs.smudge", "git-lfs smudge -- %f"),
        ("filter.x.smudge", "sh -c id"),
        ("lfs.customtransfer.x.path", "/bin/sh"),
    ]
    .iter()
    .enumerate()
    {
        git(&home, &repository, &["config", key, value]);
        let command = format!("git worktree add ../app-{index} -b filtered-{index} HEAD");
        let result = evaluate(&home, &repository, &command);
        assert_ne!(result.minimum_action, "allow", "{key}");
        git(&home, &repository, &["config", "--unset", key]);
    }
}

/// Checking out a branch that already exists into a fresh directory beside
/// the checkout is the same action whether the target is spelled from the
/// root or relative to the session, and whatever trails it in a pipe.
#[test]
fn worktree_add_attaches_an_existing_branch_beside_the_checkout() {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let base = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    std::fs::create_dir_all(&base).unwrap();
    let root = std::fs::canonicalize(base)
        .unwrap()
        .join(format!("guard-worktree-attach-{unique}"));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let code = home.join("code");
    let repository = code.join("app");
    let session = code.join("app-feature");
    for path in [&root, &home, &code, &repository, &home.join("org")] {
        directory(path, 0o755);
    }
    git(&home, &repository, &["init", "--quiet"]);
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
    git(&home, &repository, &["branch", "feat/other-branch"]);
    git(
        &home,
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature",
            "../app-feature",
        ],
    );

    for command in [
        format!(
            "git worktree add {} feat/other-branch",
            home.join("org/app-fixup").display()
        ),
        format!(
            "git worktree add {} feat/other-branch 2>&1 | tail -2",
            repository.join("wt-x").display()
        ),
        "git worktree add ../wt-y feat/other-branch 2>&1 | tail -2".to_owned(),
        "git worktree add ../wt-z -b feat/y 2>&1 | tail -2".to_owned(),
    ] {
        let result = evaluate(&home, &session, &command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }

    directory(&home.join(".config"), 0o755);
    directory(&home.join("Library/LaunchAgents"), 0o755);
    // A link out of home into a directory every user can write.
    directory(&root.join("elsewhere"), 0o777);
    std::os::unix::fs::symlink(root.join("elsewhere"), code.join("linked")).unwrap();
    for command in [
        format!(
            "git worktree add {} feat/other-branch",
            home.join(".config/app").display()
        ),
        format!(
            "git worktree add {} feat/other-branch",
            home.join("Library/LaunchAgents/next").display()
        ),
        format!(
            "git worktree add {} feat/other-branch",
            code.join("linked/wt").display()
        ),
    ] {
        let result = evaluate(&home, &session, &command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}
