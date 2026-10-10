use serde_json::json;
use std::path::Path;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

const LFS_CONFIG: &str = "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n";

fn git(directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn decide(cwd: &Path, home: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn checkout(
    name: &str,
) -> (
    fixture::FixtureCleanup,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let root = std::env::temp_dir().join(format!(
        "guard-nested-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cleanup = fixture::FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::write(home.join(".gitconfig"), LFS_CONFIG).unwrap();
    git(&repository, &["init", "--quiet"]);
    std::fs::write(repository.join("tracked.txt"), "tracked fixture\n").unwrap();
    git(&repository, &["add", "tracked.txt"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    (cleanup, home, repository)
}

const READS: [&str; 3] = [
    "git status --short",
    "git diff --stat",
    "git diff --no-ext-diff --no-textconv",
];

fn assert_reads(cwd: &Path, home: &Path, allowed: bool) {
    for command in READS {
        let result = decide(cwd, home, command);
        assert_eq!(
            result.decision == "allow",
            allowed,
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn untracked_nested_repository_does_not_block_reads_with_global_lfs_filters() {
    let (_cleanup, home, repository) = checkout("nested");
    let child = repository.join("child-tool");
    std::fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "--quiet"]);
    std::fs::write(child.join("file.txt"), "child fixture\n").unwrap();
    assert_reads(&repository, &home, true);
}

#[test]
fn untracked_linked_worktree_does_not_block_reads_with_global_lfs_filters() {
    let (_cleanup, home, repository) = checkout("linked");
    let worktree = repository.join("agent-worktree");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "agent",
            worktree.to_str().unwrap(),
        ],
    );
    assert_reads(&repository, &home, true);
}

#[test]
fn linked_worktree_target_from_parent_directory_is_routed() {
    let (_cleanup, home, repository) = checkout("route");
    let parent = home.join("worktrees");
    std::fs::create_dir_all(&parent).unwrap();
    let worktree = parent.join("feature-x");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature",
            worktree.to_str().unwrap(),
        ],
    );
    let result = decide(&parent, &home, "git -C feature-x status --short");
    assert_eq!(result.decision, "allow", "{}", result.reason_code);
    let inside = decide(&worktree, &home, "git status --short");
    assert_eq!(inside.decision, "allow", "{}", inside.reason_code);
    // A worktree registered by the working directory's repository is routable
    // even when its path is outside the working directory.
    let target = worktree.display();
    for command in [
        format!("git -C '{target}' status --short"),
        format!("git -C '{target}' log -1 --format='%h %an <%ae> %cn <%ce>'"),
        format!("git -C '{target}' show --stat --format='%h %s' HEAD"),
    ] {
        let result = decide(&repository, &home, &command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        format!("git -C '{target}' commit --allow-empty -m fixture"),
        format!("git -C '{target}' hash-object -w tracked.txt"),
    ] {
        let result = decide(&repository, &home, &command);
        assert_ne!(result.decision, "allow", "{command}");
    }
    // An unrelated repository and an unregistered copy of the pointer stay reviewed.
    let other = home.join("other-repository");
    std::fs::create_dir_all(&other).unwrap();
    git(&other, &["init", "--quiet"]);
    let forged = home.join("forged-worktree");
    std::fs::create_dir_all(&forged).unwrap();
    std::fs::copy(worktree.join(".git"), forged.join(".git")).unwrap();
    for path in [&other, &forged] {
        let command = format!("git -C '{}' status --short", path.display());
        let result = decide(&repository, &home, &command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn nested_repository_cannot_hide_filter_attributes_or_gitlinks() {
    let (_cleanup, home, repository) = checkout("negatives");
    let child = repository.join("child-tool");
    std::fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "--quiet"]);
    std::fs::write(repository.join(".gitattributes"), "* filter=lfs\n").unwrap();
    assert_reads(&repository, &home, false);
    std::fs::write(repository.join(".gitattributes"), "").unwrap();
    assert_reads(&repository, &home, true);
    git(
        &repository,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,module",
        ],
    );
    std::fs::create_dir_all(repository.join("module")).unwrap();
    for command in ["git status --short", "git diff --stat"] {
        let result = decide(&repository, &home, command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn nested_repository_cannot_hide_execution_configuration() {
    let (_cleanup, home, repository) = checkout("config");
    let child = repository.join("child-tool");
    std::fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "--quiet"]);
    for (command, _) in [
        ("git -c core.fsmonitor=./hook status --short", ()),
        ("git -c diff.external=./hook diff --stat", ()),
        ("git --exec-path=./helpers status --short", ()),
    ] {
        let result = decide(&repository, &home, command);
        assert_ne!(result.decision, "allow", "{command}");
    }
    git(&repository, &["config", "core.fsmonitor", "./hook"]);
    let result = decide(&repository, &home, "git status --short");
    assert_ne!(result.decision, "allow", "repo-local fsmonitor");
    git(&repository, &["config", "--unset", "core.fsmonitor"]);
    git(&repository, &["config", "diff.external", "./hook"]);
    let result = decide(&repository, &home, "git diff --stat");
    assert_ne!(
        result.decision, "allow",
        "diff.external without --no-ext-diff"
    );
}
