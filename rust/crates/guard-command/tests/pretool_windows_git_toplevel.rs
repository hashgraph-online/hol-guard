#![cfg(windows)]
//! `cd $(git rev-parse --show-toplevel) && ...` is how an agent returns to the
//! root of the repository it is working in. Resolving that substitution walks
//! up from the working directory to the nearest `.git`, the way Git finds it,
//! and two steps of that walk read the file system through Unix-only calls: a
//! device number for the filesystem edge Git stops at, and `st_uid` for the
//! ownership Git requires. Both returned nothing off Unix, so the walk ended
//! before it began and every such command was reviewed. The root it prints is
//! also canonical, which on Windows carries the `\\?\` prefix no shell reads.
//!
//! Each case compares the substitution with the literal path it stands for. A
//! command that resolves is judged exactly as the spelled-out `cd` is; one
//! that does not stays opaque, and is reviewed.

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod git_helper_fixture;

use git_helper_fixture::canonical_spelling;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(repository: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "{arguments:?}");
}

/// The drive path an agent writes: forward slashes, no verbatim prefix.
fn spelled(path: &Path) -> String {
    canonical_spelling(path)
        .to_str()
        .unwrap()
        .replace('\\', "/")
}

struct Layout {
    /// Kept so the fixture outlives the test. It is a system temporary
    /// directory, deliberately not the build tree: everything under the
    /// checkout has this repository's own `.git` above it, so a case about a
    /// directory under no repository could not be built there.
    _root: tempfile::TempDir,
    home: PathBuf,
    /// The repository root `git rev-parse --show-toplevel` prints.
    repository: PathBuf,
    /// A directory inside the repository, where the session stands.
    inside: PathBuf,
    /// A plain directory with no `.git` above it.
    plain: PathBuf,
}

fn layout(name: &str) -> Layout {
    let holder = tempfile::Builder::new()
        .prefix(&format!("guard-win-toplevel-{name}-"))
        .tempdir()
        .unwrap();
    // The walk compares canonical paths, and the temporary root is reached
    // through a link on some hosts.
    let root = holder.path().canonicalize().unwrap();
    assert!(
        !root.ancestors().any(|folder| folder.join(".git").exists()),
        "the fixture root has a repository above it: {}",
        root.display(),
    );
    let home = root.join("home");
    let repository = home.join("work");
    let inside = repository.join("src/deep");
    let plain = home.join("plain-notes");
    for directory in [&inside, &plain] {
        std::fs::create_dir_all(directory).unwrap();
    }
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Guard Fixture"]);
    git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("README.md"), "# fixture\n").unwrap();
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(plain.join("a.md"), "notes\n").unwrap();
    Layout {
        _root: holder,
        home,
        repository,
        inside,
        plain,
    }
}

/// The decision for `command` run from `cwd`.
fn action(layout: &Layout, cwd: &Path, command: &str) -> String {
    let home = spelled(&layout.home);
    let cwd = spelled(cwd);
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["GIT_CONFIG_NOSYSTEM", "HOME", "PATH"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.clone()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let controls = git_helper_fixture::github_controls("enabled");
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            cdpath_unset: true,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&environment),
    );
    format!("{} {}", result.minimum_action, result.reason_code)
}

/// The work an agent does after returning to the root, each step judged on
/// the path the substitution names.
const AFTER: &[&str] = &["cat README.md", "ls", "cat ./README.md", "wc -l README.md"];

#[test]
fn returning_to_the_repository_root_is_read_as_the_path_it_names() {
    let layout = layout("resolves");
    let root = spelled(&layout.repository);
    for after in AFTER {
        let substituted = action(
            &layout,
            &layout.inside,
            &format!("cd $(git rev-parse --show-toplevel) && {after}"),
        );
        let literal = action(&layout, &layout.inside, &format!("cd {root} && {after}"));
        // Equality alone would pass with both forms reviewed, which is the
        // state this test exists to rule out. The spelled-out `cd` has to
        // reach a verdict the pass actually resolved before the substitution
        // is held to it.
        assert!(
            !literal.starts_with("review") && !literal.starts_with("ask"),
            "`cd {root} && {after}` was not resolved, so it cannot stand in for the substitution: {literal}",
        );
        assert_eq!(
            substituted, literal,
            "`{after}` after the substitution reads differently from `cd {root}`",
        );
    }
}

/// The session already standing at the root walks no further than itself.
#[test]
fn the_root_itself_resolves_to_the_same_directory() {
    let layout = layout("at-root");
    let root = spelled(&layout.repository);
    let substituted = action(
        &layout,
        &layout.repository,
        "cd $(git rev-parse --show-toplevel) && cat README.md",
    );
    let literal = action(
        &layout,
        &layout.repository,
        &format!("cd {root} && cat README.md"),
    );
    assert!(
        !literal.starts_with("review") && !literal.starts_with("ask"),
        "`cd {root} && cat README.md` was not resolved: {literal}",
    );
    assert_eq!(substituted, literal);
}

/// Outside a repository the substitution has no value to stand for, so the
/// command stays opaque rather than resolving to the wrong directory.
#[test]
fn a_directory_under_no_repository_keeps_the_substitution_opaque() {
    let layout = layout("no-repository");
    let plain = spelled(&layout.plain);
    let substituted = action(
        &layout,
        &layout.plain,
        "cd $(git rev-parse --show-toplevel) && cat a.md",
    );
    let literal = action(&layout, &layout.plain, &format!("cd {plain} && cat a.md"));
    assert_ne!(
        substituted, literal,
        "a substitution with no root behind it was read as a known directory",
    );
    assert!(
        substituted.starts_with("review") || substituted.starts_with("ask"),
        "unresolved substitution was not reviewed: {substituted}",
    );
}

/// A `.git` this pass cannot prove Git reads as the worktree keeps the value
/// unknown rather than walking past it the way Git would.
#[test]
fn a_git_marker_that_is_not_a_plain_repository_stays_unknown() {
    let layout = layout("odd-marker");
    let odd = layout.home.join("odd");
    std::fs::create_dir_all(&odd).unwrap();
    // A `.git` that is neither a directory nor a `gitdir:` file.
    std::fs::write(odd.join(".git"), "not a gitdir line\n").unwrap();
    let inside = odd.join("src");
    std::fs::create_dir_all(&inside).unwrap();
    let decision = action(
        &layout,
        &inside,
        "cd $(git rev-parse --show-toplevel) && ls",
    );
    assert!(
        decision.starts_with("review") || decision.starts_with("ask"),
        "an unreadable `.git` resolved anyway: {decision}",
    );
}
