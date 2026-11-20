//! Inline `-c <key>=<value>` before an ordinary Git read.
//!
//! Agents routinely take the pager and the colour off a read so the output
//! parses: `git -c core.pager=cat log`, `git -c color.ui=never status`. Those
//! settings start no program and move no repository, so the read they carry is
//! the same read Guard proves without them. Settings that do name a program,
//! or turn on a verification that runs one, keep their review.

use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn git(directory: &std::path::Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("HOME", std::env::temp_dir())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

struct Workspace {
    home: std::path::PathBuf,
    repository: std::path::PathBuf,
}

fn workspace(label: &str) -> (Workspace, FixtureCleanup) {
    let base = if cfg!(unix) {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let root = base.join(format!(
        "guard-inline-config-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = canonical_spelling(root);
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    git(&root, &["init", "--quiet", repository.to_str().unwrap()]);
    std::fs::write(repository.join("README.md"), "# fixture\n").unwrap();
    git(&repository, &["add", "-A"]);
    git(&repository, &["commit", "--quiet", "-m", "base"]);
    (Workspace { home, repository }, FixtureCleanup(root))
}

fn decide(workspace: &Workspace, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        workspace.home.to_str(),
        workspace.repository.to_str(),
    )
}

/// Settings that switch a program off, or name none at all, leave the read
/// allowed.
#[test]
fn inert_inline_settings_leave_an_ordinary_read_allowed() {
    let (space, _cleanup) = workspace("inert");
    for command in [
        "git -c core.pager=cat log --oneline -3",
        "git -c core.pager= log --oneline -3",
        "git -c color.ui=never status --short",
        "git -c color.ui=false status --short",
        "git -c color.ui=always diff --stat",
        "git -c pager.log=false log --oneline -3",
        "git -c core.abbrev=12 log --oneline -3",
        "git -c protocol.version=2 log --oneline -3",
        "git -c core.pager=cat -c color.ui=never log --oneline -5",
        "git --no-pager -c color.ui=never log --oneline -3",
    ] {
        let result = decide(&space, command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
        assert!(result.explicitly_benign, "{command}");
    }
}

/// A setting that names a program, or turns on a verification that runs one,
/// keeps its review however ordinary the subcommand looks.
#[test]
fn an_inline_setting_that_runs_a_program_keeps_its_review() {
    let (space, _cleanup) = workspace("program");
    for command in [
        "git -c core.pager=less log --oneline -3",
        "git -c core.pager=x log",
        // Git compares the pager with `strcmp`, so only a lowercase `cat`
        // means no pager; any other spelling is a program name.
        "git -c core.pager=CAT log --oneline -3",
        "git -c pager.log=Cat log --oneline -3",
        "git -c pager.log=./synthetic-never-execute log --oneline -3",
        "git -c color.ui=./synthetic-never-execute status --short",
        "git -c log.showSignature=true log --oneline -3",
        "git -c diff.external=./synthetic-never-execute diff",
        "git -c alias.l=log l --oneline -3",
    ] {
        let result = decide(&space, command);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
        assert!(!result.explicitly_benign, "{command}");
    }
}
