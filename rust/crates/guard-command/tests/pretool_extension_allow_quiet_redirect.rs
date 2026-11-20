//! A quiet redirect beside the user's Git Allow.
//!
//! `2>/dev/null`, `>/dev/null` and `2>&1` open no file. They discard output or
//! point one descriptor at another, so the command runs exactly the programs
//! the same text without them runs. Guard still read them as redirects: the
//! workspace route claimed the command for its sandbox, and the projection
//! that removed them was outranked by a second evaluation that runs without
//! the caller's command extensions. Either one withdrew the user's own Git
//! Allow, so `git checkout -q main 2>/dev/null` asked while
//! `git checkout -q main` ran.
//!
//! A redirect that does open a file keeps its review: the write is a real
//! effect the Allow does not cover.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

/// `root/project` on `main`, one commit deep, with a GitHub `origin` so the
/// Git steps beside the redirect have something to report.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-quiet-redirect-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    fixture::git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    fixture::git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    fixture::git(
        &root,
        &project,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app-portal.git",
        ],
    );
    std::fs::write(project.join("src/index.ts"), "export const a = 1;\n").unwrap();
    fixture::git(&root, &project, &["add", "-A"]);
    fixture::git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn decide(
    root: &Path,
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

/// Discarding output costs the command nothing, so the Allow that covers the
/// bare command covers the same command beside a quiet redirect.
#[test]
fn a_redirect_that_opens_no_file_keeps_the_users_git_allow() {
    let (root, _cleanup) = checkout("allow");
    let controls = fixture::every_permission_enabled();
    for command in [
        "git checkout -q main",
        "git checkout -q main 2>/dev/null",
        "git checkout -q main 2> /dev/null",
        "git checkout -q main >/dev/null",
        "git checkout -q main >/dev/null 2>&1",
        "git checkout -q main 2>&1",
        "git checkout -q main; git log -1 --oneline",
        "git checkout -q main 2>/dev/null; git log -1 --oneline",
        "git checkout -q main >/dev/null; git log -1 --oneline",
        "git add -A 2>/dev/null; git log -1 --oneline",
        "git worktree prune 2>/dev/null && git worktree list",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command} -> {}",
                result.reason_code
            );
        }
    }
}

/// A redirect that opens a file outside the project writes where the Allow
/// never reached, so the review it earns stays.
#[test]
fn a_redirect_that_writes_outside_the_project_still_asks() {
    let (root, _cleanup) = checkout("review");
    let controls = fixture::every_permission_enabled();
    for command in [
        "git log -1 --oneline > ../outside.txt",
        "git checkout -q main 2>/dev/null > ../outside.txt",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(
                result.decision, "allow",
                "{harness}: {command} -> {}",
                result.reason_code
            );
        }
    }
}
