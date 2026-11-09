//! A repository that keeps its Git hooks inside itself must still start the
//! checkouts its user allowed.
//!
//! husky, lefthook and pre-commit all write `core.hooksPath` into the
//! repository's own configuration, and the value Git stores is relative to the
//! repository root. Guard protects any directory that holds the configured
//! hooks directory, so such a repository's root reads as protected — and the
//! checkout floor screened the working directory of every Git checkout step,
//! not just the one `git init` turns into a checkout. Every `git worktree
//! add`, `git clone` and `git submodule add` the repository started was then a
//! protected destination, which the extension-permission doors refuse to
//! settle, so the user's Allow on the Git extension could not take effect.
//!
//! The hooks directory itself, and the locations Guard always protects, stay
//! out of reach of that Allow.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

/// `root/project` on `main`, one commit deep, with a GitHub `origin`. With
/// `relative_hooks`, the checkout's own configuration points `core.hooksPath`
/// at a directory inside the checkout, the way a hook manager installs it.
fn checkout(label: &str, relative_hooks: bool) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-relative-hooks-{label}-{}",
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
    if relative_hooks {
        std::fs::create_dir_all(project.join(".githooks")).unwrap();
        fixture::git(&root, &project, &["config", "core.hooksPath", ".githooks"]);
    }
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

/// The checkouts a developer starts from the repository they are working in.
/// Each names where the tree lands, so the repository's own root is not the
/// destination and its hooks configuration says nothing about them.
const CHECKOUTS: &[&str] = &[
    "git worktree add -b fix/report-icons ../project-icons origin/main",
    "git fetch origin --quiet && git worktree add -b fix/report-icons ../project-icons origin/main",
    "git status --porcelain | head -5 && git fetch origin --quiet \
     && git worktree add -b fix/report-icons ../project-icons origin/main 2>&1 | tail -2",
    "git worktree add -b fix/lane-a ../project-a origin/main \
     && git worktree add -b fix/lane-b ../project-b origin/main",
    "git clone https://github.com/example-org/service-api.git ../service-api",
    "git submodule add https://github.com/example-org/service-api.git vendor/service-api",
];

#[test]
fn an_allowed_checkout_runs_from_a_repository_that_keeps_its_hooks_inside_itself() {
    let (root, _cleanup) = checkout("allow", true);
    let controls = fixture::every_permission_enabled();
    let mut failures = Vec::new();
    for harness in HARNESSES {
        for command in CHECKOUTS {
            let result = decide(&root, harness, command, &controls);
            if result.decision != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {} {}",
                    result.decision, result.reason_code, result.reason
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The same commands in a repository that configures no hooks directory of
/// its own. They allowed before the floor was corrected, and the case above
/// must now match them.
#[test]
fn the_same_checkouts_allow_without_a_hooks_configuration() {
    let (root, _cleanup) = checkout("plain", false);
    let controls = fixture::every_permission_enabled();
    let mut failures = Vec::new();
    for harness in HARNESSES {
        for command in CHECKOUTS {
            let result = decide(&root, harness, command, &controls);
            if result.decision != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {}",
                    result.decision, result.reason_code
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A checkout into the configured hooks directory writes the programs Git
/// runs for the repository, and a checkout into the locations Guard loads
/// from is never the user's ordinary work. No extension permission settles
/// either one.
#[test]
fn a_checkout_into_the_hooks_directory_is_still_reviewed() {
    let (root, _cleanup) = checkout("protected", true);
    let controls = fixture::every_permission_enabled();
    let home = root.to_str().unwrap().to_owned();
    let commands = [
        "git worktree add -b fix/hooks-review .githooks/review origin/main".to_owned(),
        "git init .githooks/fresh".to_owned(),
        "git clone https://github.com/example-org/service-api.git .githooks/service-api".to_owned(),
        format!("git worktree add -b fix/agents {home}/.claude/agents origin/main"),
        format!(
            "git clone https://github.com/example-org/service-api.git {home}/.codex/service-api"
        ),
    ];
    let mut allowed = Vec::new();
    for harness in HARNESSES {
        for command in &commands {
            let result = decide(&root, harness, command, &controls);
            if result.decision == "allow" {
                allowed.push(format!("{harness}: {command}: {}", result.reason_code));
            }
        }
    }
    assert!(allowed.is_empty(), "{allowed:#?}");
}
