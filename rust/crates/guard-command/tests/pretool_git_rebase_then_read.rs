//! A rebase onto a fetched branch, followed by a Git read, is ordinary
//! refresh work. A plain rebase rewrites commits and the index; it never
//! writes the configuration the read was proven against. The forms that can
//! run arbitrary commands between picks (`--exec`, `-x`, `--interactive`,
//! `-i`, `--edit-todo`, `--continue`, `--skip`) could, so they keep the read
//! under review.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(home: &Path, directory: &Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `root/project` on `main`, one commit deep, with a GitHub `origin`.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-git-rebase-then-read-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    git(&root, &project, &["init", "--quiet", "-b", "main"]);
    git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(
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
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn every_permission(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":state})
        })
        .collect();
    let value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":controls
        }]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
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

const PLAIN_REBASE_THEN_READ: &[&str] = &[
    "git rebase -q origin/main && git log --oneline -1",
    "git rebase -q origin/main; git log --oneline -3",
    "git rebase -q origin/main && git status --short",
    "git rebase --autostash origin/main && git status -sb",
    "git fetch origin main && git rebase origin/main && git log --oneline -5",
];

#[test]
fn an_allowed_plain_rebase_carries_the_read_after_it() {
    let (root, _cleanup) = checkout("plain");
    let controls = every_permission("enabled");
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in PLAIN_REBASE_THEN_READ {
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

const REBASE_THAT_RUNS_COMMANDS: &[&str] = &[
    "git rebase -x 'make' origin/main && git log --oneline -1",
    "git rebase --exec 'make' origin/main && git status --short",
    "git rebase -i origin/main && git log --oneline -1",
    "git rebase --continue && git log --oneline -3",
    "git rebase --cont && git log --oneline -3",
    "git rebase --skip && git status --short",
    "git rebase --ski && git status --short",
];

#[test]
fn a_rebase_that_runs_commands_keeps_the_read_reviewed() {
    let (root, _cleanup) = checkout("exec");
    let controls = every_permission("enabled");
    let mut allowed = Vec::new();
    for command in REBASE_THAT_RUNS_COMMANDS {
        let result = decide(&root, "claude-code", command, &controls);
        if result.decision == "allow" {
            allowed.push(*command);
        }
    }
    assert!(allowed.is_empty(), "{allowed:#?}");
}
