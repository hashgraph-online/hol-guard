#![cfg(unix)]
//! A checkout, pathspec or remote named after Guard is the user's own work.
//! When the user allows a Git or GitHub permission, a command that only
//! names such a checkout runs without review. Guard's fixed floor still holds
//! for arguments that reach Guard's state, an installed Guard program or a
//! shell command a Git alias would run.

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

/// `root/hol-guard` on `main` with a GitHub origin, a tracked installer
/// source named after the project, and a linked worktree
/// `root/hol-guard-pr-12` on branch `pr`.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-named-checkout-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("hol-guard");
    std::fs::create_dir_all(project.join("scripts/win")).unwrap();
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
            "https://github.com/example-org/hol-guard.git",
        ],
    );
    std::fs::write(project.join("scripts/win/hol-guard.wxs"), "<Wix/>\n").unwrap();
    git(&root, &project, &["add", "scripts/win/hol-guard.wxs"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let linked = root.join("hol-guard-pr-12");
    git(
        &root,
        &project,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "pr",
            linked.to_str().unwrap(),
        ],
    );
    std::fs::create_dir_all(root.join(".hol-guard")).unwrap();
    std::fs::create_dir_all(root.join(".local/pipx/venvs/hol-guard")).unwrap();
    let root = root.canonicalize().unwrap();
    (root.clone(), FixtureCleanup(root))
}

/// Every permission in the packaged catalog set to `enabled`, as the
/// Extensions page writes it when the user allows each pattern.
fn every_permission_allowed(
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":"enabled"})
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
        root.join("hol-guard").to_str(),
    )
}

fn commands(root: &Path, templates: &[&str]) -> Vec<String> {
    templates
        .iter()
        .map(|template| template.replace("{root}", root.to_str().unwrap()))
        .collect()
}

/// Commands an agent runs against a checkout named after the project it
/// works on. None of them reaches Guard itself.
const NAMED_CHECKOUT_COMMANDS: &[&str] = &[
    "git -C {root}/hol-guard-pr-12 fetch origin main",
    "git -C {root}/hol-guard-pr-12 status --short",
    "git -C {root}/hol-guard-pr-12 push -u origin pr",
    "git -C {root}/hol-guard-pr-12 push https://github.com/example-org/hol-guard.git HEAD:feature",
    "git push git@github.com:example-org/hol-guard.git HEAD:feature",
    "git restore -- scripts/win/hol-guard.wxs",
    "git checkout -- scripts/win/hol-guard.wxs",
    "git -C {root}/hol-guard worktree remove --force {root}/hol-guard-pr-12",
    "git -C {root}/hol-guard worktree move {root}/hol-guard-pr-12 {root}/moved",
    "git fetch --quiet https://github.com/example-org/hol-guard.git feature",
    "git -C {root}/hol-guard worktree remove {root}/hol-guard-pr-12 && git branch -D pr",
    "gh api repos/example-org/app-portal/commits/abc/check-runs -f check_name='hol-guard / required' -f filter=all --jq '.check_runs'",
];

#[test]
fn an_allowed_git_command_on_a_checkout_named_after_guard_runs_without_review() {
    let (root, _cleanup) = checkout("allow");
    let controls = every_permission_allowed();
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in commands(&root, NAMED_CHECKOUT_COMMANDS) {
            let result = decide(&root, harness, &command, &controls);
            if result.decision != "allow" {
                failures.push(format!("{harness}: {command}: {}", result.reason_code));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_git_command_that_reaches_guard_itself_still_waits_for_review() {
    let (root, _cleanup) = checkout("guard-itself");
    let controls = every_permission_allowed();
    for command in commands(
        &root,
        &[
            "git -C {root}/.hol-guard status --short",
            "git -C {root}/.local/pipx/venvs/hol-guard status --short",
            "cd {root}/.local/pipx/venvs/hol-guard && git status --short",
            "cd {root}/.local/pipx/venvs && git -C hol-guard status --short",
            "cd {root}/.local/pipx/venvs; cd {root}/missing; git -C hol-guard status --short",
            "git --work-tree={root}/.local/pipx/venvs/hol-guard status --short",
            "git -C /etc/hol-guard checkout -- .",
            "git -C $HOL_GUARD_HOME log -1",
            "git config alias.tidy '!hol-guard hooks remove'",
            "git -c alias.tidy='!plugin-guard uninstall' tidy",
            "gh api repos/example-org/app-portal/issues -f body=.hol-guard/config",
        ],
    ) {
        let result = decide(&root, "omp", &command, &controls);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn a_named_checkout_without_an_allow_keeps_its_default() {
    let (root, _cleanup) = checkout("default");
    let controls = fixture::github_controls("default");
    for command in commands(
        &root,
        &["git -C {root}/hol-guard-pr-12 push https://github.com/example-org/hol-guard.git HEAD:feature"],
    ) {
        let result = decide(&root, "omp", &command, &controls);
        assert_ne!(result.decision, "allow", "{command}");
    }
}
