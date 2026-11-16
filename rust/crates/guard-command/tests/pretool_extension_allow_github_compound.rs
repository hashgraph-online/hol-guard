#![cfg(unix)]
//! A user who allows the GitHub extension's merge and read permissions runs
//! `gh pr merge` followed by `gh pr view` as one shell call, often after
//! stepping into another checkout. Each step is allowed on its own, so the
//! compound is allowed too.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(root: &Path, directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn init(root: &Path, directory: &Path, remote: &str) {
    std::fs::create_dir_all(directory).unwrap();
    git(root, directory, &["init", "--quiet", "-b", "main"]);
    git(root, directory, &["config", "user.name", "Guard Fixture"]);
    git(
        root,
        directory,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(root, directory, &["remote", "add", "origin", remote]);
    std::fs::write(directory.join("tracked.txt"), "fixture\n").unwrap();
    git(root, directory, &["add", "tracked.txt"]);
    git(root, directory, &["commit", "--quiet", "-m", "fixture"]);
}

/// `root/project` is the session's checkout; `root/other` is a second
/// checkout beside it, the shape of a developer who keeps every project in
/// one directory.
fn checkouts(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-github-compound-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    init(
        &root,
        &root.join("project"),
        "https://github.com/example-org/app-portal.git",
    );
    init(
        &root,
        &root.join("other"),
        "https://github.com/example-org/points-portal.git",
    );
    let root = root.canonicalize().unwrap();
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
    cwd: &Path,
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
        cwd.to_str(),
    )
}

const MERGE: &str = "gh pr merge 8232 --repo example-org/points-portal --squash";
const VIEW: &str =
    "gh pr view 8232 --repo example-org/points-portal --json state,mergedAt,mergeCommit";

#[test]
fn an_allowed_merge_followed_by_a_read_runs_without_review() {
    let (root, _cleanup) = checkouts("merge-then-view");
    let controls = every_permission("enabled");
    let project = root.join("project");
    let other = root.join("other");
    let commands = vec![
        format!("{MERGE}; {VIEW}"),
        format!("{MERGE} && {VIEW}"),
        format!("cd {} && {MERGE}", other.display()),
        format!("cd {} && {MERGE}; {VIEW}", other.display()),
        format!("cd {} && {MERGE} && {VIEW}", other.display()),
        format!("cd ~/other && {MERGE}; {VIEW}"),
        format!("cd ../other && {MERGE}; {VIEW}"),
    ];
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in &commands {
            let result = decide(&root, &project, harness, command, &controls);
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
