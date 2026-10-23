#![cfg(unix)]
//! A user who sets an extension's merge permission to Allow has decided that
//! merge commands of that shape run without review. Guard honours that Allow
//! for the merges the extension identifies, in every harness.

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

/// `root/project` on `main` with a GitHub origin and a `feature` branch one
/// commit ahead.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-merge-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
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
    std::fs::write(project.join("tracked.txt"), "fixture\n").unwrap();
    git(&root, &project, &["add", "tracked.txt"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    git(&root, &project, &["checkout", "--quiet", "-b", "feature"]);
    std::fs::write(project.join("feature.txt"), "feature\n").unwrap();
    git(&root, &project, &["add", "feature.txt"]);
    git(&root, &project, &["commit", "--quiet", "-m", "feature"]);
    git(&root, &project, &["checkout", "--quiet", "main"]);
    let root = root.canonicalize().unwrap();
    (root.clone(), FixtureCleanup(root))
}

/// Every permission in the packaged catalog set to `state`, as the Extensions
/// page writes it when the user allows each pattern.
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

fn observed(result: &guard_contracts::PreToolResultV1) -> String {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return "no command extensions".to_owned();
    };
    let rules: Vec<_> = extensions
        .observations
        .iter()
        .map(|observation| {
            format!(
                "{}{:?}@{:?}",
                observation.rule_id,
                observation.uncertainty_reasons,
                observation.effective_segment_indexes
            )
        })
        .collect();
    let permissions: Vec<_> = extensions
        .permission_observations
        .iter()
        .map(|observation| {
            format!(
                "{}{:?}@{:?}",
                observation.permission_id,
                observation.uncertainty_reasons,
                observation
                    .matcher_evidence
                    .iter()
                    .map(|evidence| evidence.segment_index)
                    .collect::<Vec<_>>()
            )
        })
        .collect();
    format!(
        "bounded {} sensitive {} rules {rules:?} permissions {permissions:?} error {:?}",
        result.action.bounded, result.action.sensitive_target, extensions.evaluation_error
    )
}

const MERGES: &[&str] = &[
    "gh pr merge 12 --squash",
    "gh pr merge 5410 --repo example-org/app-portal --squash --delete-branch=false",
    "gh pr merge 12 --squash --delete-branch",
    "gh pr merge 12 --merge",
    // A repository named after Guard is a remote name, not Guard itself.
    "gh pr merge 5410 --repo example-org/hol-guard --squash --delete-branch=false",
    "gh pr merge 5410 -R example-org/hol-guard --squash",
    "gh pr merge 5410 --repo=example-org/hol-guard --squash",
    "gh pr merge 5410 --squash --delete-branch --repo example-org/hol-guard",
    "git merge --ff-only feature",
    "git merge feature",
];

#[test]
fn an_allowed_merge_permission_runs_the_merge_without_review() {
    let (root, _cleanup) = checkout("allow");
    let controls = every_permission("enabled");
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in MERGES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(
                result.decision,
                "allow",
                "{harness}: {command}: {} ({})",
                result.reason_code,
                observed(&result)
            );
        }
    }
}

#[test]
fn an_allowed_merge_that_names_guard_outside_the_repository_still_waits_for_review() {
    let (root, _cleanup) = checkout("guard-name");
    let controls = every_permission("enabled");
    for command in [
        "gh pr merge 12 --squash --body-file .hol-guard/notes.md",
        "gh pr merge 12 -Rexample-org/hol-guard --squash",
        "gh repo clone example-org/hol-guard .hol-guard",
        // `--desc` takes `--repo` as its value, so the Guard path is the file
        // the gist uploads; after `--` both are files.
        "gh gist create --desc --repo .hol-guard/receipts.json",
        "gh gist create -- --repo .hol-guard/receipts.json",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn a_merge_without_an_allow_still_waits_for_review() {
    let (root, _cleanup) = checkout("default");
    let controls = fixture::github_controls("default");
    for harness in ["omp", "zcode"] {
        for command in MERGES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

/// The context an agent's hook stamps from a real shell: the session started
/// in a directory that is not itself a checkout, `PATH` puts user-writable
/// tool directories first, and the environment carries a GitHub token and a
/// pager without `GIT_CONFIG_NOSYSTEM`.
fn decide_in_session(
    root: &Path,
    cwd: &Path,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
    live_environment: bool,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};
    let tools = root.join(".local/bin");
    std::fs::create_dir_all(&tools).unwrap();
    let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap());
    let home = root.to_str().unwrap().to_owned();
    let mut environment =
        std::collections::BTreeMap::from([("PATH", path.clone()), ("HOME", home.clone())]);
    if live_environment {
        environment.insert("GITHUB_TOKEN", "redacted".to_owned());
        environment.insert("PAGER", "less".to_owned());
        environment.insert("TERM", "xterm-256color".to_owned());
        environment.insert("SHELL", "/bin/zsh".to_owned());
    } else {
        environment.insert("GIT_CONFIG_NOSYSTEM", "1".to_owned());
    }
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(home.clone()),
        git_pager_disabled: false,
        pager_disabled: live_environment,
        xdg_config_home: None,
        git_config_no_system: !live_environment,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(&home),
            cwd: cwd.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&context),
    )
}

#[test]
fn an_allowed_merge_runs_from_a_session_outside_the_checkout() {
    let (root, _cleanup) = checkout("session");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let controls = every_permission("enabled");
    let mut failures = Vec::new();
    for (label, cwd, live) in [
        ("checkout", root.join("project"), false),
        ("checkout-live-env", root.join("project"), true),
        ("workspace", workspace.clone(), false),
        ("workspace-live-env", workspace.clone(), true),
    ] {
        for command in [
            "gh pr merge 5410 --repo example-org/hol-guard --squash --delete-branch=false",
            "gh pr merge 12 --squash",
        ] {
            let result = decide_in_session(&root, &cwd, command, &controls, live);
            if result.decision != "allow" {
                failures.push(format!(
                    "{label}: {command}: {} ({})",
                    result.reason_code,
                    observed(&result)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
