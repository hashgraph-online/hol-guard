//! A user who sets their Git extension permissions to Allow has decided that
//! commands of those shapes run without review. Guard's Git execution-context
//! floor has two meanings, and only one of them survives that Allow.
//!
//! Every Git read in these commands was proven helper-free against the
//! configuration Guard read for it. What keeps the command under review is the
//! order alone: an earlier step could not be proven to leave that configuration
//! as the read found it. That is a judgment of the command's shape, so the
//! user's Allow settles it. A read whose own configuration names a pager, diff
//! driver or textconv helper is the other meaning, and keeps its review however
//! much the user allowed.

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

/// `root/project` on `main`, one commit deep, with a GitHub `origin` and a
/// modified tracked file for the stash steps to move. `pager` writes a home
/// configuration naming a program Git would run to print a read's output.
fn checkout(label: &str, pager: bool) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-git-order-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    if pager {
        std::fs::write(root.join(".gitconfig"), "[core]\n\tpager = less -R\n").unwrap();
    }
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
    std::fs::write(project.join("README.md"), "fixture\n").unwrap();
    git(&root, &project, &["add", "-A"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(project.join("src/index.ts"), "export const a = 2;\n").unwrap();
    // Git for Windows reads no global configuration from a `\\?\` home, so the
    // fixture spells the root the way a user's home is spelled.
    let root = fixture::canonical_spelling(&root);
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

/// The chains a developer runs to refresh a checkout before working in it.
/// Each ends in a Git read, and each holds an earlier step — a fetch of a
/// remote Guard cannot prove, a stash, a pop — that no proof settles, so the
/// read floor rests on the order of the steps alone.
const REFRESHES: &[&str] = &[
    "git fetch upstream && git stash push -m 'warm-cache' -- src/index.ts && git status -sb",
    "git fetch upstream && git stash push -m 'warm-cache' -- src/index.ts && git log -1 --oneline",
    "git stash push -m 'warm-cache' -- src/index.ts && git stash pop && git status -sb",
    "git fetch origin main && git stash push -m 'warm-cache' -- src/index.ts README.md \
     && git merge --ff-only origin/main && git stash pop && git status -sb && git log -1 --oneline",
    "git merge --ff-only origin/main && git log -1 --oneline && git status -sb",
    "git pull --ff-only origin main && git log -1 --oneline && git status -sb",
];

#[test]
fn an_allowed_refresh_runs_its_reads_without_review() {
    let (root, _cleanup) = checkout("allow", false);
    let controls = every_permission("enabled");
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in REFRESHES {
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

/// Reads the Git extension has no permission for, each after a step the user
/// allowed. Guard proves the read on its own, and the step before it changes
/// nothing the read looks up, so the Allow on that step carries the command.
const REF_READS_AFTER_ALLOWED_STEPS: &[&str] = &[
    "git push origin HEAD:feature && git rev-parse HEAD",
    "git push -u origin HEAD && git rev-parse --short HEAD",
    "git checkout main && git pull --ff-only && git rev-parse --short HEAD",
    "git checkout -B refresh origin/main && git rev-parse --abbrev-ref HEAD",
    "git branch -D stale && git branch --show-current",
    "git reset --hard origin/main && git rev-parse HEAD",
    "git restore src/index.ts && git rev-parse HEAD",
    "git fetch upstream main && git rev-parse HEAD",
    "git push origin HEAD:feature && git merge-base HEAD origin/main",
    "git fetch upstream main && git merge-base HEAD FETCH_HEAD",
    "git commit -am 'Update index' && git push && git rev-parse HEAD",
    "git checkout -B refresh --no-track origin/main && git rev-parse --abbrev-ref HEAD \
     && git rev-parse --short HEAD && git merge-base HEAD origin/main",
    "git checkout -B refresh origin/main && docker ps",
    "git reset --hard origin/main && git rev-parse HEAD && docker images",
];

#[test]
fn a_ref_read_after_an_allowed_step_runs_without_review() {
    let (root, _cleanup) = checkout("ref-reads", false);
    let controls = every_permission("enabled");
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in REF_READS_AFTER_ALLOWED_STEPS {
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

#[test]
fn a_ref_read_keeps_the_review_of_a_step_nobody_allowed() {
    let (root, _cleanup) = checkout("ref-reads-unallowed", false);
    let defaults = fixture::github_controls("default");
    let mut reviewed_steps = 0;
    for command in REF_READS_AFTER_ALLOWED_STEPS {
        let step = command.split(" && ").next().unwrap();
        if decide(&root, "omp", step, &defaults).decision == "allow" {
            continue;
        }
        reviewed_steps += 1;
        let result = decide(&root, "omp", command, &defaults);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    assert!(reviewed_steps > 0, "no step waits for review by default");
    let allowed = every_permission("enabled");
    // A container start runs code an allowed checkout may just have changed,
    // and an allowed `git config` may name the pager the read then runs.
    for command in [
        "hol-guard hooks remove && git rev-parse HEAD",
        "git config core.pager 'sh -c true' && git log -1",
        "git config core.pager 'sh -c true' && git rev-parse HEAD && git log -1",
        "git checkout -B refresh origin/main && docker start web",
        "git reset --hard origin/main && docker container start web",
    ] {
        let result = decide(&root, "omp", command, &allowed);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A home configuration that includes a file the work tree tracks. A checkout,
/// reset or stash can replace that file, so the configuration Guard probed
/// before the command is not the one a later read runs under.
#[test]
fn a_read_after_an_allowed_checkout_waits_when_an_include_reaches_the_work_tree() {
    let (root, _cleanup) = checkout("tracked-include", false);
    std::fs::create_dir_all(root.join("project/tools")).unwrap();
    std::fs::write(root.join("project/tools/git.cfg"), "[color]\n\tui = auto\n").unwrap();
    std::fs::write(
        root.join(".gitconfig"),
        "[include]\n\tpath = ~/project/tools/git.cfg\n",
    )
    .unwrap();
    let controls = every_permission("enabled");
    for command in [
        "git checkout -B refresh origin/main && git rev-parse --abbrev-ref HEAD",
        "git reset --hard origin/main && git log -1 --oneline",
        "git stash push -m 'warm-cache' -- src/index.ts && git log -1 --oneline",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn a_refresh_without_an_allow_still_waits_for_review() {
    let (root, _cleanup) = checkout("default", false);
    let controls = fixture::github_controls("default");
    for command in [
        "git fetch upstream && git stash push -m 'warm-cache' -- src/index.ts && git status -sb",
        "git fetch origin main && git stash push -m 'warm-cache' -- src/index.ts README.md \
         && git merge --ff-only origin/main && git stash pop && git status -sb && git log -1 --oneline",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn an_allowed_read_whose_configuration_names_a_pager_still_waits_for_review() {
    let (root, _cleanup) = checkout("pager", true);
    let controls = every_permission("enabled");
    for command in [
        "git fetch upstream && git stash push -m 'warm-cache' -- src/index.ts && git log -1 --oneline",
        "git log -1 --oneline",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(result.decision, "allow", "{command}: {}", result.reason_code);
    }
}

#[test]
fn an_allowed_refresh_that_configures_git_itself_still_waits_for_review() {
    let (root, _cleanup) = checkout("configured", false);
    let controls = every_permission("enabled");
    for command in [
        "git -c core.pager=/tmp/pager status -sb",
        "git stash push -m 'warm-cache' -- src/index.ts && git -c core.pager=/tmp/pager log -1",
        "git --exec-path=/tmp/exec status -sb",
    ] {
        let result = decide(&root, "omp", command, &controls);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
