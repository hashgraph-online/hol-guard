//! A `git config --get-regexp` read under the user's Git Allow.
//!
//! The operand is matched against the keys in the configuration file, so
//! `remote.*url` is the ordinary spelling of "print the configured remotes".
//! Guard's fixed floor asks of a glob whether some longer string it matches
//! could name a private file, and that question refuses every pattern holding
//! a `.*`. Applied to a configuration pattern it set a floor no extension
//! permission can settle, so one such read anywhere in a command withdrew the
//! user's Allow from every other step as well.
//!
//! The pattern still faces the screen a search pattern faces: a glob whose own
//! text names a private file keeps its floor.

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

/// `root/project` on `main`, one commit deep, with a GitHub `origin` for the
/// configuration read to print.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-git-config-pattern-{label}-{}",
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

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

/// A step the user's Allow settles, beside a configuration pattern, keeps that
/// Allow. The floor is read over the whole command, so a pattern the floor
/// refused withdrew the Allow from the other step as well, whichever way the
/// read is spelled.
#[test]
fn an_allowed_step_keeps_its_allow_beside_a_configuration_pattern() {
    let (root, _cleanup) = checkout("allow");
    let controls = every_permission("enabled");
    for command in [
        "git config --get-regexp 'remote.*url'",
        "git config --get-regexp 'remote.*url' && git worktree add ../review main",
        "git config --get-regexp '^remote\\..*\\.url$' && git worktree add ../review main",
        "git config get --regexp 'remote.*url' && git worktree add ../review main",
        "git config --get-regexp 'remote.*url' github && git worktree add ../review main",
        "git --no-pager config --get-regexp 'branch.*remote' && git worktree add ../review main",
        "git stash list && git config --get-regexp 'remote.*url'",
        "git config --get-regexp '[r]emote.*url' && git worktree add ../review main",
        "git config --get-regexp '[a-z]emote.*url' && git worktree add ../review main",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

/// The pattern's own text still names a private file; only a `--get-regexp`
/// operand is a pattern at all, because the shell expands every other argument
/// before Git sees it; and an operand opening with a glob is a pattern here and
/// an option naming a file of the caller's choosing by the time Git reads it.
/// Each keeps the floor the user's Allow cannot settle.
#[test]
fn a_glob_that_names_a_private_file_keeps_its_floor() {
    let (root, _cleanup) = checkout("floor");
    let controls = every_permission("enabled");
    for command in [
        "git config --get-regexp '.ssh/*' && git worktree add ../review main",
        "git config --get-all 'remote.*url' && git worktree add ../review main",
        "git worktree add ../review main && git config *",
        "git config --get-regexp '[-]-file=*' x && git worktree add ../review main",
        "git config --get-regexp '[^a]-file=*' x && git worktree add ../review main",
    ] {
        for harness in HARNESSES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}
