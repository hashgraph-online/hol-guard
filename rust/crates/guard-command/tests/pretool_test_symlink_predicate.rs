#![cfg(unix)]
//! `test -L node_modules`: is this name a symbolic link?
//!
//! A linked worktree often shares its parent checkout's `node_modules`
//! through a link, and an agent checks that before it installs anything.
//! `-L` (and its older spelling `-h`) asks `lstat` for the name's own type
//! and never follows the link, so it returns one bit about the name, less
//! than `-e` already returns. It went to the workspace containment review
//! because the predicate list did not hold it. It now takes the same proof
//! as `-e`, so a name in a credential store still keeps its review.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn action(harness: &str, command: &str, home: &Path, cwd: &Path) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
    .minimum_action
}

fn fixture() -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-symlink-predicate")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/app/node_modules/zod", "work/app-wt/src", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (file, text) in [
        ("work/app/package.json", "{}\n"),
        ("work/app-wt/package.json", "{}\n"),
        ("work/app-wt/src/index.js", "x\n"),
        (".ssh/id_ed25519", "synthetic\n"),
    ] {
        std::fs::write(root.join(file), text).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    std::os::unix::fs::symlink(
        root.join("work/app/node_modules"),
        root.join("work/app-wt/node_modules"),
    )
    .unwrap();
    for repository in ["work/app", "work/app-wt"] {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(root.join(repository))
            .env("HOME", &root)
            .status()
            .unwrap();
        assert!(status.success());
    }
    root
}

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

#[test]
fn a_symlink_test_on_a_workspace_name_is_allowed() {
    let home = fixture();
    let worktree = home.join("work/app-wt");
    for harness in HARNESSES {
        for command in [
            "test -L node_modules",
            "[ -L node_modules ]",
            "test -h node_modules && echo linked",
            "[ ! -L node_modules ] || echo linked",
            "git status --short && test -L node_modules && echo linked",
            "test -L missing-folder || echo plain",
        ] {
            assert_eq!(
                action(harness, command, &home, &worktree),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_symlink_test_keeps_the_review_its_target_already_has() {
    let home = fixture();
    let worktree = home.join("work/app-wt");
    for harness in HARNESSES {
        for command in [
            // A credential store is not a place a predicate may name.
            "test -L ~/.ssh/id_ed25519",
            "[ -h ~/.ssh/id_ed25519 ]",
            // An option word is not a path.
            "test -L -e",
        ] {
            assert_ne!(
                action(harness, command, &home, &worktree),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
