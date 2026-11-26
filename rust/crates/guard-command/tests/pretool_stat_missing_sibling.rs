#![cfg(unix)]
//! `stat ../next-worktree` for a name that is not there yet.
//!
//! Before adding a worktree an agent checks the folder is free:
//! `if [ -e ../w ]; then stat -f '%N %HT' ../w; else echo available; fi`.
//! `ls -ld ../w` and `[ -e ../w ]` were allowed, and `stat` of an existing
//! sibling was allowed, but `stat` of the missing one went to review because
//! its proof had no rule for a name that does not exist. A missing name now
//! takes the listing rule `ls` uses, so a name under a credential store keeps
//! its review.

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
        .join("../../target/stat-missing-sibling")
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
fn a_stat_of_a_missing_sibling_is_allowed() {
    let home = fixture();
    let worktree = home.join("work/app-wt");
    for harness in HARNESSES {
        for command in [
            "stat ../weekly-report-wt",
            "stat -f '%N %HT' ../weekly-report-wt",
            "stat ../weekly-report-wt/src 2>/dev/null || echo available",
            "if [ -e ../weekly-report-wt ]; then stat -f '%N %HT' ../weekly-report-wt; else echo available; fi",
            "stat ~/work/weekly-report-wt",
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
fn a_stat_of_a_missing_name_in_a_credential_store_keeps_its_review() {
    let home = fixture();
    let worktree = home.join("work/app-wt");
    for harness in HARNESSES {
        for command in [
            "stat ~/.ssh/id_rsa",
            "stat ~/.aws/credentials",
            "stat ~/.config/gh/hosts.yml",
            "stat ../weekly-report-wt/.env",
        ] {
            assert_ne!(
                action(harness, command, &home, &worktree),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
