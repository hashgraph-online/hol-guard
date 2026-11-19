#![cfg(unix)]
//! A `grep` path glob that matches nothing, as in a search across a fixed
//! list of places: `grep -rn "FACT_WRITES" README.md src/config* 2>/dev/null`.
//!
//! Bash hands `grep` the literal word, which names no file, and zsh fails the
//! command, so the glob reads nothing. Under `nullglob` the word disappears:
//! that is harmless beside another root, but `grep -r` with no root left
//! walks the working directory, so a recursive search of the glob alone is
//! proven only where `grep -r` of the working directory is. A glob that
//! matches a secret, or that points into a credential store, keeps its
//! screens.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn action(harness: &str, command: &str, home: &Path) -> String {
    action_in(harness, command, home, &home.join("work/repo"))
}

fn action_in(harness: &str, command: &str, home: &Path, cwd: &Path) -> String {
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
        .join("../../target/grep-unmatched-glob-operand")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo/src/app", "work/repo/docs", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (file, text) in [
        ("work/repo/README.md", "# repo\n"),
        ("work/repo/src/app/main.py", "print('app')\n"),
        ("work/repo/docs/guide.md", "guide\n"),
        ("work/repo/.env.local", "synthetic\n"),
        (".ssh/id_ed25519", "synthetic\n"),
    ] {
        std::fs::write(root.join(file), text).unwrap();
    }
    std::fs::canonicalize(root).unwrap()
}

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

#[test]
fn a_glob_that_matches_nothing_reads_nothing() {
    let home = fixture();
    for harness in HARNESSES {
        for command in [
            r#"grep -rn "FACT_WRITES" README.md src/config* 2>/dev/null | head -5"#,
            "grep -rn FACT README.md src/*.py",
            "grep -n FACT src/config*",
            "grep -n FACT README.md docs/*.txt",
        ] {
            assert_eq!(
                action(harness, command, &home),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_glob_that_could_reach_a_secret_or_vanish_keeps_its_review() {
    let home = fixture();
    for harness in HARNESSES {
        for command in [
            // Under nullglob nothing is left, and `grep -r` walks `.`, where
            // the pattern can match `.env.local`.
            "grep -rn synthetic src/config*",
            "grep -rn FACT README.md .env*",
            "grep -rn FACT README.md ~/.ssh/id*",
            "grep -rn FACT README.md ~/.ssh/missing*",
            // A bracket class can be passed through as a literal name.
            "grep -rn FACT README.md src/[xy]*",
        ] {
            assert_ne!(
                action(harness, command, &home),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_lone_unmatched_glob_in_a_proven_folder_is_allowed() {
    // `src` holds no secret, so `grep -rn FACT .` there is proven, and an
    // empty glob reads no more under any shell option. The chain is the shape
    // agents write: after the `;` the last step may run in either folder.
    let home = fixture();
    let src = home.join("work/repo/src");
    for harness in HARNESSES {
        for command in [
            "grep -rn FACT *.ts",
            "grep -rn FACT *.ts *.tsx | head -5",
            "cd app && grep -rn FACT *.py | head; grep -rn FACT *.ts | head -5",
        ] {
            assert_eq!(
                action_in(harness, command, &home, &src),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_lone_unmatched_glob_in_a_folder_holding_a_secret_keeps_its_review() {
    // The repository root holds `.env.local`, which `grep -r` of the folder
    // would open under `nullglob`, and the pattern can match it.
    let home = fixture();
    for harness in HARNESSES {
        for command in [
            "grep -rn synthetic *.ts",
            "cd src && grep -rn synthetic *.py; grep -rn synthetic *.ts",
        ] {
            assert_ne!(
                action(harness, command, &home),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
