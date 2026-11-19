#![cfg(unix)]
//! A `for` loop over folders spelled from the home directory, as in
//! `for d in ~/work/a ~/work/b; do if [ -d "$d" ]; then ls "$d"; fi; done`.
//!
//! The loop unroller refused any word holding `~`, so the loop kept a review
//! the same loop over the absolute paths did not. The shell expands an
//! unquoted `~/` before the loop runs, so the unrolled list now writes the
//! home path out and the ordinary proofs judge each step.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

/// The decision for `command` when the shell's own HOME is `shell_home`.
fn allowed(
    harness: &str,
    command: &str,
    home: &std::path::Path,
    shell_home: &std::path::Path,
) -> bool {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("work/repo");
    let answer = evaluate_pre_tool_envelope_with_execution_context(
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
    );
    answer.minimum_action == "allow"
}

#[test]
fn a_loop_over_home_spelled_folders_is_judged_by_its_steps() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/for-loop-home-words")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/a/src", "work/b", "work/repo", ".ssh", ".aws"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("work/a/README.md"), "a\n").unwrap();
    std::fs::write(root.join("work/b/README.md"), "b\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
    for harness in ["cursor", "claude-code", "codex"] {
        for (command, expected) in [
            (
                "for d in ~/work/a ~/work/b; do if [ -d \"$d\" ]; then echo \"=== $d ===\"; ls \"$d\"; fi; done",
                true,
            ),
            ("for d in ~/work/a ~/work/missing; do echo \"$d\"; done", true),
            ("for d in ~/work/a; do cat \"$d/README.md\"; done", true),
            // Each step is still judged on its own.
            ("for f in ~/.ssh/id_ed25519 ~/work/a/README.md; do cat \"$f\"; done", false),
            ("for d in ~/work/a; do rm -rf \"$d/src\"; done", false),
            ("for d in ~/.aws; do ls \"$d\"; done", false),
            // A quoted `~` stays literal, and a pattern from home keeps its review.
            ("for d in \"~/work/a\"; do cat \"$d/README.md\"; done", false),
            ("for f in ~/.aws/*; do cat \"$f\"; done", false),
        ] {
            assert_eq!(
                allowed(harness, command, &root, &root),
                expected,
                "{harness}: {command}"
            );
        }
    }
    // The shell expands `~` from its own HOME. When that is another folder,
    // the loop reads files there, so its words are not written out from the
    // declared home and the loop keeps its review.
    let elsewhere = root.join(".ssh");
    for harness in ["cursor", "claude-code", "codex"] {
        for command in [
            "for d in ~/work/a; do cat \"$d/README.md\"; done",
            "for d in ~/work/a ~/work/b; do ls \"$d\"; done",
        ] {
            assert!(
                !allowed(harness, command, &root, &elsewhere),
                "{harness}: {command} with another shell HOME"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
