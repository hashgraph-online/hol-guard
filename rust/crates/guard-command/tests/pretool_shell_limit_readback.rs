#![cfg(unix)]

//! A prelude that raises its own soft limit usually reads it straight back
//! with the flags written together (`ulimit -Sn`). Both halves are proven on
//! their own, so the chain runs on the host the same as either half does. A
//! contained run would start under the sandbox's own descriptor ceiling, so the
//! raise the agent asked for would fail there instead.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn project(name: &str) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-shell-limit-readback")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("home/project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(project.join("package.json"), "{}").unwrap();
    let home = std::fs::canonicalize(root.join("home")).unwrap();
    (home.clone(), home.join("project"))
}

fn quiet(home: &Path, project: &Path, harness: &str, command: &str) -> (bool, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    (
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn"),
        result.reason_code,
    )
}

#[test]
fn a_soft_limit_read_back_with_joined_flags_runs_on_the_host() {
    let (home, project) = project("readback");
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "ulimit -Sn",
            "ulimit -Hn",
            "ulimit -Sn 10240; ulimit -Sn",
            "ulimit -n 10240 && ulimit -Sn",
        ] {
            let (allowed, reason) = quiet(&home, &project, harness, command);
            assert!(allowed, "{harness}: {command} -> {reason}");
        }
    }
}

#[test]
fn a_joined_flag_with_a_value_or_a_hard_limit_write_is_not_a_read() {
    let (home, project) = project("still-reviewed");
    for command in [
        "ulimit -Hn 10240; ulimit -Hn",
        "ulimit -Sc unlimited; ulimit -Sc",
    ] {
        let (allowed, reason) = quiet(&home, &project, "claude-code", command);
        assert!(!allowed, "{command} -> {reason}");
    }
}
