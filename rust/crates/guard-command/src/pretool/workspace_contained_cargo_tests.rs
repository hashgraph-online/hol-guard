//! Cargo work keeps its package review instead of the workspace sandbox.
use crate::pretool::workspace_contained_tests::{controls, workspace, CONTAINED};

const MANIFEST: &str =
    "[package]\nname = \"app-portal\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
const LOCKFILE: &str = "version = 3\n\n[[package]]\nname = \"app-portal\"\nversion = \"0.1.0\"\n";

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

#[test]
fn locked_cargo_builds_stay_reviewed_with_a_committed_lockfile() {
    let ws = workspace("cargo-locked", true);
    std::fs::write(ws.join("Cargo.toml"), MANIFEST).unwrap();
    std::fs::write(ws.join("Cargo.lock"), LOCKFILE).unwrap();
    for command in [
        "cargo check",
        "cargo check --locked",
        "cargo check 2>&1 | tail -15",
        "cargo check --locked --offline 2>&1 | tail -15",
        "cargo build --locked",
        "cargo test --locked --offline",
        "cargo check --locked --manifest-path Cargo.toml",
        "cargo check --locked --manifest-path ../app-shared/Cargo.toml",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}
