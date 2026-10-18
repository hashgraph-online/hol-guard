//! Cargo's local verbs compile and test inside the workspace sandbox; the
//! verbs that reach a registry keep the admission they have.
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

/// A checkout that is a Cargo package.
fn package(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("Cargo.toml"), MANIFEST).unwrap();
    std::fs::write(ws.join("Cargo.lock"), LOCKFILE).unwrap();
    ws
}

#[test]
fn cargo_builds_and_tests_the_package_inside_the_sandbox() {
    let ws = package("cargo-local");
    for command in [
        "cargo check",
        "cargo check --locked",
        "cargo check 2>&1 | tail -15",
        "cargo check --locked --offline 2>&1 | tail -15",
        "cargo build --locked",
        "cargo test --locked --offline",
        "cargo clippy --all-targets",
        "cargo fmt --check",
        "cargo +nightly fmt",
        "cargo run --bin app-portal",
        "cargo doc --no-deps",
        "cargo tree --depth 1",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn the_registry_verbs_and_a_bare_directory_keep_their_review() {
    let ws = package("cargo-registry");
    for command in [
        "cargo install cargo-nextest",
        "cargo add serde",
        "cargo update",
        "cargo publish --dry-run",
        "cargo fetch",
        "cargo vendor",
        "cargo check && cargo add serde",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // Without a manifest cargo searches upward, out of the workspace the
    // sandbox holds.
    let bare = workspace("cargo-bare", true);
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "cargo check", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

/// Which package a verb compiles moves with a `cd` ahead of it, so a member
/// of the workspace counts and a directory holding no manifest does not.
#[test]
fn the_package_a_verb_compiles_moves_with_the_command() {
    let ws = package("cargo-nested");
    std::fs::create_dir_all(ws.join("crates/engine")).unwrap();
    std::fs::write(ws.join("crates/engine/Cargo.toml"), MANIFEST).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "cd crates/engine && cargo test --offline", &ws);
        assert_eq!(reason, CONTAINED, "{harness}");
        let (reason, _) = outcome(harness, "cd docs && cargo test", &ws);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}
