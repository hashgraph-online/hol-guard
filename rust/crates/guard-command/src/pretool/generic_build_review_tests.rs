//! Cargo builds and tests keep the package review with build wording.
use super::BUILD_REVIEW_REASON;

fn outcome(command: &str) -> (String, String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        Some("/Users/nobody"),
        root.to_str(),
    );
    (result.minimum_action, result.reason_code, result.reason)
}

#[test]
fn cargo_builds_and_tests_keep_the_package_review_with_build_wording() {
    for command in [
        "cargo test",
        "cargo test --locked --offline",
        "cargo +nightly build --release",
        "cargo --color never clippy --all-targets",
        "/usr/local/bin/cargo check -p guard-command",
        "cargo test -p guard-command 2>&1 | tail -20",
    ] {
        let (action, code, reason) = outcome(command);
        assert_eq!(action, "review", "{command}: {reason}");
        assert_eq!(code, "native_package_review", "{command}");
        assert_eq!(reason, BUILD_REVIEW_REASON, "{command}");
    }
}

#[test]
fn installs_and_mixed_package_steps_keep_the_package_wording() {
    for command in [
        "cargo install ripgrep",
        "cargo add serde",
        "cargo fix --allow-dirty",
        "cargo test && npm install left-pad",
        "npm install left-pad",
    ] {
        let (action, code, reason) = outcome(command);
        assert_ne!(action, "allow", "{command}");
        if code == "native_package_review" {
            assert_ne!(reason, BUILD_REVIEW_REASON, "{command}");
        }
    }
}
