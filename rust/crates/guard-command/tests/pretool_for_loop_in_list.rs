#![cfg(unix)]
//! A `for` loop that is one item of a longer command list is decided like the
//! list it writes out, one body per word, with the commands around it kept.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project, removed when the guard drops. The root stays
/// below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> (tempfile::TempDir, PathBuf) {
    let parent =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/pretool-for-loop-in-list");
    std::fs::create_dir_all(&parent).unwrap();
    let root = tempfile::Builder::new()
        .prefix("home-")
        .tempdir_in(parent)
        .unwrap();
    let home = root.path().join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("README.md"), "# Fixture\n").unwrap();
    std::fs::write(project.join("src/a.md"), "a\n").unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    (root, home)
}

fn action(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("project");
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
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
    format!("{} {}", result.minimum_action, result.reason_code)
}

#[test]
fn a_read_only_loop_inside_a_list_proceeds() {
    let (_root, home) = home();
    for command in [
        "echo start; for n in 1 2; do echo $n; done",
        "for f in README.md src/a.md; do wc -l \"$f\"; done; echo done",
        "ls src && for f in README.md src/a.md; do head -3 \"$f\"; done && echo ok",
        "echo start\nfor f in README.md src/a.md; do echo \"== $f\"; done\necho end",
        "pwd; for f in README.md; do cat \"$f\"; done; for d in src; do ls \"$d\"; done",
    ] {
        assert_eq!(
            action(&home, command),
            "allow native_exact_safe_command",
            "{command}"
        );
    }
}

#[test]
fn a_loop_inside_a_list_that_writes_or_escapes_keeps_its_review() {
    let (_root, home) = home();
    for command in [
        "echo start; for f in README.md src/a.md; do rm -f \"$f\"; done",
        "echo start; for f in README.md; do echo x > \"$f\"; done",
        "echo start; for f in README.md; do cat \"$f\"; done | sh",
        "ls | for f in a b; do echo $f; done; echo end",
        "false || for d in src /; do cd \"$d\"; done; rm -f README.md",
        "echo start; for f in $(ls); do cat \"$f\"; done",
    ] {
        assert!(
            !action(&home, command).starts_with("allow"),
            "{command} was allowed"
        );
    }
}
