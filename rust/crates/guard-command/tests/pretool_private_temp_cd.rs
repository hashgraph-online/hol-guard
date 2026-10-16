//! An agent smoke-tests a CLI in a scratch directory with
//! `cd "$(mktemp -d)" && node <workspace>/src/cli.js add ...`. Inside the
//! workspace sandbox `mktemp -d` creates that directory under the run's
//! private `TMPDIR`, so the chain runs contained instead of waiting on a
//! review. A steered, climbed or misplaced temporary directory, and any other
//! substitution, stays out of the sandbox.
#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, git_github_controls, FixtureCleanup};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONTAINED: &str = "native_workspace_containment_required";

/// Home is the fixture root and the project sits below it, outside every
/// temporary root, so the project is an admissible sandbox workspace.
fn fixture(name: &str) -> (PathBuf, PathBuf, FixtureCleanup) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/private-temp-cd-tests")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    let project = root.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(project.join("test")).unwrap();
    std::fs::write(
        project.join("package.json"),
        "{\"name\":\"todo\",\"type\":\"module\"}\n",
    )
    .unwrap();
    std::fs::write(
        project.join("src/cli.js"),
        "console.log(process.argv.length);\n",
    )
    .unwrap();
    std::fs::write(
        project.join("test/cli.test.js"),
        "import test from 'node:test';\ntest('runs', () => {});\n",
    )
    .unwrap();
    let home = root.canonicalize().unwrap();
    let project = project.canonicalize().unwrap();
    (home.clone(), project, FixtureCleanup(home))
}

fn evaluate(home: &Path, project: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        Some(&git_github_controls("default", "default")),
        None,
        home.to_str(),
        project.to_str(),
    )
}

#[test]
fn a_cli_smoke_test_in_a_fresh_temporary_directory_runs_contained() {
    let (home, project, _cleanup) = fixture("contained");
    let w = project.display();
    let command = format!(
        "node --test 2>&1 | tail -12; cd \"$(mktemp -d)\" && TODO_FILE=t.json node {w}/src/cli.js add Hello world && TODO_FILE=t.json node {w}/src/cli.js list"
    );
    let result = evaluate(&home, &project, &command);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason);
    if cfg!(target_os = "macos") {
        assert_eq!(
            result.minimum_action, "sandbox-required",
            "{}",
            result.reason
        );
        assert_eq!(result.reason_code, CONTAINED, "{}", result.reason);
    }
}

#[test]
fn steered_misplaced_or_other_substitutions_stay_out_of_the_sandbox() {
    let (home, project, _cleanup) = fixture("refused");
    let w = project.display();
    for command in [
        "cd \"$(mktemp -d)\" && cat ../x".to_owned(),
        format!("TMPDIR=/etc; cd \"$(mktemp -d)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d /etc/XXX)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d -p /)\" && node {w}/src/cli.js list"),
        format!("cd \"$(whoami)\" && node {w}/src/cli.js list"),
        format!("cd \"$(mktemp -d)\" && node {w}/src/cli.js > /etc/x"),
    ] {
        let result = evaluate(&home, &project, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, CONTAINED,
            "{command}: {}",
            result.reason
        );
    }
}
