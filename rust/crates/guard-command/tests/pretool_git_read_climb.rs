//! `cd ../other && git status` reads another checkout beside the current one.
//! The Git execution-context floor probes each read where it runs, so a read
//! after a `cd` that climbs to a sibling is proven against that sibling's
//! configuration, and a `cd ...;` read against both directories.

use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const FLOOR: &str = "native_git_execution_context_review";

fn git(repository: &std::path::Path, home: &std::path::Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `home/Code/org/app` and `home/Code/org/api`, two unrelated repositories
/// side by side, each with one commit. `CARGO_TARGET_TMPDIR` keeps the
/// fixture outside `/var` on macOS, where the read screens refuse a sibling
/// for reasons unrelated to the climb under test.
fn siblings(label: &str) -> (std::path::PathBuf, std::path::PathBuf, FixtureCleanup) {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "guard-git-read-climb-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let org = home.join("Code/org");
    for name in ["app", "api"] {
        let repository = org.join(name);
        std::fs::create_dir_all(&repository).unwrap();
        git(&repository, &home, &["init", "--quiet"]);
        git(
            &repository,
            &home,
            &["config", "user.email", "fixture@example.test"],
        );
        git(&repository, &home, &["config", "user.name", "fixture"]);
        std::fs::write(repository.join("README.md"), "fixture\n").unwrap();
        git(&repository, &home, &["add", "-A"]);
        git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);
    }
    std::fs::write(home.join(".gitconfig"), "").unwrap();
    // Git for Windows cannot run under the `\\?\` form `canonicalize` returns.
    let home = canonical_spelling(home);
    let org = home.join("Code/org");
    (home, org, cleanup)
}

fn decide(
    home: &std::path::Path,
    cwd: &std::path::Path,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let controls = github_controls("default");
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

const SIBLING_READS: &[&str] = &[
    "cd ../api && git status --short",
    "cd ../api && git log -3 --oneline && git diff --stat",
    "cd ../api; git status --short",
    "cd ../api && git branch --show-current; git status --short",
];

/// Climb proofs are Unix-only (`sibling::climbed` refuses every climb on
/// Windows), so there the read keeps its review.
fn assert_climb_proof(result: &guard_contracts::PreToolResultV1, label: &str) {
    if cfg!(windows) {
        assert_ne!(result.decision, "allow", "{label}");
    } else {
        assert_ne!(result.reason_code, FLOOR, "{label}");
    }
}

#[test]
fn a_git_read_after_climbing_to_a_sibling_checkout_keeps_its_proof() {
    let (home, org, _cleanup) = siblings("allow");
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in SIBLING_READS {
            let result = decide(&home, &org.join("app"), harness, command);
            assert_climb_proof(&result, &format!("{harness}: {command}"));
        }
    }
}

#[test]
fn a_sibling_whose_configuration_starts_a_helper_is_still_reviewed() {
    let (home, org, _cleanup) = siblings("helper-there");
    git(
        &org.join("api"),
        &home,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    for command in SIBLING_READS {
        let result = decide(&home, &org.join("app"), "omp", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn a_read_after_cd_semicolon_is_also_proven_where_it_started() {
    // When the `cd` fails, the read after `;` runs in the original directory,
    // so that directory's configuration counts too.
    let (home, org, _cleanup) = siblings("helper-here");
    git(
        &org.join("app"),
        &home,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    for command in [
        "cd ../api; git status --short",
        "cd ../api && git branch --show-current; git status --short",
    ] {
        let result = decide(&home, &org.join("app"), "omp", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
    let chained = decide(
        &home,
        &org.join("app"),
        "omp",
        "cd ../api && git status --short",
    );
    assert_climb_proof(&chained, "cd ../api && git status --short");
}
