//! A plain Git read whose configuration probe ran out of hook time.
//!
//! On a loaded host the probe that proves a read helper-free can miss the
//! hook's budget. The probe used to take the whole deadline, so the extension
//! check after it timed out too and the read was held for the user. Probes
//! now stop early enough for that check to finish: the enabled Git read
//! permission settles a plain `git status`, and a diff or log runs in the
//! read-only Git sandbox. A step that may change Git's configuration first,
//! or a deadline with no time left for any check, still holds the read.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Inside the time probes leave for the work after them, so no probe starts
/// but the extension check still has the whole deadline to itself.
const PROBE_FREE_DEADLINE: Duration = Duration::from_millis(190);

const CONTAINED: (&str, &str) = (
    "sandbox-required",
    "native_git_readonly_containment_required",
);

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-git-spent-deadline-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    fixture::git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    fixture::git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(project.join("README.md"), "fixture\n").unwrap();
    fixture::git(&root, &project, &["add", "-A"]);
    fixture::git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn evaluate(root: &Path, command: &str, deadline: Instant) -> guard_contracts::PreToolResultV1 {
    let project = root.join("project");
    fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        Some(deadline),
        root.to_str(),
        project.to_str(),
    )
}

#[test]
fn reads_whose_probe_ran_out_of_time_still_run() {
    for (label, command, outcome) in [
        (
            "status",
            "git status",
            ("allow", "native_exact_safe_command"),
        ),
        (
            "status-short",
            "git status --short",
            ("allow", "native_exact_safe_command"),
        ),
        ("diff", "git diff", CONTAINED),
        ("diff-stat", "git diff --stat", CONTAINED),
        ("log", "git log --oneline -3", CONTAINED),
    ] {
        let (root, _cleanup) = checkout(label);
        let result = evaluate(&root, command, Instant::now() + PROBE_FREE_DEADLINE);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            outcome,
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_config_change_before_the_read_is_still_held() {
    let (root, _cleanup) = checkout("config-first");
    let result = evaluate(
        &root,
        "git config core.pager cat; git status",
        Instant::now() + PROBE_FREE_DEADLINE,
    );
    assert_ne!(
        result.minimum_action, "sandbox-required",
        "{}",
        result.reason
    );
    assert_ne!(result.decision, "allow", "{}", result.reason);
}

#[test]
fn a_spent_deadline_is_still_held() {
    let (root, _cleanup) = checkout("spent");
    let result = evaluate(
        &root,
        "git status",
        Instant::now() - Duration::from_millis(1),
    );
    assert_eq!(
        result.minimum_action, "require-reapproval",
        "{}",
        result.reason
    );
}

/// A configuration include that never finishes reading (here a FIFO with no
/// writer) stalls the probe until its deadline. Before probes left time on
/// the hook's deadline, the extension check then timed out as well and the
/// diff was held instead of contained.
#[test]
fn a_stalled_probe_leaves_time_for_the_extension_check() {
    let (root, _cleanup) = checkout("stalled");
    let include = root.join("stalled.config");
    let made = std::process::Command::new("mkfifo")
        .arg(&include)
        .status()
        .unwrap();
    assert!(made.success());
    fixture::git(
        &root,
        &root.join("project"),
        &["config", "include.path", include.to_str().unwrap()],
    );
    let result = evaluate(
        &root,
        "git diff",
        Instant::now() + Duration::from_millis(1500),
    );
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        CONTAINED,
        "{}",
        result.reason
    );
}
