//! Credential words that name nothing the command reads, and a `--home` that
//! names the Guard home the launcher already uses.
//!
//! `pytest -k password` selects collected tests and `find src -name
//! "*password*"` prints matching names; neither opens a file the word names,
//! so neither is a secret read. The same names handed to a program that
//! opens them still are. `hol-guard approvals wait <id> --home <HOME>/.hol-guard`
//! reads the store the plain `approvals wait` reads, while another home or a
//! decision subcommand stays under review.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-name-patterns-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("tests")).unwrap();
    std::fs::create_dir_all(project.join("examples")).unwrap();
    std::fs::create_dir_all(root.join(".hol-guard")).unwrap();
    std::fs::write(
        project.join("tests/test_options.py"),
        "def test_password_prompt():\n    pass\n",
    )
    .unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn outcome(root: &Path, command: &str) -> (String, String) {
    let command = command.replace("{home}", root.to_str().unwrap());
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn credential_words_in_name_patterns_run_as_ordinary_work() {
    let (root, _cleanup) = checkout("patterns");
    for (command, expected) in [
        (
            "python -m pytest tests/ -k password -v",
            (
                "sandbox-required",
                "native_pytest_readonly_containment_required",
            ),
        ),
        (
            "python -m pytest tests/test_options.py -k password -v",
            (
                "sandbox-required",
                "native_pytest_readonly_containment_required",
            ),
        ),
        (
            "find examples -name \"*password*\" -o -name \"*prompt*\" | head -10",
            ("allow", "native_exact_safe_command"),
        ),
        (
            "find examples -name \"*password*\"",
            ("allow", "native_exact_safe_command"),
        ),
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), expected, "{command}");
    }
}

#[test]
fn names_handed_to_a_reader_are_still_reviewed() {
    let (root, _cleanup) = checkout("readers");
    for command in [
        "find examples -name \"*password*\" | xargs cat",
        "find examples -name \"*password*\" -exec cat {} \\;",
        "find examples -name \"*password*\" | head -3 | xargs cat",
        "find ~/.ssh -name \"*key*\"",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!(
            (action.as_str(), reason.as_str()),
            ("review", "native_sensitive_access_review"),
            "{command}"
        );
    }
}

#[test]
fn a_wait_on_the_own_guard_home_runs() {
    let (root, _cleanup) = checkout("own-home");
    for command in [
        "hol-guard approvals wait c3aae7fd16694cecbe5d5e0a6015063e --json --home {home}/.hol-guard --timeout 120",
        "hol-guard approvals wait c3aae7fd16694cecbe5d5e0a6015063e --json --home {home}/.hol-guard",
        "hol-guard approvals list --home={home}/.hol-guard/",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!(
            (action.as_str(), reason.as_str()),
            ("allow", "native_exact_safe_command"),
            "{command}"
        );
    }
}

#[test]
fn another_guard_home_or_a_decision_is_still_reviewed() {
    let (root, _cleanup) = checkout("other-home");
    for command in [
        "hol-guard approvals wait c3aae7fd16694cecbe5d5e0a6015063e --json --home /tmp/other/.hol-guard",
        "hol-guard approvals wait c3aae7fd16694cecbe5d5e0a6015063e --home {home}/.hol-guard --home /tmp/other",
        "hol-guard approvals approve c3aae7fd16694cecbe5d5e0a6015063e --home {home}/.hol-guard",
        "hol-guard approvals list --guard-home {home}/.hol-guard",
    ] {
        let (action, _) = outcome(&root, command);
        assert_ne!(action, "allow", "{command}");
    }
}
