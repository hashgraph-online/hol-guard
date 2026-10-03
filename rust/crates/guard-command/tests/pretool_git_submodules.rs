use serde_json::json;
#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

#[test]
fn indexed_submodules_require_review_unless_all_submodule_processing_is_disabled() {
    let root = std::env::temp_dir().join(format!(
        "guard-submodule-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    // A gitlink can exist without .gitmodules or initialized module directories.
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,child"
        ])
        .status()
        .unwrap()
        .success());
    std::fs::create_dir_all(repository.join("nested")).unwrap();
    let controls = fixture::github_controls("enabled");
    for (command, allowed) in [
        ("git status --short", false),
        ("git diff --no-ext-diff --no-textconv", false),
        ("git -C . status --short", false),
        ("git -C nested status --short", false),
        ("git status --ignore-submodules=all", true),
        (
            "git diff --ignore-submodules=all --no-ext-diff --no-textconv",
            true,
        ),
        (
            "git status --ignore-submodules=all --ignore-submodules=none",
            false,
        ),
    ] {
        let result = fixture::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(
            result.decision == "allow",
            allowed,
            "{command}: {}",
            result.reason_code
        );
        if !allowed {
            assert_eq!(result.minimum_action, "require-reapproval");
        }
    }
    let nested = repository.join("nested");
    let from_nested = fixture::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
        Some(&controls),
        None,
        home.to_str(),
        nested.to_str(),
    );
    assert_eq!(from_nested.minimum_action, "require-reapproval");
}

#[test]
fn unstamped_git_context_retains_the_legacy_fail_closed_path() {
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
        None,
        None,
        None,
        None,
    );
    assert_eq!(result.minimum_action, "require-reapproval");
    assert!(!result.explicitly_benign);
}
