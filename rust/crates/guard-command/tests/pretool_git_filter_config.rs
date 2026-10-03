#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::*;
use serde_json::json;

#[test]
fn unused_global_filters_do_not_block_unrelated_repository_inspection() {
    let root = std::env::temp_dir().join(format!("guard-unused-filters-{}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("ordinary.txt"), "ordinary fixture\n").unwrap();
    let marker = root.join("filter-executed");
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[filter \"synthetic\"]\n\tclean = touch {}\n\tsmudge = touch {}\n",
            marker.display(),
            marker.display()
        ),
    )
    .unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let controls = github_controls("enabled");
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git -C src status --short",
            "git diff --no-ext-diff --no-textconv",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
    // Routing into src must not hide a filter attached to a root-level path.
    std::fs::write(
        repository.join(".gitattributes"),
        "ordinary.txt filter=synthetic\n",
    )
    .unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git -C src status --short",
            "git diff --no-ext-diff --no-textconv",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.reason_code, "native_git_execution_context_review");
        }
    }
    assert!(
        !marker.exists(),
        "inspection must never execute configured filters"
    );
    std::fs::write(repository.join(".gitattributes"), "").unwrap();
    std::fs::create_dir(repository.join("module")).unwrap();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,module"
        ])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git -C src status --short"}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(
            result.reason_code, "native_git_execution_context_review",
            "submodule filter context is not proven"
        );
    }
}
