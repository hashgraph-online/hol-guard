#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::*;
use serde_json::json;

#[test]
fn configured_fsmonitor_cannot_be_admitted_as_a_benign_read() {
    let root = std::env::temp_dir().join(format!("guard-git-config-{}", std::process::id()));
    let home = root.join("home");
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let enabled = github_controls("enabled");
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["config", "core.fsmonitor", "./synthetic-never-execute"])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git diff --no-ext-diff --no-textconv",
            "git -P status --short",
            "git -P diff --no-ext-diff --no-textconv",
            "echo ready && git status --short",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.reason_code, "native_git_execution_context_review");
        }
    }
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["config", "core.fsmonitor", "false"])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        std::fs::write(home.join(".gitconfig"), "").unwrap();
        let clean = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git log --no-ext-diff --no-textconv -1"}}),
            Some(&enabled),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(
            clean.decision, "allow",
            "{harness}: clean log must be admitted"
        );
        for option in [
            "--format=%G?",
            "--pretty=%GG",
            "--remerge-diff",
            "--submodule=diff",
        ] {
            let command = format!("git log --no-ext-diff --no-textconv {option} -1");
            let formatted = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(formatted.minimum_action, "require-reapproval", "{command}");
        }
        std::fs::write(home.join(".gitconfig"), "[pretty]\nsigned = format:%G?\n").unwrap();
        let alias = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git log --no-ext-diff --no-textconv --pretty=signed -1"}}),
            Some(&enabled),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(alias.minimum_action, "require-reapproval");
        // Reset for each harness so the negative assertion tests this config,
        // not leftovers from the preceding harness or an explicit CLI flag.
        std::fs::write(
            home.join(".gitconfig"),
            "[gpg]\n\tprogram = /tmp/synthetic-never-execute\n[log]\n\tshowSignature = true\n",
        )
        .unwrap();
        for command in [
            "git status --short",
            "git -c core.quotepath=false status --short",
            "git -c core.fsmonitor=false status --short",
            "git -P -c core.quotepath=false -C . status --short",
            "echo ready && git status --short | head -1",
            "git status --short && gh api repos/owner/repo/compare/base...main | head -1",
            "gh api repos/hashgraph-online/points-portal/compare/dc1ace862c...main --jq '[.files[].filename] | map(select(test(\"protection|protect-page|protect-resource|guard-protect-asset\"))) | .[]'",
            "git status --short && gh api repos/owner/repo/compare/base...main --jq '[.files[].filename] | .[]' | head -1",
            "gh api repos/owner/repo/compare/base...main; git status --short",
            "git status --short || gh api repos/owner/repo/compare/base...main",
            "gh api repos/owner/repo/compare/base...main | git status --short",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: safe configuration must stay quiet: {} / {}",
                result.reason_code, result.reason
            );
        }
        for command in [
            "git log --no-ext-diff --no-textconv -1",
            "git show --no-ext-diff --no-textconv HEAD",
            "git log --no-ext-diff --no-textconv --show-signature -1",
            "git log --no-ext-diff --no-textconv --show-signature --no-show-signature -1",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_ne!(
                result.decision, "allow",
                "{harness}: {command}: signature reads must retain review"
            );
        }
    }
    let disabled = github_controls("disabled");
    let defaults = github_controls("default");
    for harness in ["omp", "zcode"] {
        for command in [
            "gh api repos/hashgraph-online/points-portal/compare/dc1ace862c...main --jq '[.files[].filename] | map(select(test(\"protection|protect-page|protect-resource|guard-protect-asset\"))) | .[]'",
            "git status --short && gh api repos/owner/repo/compare/base...main | head -1",
            "gh api repos/owner/repo/compare/base...main; git status --short",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&defaults),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.decision, "allow", "{harness}: default permissions: {command}: {}", result.reason_code);
        }
    }
    for (git_state, github_state) in [("disabled", "enabled"), ("enabled", "disabled")] {
        let mixed = git_github_controls(git_state, github_state);
        for harness in ["omp", "zcode"] {
            for command in [
                "git status --short && gh api repos/owner/repo/compare/base...main | head -1",
                "gh api repos/owner/repo/compare/base...main; git status --short",
                "git status --short || gh api repos/owner/repo/compare/base...main",
                "gh api repos/owner/repo/compare/base...main | git status --short",
                "git -P status --short && gh api repos/owner/repo/compare/base...main",
                "git status --short && gh api repos/owner/repo/compare/base...main --jq '[.files[].filename] | .[]' | head -1",
            ] {
                let result = evaluate_pre_tool_envelope_with_context(
                    harness,
                    "PreToolUse",
                    &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                    Some(&mixed),
                    None,
                    home.to_str(),
                    repository.to_str(),
                );
                assert_eq!(
                    result.minimum_action, "block",
                    "{harness}: {git_state}/{github_state}: {command}"
                );
            }
        }
    }
    for harness in ["omp", "zcode"] {
        for command in [
            "echo ready && git status --short | head -1",
            "git status --short && gh api repos/owner/repo/compare/base...main",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&disabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.minimum_action, "block", "{harness}: {command}");
        }
        for command in [
            "git config core.fsmonitor ./synthetic-never-execute && git status --short",
            "GIT_CONFIG_GLOBAL=/tmp/synthetic-never-read git status --short",
            "GIT_EXTERNAL_DIFF=/tmp/synthetic-never-execute git status --short",
            "PAGER=/tmp/synthetic-never-execute git status --short",
            "gh api repos/owner/repo; cat .env",
            "git status --short; rm -rf src",
            "git status --short && synthetic-unknown-tool",
            "synthetic-unknown-tool; gh api repos/owner/repo/compare/base...main",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
    std::fs::write(
        repository.join(".gitattributes"),
        "fixture.txt filter=fixture\n",
    )
    .unwrap();
    std::fs::write(repository.join("fixture.txt"), "ordinary fixture\n").unwrap();
    for key in [
        "filter.fixture.clean",
        "filter.fixture.process",
        "filter.fixture.smudge",
    ] {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", key, "./synthetic-never-execute"])
            .status()
            .unwrap()
            .success());
        for harness in ["omp", "zcode"] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
                Some(&enabled),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.reason_code, "native_git_execution_context_review",
                "{harness}: {key}"
            );
        }
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", "--unset", key])
            .status()
            .unwrap()
            .success());
    }
}
