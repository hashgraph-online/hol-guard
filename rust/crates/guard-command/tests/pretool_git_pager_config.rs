#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::*;
use serde_json::json;

#[test]
fn pager_checks_follow_the_actual_subcommand_and_global_override() {
    let root = std::env::temp_dir().join(format!("guard-git-pager-{}", std::process::id()));
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
    let config = repository.join(".git/config");
    let enabled = github_controls("enabled");
    for (settings, command, expected) in [
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git status --short",
            "allow",
        ),
        (
            "[pager]\nlog = ./synthetic-never-execute\n",
            "git status --short",
            "allow",
        ),
        (
            "[pager]\nstatus = ./synthetic-never-execute\n",
            "git status --short",
            "deny",
        ),
        ("[pager]\nstatus = true\n", "git status --short", "deny"),
        (
            "[core]\npager = ./synthetic-never-execute\n[pager]\nstatus = true\n",
            "git status --short",
            "deny",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n[pager]\nstatus = false\n",
            "git status --short",
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n[pager]\nstatus = cat\n",
            "git status --short",
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git --no-pager diff --no-ext-diff --no-textconv",
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git -P diff --no-ext-diff --no-textconv",
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git diff --no-ext-diff --no-textconv -- -P",
            "deny",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git diff --no-ext-diff --no-textconv",
            "deny",
        ),
    ] {
        std::fs::write(&config, settings).unwrap();
        for harness in ["omp", "zcode"] {
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
                result.decision, expected,
                "{harness}: {command}: {settings}"
            );
        }
    }
    std::fs::write(&config, "[pager]\nstatus = true\n").unwrap();
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into(), "GIT_PAGER".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    for (command, expected) in [
        ("git status --short", "deny"),
        ("git --no-pager status --short", "allow"),
    ] {
        let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&enabled),
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
            },
            Some(&context),
        );
        assert_eq!(result.decision, expected, "{command}: inherited pager");
    }
    for (settings, pager_disabled, expected) in [
        (
            "[pager]\nstatus = ./synthetic-never-execute\n",
            true,
            "deny",
        ),
        ("[pager]\nstatus = cat\n", false, "allow"),
        ("[core]\npager = cat\n", false, "allow"),
    ] {
        std::fs::write(&config, settings).unwrap();
        let mut caller = context.clone();
        caller.environment_names = vec!["GIT_CONFIG_NOSYSTEM".into(), "PAGER".into()];
        caller.pager_disabled = pager_disabled;
        let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
            Some(&enabled),
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
            },
            Some(&caller),
        );
        assert_eq!(result.decision, expected, "PAGER override: {settings}");
    }
    for (settings, git_pager_disabled, pager_disabled, expected) in [
        (
            "[core]\npager = ./synthetic-never-execute\n[pager]\nstatus = true\n",
            true,
            false,
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n[pager]\nstatus = true\n",
            false,
            true,
            "deny",
        ),
        ("[pager]\nstatus = true\n", false, true, "allow"),
    ] {
        std::fs::write(&config, settings).unwrap();
        let mut caller = context.clone();
        caller.environment_names = vec![
            "GIT_CONFIG_NOSYSTEM".into(),
            if git_pager_disabled {
                "GIT_PAGER"
            } else {
                "PAGER"
            }
            .into(),
        ];
        caller.git_pager_disabled = git_pager_disabled;
        caller.pager_disabled = pager_disabled;
        let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
            Some(&enabled),
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
            },
            Some(&caller),
        );
        assert_eq!(
            result.decision, expected,
            "disabled pager precedence: {settings}: {} / {}",
            result.reason_code, result.reason
        );
    }
}
