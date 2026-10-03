use serde_json::json;

struct FixtureCleanup(std::path::PathBuf);

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Cargo injects dynamic-loader settings into the test process. Model the
// synthetic hook caller explicitly rather than inheriting the build harness.
fn evaluate_pre_tool_envelope_with_context(
    harness: &str,
    event: &str,
    payload: &serde_json::Value,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    deadline: Option<std::time::Instant>,
    home: Option<&str>,
    cwd: Option<&str>,
) -> guard_contracts::PreToolResultV1 {
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        harness,
        event,
        payload,
        controls,
        deadline,
        home,
        cwd,
        Some(&context),
    )
}

fn github_controls(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    git_github_controls(state, state)
}

fn git_github_controls(
    git_state: &str,
    github_state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[
                {"target_kind":"permission", "target_id":"command.git.permission.status", "state":git_state},
                {"target_kind":"permission", "target_id":"command.git.permission.diff", "state":git_state},
                {"target_kind":"permission", "target_id":"command.git.permission.log", "state":git_state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-local", "state":github_state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-remote", "state":github_state}
            ]
        }]
    });
    value["layers"][0]["controls"]
        .as_array_mut()
        .unwrap()
        .retain(|control| control["state"] != "default");
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

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
            home.to_str(),
            repository.to_str(),
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
            home.to_str(),
            repository.to_str(),
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
            home.to_str(),
            repository.to_str(),
            Some(&caller),
        );
        assert_eq!(
            result.decision, expected,
            "disabled pager precedence: {settings}: {} / {}",
            result.reason_code, result.reason
        );
    }
}

#[test]
fn git_query_uses_bounded_request_context_not_resident_path() {
    use guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context;
    use guard_contracts::GuardExecutionEnvironmentV1;
    let root = std::env::temp_dir().join(format!("guard-git-lookup-{}", std::process::id()));
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
    let original_path = std::env::var("PATH").unwrap();
    let evaluate = |context: &GuardExecutionEnvironmentV1| {
        evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
            None,
            None,
            home.to_str(),
            repository.to_str(),
            Some(context),
        )
    };
    let context = GuardExecutionEnvironmentV1 {
        path: original_path.clone(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    assert_eq!(evaluate(&context).decision, "allow");
    let caller_home = root.join("actual-caller-home");
    std::fs::create_dir_all(&caller_home).unwrap();
    std::fs::write(
        caller_home.join(".gitconfig"),
        b"[core]\nfsmonitor = ./synthetic-never-execute\n",
    )
    .unwrap();
    let mut home_routed = context.clone();
    home_routed.home = Some(caller_home.to_string_lossy().into_owned());
    assert_eq!(evaluate(&home_routed).decision, "deny");
    std::fs::write(
        caller_home.join(".gitconfig"),
        b"[core]\nfsmonitor = false\n",
    )
    .unwrap();
    let home_routed_safe = evaluate(&home_routed);
    assert_eq!(
        home_routed_safe.decision, "allow",
        "safe caller home: {} / {}",
        home_routed_safe.reason_code, home_routed_safe.reason
    );
    assert_eq!(
        evaluate(&GuardExecutionEnvironmentV1::unavailable()).decision,
        "deny"
    );
    let xdg = root.join("custom-config");
    std::fs::create_dir_all(xdg.join("git")).unwrap();
    std::fs::write(
        xdg.join("git/config"),
        b"[core]\nfsmonitor = ./synthetic-never-execute\n",
    )
    .unwrap();
    let mut routed = context.clone();
    routed.xdg_config_home = Some(xdg.to_string_lossy().into_owned());
    routed.environment_names.push("XDG_CONFIG_HOME".into());
    assert_eq!(evaluate(&routed).decision, "deny");
    std::fs::write(xdg.join("git/config"), b"[core]\nfsmonitor = false\n").unwrap();
    let routed_safe = evaluate(&routed);
    assert_eq!(routed_safe.decision, "allow");
    for context in [
        GuardExecutionEnvironmentV1 {
            path: "/synthetic-no-git".into(),
            environment_names: vec![],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec!["GIT_EXTERNAL_DIFF".into()],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec!["git_config_global".into()],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec!["GIT_DISCOVERY_ACROSS_FILESYSTEM".into()],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec![],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: Some(xdg.to_string_lossy().into_owned()),
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: original_path.clone(),
            environment_names: vec!["XDG_CONFIG_HOME".into()],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
        GuardExecutionEnvironmentV1 {
            path: "x".repeat(32769),
            environment_names: vec![],
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        },
    ] {
        assert_eq!(evaluate(&context).decision, "deny");
    }
    let shadow = repository.join("bin");
    std::fs::create_dir_all(&shadow).unwrap();
    let shadow_executable = if cfg!(windows) { "git.exe" } else { "git" };
    std::fs::write(
        shadow.join(shadow_executable),
        b"synthetic executable must never run",
    )
    .unwrap();
    let shadow_path =
        std::env::join_paths(std::iter::once(shadow).chain(std::env::split_paths(&original_path)))
            .unwrap();
    let context = GuardExecutionEnvironmentV1 {
        path: shadow_path.to_string_lossy().into_owned(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    assert_eq!(evaluate(&context).decision, "deny");
}

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
    std::fs::write(
        home.join(".gitconfig"),
        "[gpg]\n\tprogram = /tmp/synthetic-never-execute\n[log]\n\tshowSignature = true\n",
    )
    .unwrap();
    for harness in ["omp", "zcode"] {
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
