#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::*;
use serde_json::json;

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
    let mut init = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        init.env_remove(name);
    }
    assert!(init
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
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
                cdpath_unset: false,
            },
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
    // The absent HOME field falls back to the verified home spelling. This
    // must still read global configuration on Git for Windows.
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\nfsmonitor = ./synthetic-never-execute\n",
    )
    .unwrap();
    assert_eq!(evaluate(&context).decision, "deny");
    std::fs::write(home.join(".gitconfig"), "").unwrap();
    assert_eq!(evaluate(&context).decision, "allow");

    for name in [
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    ] {
        let mut overridden = context.clone();
        overridden.environment_names.push(name.into());
        assert_eq!(
            evaluate(&overridden).minimum_action,
            "require-reapproval",
            "{name}"
        );
    }
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
fn stamped_git_reads_allow_only_when_no_diff_helper_is_configured() {
    use guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context;
    use guard_contracts::GuardExecutionEnvironmentV1;
    let root = std::env::temp_dir().join(format!("guard-git-helpers-{}", std::process::id()));
    let home = root.join("home");
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    let mut init = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        init.env_remove(name);
    }
    assert!(init
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let stamped = GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    let evaluate = |command: &str, context: Option<&GuardExecutionEnvironmentV1>| {
        evaluate_pre_tool_envelope_with_execution_context(
            "cursor",
            "PreToolUse",
            &json!({"tool_name":"Shell", "tool_input":{"command":command}}),
            None,
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
                cdpath_unset: false,
            },
            context,
        )
    };
    for command in ["git log -3 --oneline", "git diff", "git show HEAD"] {
        let unstamped = evaluate(command, None);
        assert_eq!(unstamped.decision, "deny", "{command}");
        let verified = evaluate(command, Some(&stamped));
        assert_eq!(
            verified.decision, "allow",
            "{command}: {} / {}",
            verified.reason_code, verified.reason
        );
    }
    let config = repository.join(".git/config");
    let original = std::fs::read_to_string(&config).unwrap();
    for helper in [
        "[diff \"synthetic\"]\n\ttextconv = ./synthetic-never-execute\n",
        "[diff \"synthetic\"]\n\tcommand = ./synthetic-never-execute\n",
        "[diff]\n\texternal = ./synthetic-never-execute\n",
    ] {
        std::fs::write(&config, format!("{original}{helper}")).unwrap();
        for command in ["git log -p -1", "git diff"] {
            assert_eq!(
                evaluate(command, Some(&stamped)).decision,
                "deny",
                "{command} with {helper}"
            );
        }
    }
    std::fs::write(&config, original).unwrap();
    let assigned = evaluate("GIT_EXTERNAL_DIFF=./x git diff", Some(&stamped));
    assert_eq!(assigned.decision, "deny");
}
