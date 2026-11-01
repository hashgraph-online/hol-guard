use crate::git_helper_fixture as fixture;
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
    let evaluate_command = |command: &str, context: &GuardExecutionEnvironmentV1| {
        evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            None,
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                gem_config_absent: false,
                http_config_absent: false,
                psql_environment: Default::default(),
                creates_nothing: false,
            },
            Some(context),
        )
    };
    let evaluate =
        |context: &GuardExecutionEnvironmentV1| evaluate_command("git status --short", context);
    let context = GuardExecutionEnvironmentV1 {
        path: original_path.clone(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
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
    // The config probe clears the environment, but an allowed `git` still
    // runs in the caller environment, so a search path of `.` or an empty
    // entry can load a library the probe never saw. A search path declared by
    // name only, without a stamped value, stays unproven. The Windows loader
    // never reads these search paths, so there they leave the proof intact.
    for name in guard_contracts::LIBRARY_SEARCH_PATH_NAMES {
        let mut loader = context.clone();
        loader.environment_names.push((*name).into());
        assert_eq!(
            evaluate(&loader).decision == "allow",
            cfg!(windows),
            "{name}"
        );
    }
    // Injection variables are refused on every platform.
    for name in ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"] {
        let mut loader = context.clone();
        loader.environment_names.push(name.into());
        assert_ne!(evaluate(&loader).decision, "allow", "{name}");
    }
    // A model-chosen search path on the command line is not the exported
    // toolchain environment and still is not a proven Git read.
    for command in [
        "LD_LIBRARY_PATH=. git status --short",
        "DYLD_LIBRARY_PATH=. git status --short",
        "env LD_LIBRARY_PATH=. git status --short",
    ] {
        assert_ne!(
            evaluate_command(command, &context).decision,
            "allow",
            "{command}"
        );
    }
    #[cfg(unix)]
    {
        // A stamped search path keeps the proof only when every entry is an
        // existing canonical directory that no other user can write: a system
        // directory, or one below home and outside the working tree.
        let stamped = |names: &[(&str, &str)]| {
            let mut loader = context.clone();
            for (name, value) in names {
                loader.environment_names.push((*name).into());
                loader
                    .library_search_paths
                    .insert((*name).into(), (*value).into());
            }
            evaluate(&loader).decision
        };
        for name in [
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_FALLBACK_FRAMEWORK_PATH",
        ] {
            assert_eq!(stamped(&[(name, "/usr/lib")]), "allow", "{name}");
            assert_eq!(stamped(&[(name, "/usr/lib:/usr")]), "allow", "{name}");
        }
        let repository_lib = repository.join("lib");
        let home_lib = home.join(".local/lib");
        std::fs::create_dir_all(&repository_lib).unwrap();
        std::fs::create_dir_all(&home_lib).unwrap();
        // The loader searches the literal entry, so the stamped value is the
        // canonical spelling (`/private/var` rather than `/var` on macOS).
        let home_lib = std::fs::canonicalize(&home_lib).unwrap();
        let canonical_home = std::fs::canonicalize(&home).unwrap();
        // The same exported path reaches every other process the agent starts,
        // so a home toolchain directory keeps the Git read quiet.
        assert_eq!(
            stamped(&[("LD_LIBRARY_PATH", home_lib.to_str().unwrap())]),
            "allow"
        );
        assert_eq!(
            stamped(&[(
                "LD_LIBRARY_PATH",
                &format!("/usr/lib:{}", home_lib.display())
            )]),
            "allow"
        );
        let linked_lib = canonical_home.join("linked-lib");
        std::os::unix::fs::symlink(&home_lib, &linked_lib).unwrap();
        let shared_lib = canonical_home.join("shared-lib");
        std::fs::create_dir_all(&shared_lib).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared_lib, std::fs::Permissions::from_mode(0o777)).unwrap();
        let below_shared = shared_lib.join("lib");
        std::fs::create_dir_all(&below_shared).unwrap();
        let repository_lib = repository_lib.to_str().unwrap();
        let temporary = root.to_str().unwrap();
        let home_dir = canonical_home.to_str().unwrap();
        let linked_lib = linked_lib.to_str().unwrap();
        let shared_lib = shared_lib.to_str().unwrap();
        let below_shared = below_shared.to_str().unwrap();
        let missing_home_lib = canonical_home.join("missing-lib");
        let missing_home_lib = missing_home_lib.to_str().unwrap();
        for value in [
            ".",
            "",
            "lib",
            "./lib",
            "/usr/lib:",
            ":/usr/lib",
            "/usr/lib::/usr",
            "/usr/lib:.",
            "/usr/lib/synthetic-missing-directory",
            "/tmp",
            repository_lib,
            temporary,
            home_dir,
            linked_lib,
            shared_lib,
            below_shared,
            missing_home_lib,
        ] {
            assert_ne!(stamped(&[("LD_LIBRARY_PATH", value)]), "allow", "{value:?}");
        }
        // Injection variables are never stamped by value, so a value for one
        // makes the whole context invalid.
        for name in ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"] {
            assert_ne!(stamped(&[(name, "/usr/lib")]), "allow", "{name}");
        }
        // Every declared search path needs its own trusted value.
        let mut partial = context.clone();
        partial.environment_names.push("DYLD_LIBRARY_PATH".into());
        partial.environment_names.push("LD_LIBRARY_PATH".into());
        partial
            .library_search_paths
            .insert("LD_LIBRARY_PATH".into(), "/usr/lib".into());
        assert_ne!(evaluate(&partial).decision, "allow");
        // A value whose name the hook did not declare is inconsistent.
        let mut undeclared = context.clone();
        undeclared
            .library_search_paths
            .insert("LD_LIBRARY_PATH".into(), "/usr/lib".into());
        assert_ne!(evaluate(&undeclared).decision, "allow");
        // Inline assignments are not the exported environment.
        let mut exported = context.clone();
        exported.environment_names.push("LD_LIBRARY_PATH".into());
        exported
            .library_search_paths
            .insert("LD_LIBRARY_PATH".into(), "/usr/lib".into());
        assert_ne!(
            evaluate_command("LD_LIBRARY_PATH=. git status --short", &exported).decision,
            "allow"
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        ..Default::default()
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
        ..Default::default()
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
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                gem_config_absent: false,
                http_config_absent: false,
                psql_environment: Default::default(),
                creates_nothing: false,
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

/// A `-C` route to a directory that holds no repository skips the
/// configuration probe, because Git stops in its own setup there. The probe
/// was also where the Git binary was checked, so a planted `git` ahead of the
/// real one on the search path must still keep the review.
#[test]
fn a_route_to_no_repository_still_needs_a_trusted_git() {
    use guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context;
    use guard_contracts::GuardExecutionEnvironmentV1;
    // The same layout `pretool_git_absent_repository` proves on every host: a
    // root below `/tmp` on unix (the read screens refuse the macOS per-user
    // temporary directory under `/var`) and below the per-user temporary
    // directory on Windows, spelled without the verbatim prefix. The route
    // names a plain directory below the declared home, outside a checkout.
    #[cfg(unix)]
    let base = std::path::PathBuf::from("/tmp");
    #[cfg(windows)]
    let base = std::env::temp_dir();
    let root = std::fs::canonicalize(base).unwrap().join(format!(
        "guard-git-no-repository-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let root = fixture::canonical_spelling(root);
    let home = root.join("home");
    let workspace = home.join("Code").join("app-portal");
    std::fs::create_dir_all(&workspace).unwrap();
    crate::pretool_home_layout_reads::repository(&workspace);
    let plain = home.join("Code").join("scratch-notes");
    std::fs::create_dir_all(&plain).unwrap();
    let original_path = std::env::var("PATH").unwrap();
    let environment = |path: String| GuardExecutionEnvironmentV1 {
        path,
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into(), "HOME".into(), "PATH".into()],
        environment_digest: "0".repeat(64),
        home: home.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    };
    let evaluate = |command: &str, context: &GuardExecutionEnvironmentV1| {
        evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            None,
            None,
            guard_command::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: workspace.to_str(),
                ..Default::default()
            },
            Some(context),
        )
    };
    let route = fixture::shell_word(&plain);
    let commands = [
        format!("git -C {route} status --short"),
        format!("git -C {route} status --short && echo \"---FILES---\""),
    ];
    let trusted = environment(original_path.clone());
    for command in &commands {
        let result = evaluate(command, &trusted);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }

    // The route expands `~` against the declared home. A shell whose own
    // home is elsewhere sends Git to a directory the route never looked at,
    // which may hold a repository, so that read keeps the review.
    let from_home = "git -C ~/Code/scratch-notes status --short";
    let result = evaluate(from_home, &trusted);
    assert_eq!(
        result.decision, "allow",
        "{from_home}: {}",
        result.reason_code
    );
    let other_home = root.join("other-home");
    crate::pretool_home_layout_reads::repository(&other_home.join("Code").join("scratch-notes"));
    let mut elsewhere = environment(original_path.clone());
    elsewhere.home = other_home.to_str().map(str::to_owned);
    let result = evaluate(from_home, &elsewhere);
    assert_ne!(result.decision, "allow", "{from_home}");
    assert_eq!(result.minimum_action, "require-reapproval", "{from_home}");

    let shadow = home.join("bin");
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
    let planted = environment(shadow_path.to_string_lossy().into_owned());
    for command in &commands {
        let result = evaluate(command, &planted);
        assert_ne!(result.decision, "allow", "{command}");
        assert_eq!(result.minimum_action, "require-reapproval", "{command}");
        assert_eq!(
            result.reason_code, "native_git_execution_context_review",
            "{command}"
        );
    }

    // The probe screened the environment as well as the binary. A directory
    // that holds no repository holds one once `GIT_DIR` names it, and that
    // repository's own `core.fsmonitor` runs on the status read; a loader
    // variable reaches even the trusted Git. Each keeps the review.
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_EXEC_PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        let mut directed = environment(original_path.clone());
        directed.environment_names.push(name.to_owned());
        for command in &commands {
            let result = evaluate(command, &directed);
            assert_ne!(result.decision, "allow", "{name} {command}");
            assert_eq!(
                result.minimum_action, "require-reapproval",
                "{name} {command}"
            );
            assert_eq!(
                result.reason_code, "native_git_execution_context_review",
                "{name} {command}"
            );
        }
    }
}
