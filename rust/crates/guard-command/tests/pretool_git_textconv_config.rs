use crate::git_helper_fixture as fixture;
use fixture::*;
use guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context;
use guard_contracts::GuardExecutionEnvironmentV1;
use serde_json::json;

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

// Git for Windows configures a textconv driver for every user. It runs only
// while Git prints patch text, so ordinary status and summary reads stay quiet.
#[test]
fn textconv_driver_is_reviewed_only_where_git_can_run_it() {
    let root = std::env::temp_dir().join(format!("guard textconv {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    let marker = root.join("textconv-executed");
    let marker_path = marker.to_string_lossy().replace('\\', "/");
    let marker_command = format!("touch '{}'", marker_path.replace('\'', "'\\''"));
    let config_command = serde_json::to_string(&marker_command).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("[diff \"synthetic\"]\n\ttextconv = {config_command}\n"),
    )
    .unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join(".gitattributes"), "*.doc diff=synthetic\n").unwrap();
    std::fs::write(repository.join("notes.doc"), "first\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(repository.join("notes.doc"), "second\n").unwrap();
    git(&repository, &home, &["add", "notes.doc"]);

    let controls = github_controls("enabled");
    for harness in ["omp", "zcode"] {
        let evaluate = |command: &str| {
            evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                home.to_str(),
                repository.to_str(),
            )
        };
        for command in ["git status", "git status --short"] {
            let result = evaluate(command);
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
        for command in ["git status -v", "git status --verbose"] {
            let result = evaluate(command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.reason_code, "native_git_execution_context_review");
        }
    }

    let stamped = GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let evaluate = |command: &str| {
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
                shell_home_matches: false,
                ripgrep_config_absent: false,
            },
            Some(&stamped),
        )
    };
    for command in [
        "git log -3 --oneline",
        "git diff --cached --stat",
        "git show --stat HEAD",
    ] {
        let result = evaluate(command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {} / {}",
            result.reason_code, result.reason
        );
    }
    for command in [
        "git diff --cached",
        "git show HEAD",
        "git log -p -1",
        "git log -Sfirst",
    ] {
        assert_eq!(evaluate(command).decision, "deny", "{command}");
    }
    assert!(
        !marker.exists(),
        "inspection must never run a textconv driver"
    );
}
