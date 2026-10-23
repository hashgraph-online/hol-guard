#![cfg(unix)]
//! `cd ~/...` prefixes: the shell expands an unquoted `~` from its HOME, so
//! the target is proved against home only when that HOME is the declared one.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding the hook workspace, a sibling worktree and a plain
/// directory. The root stays below the target directory: `$TMPDIR` on macOS
/// resolves under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-cd")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/src")).unwrap();
    std::fs::write(home.join("project/src/one.ts"), "export {};\n").unwrap();
    std::fs::create_dir_all(home.join("sibling/dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(home.join("sibling/.git"), "gitdir: /nonexistent\n").unwrap();
    std::fs::create_dir_all(home.join("outside")).unwrap();
    std::fs::create_dir_all(root.join("other-home")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn classify(
    home: &Path,
    shell_home: &Path,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["HOME".into(), "PATH".into()],
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: project.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
}

const BUILD: &str = "native_node_build_output_containment_required";

#[test]
fn home_relative_cd_reaches_the_same_proofs_as_the_absolute_path() {
    let home = home();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "cd ~/project && ls src",
            "cd ~/project/src && cat one.ts",
            "cd ~/project && rg -n export src",
        ] {
            let result = classify(&home, &home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
        for command in [
            "cd ~/sibling/dashboard && ./node_modules/.bin/vite build 2>&1 | tail -15",
            "cd ~/sibling/dashboard && node node_modules/vite/bin/vite.js build 2>&1 | tail -12",
            "cd ~/project && node node_modules/vite/bin/vite.js build",
        ] {
            let result = classify(&home, &home, harness, command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(result.reason_code, BUILD, "{harness}: {command}");
            }
        }
    }
}

#[test]
fn doubled_slash_after_tilde_is_still_the_home_directory() {
    let home = home();
    let result = classify(&home, &home, "codex", "cd ~//project && ls src");
    assert_eq!(result.decision, "allow", "{result:?}");
    let quoted_slash = classify(&home, &home, "codex", "cd ~/\"project\" && ls src");
    assert_eq!(quoted_slash.decision, "allow", "{quoted_slash:?}");
}

#[test]
fn mixed_quote_after_tilde_is_not_proved_as_home() {
    let home = home();
    // A real directory whose name is `~`, so a literal tilde word can resolve.
    std::fs::create_dir_all(home.join("project/~")).unwrap();
    for command in [
        "cd ~\"/project\" && ls src",
        "cd ~'/project' && ls src",
        "cd ~\"/sibling/dashboard\" && ./node_modules/.bin/vite build",
    ] {
        let result = classify(&home, &home, "codex", command);
        assert_ne!(result.decision, "allow", "{command}: {result:?}");
        assert_ne!(
            result.minimum_action, "sandbox-required",
            "{command}: {result:?}"
        );
    }
}

#[test]
fn unproven_home_spellings_are_not_upgraded() {
    let home = home();
    let other = home.parent().unwrap().join("other-home");
    for harness in ["omp", "codex"] {
        // A shell HOME that names another directory expands `~` there.
        for command in [
            "cd ~/project && ls src",
            "cd ~/sibling/dashboard && ./node_modules/.bin/vite build",
        ] {
            let result = classify(&home, &other, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
        for command in [
            // A quoted or escaped `~` is a literal relative directory.
            "cd \"~/project\" && ls src",
            "cd '~/project' && ls src",
            "cd \\~/project && ls src",
            "cd ~nobody/project && ls src",
            "cd ~+/project && ls src",
            "cd ~/outside && ./node_modules/.bin/vite build",
            "cd ~/sibling/dashboard && ./node_modules/.bin/vite build | sh",
            "cd ~/project && node node_modules_evil/vite/bin/vite.js build",
            "cd ~/project && node xnode_modules/vite/bin/vite.js build",
        ] {
            let result = classify(&home, &home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
    }
}
