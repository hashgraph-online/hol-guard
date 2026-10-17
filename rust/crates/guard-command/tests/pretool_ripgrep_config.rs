use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

#[test]
fn an_inherited_ripgrep_config_keeps_file_searches_on_review() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/ripgrep-config")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let project = root.join("project");
    std::fs::write(project.join("notes.txt"), "needle\n").unwrap();

    for harness in ["codex", "claude-code"] {
        // No inherited config: the arguments alone decide.
        for command in [
            "rg needle",
            "rg -n needle notes.txt",
            "rg -z needle notes.txt",
        ] {
            assert_eq!(
                decide_with(harness, &[], command, &home, &project),
                "allow",
                "{harness} `{command}`"
            );
        }
        // The config's lines are prepended to the arguments, so a `--pre` or
        // `--hidden` there is invisible to the proof.
        for name in ["RIPGREP_CONFIG_PATH", "ripgrep_config_path"] {
            for command in [
                "rg needle",
                "rg -n needle notes.txt",
                "rg -e --no-config notes.txt",
                "rg --regexp --no-config notes.txt",
                "rg needle -- --no-config",
            ] {
                assert_ne!(
                    decide_with(harness, &[name], command, &home, &project),
                    "allow",
                    "{harness} {name} `{command}`"
                );
            }
        }
        // `--no-config` makes ripgrep skip the file entirely.
        for command in [
            "rg --no-config needle",
            "rg -n --no-config needle notes.txt",
        ] {
            assert_eq!(
                decide_with(harness, &["RIPGREP_CONFIG_PATH"], command, &home, &project),
                "allow",
                "{harness} `{command}`"
            );
        }
    }
}

/// A piped search reads its input instead of walking the tree, so the config
/// proof is the only thing between an inherited RIPGREP_CONFIG_PATH and a
/// path operand the config adds. The flag clears that config only where
/// ripgrep parses it as an option: as the value of one it is a pattern or a
/// replacement, and the config still loads.
#[test]
fn a_piped_search_answers_for_a_config_its_pattern_cannot_clear() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/ripgrep-config-pipe")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let project = root.join("project");
    std::fs::write(project.join("notes.txt"), "needle\n").unwrap();

    for harness in ["codex", "claude-code"] {
        // Without a config the filter stands on its own.
        assert_eq!(
            decide_with(harness, &[], "cat notes.txt | rg needle", &home, &project),
            "allow",
            "{harness} plain pipe"
        );
        // The flag parsed as an option: ripgrep reads no config at all.
        for command in [
            "cat notes.txt | rg --no-config needle",
            "cat notes.txt | rg -n --no-config needle",
        ] {
            assert_eq!(
                decide_with(harness, &["RIPGREP_CONFIG_PATH"], command, &home, &project),
                "allow",
                "{harness} `{command}`"
            );
        }
        // The same spelling as a value, and past the end-of-options marker:
        // the config still loads and can hand the search a path of its own.
        for command in [
            "cat notes.txt | rg needle",
            "cat notes.txt | rg -e --no-config",
            "cat notes.txt | rg --regexp --no-config",
            "cat notes.txt | rg --replace --no-config needle",
            "cat notes.txt | rg needle -- --no-config",
        ] {
            assert_ne!(
                decide_with(harness, &["RIPGREP_CONFIG_PATH"], command, &home, &project),
                "allow",
                "{harness} `{command}`"
            );
        }
    }
}

fn decide_with(
    harness: &str,
    environment_names: &[&str],
    command: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap_or_default(),
        environment_names: environment_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&github_controls("enabled")),
        None,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..Default::default()
        },
        Some(&environment),
    )
    .decision
}
