//! Cursor and VS Code export `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=core.quotePath`
//! and `GIT_CONFIG_VALUE_0=false` in every terminal they open. The entry only
//! changes how Git quotes paths, so a Git read from those terminals takes the
//! same answer as one from a plain shell once the hook has judged it inert.

use crate::git_helper_fixture::FixtureCleanup;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::GuardExecutionEnvironmentV1;
use serde_json::json;

const EDITOR_ENTRY: [&str; 3] = ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"];

fn stamp(extra: &[&str], inert: bool) -> GuardExecutionEnvironmentV1 {
    let mut names: Vec<String> = ["HOME", "PATH"]
        .iter()
        .chain(EDITOR_ENTRY.iter())
        .chain(extra.iter())
        .map(|name| (*name).to_owned())
        .collect();
    names.sort();
    GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names,
        environment_digest: "0".repeat(64),
        git_config_environment_inert: inert,
        ..Default::default()
    }
}

#[test]
fn a_git_read_from_an_editor_terminal_is_allowed_when_its_config_entry_is_inert() {
    let root = std::env::temp_dir().join(format!("guard-git-editor-env-{}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    let mut init = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
    ] {
        init.env_remove(name);
    }
    assert!(init
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let decide = |harness: &str, command: &str, environment: &GuardExecutionEnvironmentV1| {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        });
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &payload,
            None,
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: repository.to_str(),
                ..PathContext::default()
            },
            Some(environment),
        )
    };
    let reads = [
        "git status --short",
        "git log --oneline -3",
        "git diff --stat",
        "git branch --show-current",
    ];
    for harness in ["cursor", "codex", "claude-code"] {
        for command in reads {
            // A plain shell is the baseline the editor terminal now matches.
            let plain = GuardExecutionEnvironmentV1 {
                environment_names: vec!["HOME".into(), "PATH".into()],
                ..stamp(&[], false)
            };
            assert_eq!(
                decide(harness, command, &plain).decision,
                "allow",
                "{harness} {command} from a plain shell"
            );
            let result = decide(harness, command, &stamp(&[], true));
            assert_eq!(
                result.decision, "allow",
                "{harness} {command}: {} {}",
                result.reason_code, result.reason
            );
            // The same names without the hook's verdict could set a pager,
            // an fsmonitor command or an include, and keep their review.
            assert_ne!(
                decide(harness, command, &stamp(&[], false)).decision,
                "allow",
                "{harness} {command} without the verdict"
            );
            // The verdict covers only the counted entries. Other ways to hand
            // Git configuration keep their review beside it.
            for other in [
                "GIT_CONFIG_PARAMETERS",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_CONFIG",
                "GIT_DIR",
                "GIT_EXEC_PATH",
            ] {
                assert_ne!(
                    decide(harness, command, &stamp(&[other], true)).decision,
                    "allow",
                    "{harness} {command} with {other}"
                );
            }
        }
    }
}
