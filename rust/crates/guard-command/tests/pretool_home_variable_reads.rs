#![cfg(unix)]
//! A read that names the home directory as `$HOME` or `${HOME}` gets the same
//! verdict as the same read written with `~`, once the shell's HOME is the
//! declared home. Credential stores, single-quoted text and a HOME the
//! command could reassign keep review.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with installed Node versions, an unpacked download, a credential
/// store and a project. The root stays below the target directory: `$TMPDIR`
/// on macOS resolves under `/private/var`, which the sensitive-root screen
/// rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-variable-reads")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".nvm/versions/node/v22.11.0",
        ".nvm/versions/node/v24.2.0",
        "Downloads/widgets-1.4.0",
        ".ssh",
        "work/project",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    std::fs::write(home.join("Downloads/widgets-1.4.0/README"), "widgets\n").unwrap();
    std::fs::write(home.join(".ssh/config"), "Host example\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, shell_home: &Path, command: &str) -> String {
    let cwd = home.join("work/project");
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            // As the daemon edge does: the stamped HOME decides whether the
            // shell's home is the declared one.
            ..PathContext::default()
        },
        Some(&environment),
    )
    .minimum_action
}

#[test]
fn home_variable_reads_match_their_tilde_spelling() {
    let home = home("pair");
    for pair in [
        [
            "find ~/.nvm/versions/node -mindepth 1 -maxdepth 1 -type d -print",
            "find \"$HOME/.nvm/versions/node\" -mindepth 1 -maxdepth 1 -type d -print",
            "find ${HOME}/.nvm/versions/node -mindepth 1 -maxdepth 1 -type d -print",
        ],
        [
            "ls ~/Downloads/widgets-1.4.0",
            "ls \"$HOME/Downloads/widgets-1.4.0\"",
            "ls \"${HOME}/Downloads/widgets-1.4.0\"",
        ],
        [
            "shasum -a 256 ~/Downloads/widgets-1.4.0/*",
            "shasum -a 256 $HOME/Downloads/widgets-1.4.0/*",
            "shasum -a 256 ${HOME}/Downloads/widgets-1.4.0/*",
        ],
        [
            "find ~/Downloads/widgets-1.4.0 -type f -print | sort",
            "find \"$HOME/Downloads/widgets-1.4.0\" -type f -print | sort",
            "find $HOME/Downloads/widgets-1.4.0 -type f -print | sort",
        ],
    ] {
        for command in pair {
            assert_eq!(action(&home, &home, command), "allow", "{command}");
        }
    }
}

#[test]
fn home_variable_reads_of_stores_or_reassigned_homes_keep_review() {
    let home = home("review");
    for command in [
        "cat \"$HOME/.ssh/config\"",
        "ls ${HOME}/.ssh",
        "cat ~/.ssh/config",
        // Single quotes keep `$HOME` literal: no such directory exists.
        "ls '$HOME/Downloads/widgets-1.4.0'",
        "HOME=/etc; cat \"$HOME/passwd\"",
        "export HOME=/etc && cat $HOME/passwd",
        "cat ${HOME%/*}/README",
    ] {
        assert_ne!(action(&home, &home, command), "allow", "{command}");
    }
}

#[test]
fn a_shell_home_elsewhere_keeps_home_variable_reads_opaque() {
    let home = home("declared");
    let elsewhere = home.join("work");
    for command in [
        "ls \"$HOME/Downloads/widgets-1.4.0\"",
        "find $HOME/.nvm/versions/node -mindepth 1 -maxdepth 1 -type d -print",
    ] {
        assert_ne!(action(&home, &elsewhere, command), "allow", "{command}");
    }
}
