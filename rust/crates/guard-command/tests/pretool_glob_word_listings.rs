#![cfg(unix)]
//! A glob handed to a program that prints its words is a directory listing:
//! `echo ~/.ssh/id_*` prints the key file names `ls ~/.ssh` would. So is a
//! glob bound to a variable and expanded later at a bare `$NAME`. Both keep
//! review inside credential directories, while project globs still proceed.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with SSH keys, AWS and GitHub CLI credentials, and a project. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-glob-word-listings")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".ssh",
        ".aws",
        ".config/gh",
        "work/project/.git",
        "work/project/src",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".ssh/id_rsa", "synthetic\n"),
        (".ssh/id_rsa.pub", "synthetic\n"),
        (".aws/credentials", "[default]\n"),
        (".config/gh/hosts.yml", "example.com:\n"),
        ("work/project/.git/HEAD", "ref: refs/heads/main\n"),
        ("work/project/src/lib.rs", "pub fn one() {}\n"),
        ("work/project/src/main.rs", "fn main() {}\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let cwd = home.join("work/project");
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn printed_and_bound_credential_globs_keep_review() {
    let home = home("credentials");
    for harness in ["codex", "claude-code", "cursor"] {
        for command in [
            "P=~/.ssh/id_*; echo $P",
            "P=~/.ssh; echo $P/*",
            "P=~/.ssh/*; printf '%s\\n' $P",
            "P=~/.aws/*; echo $P",
            "export P=~/.aws/*; echo $P",
            "echo ~/.aws/*",
            "echo ~/.aws/cred*",
            "echo ~/.config/gh/*",
            "echo ~/.*",
            "printf '%s\\n' ~/.aws/*",
            "which ~/.aws/*",
            "basename ~/.aws/*",
            "dirname ~/.aws/*",
            "P=*; echo ~/.aws/$P",
            "P=cred*; echo ~/.aws/$P",
            "P=*; echo ~/.config/gh/$P",
            "P=*; printf '%s\\n' ~/.aws/$P",
            "echo ${X:-~/.aws/*}",
        ] {
            assert_ne!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn project_globs_and_quoted_words_still_print() {
    let home = home("project");
    for command in [
        "echo src/*",
        "echo src/*.rs",
        "printf '%s\\n' src/*",
        "P=src/*; echo $P",
        "echo missing/*",
        "echo '*' \\? \"$?\"",
        "echo $?",
        "P=~/.ssh/id_rsa; echo $P",
        "echo ok # /tmp/*",
    ] {
        assert_eq!(action(&home, "codex", command), "allow", "{command}");
    }
}
