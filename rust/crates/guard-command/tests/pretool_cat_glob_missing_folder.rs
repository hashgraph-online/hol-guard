#![cfg(unix)]
//! A reader's glob below a folder that is not there, as in a look for an
//! optional note: `cat docs/NOTE* 2>/dev/null` in a checkout with no `docs`.
//!
//! The shell finds nothing to expand, so `cat` is handed the literal word and
//! prints `No such file or directory`, zsh fails the command, and `nullglob`
//! leaves `cat` reading standard input. The literal read of a missing name,
//! `cat docs/NOTES.md`, was already allowed on the listing rule; the glob
//! spelling went to review only because the proof listed the folder first.
//! The missing folder now has to clear that same listing rule, so a pattern
//! under a credential store, or a chain that can create the folder before the
//! shell expands the pattern, keeps its review.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn action(harness: &str, command: &str, home: &Path, cwd: &Path) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
    .minimum_action
}

fn fixture() -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cat-glob-missing-folder")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/repo/src", "work/notes-repo", ".ssh", ".aws"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (file, text) in [
        ("work/repo/README.md", "# repo\n"),
        ("work/repo/src/main.py", "print('app')\n"),
        ("work/notes-repo/NOTES.md", "notes\n"),
        (".ssh/id_ed25519", "synthetic\n"),
        (".aws/credentials", "synthetic\n"),
    ] {
        std::fs::write(root.join(file), text).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    for repository in ["work/repo", "work/notes-repo"] {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(root.join(repository))
            .env("HOME", &root)
            .status()
            .unwrap();
        assert!(status.success());
    }
    root
}

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

#[test]
fn a_glob_below_a_missing_folder_reads_nothing() {
    let home = fixture();
    let repo = home.join("work/repo");
    let sibling = home.join("work/notes-repo");
    let sibling_word = sibling.to_str().unwrap();
    for harness in HARNESSES {
        for (cwd, command) in [
            (&repo, "cat docs/NOTE* 2>/dev/null".to_owned()),
            (&repo, "head -20 docs/adr/*.md".to_owned()),
            (&repo, format!("cat {sibling_word}/docs/NOTE* 2>/dev/null")),
            (
                &repo,
                "cat ~/work/notes-repo/docs/NOTE* 2>/dev/null".to_owned(),
            ),
            (
                &repo,
                format!("cd {sibling_word} && cat docs/NOTE* 2>/dev/null"),
            ),
            (&sibling, "cat docs/NOTE* 2>/dev/null".to_owned()),
        ] {
            assert_eq!(
                action(harness, &command, &home, cwd),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_missing_folder_glob_that_could_read_a_secret_keeps_its_review() {
    let home = fixture();
    let repo = home.join("work/repo");
    for harness in HARNESSES {
        for command in [
            // Below a credential store, the probe itself spells the account.
            "cat ~/.ssh/keys/id*",
            "cat ~/.aws/sso/cache/*.json",
            "cat ~/.config/gh/hosts/*",
            // A step before the read can create the folder and a link in it.
            "mkdir docs && ln -s ~/.ssh/id_ed25519 docs/NOTE; cat docs/NOTE*",
            "ln -s ~/.ssh docs; cat docs/id*",
            // The pattern names a secret even though the folder is missing.
            "cat config/.env*",
        ] {
            assert_ne!(
                action(harness, command, &home, &repo),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
