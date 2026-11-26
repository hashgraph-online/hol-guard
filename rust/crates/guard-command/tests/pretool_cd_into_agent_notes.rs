#![cfg(unix)]
//! A `cd` into an agent's own notes directory before reading a note.
//!
//! `sed -n 1,5p ~/.codex/plans/plan-todo.md` was already allowed, but the
//! same read spelled `cd ~/.codex/plans && sed -n 1,5p plan-todo.md` went to
//! review: the hidden home component kept the `cd` from being proved. Every
//! read after the `cd` still clears its own operand proof, and writes keep
//! the stricter directory proof they always had.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// The root stays below the target directory: `$TMPDIR` on macOS resolves
/// under `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-cd-into-agent-notes")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".codex/plans/archive",
        ".codex/plans/.drafts",
        ".codex/sessions",
        ".claude/plans",
        ".claude/projects/sample-app/memory",
        ".claude/projects/sample-app/logs",
        ".claude/projects/.hidden-app/memory",
        "work/project",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".codex/plans/plan-todo.md", "# Plan\n- step\n"),
        (".codex/plans/archive/old-plan.md", "# Old\n"),
        (".codex/auth.json", "{}\n"),
        (".codex/config.toml", "model = \"x\"\n"),
        (".claude/plans/next-steps.md", "# Next\n"),
        (".claude/projects/sample-app/memory/MEMORY.md", "- note\n"),
        (
            ".claude/projects/sample-app/memory/build-notes.md",
            "# Build\n",
        ),
        (".claude/projects/sample-app/session.jsonl", "{}\n"),
        ("work/project/README.md", "# Project\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    action_with_shell_home(home, home, harness, command)
}

/// The shell expands an unquoted `~` from its own HOME, which the harness
/// stamps into the execution environment.
fn action_with_shell_home(home: &Path, shell_home: &Path, harness: &str, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["HOME".into(), "PATH".into()],
        environment_digest: "0".repeat(64),
        home: Some(shell_home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("work/project");
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

#[test]
fn a_note_read_after_entering_its_directory_is_allowed() {
    let home = home("allowed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "sed -n 1,5p ~/.codex/plans/plan-todo.md",
            "cd ~/.codex/plans && sed -n 1,5p plan-todo.md",
            "cd ~/.codex/plans && wc -l plan-todo.md",
            "cd ~/.codex/plans && ls",
            "cd ~/.codex/plans/archive && cat old-plan.md",
            "cd ~/.claude/plans && head -3 next-steps.md",
            "cd ~/.claude/projects/sample-app/memory && sed -n 1,5p build-notes.md; sed -n 1,5p MEMORY.md",
        ] {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn the_notes_directory_is_no_wider_door() {
    let home = home("review");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cd ~/.codex/plans && cat ../auth.json",
            "cd ~/.codex/plans && grep -rn model ..",
            "cd ~/.codex && cat config.toml",
            "cd ~/.codex/plans/.drafts && ls",
            "cd ~/.codex/plans/../sessions && ls",
            "cd ~/.claude/projects/sample-app && cat session.jsonl",
            "cd ~/.claude/projects/sample-app/logs && ls",
            "cd ~/.claude/projects/.hidden-app/memory && ls",
            "cd ~/.codex/plans && touch draft.md",
            "cd ~/.codex/plans && echo step > plan-todo.md",
            "cd ~/.codex/plans && rm plan-todo.md",
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
fn a_linked_notes_root_is_not_proved() {
    let home = home("linked");
    // A link out of a notes root into session state, where a direct read of
    // the same file stays under review.
    let elsewhere = home.join(".codex/sessions");
    std::fs::write(elsewhere.join("plan.md"), "# Plan\n").unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.join(".claude/plans/linked")).unwrap();
    std::fs::remove_dir_all(home.join(".codex/memories")).ok();
    std::os::unix::fs::symlink(home.join(".codex"), home.join(".codex/memories")).unwrap();
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.codex/sessions/plan.md",
            "cd ~/.claude/plans/linked && cat plan.md",
            "cd ~/.codex/memories && cat auth.json",
            "cd ~/.codex/memories && ls",
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
fn a_tilde_is_proved_only_against_the_declared_home() {
    let home = home("shell-home");
    let other = home.join("work/project");
    for harness in ["claude-code", "codex", "omp"] {
        assert_ne!(
            action_with_shell_home(
                &home,
                &other,
                harness,
                "cd ~/.codex/plans && sed -n 1,5p plan-todo.md"
            ),
            "allow",
            "{harness}"
        );
    }
}
