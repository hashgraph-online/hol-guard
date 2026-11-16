#![cfg(unix)]
//! A Git command handed the commit another Git command looks up:
//! `git show --stat $(git log -1 --format=%h -- README.md)` or
//! `git diff $(git merge-base HEAD main) --stat`.
//!
//! The lookup prints a hash or nothing, so the outer command is judged with a
//! fixed hash in its place. Lookups that can print other text, and outer
//! commands that are not Git, keep the review.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A home holding one repository with two commits on `main`. The root stays
/// below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-hash-substitution")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let project = root.join("home/org/app");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("README.md"), "# app\n").unwrap();
    std::fs::write(project.join("src/one.ts"), "export const one = 1;\n").unwrap();
    git(&project, &["init", "--quiet", "--initial-branch=main"]);
    git(&project, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&project, &["add", "."]);
    git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    std::fs::write(project.join("README.md"), "# app\n\nMore.\n").unwrap();
    git(&project, &["commit", "--quiet", "-am", "Synthetic update"]);
    std::fs::canonicalize(root.join("home")).unwrap()
}

fn classify(home: &Path, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    };
    let project = home.join("org/app");
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

const HARNESSES: [&str; 3] = ["claude-code", "codex", "omp"];

#[test]
fn a_git_read_of_a_looked_up_commit_proceeds() {
    let home = home();
    for harness in HARNESSES {
        for command in [
            "git show --stat $(git log -1 --format=%h -- README.md)",
            "git show --stat $(git rev-parse HEAD~1)",
            "git diff $(git merge-base HEAD main) --stat",
            "git diff $(git rev-parse --short HEAD~1) $(git rev-parse HEAD) --stat",
            "git log --oneline $(git merge-base HEAD main)..HEAD",
            r#"git diff "$(git merge-base HEAD main)" --stat"#,
            r#"git show --stat "$(git rev-parse HEAD~1)"; git status"#,
        ] {
            let verdict = classify(&home, harness, command);
            assert_eq!(
                verdict.minimum_action, "allow",
                "{harness}: {command}: {}",
                verdict.reason_code
            );
        }
    }
}

#[test]
fn other_lookups_and_other_programs_keep_the_review() {
    let home = home();
    for harness in HARNESSES {
        for command in [
            // A bare rev-parse echoes a name it cannot resolve.
            "git show $(git rev-parse .env)",
            // A subject line is text the commit author chose.
            "git show $(git log -1 --format=%s)",
            // An empty lookup drops the word: grep would search the directory.
            "grep -r TODO $(git rev-parse HEAD)",
            "cat $(git rev-parse HEAD)",
            "git reset --hard $(git rev-parse HEAD~1)",
            "git diff $(git rev-parse HEAD) --output=../out.txt",
            // Glued text: an empty lookup leaves an option or a file name.
            "git diff $(git rev-parse HEAD)--output=../out.txt",
            "git show HEAD:.$(git log -1 --format=%h -- README.md)env",
        ] {
            let verdict = classify(&home, harness, command);
            assert_ne!(
                verdict.minimum_action, "allow",
                "{harness}: {command}: {}",
                verdict.reason_code
            );
        }
    }
}
