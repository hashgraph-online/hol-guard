#![cfg(unix)]
//! `git ls-tree` and `git cat-file` object reads, in the current repository
//! and in a sibling repository named by `-C`.
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

/// A home holding two committed repositories under a non-repository parent.
/// The root stays below the target directory: `$TMPDIR` on macOS resolves
/// under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-object-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for name in ["app", "api"] {
        let project = home.join("org").join(name);
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(project.join("src/one.ts"), "export const one = 1;\n").unwrap();
        std::fs::write(project.join("README.md"), format!("# {name}\n")).unwrap();
        git(&project, &["init", "--quiet", "--initial-branch=main"]);
        git(&project, &["config", "user.name", "Fixture"]);
        git(
            &project,
            &["config", "user.email", "fixture@example.invalid"],
        );
        git(&project, &["add", "."]);
        git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    }
    std::fs::canonicalize(home).unwrap()
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
        library_search_paths: Default::default(),
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

const HARNESSES: [&str; 4] = ["omp", "zcode", "claude-code", "codex"];

#[test]
fn object_listings_and_reads_proceed() {
    let home = home();
    let sibling = home.join("org/api");
    let sibling = sibling.to_str().unwrap();
    let routed_listing = format!("git -C {sibling} ls-tree HEAD --name-only src/ | grep one");
    let routed_type = format!("git -C {sibling} cat-file -t HEAD");
    for harness in HARNESSES {
        for command in [
            "git ls-tree HEAD --name-only src/",
            "git ls-tree -r HEAD",
            "git ls-tree -rtz --abbrev=8 HEAD -- src",
            "git ls-tree --format='%(objectname) %(path)' HEAD",
            "git cat-file -p HEAD:README.md",
            "git cat-file -t HEAD",
            "git cat-file -s HEAD:src/one.ts",
            "git cat-file -e HEAD",
            "git cat-file blob HEAD:README.md",
            "git -C ../api ls-tree -r HEAD",
            "git -C ../api cat-file -p HEAD:README.md",
            routed_listing.as_str(),
            routed_type.as_str(),
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn driver_stdin_and_configured_object_reads_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            // These run configured textconv or filter drivers.
            "git cat-file --textconv HEAD:README.md",
            "git cat-file --filters HEAD:README.md",
            "git cat-file --path=README.md blob HEAD",
            // Batch modes read object names from stdin.
            "git cat-file --batch",
            "git cat-file --batch-check",
            "git cat-file --batch-all-objects --batch-check",
            "git cat-file -p",
            "git ls-tree --format HEAD",
            // Global options that can execute code keep their review.
            "git -c pager.ls-tree=x ls-tree HEAD",
            "git -c core.pager=x cat-file -p HEAD:README.md",
            "git --exec-path=/tmp ls-tree HEAD",
            "GIT_PAGER=less git cat-file -p HEAD:README.md",
            // Like `git show HEAD:.env`, a credential path keeps its review.
            "git cat-file -p HEAD:.env",
            "git ls-tree HEAD .env",
            "git cat-file -p :README.md",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn object_read_configuration_is_probed() {
    let home = home();
    let project = home.join("org/app");
    // A textconv driver never runs for these forms, so it does not block them.
    git(&project, &["config", "diff.fixture.textconv", "sh -c id"]);
    let result = classify(&home, "codex", "git cat-file -p HEAD:README.md");
    assert_eq!(result.decision, "allow", "{result:?}");
    git(&project, &["config", "pager.cat-file", "sh -c id"]);
    let result = classify(&home, "codex", "git cat-file -p HEAD:README.md");
    assert_ne!(result.decision, "allow", "{result:?}");
    git(&project, &["config", "--unset", "pager.cat-file"]);
    git(&project, &["config", "pager.ls-tree", "sh -c id"]);
    let result = classify(&home, "codex", "git ls-tree -r HEAD");
    assert_ne!(result.decision, "allow", "{result:?}");
    git(&project, &["config", "--unset", "pager.ls-tree"]);
    // A promisor remote can fetch a missing object during the read.
    git(&project, &["config", "remote.origin.promisor", "true"]);
    let result = classify(&home, "codex", "git ls-tree -r HEAD");
    assert_ne!(result.decision, "allow", "{result:?}");
}
