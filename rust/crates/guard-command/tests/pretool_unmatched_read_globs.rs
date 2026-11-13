#![cfg(unix)]
//! A reader whose glob matches nothing, such as `wc -l snapshot*.py` in a
//! directory with no snapshot file. The shell passes the word on unchanged
//! and the reader reports a missing file, so nothing is read. The same
//! pattern after `cd src;` is proven in both directories, and the one it does
//! not match must not stop it.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git_init(directory: &Path) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["init", "--quiet"])
        .env("HOME", std::env::temp_dir())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success());
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-unmatched-read-globs")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("home/work/app");
    std::fs::create_dir_all(&repo).unwrap();
    git_init(&repo);
    write(repo.join("src/policy_snapshot.py"), "SNAPSHOT = {}\n");
    write(
        repo.join("src/policy_snapshot_io.py"),
        "def load():\n    pass\n",
    );
    write(repo.join("README.md"), "# app\n");
    write(repo.join(".env.bak"), "COOKIE_NAME=synthetic\n");
    let root = std::fs::canonicalize(&root).unwrap();
    Fixture {
        home: root.join("home"),
        repo: root.join("home/work/app"),
        root,
    }
}

fn shell(fixture: &Fixture, command: &str) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        fixture.repo.to_str(),
    )
}

#[test]
fn a_reader_glob_that_matches_nothing_proceeds() {
    let f = fixture("allow");
    let src = f.repo.join("src");
    let src = src.display();
    for command in [
        "wc -l policy_snapshot*.py".to_owned(),
        // The pattern matches in `src` and nothing in the starting
        // directory, where the `wc` runs if the `cd` fails.
        format!("cd {src}; wc -l policy_snapshot*.py"),
        format!("cd {src} && wc -l policy_cache*.py; head -3 policy_snapshot*.py"),
        "head -3 src/policy_cache*.py".to_owned(),
        "cat src/missing_*.py README.md".to_owned(),
        "wc -l src/policy_snapshot*.py src/policy_cache*.py".to_owned(),
    ] {
        let command = command.as_str();
        let result = shell(&f, command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_glob_that_could_reach_a_hidden_file_keeps_the_review() {
    let f = fixture("held");
    // Nothing visible matches, but `dotglob` would expand `*.bak` to the
    // dotfile, so this is not an empty match.
    let result = shell(&f, "cat *.bak");
    assert_ne!(result.minimum_action, "allow", "cat *.bak");
}

#[test]
fn a_step_that_could_plant_a_match_keeps_the_review() {
    let f = fixture("planted");
    for command in [
        "ln -s ~/.ssh/id_rsa k.txt; cat k*.txt",
        "cat k*.txt; ln -s ~/.ssh/id_rsa k.txt",
        "cp .env.bak src/policy_cache.py; head -3 src/policy_cache*.py",
        "touch notes.txt && wc -l note*.txt",
        "cd src && wc -l policy_cache*.py > policy_cache.txt",
    ] {
        let result = shell(&f, command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}
