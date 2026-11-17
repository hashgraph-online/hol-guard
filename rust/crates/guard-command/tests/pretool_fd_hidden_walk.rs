#![cfg(unix)]
//! `fd --hidden` and `fd --no-ignore` walk what `find` walks, and print names.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a repository with dot entries and an ignored directory, a
/// sibling repository, and the stores a widened walk must never start in.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-fd-hidden-walk")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in [
        "work/project/.git",
        "work/project/.github/workflows",
        "work/project/node_modules/left-pad",
        "work/project/src",
        "work/other/.git",
        ".codex/plans",
        ".ssh",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        ("work/project/.git/HEAD", "ref: refs/heads/main\n"),
        ("work/project/.gitignore", "node_modules/\n"),
        ("work/project/.github/workflows/ci.yml", "on: push\n"),
        ("work/project/node_modules/left-pad/index.js", "\n"),
        ("work/project/src/main.rs", "fn main() {}\n"),
        ("work/other/.git/HEAD", "ref: refs/heads/main\n"),
        (".codex/plans/todo.md", "# Todo\n"),
        (".ssh/id_ed25519", "key\n"),
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
fn a_hidden_walk_lists_names_from_a_root_find_may_list() {
    let home = home("allowed");
    let work = home.join("work");
    let work = work.display();
    for harness in ["claude-code", "codex", "cursor", "zcode"] {
        for command in [
            "fd --hidden . -d 1".to_owned(),
            "fd -H -t d . -d 2".to_owned(),
            "fd -u workflow .".to_owned(),
            "fd --no-ignore left-pad".to_owned(),
            "fd -HI -t d '^\\.git$' . -d 3".to_owned(),
            format!("fd --hidden --no-ignore -t d '^\\.git$' {work} -d 4 | head -40"),
            format!("fd -H -t d '^\\.git$' --search-path {work} -d 3"),
        ] {
            assert_eq!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_hidden_walk_from_home_or_a_store_keeps_its_review() {
    let home = home("refused");
    let root = home.display();
    for command in [
        // Home itself holds every store; `find` keeps the same review.
        format!("fd -H id_ed25519 {root}"),
        // A home dot-directory is bounded only by a pattern that never meets
        // a hidden entry, which a widened walk no longer promises.
        format!("fd -H plans {root}/.codex"),
        format!("fd --hidden todo {root}/.codex/plans"),
        format!("fd -H id {root}/.ssh"),
        // Following a link, running a program per match and reading an
        // ignore file stay outside the names-only shape.
        "fd -H -L main .".to_owned(),
        "fd -H -t f -x cat".to_owned(),
        format!("fd -H --ignore-file {root}/.ssh/id_ed25519 main ."),
    ] {
        for harness in ["claude-code", "codex", "cursor", "zcode"] {
            assert_ne!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
