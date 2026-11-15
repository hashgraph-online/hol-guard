#![cfg(unix)]
//! A `sed` that trims what it reads with a line delete, an early quit or an
//! addressed substitution -- `sed '1d;$d'`, `sed 5q`, `sed '12s/a/b/'` --
//! reads like the print and the bare substitution it sits beside. A script
//! that writes, reads another file or runs a command keeps its review, and so
//! does a sensitive file.

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

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-sed-stream-edits")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("home/work/app");
    write(repo.join("README.md"), "# App\n\nUsage notes.\n\nEnd.\n");
    write(
        repo.join("src/main.rs"),
        "// header\nuse std::io;\nfn main() {}\n",
    );
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
fn line_deletes_quits_and_addressed_substitutions_proceed() {
    let f = fixture("allow");
    for command in [
        "sed '1d;$d' README.md",
        "sed '/^$/d' README.md",
        "sed '/^\\/\\//d' src/main.rs",
        "sed 3q README.md",
        "sed '2s/use/import/' src/main.rs",
        "sed -e 1d -e '$d' README.md",
        "cat README.md | sed '1d'",
        "sed -n '2,3p' README.md | sed '1d'",
        "sed '1d' README.md | head -2",
    ] {
        let result = shell(&f, command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_script_that_leaves_the_stream_or_a_sensitive_file_keeps_the_review() {
    let f = fixture("held");
    for command in [
        "sed '1d;w copy.txt' README.md",
        "sed '2s/use/import/w copy.txt' src/main.rs",
        "sed '1d;r .env.bak' README.md",
        "sed '1d;e id' README.md",
        // BSD sed reads these brackets through to the next delimiter, so its
        // second command is a write or a shell command.
        "sed '/[]/d;s/]/w copy.txt/g' README.md",
        "sed '/[[:space:]/p;s/]/w copy.txt/g' README.md",
        "sed '1s@[@]@;s@w copy@x@' README.md",
        "sed '1!G;h;$!d' README.md",
        "sed '1d' .env.bak",
        "cat .env.bak | sed '1d'",
    ] {
        let result = shell(&f, command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}
