#![cfg(unix)]
//! `find` operands the shell expands before `find` reads them.
//!
//! A brace with a comma at its own level is several words by the time `find`
//! parses its expression, so a word this screen reads as one pattern can
//! carry an action of its own.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-find-brace-expansion")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let (home, workspace) = (base.join("home"), base.join("ws"));
    std::fs::create_dir_all(&home).unwrap();
    for file in ["src/main.ts", "src/lib/index.ts", "docs/readme.md"] {
        let path = workspace.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic\n").unwrap();
    }
    Fixture {
        home: std::fs::canonicalize(home).unwrap(),
        workspace: std::fs::canonicalize(workspace).unwrap(),
    }
}

fn action(fixture: &Fixture, harness: &str, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        fixture.workspace.to_str(),
    )
    .minimum_action
}

#[test]
fn a_brace_the_shell_expands_keeps_its_review() {
    let fixture = fixture("expanded");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            // Each of these is one pattern here and an action, an
            // alternation or a second root to `find`.
            "find src -type f -name {x,-delete}",
            "find src -type f -name {\"*.ts\",-o,-name,\"*\"}",
            "find src -maxdepth 2 -name {notes.md,-exec,cat}",
            "find {src,/etc} -type f -name \"*.ts\"",
            // A sequence brace is not followed, so what `find` receives is
            // not what this screen read.
            "find src -type f -name \"a{1..3}.md\"",
            // The fan-out producer and its child are read as written too.
            "find src -type f -name {\"*.ts\",-delete} -exec cat {} +",
            "find src -type f -name {\"*.ts\",-o,-name,\"*\"} -print0 | xargs -0 cat",
        ] {
            assert_ne!(
                action(&fixture, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_word_the_shell_leaves_alone_still_lists() {
    let fixture = fixture("written");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "find src -type f -name \"*.ts\"",
            "find src -maxdepth 2 -type f",
            // The `{}` of an `-exec` body has no comma, so the shell hands it
            // to `find` as written.
            "find src -type f -name \"*.ts\" -exec cat {} +",
            "find src -type f -name \"*.ts\" -print0 | xargs -0 cat",
        ] {
            assert_eq!(
                action(&fixture, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
