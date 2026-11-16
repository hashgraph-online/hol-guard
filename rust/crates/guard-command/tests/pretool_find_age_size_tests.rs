#![cfg(unix)]
//! `find` age, size and emptiness tests.
//!
//! `-mtime +1` or `-size +10M` compares each entry's own metadata with a
//! number the command spells, so it only narrows which names are printed.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-find-age-size")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let (home, workspace) = (base.join("home"), base.join("ws"));
    std::fs::create_dir_all(&home).unwrap();
    for file in ["src/main.py", "src/lib/util.py", "build/old/log.txt"] {
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
fn age_and_size_tests_keep_a_listing_read_only() {
    let fixture = fixture("allowed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "find . -name '*.py' -mtime -1",
            "find build -mindepth 1 -maxdepth 1 -type d -name 'old*' -mtime +1 -print",
            "find src -type f -mmin -30",
            "find . -type f -size +10M",
            "find build -type d -empty",
            "find src -atime 2 -name '*.py'",
            "find . -size -1k -ctime +7 -cmin -5 -amin +60",
        ] {
            assert_eq!(
                action(&fixture, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn malformed_or_reading_operands_keep_review() {
    let fixture = fixture("reviewed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            // `-newer` reads another path's metadata.
            "find src -newer /etc/passwd",
            "find src -mtime",
            "find src -mtime +1d",
            "find src -mmin '+'",
            "find src -size +10X",
            "find src -mtime 1 -delete",
            "find src -size +1M -exec cat {} +",
        ] {
            assert_ne!(
                action(&fixture, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
