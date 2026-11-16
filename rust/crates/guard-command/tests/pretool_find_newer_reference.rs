#![cfg(unix)]
//! `find -newer FILE`, as in a search for what changed since a document
//! was written: `find . -maxdepth 3 -iname '*report*' -newer PRD.md`.
//!
//! The test reads only the reference file's modification time, so a file a
//! plain read could open may be the reference. A credential file, a home
//! dot-directory and a system path keep the review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-find-newer-reference")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let (home, workspace) = (base.join("home"), base.join("home/projects/ws"));
    for file in [
        "README.md",
        "docs/PRD.md",
        "src/main.py",
        "reports/bing-export.csv",
        ".env",
    ] {
        let path = workspace.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic\n").unwrap();
    }
    for file in [".ssh/id_ed25519", ".aws/credentials"] {
        let path = home.join(file);
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

// Quote the complete path for POSIX shells, including embedded apostrophes.
fn shell_quote_path(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\"'\"'"))
}

#[test]
fn a_project_file_may_be_the_reference() {
    let fixture = fixture("allowed");
    let prd = fixture.workspace.join("docs/PRD.md");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "find . -maxdepth 3 -iname '*bing*' -newer README.md".to_owned(),
            "find src -name '*.py' -newer docs/PRD.md -type f".to_owned(),
            format!(
                "find . -maxdepth 3 -iname '*bing*' -newer {}",
                shell_quote_path(&prd)
            ),
            "find reports -newer ./README.md 2>/dev/null | head -10".to_owned(),
        ] {
            assert_eq!(
                action(&fixture, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn a_reference_path_with_spaces_and_apostrophe_is_one_operand() {
    let fixture = fixture("allowed with space and 'apostrophe");
    let prd = fixture.workspace.join("docs/PRD.md");
    let command = format!(
        "find . -maxdepth 3 -iname '*bing*' -newer {}",
        shell_quote_path(&prd)
    );
    for harness in ["claude-code", "codex", "omp"] {
        assert_eq!(
            action(&fixture, harness, &command),
            "allow",
            "{harness}: {command}"
        );
    }
}

#[test]
fn a_secret_or_system_reference_keeps_review() {
    let fixture = fixture("reviewed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "find src -newer ~/.ssh/id_ed25519",
            "find src -newer ~/.aws/credentials -name '*.py'",
            "find . -maxdepth 2 -newer .env",
            "find src -newer /etc/passwd",
            "find src -newer",
            "find src -newer -delete",
            "find . -newer README.md -delete",
        ] {
            assert_ne!(
                action(&fixture, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
