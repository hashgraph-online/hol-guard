#![cfg(unix)]
//! A recursive `grep` whose pattern is written the way basic `grep` spells
//! alternatives and literal dots (`a\|b`, `policy\.clear`), or that names
//! several `-e` patterns. Each reaches a plugin fixture and a `.env.bak`; the
//! search proceeds when none of the alternatives can occur in them, as a
//! plain word does, and keeps its review when one can.

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
        .join("../../target/pretool-grep-escaped-alternatives")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("home/work/app");
    write(
        repo.join("src/policy.py"),
        "def policy_upsert():\n    pass\n",
    );
    write(
        repo.join("tests/test_policy.py"),
        "def test_policy_clear():\n    pass\n",
    );
    write(
        repo.join("tests/fixtures/bad-plugin/.codex-plugin/plugin.json"),
        "{\"name\": \"bad-plugin\"}\n",
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
fn escaped_alternatives_none_of_which_can_match_proceed() {
    let f = fixture("allow");
    for command in [
        r#"grep -rn "policy_upsert\|policy_clear\|policy\.upsert\|policy\.clear" tests"#,
        r#"grep -rn "policy_upsert\|policy_clear" ."#,
        r#"grep -rn "policy\.upsert" ."#,
        "grep -rn -e policy_upsert -e policy_clear .",
        "grep -rn -e policy_upsert -e 'policy\\.clear' tests",
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
fn an_alternative_that_could_match_keeps_the_review() {
    let f = fixture("held");
    for command in [
        // One alternative occurs in `.env.bak` or the plugin manifest, in any
        // letter case.
        r#"grep -rn "policy_upsert\|cookie_name" ."#,
        r#"grep -rn "policy_upsert\|bad-plugin" tests"#,
        r#"grep -rn "cookie\.name" ."#,
        "grep -rn -e policy_upsert -e COOKIE_NAME .",
        // Another escape, an empty alternative, or a pattern list Guard
        // cannot read is never a clearance.
        r#"grep -rn "policy\w" ."#,
        r#"grep -rn "policy_upsert\|" ."#,
        "grep -rn -e policy_upsert -e '' .",
        "grep -rn -e policy_upsert -f patterns.txt .",
        // `-v` prints the lines that do not match.
        "grep -rvn -e policy_upsert -e policy_clear .",
    ] {
        let result = shell(&f, command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}
