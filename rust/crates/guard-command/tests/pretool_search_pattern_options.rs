//! `rg` and `grep` take their first positional as the pattern only when no
//! `-e` or `-f` supplies one, wherever that option appears. Otherwise every
//! positional is a file to read, so `rg .env -e KEY` and
//! `grep -f patterns.txt .env` both read `.env`.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repository: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-search-pattern-options")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    let repository = root.join("home/project");
    std::fs::create_dir_all(repository.join(".git")).unwrap();
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join(".env"), "KEY=synthetic\n").unwrap();
    std::fs::write(repository.join("patterns.txt"), "KEY\n").unwrap();
    std::fs::write(repository.join("src/main.rs"), "fn main() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    Fixture {
        home: root.join("home"),
        repository: root.join("home/project"),
        root,
    }
}

fn assert_actions(fixture: &Fixture, commands: &[&str], expected: &str) {
    for command in commands {
        let action = evaluate_pre_tool_envelope_with_context(
            "claude-code",
            "PreToolUse",
            &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
            None,
            None,
            fixture.home.to_str(),
            fixture.repository.to_str(),
        )
        .minimum_action;
        assert_eq!(action, expected, "{command}");
    }
}

#[test]
fn a_pattern_option_anywhere_makes_every_positional_a_path() {
    let fixture = fixture();
    assert_actions(
        &fixture,
        &[
            "rg .env -e KEY",
            "rg .env --regexp=KEY",
            "rg .env --regexp KEY",
            "rg .env -f patterns.txt",
            "rg -f patterns.txt .env",
            "rg --file patterns.txt .env",
            "rg -fpatterns.txt .env",
            "grep .env -e KEY",
            "grep .env --regexp=KEY",
            "grep .env -f patterns.txt",
            "grep -f patterns.txt .env",
            "grep -fpatterns.txt .env",
        ],
        "review",
    );
}

#[test]
fn ordinary_pattern_searches_stay_allowed() {
    let fixture = fixture();
    assert_actions(
        &fixture,
        &[
            "rg -n KEY src",
            "rg -e KEY src",
            "rg src -e KEY",
            "rg -f patterns.txt src/main.rs",
            "rg -- .env src",
            "grep -n KEY src/main.rs",
            "grep src/main.rs -e KEY",
            "grep -f patterns.txt src/main.rs",
            "grep -- .env src/main.rs",
        ],
        "allow",
    );
}
