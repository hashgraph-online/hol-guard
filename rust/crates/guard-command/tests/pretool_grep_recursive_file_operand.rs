#![cfg(unix)]

//! `grep -r` walks only a directory operand. A file operand named through
//! `..` is opened once, exactly as plain `grep` opens it, so the two spellings
//! must reach the same decision.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
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

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-recursive-file-operand")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let app = home.join("app");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    write(
        app.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/a\"]\n",
    );
    write(
        app.join("build/inputs.json"),
        "{\"files\": [\"src/lib.rs\"]}\n",
    );
    write(app.join("crates/a/Cargo.toml"), "[package]\nname = \"a\"\n");
    write(app.join("crates/a/src/lib.rs"), "pub fn a() {}\n");
    write(app.join(".env"), "KEY=1\n");
    write(app.join(".gitignore"), ".env\n");
    std::os::unix::fs::symlink(&app, app.join("crates/a/src/up")).unwrap();
    Fixture { root, home }
}

fn run(f: &Fixture, cwd: &str, command: &str) -> PreToolResultV1 {
    let cwd = f.home.join(cwd);
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    )
}

const SRC: &str = "app/crates/a/src";

#[test]
fn a_recursive_grep_of_one_parent_file_matches_the_plain_grep() {
    let f = fixture();
    for operand in [
        "../Cargo.toml",
        "../../../Cargo.toml",
        "../../../build/inputs.json",
    ] {
        let plain = run(&f, SRC, &format!("grep -n members {operand}"));
        assert_eq!(plain.minimum_action, "allow", "plain grep {operand}");
        for flags in ["-rn", "-R", "-rln"] {
            let command = format!("grep {flags} members {operand}");
            let recursive = run(&f, SRC, &command);
            assert_eq!(
                recursive.minimum_action, "allow",
                "{command}: {} {}",
                recursive.minimum_action, recursive.reason_code
            );
        }
    }
    let piped = run(
        &f,
        SRC,
        "grep -rn members ../../../build/inputs.json | head -5",
    );
    assert_eq!(piped.minimum_action, "allow", "{}", piped.reason_code);
}

#[test]
fn a_recursive_grep_through_a_parent_still_reviews_a_tree_or_a_secret() {
    let f = fixture();
    for command in [
        // A directory starts a walk that reaches the ignored `.env`.
        "grep -rn KEY ../../..",
        "grep -rn KEY ../../../",
        // A link named as an operand is followed to the tree it points at.
        "grep -rn KEY up",
        // The secret file itself keeps the plain read's review.
        "grep -rn KEY ../../../.env",
        "grep -n KEY ../../../.env",
        // A glob is left to the glob proof.
        "grep -rn KEY ../../../.en*",
    ] {
        let r = run(&f, SRC, command);
        assert_ne!(
            r.minimum_action, "allow",
            "{command}: {} {}",
            r.minimum_action, r.reason_code
        );
    }
}
