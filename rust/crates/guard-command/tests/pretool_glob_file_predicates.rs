#![cfg(unix)]

//! A file test over a pattern, as a loop over a glob writes it.
//!
//! `for f in tests/*.py; do [ -f "$f" ] || continue; rg -l x "$f"; done` is
//! how an agent skips a pattern that matched nothing. The loop is unrolled so
//! the ordinary proofs judge each step, which hands `[` the pattern itself,
//! and the file test refused any target holding `*`, `?` or `[`. The same
//! loop without the guard was allowed. A file test only reads metadata, so a
//! pattern is now accepted when no file carries its literal spelling and every
//! match clears the read proof, or nothing matches.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_file_test_over_a_workspace_pattern_reads_only_metadata() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/glob-file-predicate-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work/tests")).unwrap();
    std::fs::create_dir_all(root.join("work/links")).unwrap();
    std::fs::create_dir_all(root.join(".aws")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("work/tests/one.py"), "def test_one(): pass\n").unwrap();
    std::fs::write(root.join("work/tests/two.py"), "def test_two(): pass\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
    std::os::unix::fs::symlink(
        root.join(".aws/credentials"),
        root.join("work/links/[ab].py"),
    )
    .unwrap();
    let home = root.to_str().unwrap();
    let cwd = root.join("work");
    let cwd = cwd.to_str().unwrap();
    for harness in ["codex", "omp"] {
        for (command, allowed) in [
            ("[ -f tests/*.py ]", true),
            ("test -e tests/*.py", true),
            (
                "for f in tests/*.py; do [ -f \"$f\" ] || continue; rg -l download \"$f\"; done",
                true,
            ),
            (
                "for f in tests/*.py; do test -f \"$f\" && echo \"$f\"; done",
                true,
            ),
            // A pattern that matches nothing reaches the test as its own text.
            (
                "for f in tests/*.py tests/*.tsx; do [ -f \"$f\" ] || continue; rg -l download \"$f\"; done",
                true,
            ),
            // A file named as the pattern is spelled is what the test reads.
            ("test -s links/[ab].py", false),
            ("test -s 'links/[ab].py'", false),
            // The pattern still has to name what a listing may name.
            ("[ -f ~/.aws/* ]", false),
            (
                "for f in ~/.aws/*; do [ -f \"$f\" ] || continue; echo \"$f\"; done",
                false,
            ),
            // The guard proves nothing about what the body does after it.
            (
                "for f in tests/*.py; do [ -f \"$f\" ] || continue; rm \"$f\"; done",
                false,
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                Some(home),
                Some(cwd),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
}

#[test]
fn a_quoted_home_pattern_needs_no_literal_tilde_entry() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/glob-file-predicate-fixtures")
        .join(format!("tilde-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for directory in ["notes", "plain", "planted/~/notes", ".aws"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("notes/a.py"), "print('a')\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
    // A quoted `~` stays literal, so the test reads `./~/notes/*.py`.
    std::os::unix::fs::symlink(
        root.join(".aws/credentials"),
        root.join("planted/~/notes/*.py"),
    )
    .unwrap();
    let home = root.to_str().unwrap();
    for (cwd, allowed) in [("plain", true), ("planted", false)] {
        let cwd = root.join(cwd);
        let result = evaluate_pre_tool_envelope_with_context(
            "codex",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"test -s '~/notes/*.py'"}}),
            None,
            None,
            Some(home),
            cwd.to_str(),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{}: {} / {}",
            cwd.display(),
            result.minimum_action,
            result.reason_code
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
