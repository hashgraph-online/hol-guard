#![cfg(unix)]

//! A file test over a pattern, as a loop over a glob writes it.
//!
//! `for f in tests/*.py; do [ -f "$f" ] || continue; rg -l x "$f"; done` is
//! how an agent skips a pattern that matched nothing. The loop is unrolled so
//! the ordinary proofs judge each step, which hands `[` the pattern itself,
//! and the file test refused any target holding `*`, `?` or `[`. The same
//! loop without the guard was allowed. A file test only reads metadata, so a
//! pattern now takes the listing proof `echo tests/*.py` already takes.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_file_test_over_a_workspace_pattern_reads_only_metadata() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/glob-file-predicate-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work/tests")).unwrap();
    std::fs::create_dir_all(root.join(".aws")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("work/tests/one.py"), "def test_one(): pass\n").unwrap();
    std::fs::write(root.join("work/tests/two.py"), "def test_two(): pass\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
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
