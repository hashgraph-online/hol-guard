#![cfg(unix)]
//! A `for` loop over folders spelled from the home directory, as in
//! `for d in ~/work/a ~/work/b; do if [ -d "$d" ]; then ls "$d"; fi; done`.
//!
//! The loop unroller refused any word holding `~`, so the loop kept a review
//! the same loop over the absolute paths did not. The shell expands an
//! unquoted `~/` before the loop runs, so the unrolled list now writes the
//! home path out and the ordinary proofs judge each step.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_loop_over_home_spelled_folders_is_judged_by_its_steps() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/for-loop-home-words")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work/a/src", "work/b", "work/repo", ".ssh", ".aws"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("work/a/README.md"), "a\n").unwrap();
    std::fs::write(root.join("work/b/README.md"), "b\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
    let cwd = root.join("work/repo");
    for harness in ["cursor", "claude-code", "codex"] {
        for (command, allowed) in [
            (
                "for d in ~/work/a ~/work/b; do if [ -d \"$d\" ]; then echo \"=== $d ===\"; ls \"$d\"; fi; done",
                true,
            ),
            ("for d in ~/work/a ~/work/missing; do echo \"$d\"; done", true),
            ("for d in ~/work/a; do cat \"$d/README.md\"; done", true),
            // Each step is still judged on its own.
            ("for f in ~/.ssh/id_ed25519 ~/work/a/README.md; do cat \"$f\"; done", false),
            ("for d in ~/work/a; do rm -rf \"$d/src\"; done", false),
            ("for d in ~/.aws; do ls \"$d\"; done", false),
            // A quoted `~` stays literal, and a pattern from home keeps its review.
            ("for d in \"~/work/a\"; do cat \"$d/README.md\"; done", false),
            ("for f in ~/.aws/*; do cat \"$f\"; done", false),
        ] {
            let answer = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name": "bash", "tool_input": {"command": command}}),
                None,
                None,
                root.to_str(),
                cwd.to_str(),
            );
            assert_eq!(
                answer.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                answer.minimum_action,
                answer.reason_code
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
