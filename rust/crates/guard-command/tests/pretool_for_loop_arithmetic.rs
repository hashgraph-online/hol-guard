#![cfg(unix)]

//! A `for` loop whose body works out a number from the loop variable.
//!
//! `for n in 40 90; do sed -n "$n,$((n+6))p" job.log; done` prints a few lines
//! from two places in a log. The unroller refused any `$((...))` in the body,
//! so the loop went to review while each pass written out was allowed. When
//! the words are plain numbers and the expansion holds only the variable,
//! numbers, `+`, `-` and `*`, each pass is written out with its value and
//! takes the ordinary proofs.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_loop_over_numbers_with_simple_arithmetic_reads_each_pass() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/loop-arithmetic-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(root.join("logs")).unwrap();
    let lines: String = (1..=200).map(|line| format!("line {line}\n")).collect();
    std::fs::write(root.join("logs/job.log"), lines).unwrap();
    std::fs::write(root.join("part1.md"), "one\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "codex", "claude-code"] {
        for (command, allowed) in [
            (
                r#"for n in 40 90; do sed -n "$n,$((n+6))p" logs/job.log | cut -c1-80; done"#,
                true,
            ),
            (
                "for n in 3 5; do head -n $(( n * 2 - 1 )) logs/job.log; done",
                true,
            ),
            // The value still names the file each pass reads.
            ("for n in 0; do cat part$((n+1)).md; done", true),
            ("for n in 0; do cat .env$((n+1)); done", false),
            // Arithmetic this does not evaluate keeps the review.
            ("for n in 1 2; do echo $((n++)); done", false),
            ("for n in 1 2; do echo $((n+$(id -u))); done", false),
            ("for f in a b; do echo $((f+1)); done; rm -rf logs", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} -> {} {}",
                result.minimum_action,
                result.reason
            );
        }
    }
}
