#![cfg(unix)]
//! A `for` loop over a quoted word holding square brackets, such as
//! `for d in items "[slug]"; do ls "app/items/$d"; done`.
//!
//! Route directories named like `[slug]` are common in web projects. Inside
//! quotes the brackets are text, but the unroller only took a bracket in a
//! header word as an unquoted pattern, so the loop kept a review the same
//! commands written out one by one did not get.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

fn action(harness: &str, command: &str, root: &std::path::Path) -> String {
    let cwd = root.join("work");
    let answer = evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: root.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        None,
    );
    answer.minimum_action
}

#[test]
fn a_loop_over_a_quoted_bracket_directory_reads_each_directory() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/for-loop-bracket-words")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("work/app/items/[slug]")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("work/app/items/page.tsx"), "export {};\n").unwrap();
    std::fs::write(root.join("work/app/items/[slug]/page.tsx"), "export {};\n").unwrap();
    std::fs::write(root.join("work/README.md"), "# Notes\n").unwrap();
    std::fs::write(root.join("work/.env"), "TOKEN=x\n").unwrap();
    for harness in ["omp", "codex", "claude-code"] {
        for (command, allowed) in [
            (
                "for d in items \"[slug]\"; do ls \"app/items/$d\"; done",
                true,
            ),
            ("for d in . \"[slug]\"; do ls \"app/items/$d\"; done", true),
            (
                "for f in \"app/items/[slug]/page.tsx\" README.md; do head -5 \"$f\"; done",
                true,
            ),
            // The words still name what the body reads.
            ("for f in \"[x]\" .env; do cat \"$f\"; done", false),
            // Brackets outside the quotes still expand to `.env`.
            ("for f in .en[v]\"\"; do cat \"$f\"; done", false),
            // A bare reference hands the shell the brackets as a pattern.
            ("for d in \"[slug]\"; do ls app/items/$d; done", false),
            // One part of the compound that is not read-only reviews it all.
            (
                "for d in items \"[slug]\"; do ls \"app/items/$d\"; done; rm -rf app",
                false,
            ),
        ] {
            let action = action(harness, command, &root);
            assert_eq!(
                action == "allow",
                allowed,
                "{harness}: {command} -> {action}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}
