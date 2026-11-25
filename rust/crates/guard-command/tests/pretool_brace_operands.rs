#![cfg(unix)]

//! A read whose operands are written as a comma brace.
//!
//! `wc -l {README.md,AGENTS.md}` is `wc -l README.md AGENTS.md` by the time
//! `wc` runs: bash and zsh expand the brace into two operands first. The
//! single-command proofs read the braced word as one operand they could not
//! name, so the command went to review while its spelled-out form was
//! allowed. The rewritten list holds the words the shell makes, and each of
//! them faces the same proofs as when it is typed out, so a brace that names
//! a credential file, a write or a destination keeps its review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_read_of_braced_operands_reads_each_operand() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/brace-operand-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::create_dir_all(root.join("ci")).unwrap();
    for file in ["README.md", "AGENTS.md", "docs/guide.md", "ci/run.md"] {
        std::fs::write(root.join(file), "Retry limit: 3\n").unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "codex", "claude-code"] {
        for (command, allowed) in [
            ("wc -l {README.md,AGENTS.md}", true),
            ("ls -la {docs,ci}", true),
            ("cat {README,AGENTS}.md", true),
            ("head -3 {README.md,docs/guide.md} 2>/dev/null", true),
            ("wc -l {docs,ci}/*.md | sort -n", true),
            // A backup copy inside the workspace, as `cp README.md README.md.bak`.
            ("cp README.md{,.bak}", true),
            // Each word the shell makes faces its own proofs.
            ("cat {README.md,.env}", false),
            ("cat {README.md,../outside.md}", false),
            ("rm {README.md,AGENTS.md}", false),
            ("cat README.md > {a,b}.txt", false),
            ("cat part{1..3}.md", false),
            // A `#` from a brace is a literal word, not a comment.
            ("head -5 README.md {#,.env}", false),
            ("ls {#,x}; rm -rf docs", false),
            ("cat {README.md,2}<.env", false),
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
