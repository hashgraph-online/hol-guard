#![cfg(unix)]
//! A listing pattern with a wildcard on both sides, as in
//! `ls -d ~/work/*pr7519*`, is judged by the names it can expand to.
//!
//! The screen used to approximate the matches by the literal text before the
//! first wildcard and after the last one. For `*pr7519*` both are empty, so
//! every sibling counted as a match, and one hidden directory beside the
//! worktree kept the listing reviewed although the shell never hands it over.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_pattern_wildcarded_on_both_sides_is_judged_by_its_matches() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/leaf-glob-exact-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("work/repo")).unwrap();
    std::fs::create_dir_all(root.join("work/guard-pr7519")).unwrap();
    std::fs::create_dir_all(root.join("work/.factory")).unwrap();
    std::fs::create_dir_all(root.join("work/.x\u{e9}config")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("work/repo/README.md"), "readme\n").unwrap();
    std::fs::write(root.join("work/guard-pr7519/README.md"), "readme\n").unwrap();
    std::fs::write(root.join("work/.factory/settings.json"), "{}\n").unwrap();
    let work = root.join("work");
    let work = work.to_str().unwrap();
    let cwd = root.join("work/repo");
    for harness in ["cursor", "codex", "omp"] {
        for (command, allowed) in [
            (format!("ls -d {work}/*pr7519*"), true),
            (format!("ls -d {work}/*pr7519* 2>/dev/null; true"), true),
            (format!("ls {work}/*pr75*"), true),
            (format!("ls -d {work}/*7519"), true),
            // A pattern that does reach the hidden directory keeps its review.
            (format!("ls {work}/*factory*"), false),
            (format!("ls {work}/*f*"), false),
            // A UTF-8 shell's `?` takes the two-byte `é` in `.xéconfig`.
            (format!("ls {work}/*x?config*"), false),
            // zsh `EXTENDED_GLOB` reads `#` as an operator, not a letter.
            (format!("ls {work}/*fact#ory*"), false),
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
