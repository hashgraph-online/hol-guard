#![cfg(unix)]
//! A listing narrowed by a dot-leading pattern prints the names a bare
//! `ls -a` of the same directory prints, so it answers like the literal
//! spelling of the same file. Reading those bytes keeps its review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn verdict(command: &str, root: &std::path::Path) -> (String, String) {
    let answer = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        root.to_str(),
        root.to_str(),
    );
    (answer.minimum_action.clone(), answer.reason_code.clone())
}

#[test]
fn hidden_listing_globs_answer_like_the_literal_spelling() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hidden-listing-glob-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("one.txt"), "one\n").unwrap();
    std::fs::write(root.join(".deploy-production.lock"), "lock\n").unwrap();
    std::fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    std::fs::create_dir_all(root.join(".github")).unwrap();
    std::fs::write(root.join(".github/ci.yml"), "ci\n").unwrap();

    // The literal spelling is the baseline the pattern has to match.
    for command in [
        "ls -a",
        "ls .deploy-production.lock",
        "ls -la .deploy-production.lock",
    ] {
        assert_eq!(verdict(command, &root).0, "allow", "baseline {command}");
    }

    // One `*` must not change what the same listing prints.
    for command in [
        "ls .deploy*",
        "ls -la .deploy-production.lock*",
        "ls .*.lock",
        "ls -a .deploy-production.lock*",
        "ls .gitignore*",
        "ls -la .gitignore*",
    ] {
        assert_eq!(verdict(command, &root).0, "allow", "listing {command}");
    }

    // Reading the bytes of the same match is a different question, and a
    // pattern that stands for `.` or `..` prints another directory's entries.
    for command in [
        "cat .deploy*",
        "head -5 .deploy*",
        "cat .gitignore*",
        "ls -d .*",
        "ls .git*",
    ] {
        assert_eq!(
            verdict(command, &root),
            (
                "review".to_owned(),
                "native_command_review_required".to_owned()
            ),
            "kept review {command}"
        );
    }

    std::fs::remove_dir_all(root).unwrap();
}
