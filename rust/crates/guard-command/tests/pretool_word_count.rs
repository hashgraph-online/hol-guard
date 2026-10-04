#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn word_counts_do_not_gain_secret_or_file_list_access() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/word-count-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join("two.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("-l")).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("wc -l one.txt", true),
            ("wc -lwmc one.txt two.txt", true),
            ("wc --lines one.txt", true),
            ("wc -- one.txt", true),
            ("cat one.txt | wc -l", true),
            ("cat one.txt | wc -- -", true),
            ("cat one.txt | wc", true),
            ("wc -l .env", false),
            ("cat .env | wc -l", false),
            ("wc one.txt -l", false),
            ("wc -- -l", false),
            ("wc --files0-from=one.txt", false),
            ("wc --files0-from .env", false),
            ("wc one.txt --files0-from=.env", false),
            ("cat one.txt | wc --files0-from=.env", false),
            ("wc -l", false),
            ("wc -l one.txt; rm -rf project", false),
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
                "{harness}: {command}"
            );
        }
    }
}
