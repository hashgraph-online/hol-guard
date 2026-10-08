#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn stdin_filters_cannot_load_files_or_execute_helpers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/stdin-filter-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("cat one.txt | sort", true),
            ("cat one.txt | sort -u", true),
            ("cat one.txt | sort -nr | uniq -c", true),
            ("cat one.txt | cut -d ' ' -f 1", true),
            ("cat one.txt | cut -c1-5", true),
            ("cat one.txt | sort -o .env", false),
            ("cat one.txt | sort --compress-program=sh", false),
            ("cat one.txt | sort --random-source=.env", false),
            ("cat one.txt | sort .env", false),
            ("cat .env | sort -u", false),
            ("cat one.txt | uniq .env output.txt", false),
            ("cat one.txt | cut -f1 .env", false),
            (
                "cat one.txt | cut --output-delimiter='$(cat .env)' -f1",
                false,
            ),
            ("cat one.txt | cut -f0", false),
            ("cat one.txt | cut -f5-1", false),
            ("cat one.txt | cut -f1-2-3", false),
            ("sort -u", false),
            ("uniq -c", false),
            ("cut -f1", false),
            ("python3 unknown.py | sort -u", false),
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
