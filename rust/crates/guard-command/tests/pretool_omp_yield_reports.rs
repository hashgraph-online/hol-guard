#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

#[test]
fn bounded_yield_reports_preserve_file_and_envelope_checks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-yield-reports")
        .join(format!("home-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("README.md"), "synthetic reference").unwrap();
    std::fs::write(root.join(".env"), "synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("linked.md")).unwrap();
    let evaluate = |harness: &str, input: Value| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &input,
            None,
            None,
            root.to_str(),
            root.to_str(),
        )
    };
    let report = json!({"tool_name":"yield", "tool_input":{
        "type":"result", "error":"x", "data":{"summary":"Read complete", "report":"synthetic reference",
        "architecture":"", "files":[{"path":"README.md", "description":"Read only"}]}
    }});
    let good = evaluate("omp", report.clone());
    assert_eq!(good.minimum_action, "allow", "{}", good.reason_code);
    assert_eq!(good.reason_code, "native_omp_yield_metadata");
    for path in [".env", "linked.md", "https://example.com", "proc://job"] {
        let mut bad = report.clone();
        bad["tool_input"]["data"]["files"][0]["path"] = json!(path);
        assert_ne!(evaluate("omp", bad).minimum_action, "allow", "{path}");
    }
    for key in ["command", "url", "arguments"] {
        let mut bad = report.clone();
        bad["tool_input"]["data"][key] = json!("extra operation");
        assert_ne!(evaluate("omp", bad).minimum_action, "allow", "{key}");
    }
    let mut ambiguous = report.clone();
    ambiguous["toolInput"] = json!({"data":"different"});
    assert_ne!(evaluate("omp", ambiguous).minimum_action, "allow");
    assert_ne!(evaluate("codex", report).minimum_action, "allow");
    std::fs::remove_dir_all(root).unwrap();
}
