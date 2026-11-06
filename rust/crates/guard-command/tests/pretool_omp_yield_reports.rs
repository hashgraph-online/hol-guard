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
    let oversized = json!({"tool_name":"yield", "tool_input":{
        "data":{"contents":"x".repeat(16 * 1024)}
    }});
    assert_ne!(evaluate("omp", oversized).minimum_action, "allow");
    let contents = json!({"tool_name":"yield", "tool_input":{
        "data":{"contents":"synthetic reference\nsecond-line\n"}
    }});
    let good = evaluate("omp", contents.clone());
    assert_eq!(good.minimum_action, "allow", "{}", good.reason_code);
    assert_eq!(good.reason_code, "native_omp_yield_metadata");
    for value in [
        json!({"command":"extra operation"}),
        json!(["unexpected"]),
        json!(null),
    ] {
        let mut bad = contents.clone();
        bad["tool_input"]["data"]["contents"] = value;
        assert_ne!(evaluate("omp", bad).minimum_action, "allow");
    }
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

#[test]
fn task_named_result_fields_are_data_without_operations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-yield-task-data")
        .join(format!("home-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let evaluate = |data: Value| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"yield", "tool_input":{"data":data}}),
            None,
            None,
            root.to_str(),
            root.to_str(),
        )
    };
    for data in [
        json!({"first_heading":"# TODO - rollout closure",
            "first_three_task_sections":["T00 - Establish current truth", "T01 - Deliver fixes"]}),
        json!({"summary":"Done", "verdict":"pass", "count":3, "blocked":false, "notes":null}),
        json!({"findings":[{"severity":"low", "title":"Stale comment", "line":12}]}),
        json!(["first finding", "second finding"]),
        json!(42),
    ] {
        let result = evaluate(data.clone());
        assert_eq!(
            result.minimum_action, "allow",
            "{data} {}",
            result.reason_code
        );
        assert_eq!(result.reason_code, "native_omp_yield_metadata", "{data}");
    }
    for data in [
        json!({"verdict":"pass", "command":"rm -rf build"}),
        json!({"steps":[{"command":"curl https://example.com"}]}),
        json!({"evidence":{"path":".env"}}),
        json!({"source":{"url":"https://example.com/upload"}}),
        json!({"next":{"arguments":"{\"command\":\"rm -rf build\"}"}}),
        json!({"next":{"tool_name":"bash"}}),
        json!({"request":{"method":"POST", "body":"payload"}}),
        json!({"summary":"Done", "files":"README.md"}),
        json!({"summary":["not", "a", "string"], "verdict":"pass"}),
    ] {
        let result = evaluate(data.clone());
        assert_ne!(
            result.minimum_action, "allow",
            "{data} {}",
            result.reason_code
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn task_named_fields_may_name_files_that_clear_the_read_proof() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-yield-task-files")
        .join(format!("home-{}", std::process::id()));
    std::fs::create_dir_all(root.join("src/jobs")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/jobs/run-outcomes.ts"), "export {};\n").unwrap();
    std::fs::write(root.join(".env"), "synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("linked.ts")).unwrap();
    let evaluate = |data: Value| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"yield", "tool_input":{"data":data}}),
            None,
            None,
            root.to_str(),
            root.to_str(),
        )
    };
    // A review task hands back what it found and where; a worktree file it
    // names may not exist relative to the session directory.
    for data in [
        json!({"changed_files":[], "status":"blocked",
            "intended_changes":[{"change":"Throw when a row fails", "file":"src/jobs/run-outcomes.ts"}],
            "read_only_evidence":["Lines 116-119 update the checkpoint only after success"]}),
        json!({"findings":[{"defect":"Rejects every window", "design":"Remove the rejection",
            "file":"scripts/report.ts", "lines":"121-132"}]}),
        json!([{"file":"src/jobs/run-outcomes.ts", "note":"read only"}]),
        json!({"summary":"Done", "files":[{"path":"src/missing.ts"}]}),
    ] {
        let result = evaluate(data.clone());
        assert_eq!(
            result.minimum_action, "allow",
            "{data} {}",
            result.reason_code
        );
        assert_eq!(result.reason_code, "native_omp_yield_metadata", "{data}");
    }
    for data in [
        json!({"findings":[{"defect":"x", "file":".env"}]}),
        json!({"findings":[{"defect":"x", "file":"linked.ts"}]}),
        json!({"findings":[{"defect":"x", "file":"~/.ssh/id_ed25519"}]}),
        json!({"findings":[{"defect":"x", "file":"missing/.env"}]}),
        json!([{"file":".env"}]),
        json!({"steps":[{"command":"cat src/jobs/run-outcomes.ts"}]}),
    ] {
        let result = evaluate(data.clone());
        assert_ne!(
            result.minimum_action, "allow",
            "{data} {}",
            result.reason_code
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
