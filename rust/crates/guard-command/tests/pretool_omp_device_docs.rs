//! Oh My Pi's `xd://` URLs. `read xd://` lists the session's mounted tool
//! devices and `read xd://<tool>[/<topic>]` returns that tool's docs, text
//! omp writes itself. A write to `xd://<tool>` runs the tool.
#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pretool-omp-device-docs")
            .join(format!(
                "home-{}-{}",
                std::process::id(),
                crate::unique_nanos::unique_nanos()
            ));
        std::fs::create_dir_all(root.join("home/project")).unwrap();
        Self {
            root: std::fs::canonicalize(root).unwrap(),
        }
    }

    fn run(&self, harness: &str, tool: &str, input: Value) -> PreToolResultV1 {
        let home = self.root.join("home");
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": input}),
            None,
            None,
            home.to_str(),
            home.join("project").to_str(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn omp(fixture: &Fixture, tool: &str, input: Value) -> PreToolResultV1 {
    fixture.run("omp", tool, input)
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

/// `read xd://...` returns the docs of the session's mounted tool devices.
/// Only a write to `xd://<tool>` runs one.
#[test]
fn device_doc_references_are_reads_of_the_hosts_tool_docs() {
    let f = Fixture::new();
    for path in ["xd://", "xd://eval", "xd://eval/helpers", "xd://web_search"] {
        let result = omp(&f, "read", json!({"path": path}));
        assert!(allowed(&result), "{path}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_omp_device_docs_read", "{path}");
    }
    for path in [
        "xd:///etc/passwd",
        "xd://../.ssh/id_rsa",
        "xd://eval/../../x",
        "xd://eval/helpers/more",
        "xd://.hidden",
        "xd://eval/",
        "xd://~",
        "xd://a%2e%2e",
        "XD://eval",
    ] {
        let result = omp(&f, "read", json!({"path": path}));
        assert_ne!(result.reason_code, "native_omp_device_docs_read", "{path}");
    }
    for tool in ["write", "edit"] {
        let result = omp(&f, tool, json!({"path": "xd://eval", "content": "{}"}));
        assert_ne!(result.reason_code, "native_omp_device_docs_read", "{tool}");
    }
    assert_ne!(
        f.run("codex", "read", json!({"path": "xd://eval"}))
            .reason_code,
        "native_omp_device_docs_read"
    );
}
