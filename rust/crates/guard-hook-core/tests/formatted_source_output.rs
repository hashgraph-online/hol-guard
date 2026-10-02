use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "guard-formatted-source-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(root: &std::path::Path, output: &str) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("formatted-read".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": "example.py"},
            "tool_response": output,
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": "example.py", "tool_input_path": "example.py",
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "output_chars": output.chars().count()}
        }),
        cwd: Some(root.to_string_lossy().into()),
        home_dir: root.to_string_lossy().into(),
        guard_home: root.join("guard").to_string_lossy().into(),
        source_ref_external_allowed: true,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

#[test]
fn formatted_reads_require_complete_scanned_output_and_clean_source() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    std::fs::write(&source, "print(1 + 1)\n").unwrap();
    let output = "[example.py#ABCD]\n1: print(1 + 1)";
    let base = request(root.path(), output);
    let allowed = review_post_tool(&base);
    assert_eq!(allowed.reason_code, "output_scan_allow");
    assert_eq!(allowed.model_output_action, "allow_original");

    let mut mismatch = base.clone();
    mismatch.payload["guard_source_ref"]["output_chars"] = json!(output.len() + 1);
    assert_ne!(
        review_post_tool(&mismatch).model_output_action,
        "allow_original"
    );

    let mut truncated = base.clone();
    truncated.payload["tool_response_summary"] = json!({"excerpt_truncated": true});
    assert_ne!(
        review_post_tool(&truncated).model_output_action,
        "allow_original"
    );

    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let unsafe_output = request(root.path(), &format!("1: {token}"));
    assert_eq!(
        review_post_tool(&unsafe_output).reason_code,
        "output_secret_match"
    );

    std::fs::write(&source, format!("token = '{token}'\n")).unwrap();
    assert_eq!(review_post_tool(&base).reason_code, "source_secret_match");
}
