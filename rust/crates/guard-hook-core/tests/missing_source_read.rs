use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "guard-missing-source-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An Oh My Pi `read` result as the extension sends it: a source reference
/// to the requested path beside the text the host presented.
fn failed_read(root: &std::path::Path, path: &str, output: &str) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("missing-read".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": path},
            "tool_response": output,
            "is_error": true,
            "tool_response_summary": {"kind": "text", "text_excerpt": output,
                "excerpt_chars": output.chars().count(),
                "output_chars": output.chars().count(),
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "excerpt_truncated": false},
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": path, "tool_input_path": path,
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
fn the_host_error_for_a_missing_file_reaches_the_agent() {
    let root = TestRoot::new();
    for path in [
        "app-portal-fix/package.json",
        "app-portal-fix/src/report.ts:42-142",
        "../app-portal-fix/src/report.ts",
    ] {
        let result = review_post_tool(&failed_read(
            &root.0,
            path,
            "Path not found: app-portal-fix",
        ));
        assert_eq!(result.reason_code, "output_scan_allow", "{path}");
        assert_eq!(result.model_output_action, "allow_original", "{path}");
    }
}

#[test]
fn a_failed_read_is_still_held_to_the_presented_text() {
    let root = TestRoot::new();
    let path = "app-portal-fix/package.json";
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let leaked = failed_read(&root.0, path, &format!("Path not found: {token}"));
    assert_eq!(review_post_tool(&leaked).reason_code, "output_secret_match");

    // The digest must describe the complete presented text.
    let mut partial = failed_read(&root.0, path, "Path not found: app-portal-fix");
    partial.payload["tool_response_summary"]["excerpt_truncated"] = json!(true);
    assert_eq!(
        review_post_tool(&partial).reason_code,
        "no_output_to_review"
    );
    let mut mismatch = failed_read(&root.0, path, "Path not found: app-portal-fix");
    mismatch.payload["guard_source_ref"]["output_chars"] = json!(1);
    assert_eq!(
        review_post_tool(&mismatch).reason_code,
        "no_output_to_review"
    );

    // A sensitive path keeps its own decision.
    let key = failed_read(&root.0, "~/.ssh/id_ed25519", "Path not found");
    assert_eq!(review_post_tool(&key).reason_code, "sensitive_path");
}

#[test]
fn only_a_failed_read_of_a_missing_path_skips_the_source_read() {
    let root = TestRoot::new();
    let output = "Path not found: app-portal-fix";
    // Without the host's error flag the reference must still be backed by a file.
    let mut quiet = failed_read(&root.0, "app-portal-fix/package.json", output);
    quiet.payload["is_error"] = json!(false);
    assert_eq!(review_post_tool(&quiet).reason_code, "no_output_to_review");

    // A selector on an existing file is a read of that file, which is
    // re-read and scanned as usual.
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    std::fs::write(root.0.join("notes.txt"), format!("token = '{token}'\n")).unwrap();
    let selected = failed_read(&root.0, "notes.txt:1-1", output);
    assert_ne!(
        review_post_tool(&selected).model_output_action,
        "allow_original"
    );
}
