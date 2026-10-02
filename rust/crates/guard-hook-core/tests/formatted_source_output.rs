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

#[cfg(unix)]
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

#[cfg(not(unix))]
#[test]
fn formatted_reads_fail_closed_without_descriptor_verified_source_reads() {
    let root = TestRoot::new();
    let source = root.path().join("example.py");
    std::fs::write(&source, "print(1 + 1)\n").unwrap();
    let result = review_post_tool(&request(root.path(), "[example.py#ABCD]\n1: print(1 + 1)"));
    assert_eq!(result.reason_code, "no_output_to_review");
    assert_eq!(result.model_output_action, "block");
}

#[cfg(unix)]
#[test]
fn external_and_linked_plaintext_is_scanned_without_checkout_location_allowlists() {
    let root = TestRoot::new();
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let outside = root.path().join("ordinary.txt");
    std::fs::write(&outside, "ordinary fixture\n").unwrap();
    let link = workspace.join("guide.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    for target in [
        outside.to_string_lossy().as_ref(),
        "guide.txt",
        "../ordinary.txt",
    ] {
        let mut input = request(&workspace, "ordinary fixture");
        input.payload["tool_input"]["path"] = json!(target);
        input.payload["guard_source_ref"]["path"] = json!(target);
        input.payload["guard_source_ref"]["tool_input_path"] = json!(target);
        let result = review_post_tool(&input);
        assert_eq!(
            result.model_output_action, "allow_original",
            "{target}: {result:?}"
        );
        input.source_ref_external_allowed = false;
        assert_ne!(
            review_post_tool(&input).model_output_action,
            "allow_original",
            "{target}"
        );
    }
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    std::fs::write(&outside, format!("{token}\n")).unwrap();
    let mut secret = request(&workspace, "ordinary fixture");
    for field in ["path", "tool_input_path"] {
        secret.payload["guard_source_ref"][field] = json!("guide.txt");
    }
    secret.payload["tool_input"]["path"] = json!("guide.txt");
    assert_eq!(review_post_tool(&secret).reason_code, "source_secret_match");
    let dotenv = root.path().join(".env");
    std::fs::write(&dotenv, "synthetic fixture only\n").unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&dotenv, &link).unwrap();
    assert_ne!(
        review_post_tool(&secret).model_output_action,
        "allow_original"
    );
}
