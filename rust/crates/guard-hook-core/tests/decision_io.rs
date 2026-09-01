use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("test".into()),
        harness: "claude-code".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/tmp".into(),
        guard_home: "/tmp/guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn source_request(cwd: &Path, output_sha256: String, output_chars: i64) -> NativeHookRequestV1 {
    let mut value = request(json!({
        "tool_input": {"file_path": "source.rs"},
        "guard_source_ref": {
            "version": 1,
            "path": "source.rs",
            "output_sha256": output_sha256,
            "output_chars": output_chars
        }
    }));
    value.cwd = Some(cwd.to_string_lossy().into_owned());
    value.home_dir = cwd.to_string_lossy().into_owned();
    value
}

#[test]
fn source_replacement_between_observations_is_not_equivalent() {
    let root = std::env::temp_dir().join(format!(
        "guard-hook-core-replacement-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("source.rs");
    let original = b"fn original() {}\n";
    fs::write(&path, original).unwrap();
    fs::write(&path, b"fn replacement() {}\n").unwrap();

    let response = review_post_tool(&source_request(&root, digest(original), 18));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn source_growth_after_expected_output_is_not_equivalent() {
    let root = std::env::temp_dir().join(format!("guard-hook-core-growth-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("source.rs");
    let original = b"safe";
    fs::write(&path, b"safe growth").unwrap();

    let response = review_post_tool(&source_request(&root, digest(original), 4));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn invalid_utf8_source_is_fail_closed_without_materializing_bytes() {
    let root =
        std::env::temp_dir().join(format!("guard-hook-core-encoding-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("source.rs");
    fs::write(&path, [0xf0_u8, 0x28, 0x8c, 0x28]).unwrap();

    let response = review_post_tool(&source_request(&root, "a".repeat(64), 4));
    let serialized = serde_json::to_string(&response).unwrap();

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    assert!(!serialized.contains("f0"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlink_source_is_fail_closed() {
    let root = std::env::temp_dir().join(format!("guard-hook-core-symlink-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let target = root.join("target.rs");
    let source = root.join("source.rs");
    fs::write(&target, b"safe").unwrap();
    std::os::unix::fs::symlink(&target, &source).unwrap();

    let response = review_post_tool(&source_request(&root, digest(b"safe"), 4));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}
