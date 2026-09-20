#![cfg(windows)]

use guard_contracts::{HookReviewResponseV1, NativeHookRequestV1};
use guard_hook_core::{review_post_tool, review_post_tool_with_deadline};
use guard_rules::MAX_SCAN_BYTES;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-windows-hook-source-{name}-{}",
            std::process::id()
        ));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        Self { root, workspace }
    }

    fn request(&self, harness: &str, content: &[u8], observed: &str) -> NativeHookRequestV1 {
        fs::write(self.workspace.join("source.rs"), content).unwrap();
        NativeHookRequestV1 {
            protocol_version: 1,
            request_id: Some("windows-source-contract".into()),
            harness: harness.into(),
            event_name: "PostToolUse".into(),
            payload: json!({
                "tool_input": {"file_path": "source.rs"},
                "guard_source_ref": {
                    "version": 1,
                    "path": "source.rs",
                    "output_sha256": digest(observed.as_bytes()),
                    "output_chars": observed.chars().count(),
                },
            }),
            cwd: Some(self.workspace.to_string_lossy().into_owned()),
            home_dir: self.root.to_string_lossy().into_owned(),
            guard_home: self.root.join("guard").to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
            observe_mode: false,
            deadline_budget_ms: Some(9_000),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn digest(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

fn assert_inconclusive(response: HookReviewResponseV1) {
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    assert_eq!(response.model_output_action, "block");
    assert_eq!(response.reviewed_output_sha256, None);
    assert_eq!(response.reviewed_excerpt, None);
}

fn point_at(request: &mut NativeHookRequestV1, path: &Path) {
    let path = path.to_string_lossy().into_owned();
    request.payload["tool_input"]["file_path"] = json!(path);
    request.payload["guard_source_ref"]["path"] =
        request.payload["tool_input"]["file_path"].clone();
}

#[test]
fn pi_and_omp_preserve_unicode_newline_equivalence_and_response_schema() {
    let fixture = Fixture::new("equivalence");
    for harness in ["pi", "omp"] {
        for observed in ["let label = \"α🙂\";\n", "let label = \"α🙂\";"] {
            let request = fixture.request(harness, "let label = \"α🙂\";\n".as_bytes(), observed);
            let response = review_post_tool(&request);
            assert_eq!(
                serde_json::to_value(response).unwrap(),
                json!({
                    "decision": "allow",
                    "model_output_action": "allow_original",
                    "reviewed_output_sha256": digest(observed.as_bytes()),
                    "notice": "none",
                    "reason_code": "source_full_scan_allow",
                    "policy_action": "allow",
                })
            );
        }
    }
}

#[test]
fn source_secret_is_blocked_without_plaintext_or_path_in_response() {
    let fixture = Fixture::new("secret");
    let secret = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    for harness in ["pi", "omp"] {
        let request = fixture.request(harness, secret.as_bytes(), &secret);
        let response = review_post_tool(&request);
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "source_secret_match");
        assert_eq!(response.reviewed_output_sha256, None);
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains(&secret));
        assert!(!encoded.contains("source.rs"));
        assert!(!encoded.contains("security_descriptor"));
    }
}

#[test]
fn pi_and_omp_reject_unbound_reference_fields() {
    let fixture = Fixture::new("references");
    let content = "fn source() {}\n";
    fs::write(fixture.workspace.join("other.rs"), content).unwrap();
    for harness in ["pi", "omp"] {
        for (key, replacement) in [
            ("version", json!(2)),
            ("output_sha256", json!("a".repeat(64))),
            ("output_sha256", json!("invalid")),
            ("output_chars", json!(-1)),
            ("output_chars", json!(content.chars().count() + 1)),
            ("output_chars", json!(MAX_SCAN_BYTES + 1)),
            ("path", json!("other.rs")),
            ("tool_input_path", json!("other.rs")),
        ] {
            let mut request = fixture.request(harness, content.as_bytes(), content);
            request.payload["guard_source_ref"][key] = replacement;
            assert_inconclusive(review_post_tool(&request));
        }
    }
}

#[test]
fn pi_and_omp_preserve_plaintext_byte_and_deadline_bounds() {
    let fixture = Fixture::new("bounds");
    for harness in ["pi", "omp"] {
        for bytes in [vec![0xf0, 0x28, 0x8c, 0x28], b"safe\0data".to_vec()] {
            let request = fixture.request(harness, &bytes, "safe");
            assert_inconclusive(review_post_tool(&request));
        }
        let oversized = vec![b'x'; MAX_SCAN_BYTES + 1];
        let request = fixture.request(harness, &oversized, "safe");
        assert_inconclusive(review_post_tool(&request));
        let request = fixture.request(harness, b"fn source() {}\n", "fn source() {}\n");
        assert_inconclusive(review_post_tool_with_deadline(
            &request,
            Some(Instant::now() - Duration::from_millis(1)),
        ));
    }
}

#[test]
fn external_source_requires_pi_or_omp_and_explicit_permission() {
    let fixture = Fixture::new("external");
    let sibling = fixture.root.join("sibling");
    fs::create_dir_all(sibling.join(".git")).unwrap();
    let path = sibling.join("source.rs");
    let content = "fn sibling() {}\n";
    fs::write(&path, content).unwrap();
    for harness in ["pi", "omp", "claude-code"] {
        let mut request = fixture.request(harness, content.as_bytes(), content);
        point_at(&mut request, &path);
        assert_inconclusive(review_post_tool(&request));
        request.source_ref_external_allowed = true;
        let response = review_post_tool(&request);
        if harness == "claude-code" {
            assert_inconclusive(response);
        } else {
            assert_eq!(response.decision, "allow");
            assert_eq!(response.reason_code, "source_full_scan_allow");
        }
        request.home_dir = fixture.workspace.to_string_lossy().into_owned();
        assert_inconclusive(review_post_tool(&request));
    }
}

#[test]
fn external_sensitive_names_and_non_checkout_sources_stay_denied() {
    let fixture = Fixture::new("external-negative");
    let sibling = fixture.root.join("sibling");
    fs::create_dir_all(&sibling).unwrap();
    let path = sibling.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    for harness in ["pi", "omp"] {
        let mut request = fixture.request(harness, b"safe", "safe");
        request.source_ref_external_allowed = true;
        point_at(&mut request, &path);
        assert_inconclusive(review_post_tool(&request));
    }
    fs::create_dir_all(sibling.join(".git")).unwrap();
    let sensitive = sibling.join("auth_token.ts");
    fs::write(&sensitive, b"safe").unwrap();
    for harness in ["pi", "omp"] {
        let mut request = fixture.request(harness, b"safe", "safe");
        request.source_ref_external_allowed = true;
        point_at(&mut request, &sensitive);
        assert_inconclusive(review_post_tool(&request));
    }
}

#[test]
fn matching_hash_cannot_allow_a_hard_linked_source() {
    let fixture = Fixture::new("hard-link");
    let request = fixture.request("pi", b"safe", "safe");
    fs::hard_link(
        fixture.workspace.join("source.rs"),
        fixture.workspace.join("alias.rs"),
    )
    .unwrap();
    assert_inconclusive(review_post_tool(&request));
}

#[test]
fn matching_hash_cannot_allow_a_junction_before_source_classification() {
    let fixture = Fixture::new("junction");
    let target = fixture.workspace.join("real");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("source.rs"), b"safe").unwrap();
    let alias = fixture.workspace.join("alias");
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&alias)
        .arg(&target)
        .output()
        .unwrap();
    assert!(output.status.success());
    for harness in ["pi", "omp"] {
        let mut request = fixture.request(harness, b"safe", "safe");
        point_at(&mut request, &alias.join("source.rs"));
        assert_inconclusive(review_post_tool(&request));
    }
    fs::remove_dir(alias).unwrap();
}

#[test]
fn observe_source_secret_preserves_the_verified_original_digest() {
    let fixture = Fixture::new("observe");
    let secret = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    let mut request = fixture.request("omp", secret.as_bytes(), &secret);
    request.observe_mode = true;
    let response = review_post_tool(&request);
    assert_eq!(response.decision, "allow");
    assert_eq!(response.reason_code, "observe_source_secret_match");
    assert_eq!(
        response.reviewed_output_sha256,
        Some(digest(secret.as_bytes()))
    );
    assert_eq!(response.observed_policy_action.as_deref(), Some("block"));
    assert!(response.observe_mode);
    assert!(serde_json::to_value(response)
        .unwrap()
        .get("reviewed_excerpt")
        .is_none());
}
