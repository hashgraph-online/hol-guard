use guard_contracts::NativeHookRequestV1;
use guard_hook_core::{extract_payload_output, review_post_tool, sha256_text};
use serde_json::{json, Value};

fn request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("adjacent-output-fields".into()),
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

fn aws_like_access_key() -> String {
    let prefix = ["AK", "IA"].concat();
    format!("{prefix}{}", "A".repeat(16))
}

#[test]
fn adjacent_fields_keep_the_word_boundary_a_secret_rule_needs() {
    // Concatenating the fields of an unreadable patch produced
    // `aaAKIA...`, and the access-key rule needs a word boundary ahead of
    // the prefix, so the credential scanned clean.
    let payload = json!({
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/config.ts"},
        "tool_response": {
            "originalFile": "a",
            "oldString": "a",
            "newString": aws_like_access_key(),
        }
    });
    let extracted = extract_payload_output(&payload);
    assert!(
        !extracted
            .boundary_text
            .contains(&format!("a{}", aws_like_access_key())),
        "{}",
        extracted.boundary_text
    );
    let response = review_post_tool(&request(payload));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "output_secret_match");
}

#[test]
fn the_proof_digest_still_covers_the_concatenated_output() {
    // The Pi extension recomputes this digest over its own copy of the
    // output, hashing each text part with nothing between them, and blocks
    // the result when the two digests differ. A separator added for the scan
    // must therefore never reach the digested bytes.
    let payload = json!({
        "tool_name": "Bash",
        "tool_response": {
            "content": [
                {"type": "text", "text": "first line\r\n"},
                {"type": "metadata", "value": "ignored"},
                {"type": "text", "text": "second line\n"},
            ]
        }
    });
    let extracted = extract_payload_output(&payload);
    assert_eq!(extracted.text, "first line\r\nsecond line\n");
    assert_eq!(extracted.boundary_text, "first line\r\n\nsecond line\n");
    assert_eq!(extracted.chars, extracted.text.chars().count());

    let response = review_post_tool(&request(payload));
    assert_eq!(response.decision, "allow");
    assert_eq!(
        response.reviewed_output_sha256,
        Some(sha256_text("first line\r\nsecond line\n"))
    );
}
