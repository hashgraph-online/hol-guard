use guard_contracts::NativeHookRequestV1;
use guard_hook_core::{extract_payload_output, review_post_tool};
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
            .text
            .contains(&format!("a{}", aws_like_access_key())),
        "{}",
        extracted.text
    );
    let response = review_post_tool(&request(payload));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "output_secret_match");
}
