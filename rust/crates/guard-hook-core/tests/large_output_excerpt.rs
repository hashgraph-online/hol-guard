use guard_contracts::NativeHookRequestV1;
use guard_hook_core::{extract_payload_output, review_post_tool};
use guard_rules::{MAX_OUTPUT_CHARS, REVIEWED_EXCERPT_CHARS};
use serde_json::{json, Value};

fn request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("large-output-excerpt".into()),
        harness: "claude-code".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/tmp".into(),
        guard_home: "/tmp/guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(9_000),
    }
}

fn oversized_payload() -> Value {
    // Two output keys, each large enough on its own to spend the whole
    // character budget.
    json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cat big.log other.log"},
        "stdout": "a".repeat(MAX_OUTPUT_CHARS),
        "stderr": "b".repeat(MAX_OUTPUT_CHARS),
    })
}

#[test]
fn both_output_forms_cover_the_same_characters() {
    // The separated form used to be built from every key in full while the
    // concatenated form was capped, so it carried content the cap had
    // already dropped.
    let extracted = extract_payload_output(&oversized_payload());
    assert!(extracted.truncated);
    assert_eq!(
        extracted.boundary_text.chars().count(),
        extracted.text.chars().count(),
        "the separated form must not reach past the character budget"
    );
    assert!(extracted.text.chars().count() <= MAX_OUTPUT_CHARS);
}

#[test]
fn an_oversized_output_still_comes_back_as_a_reviewed_excerpt() {
    // The scan adds the separators back so it always covers the content the
    // excerpt returns. While the separated form ran past the budget, that
    // allowance counted the dropped content too, pushed the scan past its
    // own byte limit and turned a reviewed excerpt into a deny.
    let response = review_post_tool(&request(oversized_payload()));
    assert_eq!(response.decision, "allow", "{:?}", response.reason_code);
    assert_eq!(response.reason_code, "output_too_large");
    assert_eq!(
        response.model_output_action,
        "replace_with_reviewed_excerpt"
    );
    let excerpt = response.reviewed_excerpt.expect("a reviewed excerpt");
    assert_eq!(excerpt.chars().count(), REVIEWED_EXCERPT_CHARS);
}
