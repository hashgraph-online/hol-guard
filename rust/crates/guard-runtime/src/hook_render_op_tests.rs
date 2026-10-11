use super::*;
use serde_json::json;

fn request(kind: &str) -> HookRenderRequestV1 {
    HookRenderRequestV1 {
        schema: guard_contracts::HOOK_RENDER_REQUEST_SCHEMA.to_owned(),
        request_id: "render-1".to_owned(),
        kind: kind.to_owned(),
        harness: "codex".to_owned(),
        verdict: None,
        approval: None,
        linked_reason: None,
        reason_code: None,
        reason: None,
        cli: None,
    }
}

fn decode(bytes: Vec<u8>) -> HookRenderResultV1 {
    serde_json::from_slice(&bytes).expect("result decodes")
}

#[test]
fn review_response_uses_the_linked_reason() {
    let mut req = request("pre_tool_review");
    req.verdict = Some(json!({
        "decision": "deny", "minimum_action": "review",
        "reason_code": "native_network_review", "reason": "needs review",
    }));
    req.approval = Some(json!({"approval_url": "https://example.test/a", "request_id": "r1"}));
    req.linked_reason = Some("needs review https://example.test/a".to_owned());
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    let response = &result.payload.expect("payload")["response"];
    assert_eq!(response["policy_action"], "review");
    assert!(response["reason"]
        .as_str()
        .expect("reason")
        .contains("https://example.test/a"));
}

#[test]
fn recording_only_response_continues() {
    let mut req = request("recording_only_pre_tool");
    req.reason_code = Some("watch_recording_only".to_owned());
    req.reason = Some("recorded".to_owned());
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    assert_eq!(
        result.payload.expect("payload")["response"]["policy_action"],
        "warn"
    );
}

#[test]
fn missing_verdict_and_unknown_kind_are_invalid() {
    for kind in ["pre_tool", "pre_tool_review", "other"] {
        let result = decode(evaluate_hook_render_request(&request(kind)).expect("encoded"));
        assert_eq!(result.status, "error");
        assert_eq!(result.code, "native_hook_render_invalid");
        assert!(result.payload.is_none());
    }
}

#[test]
fn oversized_request_is_rejected() {
    let mut req = request("pre_tool");
    req.verdict = Some(json!({ "reason": "x".repeat(guard_contracts::HOOK_RENDER_MAX_BYTES) }));
    assert_eq!(
        evaluate_hook_render_request(&req).unwrap_err(),
        "native_hook_render_too_large"
    );
}

#[test]
fn cli_kinds_wrap_the_composed_outcome() {
    let mut req = request("cli_document");
    req.harness = "claude-code".to_owned();
    req.cli = Some(json!({
        "canonical_harness": "claude-code", "event_name": "PreToolUse",
        "policy_action": "block", "reason": "no",
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(payload["response"]["decision"], "block");

    req.cli = Some(json!({"canonical_harness": "copilot", "event_name": "Stop"}));
    req.harness = "copilot".to_owned();
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "fallback");

    req.kind = "cli_response".to_owned();
    req.harness = "codex".to_owned();
    req.cli = Some(
        json!({"canonical_harness": "codex", "event_name": "PreToolUse", "policy_action": "allow"}),
    );
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "silent");
}

#[test]
fn cli_kinds_require_params() {
    let result = decode(evaluate_hook_render_request(&request("cli_response")).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}
