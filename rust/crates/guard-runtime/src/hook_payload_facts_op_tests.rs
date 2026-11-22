use super::*;
use serde_json::json;

#[test]
fn event_aliases_are_normalized_by_the_resident() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-1".to_owned(),
        payload: json!({"event": "before-shell-execution"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "PreToolUse");
}

#[test]
fn cli_admission_uses_a_bounded_seconds_or_milliseconds_hint() {
    for (payload, budget) in [
        (json!({}), 9.75),
        (json!({"guard_remaining_seconds": 99.0}), 9.75),
        (json!({"guard_remaining_seconds": 0.2}), 0.1),
        (
            json!({"guard_remaining_seconds": 2, "guard_remaining_ms": 100}),
            1.75,
        ),
        (
            json!({"guard_remaining_seconds": -5, "guard_remaining_ms": 2000}),
            1.75,
        ),
        (
            json!({"guard_remaining_seconds": true, "guard_remaining_ms": 2000}),
            1.75,
        ),
        (
            json!({"guard_remaining_seconds": null, "guard_remaining_ms": 2000}),
            1.75,
        ),
    ] {
        let output = cli_admission(payload.to_string().as_bytes()).unwrap();
        assert_eq!(output["budget_seconds"], budget);
        assert_eq!(output["event_name"], "PreToolUse");
    }
}

#[test]
fn cli_availability_owns_event_posture_without_a_resident() {
    for (event, pauses, permission_request) in [
        ("UserPromptSubmit", true, false),
        ("user_prompt_submitted", true, false),
        ("PreToolUse", true, false),
        ("beforeShellExecution", true, false),
        ("PermissionRequestV2", true, true),
        ("copilotPermissionRequest", true, true),
        ("PostToolUse", false, false),
        ("post_tool", false, false),
        ("afterShellExecution", false, false),
        ("SessionStart", false, false),
        ("Stop", false, false),
    ] {
        let input = serde_json::json!({"hook_event_name": event}).to_string();
        let output = cli_availability(input.as_bytes()).unwrap();
        assert_eq!(output["pauses"], pauses, "{event}");
        assert_eq!(output["permission_request"], permission_request, "{event}");
    }

    let output = cli_availability(br#"{"hook_event_name":"copilotPermissionRequest"}"#).unwrap();
    assert_eq!(output["event_name"], "PermissionRequest");
}

#[test]
fn copilot_permission_alias_preserves_the_raw_event_name() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-copilot-permission".to_owned(),
        payload: json!({"event": "copilotPermissionRequest"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "copilotPermissionRequest");
}

#[test]
fn python_control_strip_is_preserved() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-2".to_owned(),
        payload: json!({"event": "\u{1c}PreToolUse\u{1c}"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "PreToolUse");
}

#[test]
fn command_and_launch_facts_are_resident_owned() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-3".to_owned(),
        payload: json!({
            "toolName": "Bash",
            "toolInput": {"command": "  echo hi  "}
        }),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["command"], "  echo hi  ");
    assert_eq!(output["result"]["tool_name"], "Bash");
    assert_eq!(output["result"]["launch_target"], "  echo hi  ");
}

#[test]
fn oversized_tool_input_is_rejected_before_response_encoding() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-large".to_owned(),
        payload: json!({"toolInput": {"command": "x".repeat(guard_contracts::MAX_NATIVE_RESPONSE_BYTES)}}),
    };
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "hook_payload_facts_response_too_large"
    );
}
