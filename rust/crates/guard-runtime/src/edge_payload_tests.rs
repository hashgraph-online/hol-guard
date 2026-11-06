use super::*;

#[test]
fn unknown_and_ambiguous_pretool_payloads_never_receive_an_allow_floor() {
    let unknown = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({"toolName": "future_tool", "opaque": true}),
    ))
    .unwrap();
    let unknown_result: GuardHookEdgeResultV2 = serde_json::from_slice(&unknown).unwrap();
    assert_eq!(unknown_result.result["minimum_action"], "review");

    let ambiguous = evaluate_isolated(envelope(
        "PreToolUse",
        serde_json::json!({"command": "pwd", "cmd": "whoami"}),
    ))
    .unwrap();
    let ambiguous_result: GuardHookEdgeResultV2 = serde_json::from_slice(&ambiguous).unwrap();
    assert_eq!(ambiguous_result.result["minimum_action"], "block");
    assert_eq!(
        ambiguous_result.result["reason_code"],
        "native_pre_tool_ambiguous_payload"
    );
}
