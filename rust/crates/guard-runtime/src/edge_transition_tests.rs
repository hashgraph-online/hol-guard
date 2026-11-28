use super::*;

#[test]
fn stamps_transition_probe_observation_on_the_edge_result() {
    let operation_id = "12345678-1234-5678-1234-567812345678";
    let request_id = "transition-hook-0123456789abcdef0123456789abcdef";
    let mut request = envelope(
        "PreToolUse",
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd"},
            "guard_transition_probe": {
                "schema": "hol-guard.transition-hook-probe.v1",
                "operation_id": operation_id,
                "request_id": request_id,
            },
        }),
    );
    request.harness = "codex".to_owned();
    request.request_id = None;
    let edge: GuardHookEdgeResultV2 =
        serde_json::from_slice(&evaluate_isolated(request).unwrap()).unwrap();
    assert_eq!(edge.receipt.request_id, request_id);
    assert_eq!(
        edge.transition_hook_observation
            .as_ref()
            .and_then(|value| value.get("operation_id"))
            .and_then(Value::as_str),
        Some(operation_id)
    );
    assert_eq!(
        edge.transition_hook_observation
            .as_ref()
            .and_then(|value| value.get("observation"))
            .and_then(|value| value.get("request_id"))
            .and_then(Value::as_str),
        Some(request_id)
    );
}

#[test]
fn rejects_a_request_id_that_does_not_match_the_transition_probe() {
    let mut request = envelope(
        "PreToolUse",
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd"},
            "guard_transition_probe": {
                "schema": "hol-guard.transition-hook-probe.v1",
                "operation_id": "12345678-1234-5678-1234-567812345678",
                "request_id": "transition-hook-0123456789abcdef0123456789abcdef",
            },
        }),
    );
    request.request_id = Some("request-foreign".to_owned());
    let error = evaluate_isolated(request).unwrap_err();
    assert_eq!(error, "native_hook_request_id_probe_mismatch");
}
