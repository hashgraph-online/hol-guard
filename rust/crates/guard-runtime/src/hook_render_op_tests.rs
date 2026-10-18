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

#[test]
fn copilot_hook_response_kind_always_renders_a_document() {
    let mut req = request("copilot_hook_response");
    req.harness = "copilot".to_owned();
    req.cli = Some(json!({"policy_action": "block", "reason": "no"}));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(payload["response"]["permissionDecision"], "deny");
    assert_eq!(payload["response"]["permissionDecisionReason"], "no");

    req.cli = Some(json!({"policy_action": "allow", "reason": "no"}));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(payload["response"]["permissionDecision"], "allow");
    assert!(payload["response"]["permissionDecisionReason"].is_null());
}

#[test]
fn claude_approval_copy_kind_returns_one_named_piece_of_text() {
    let mut req = request("claude_approval_copy");
    req.harness = "claude-code".to_owned();
    req.cli = Some(json!({
        "which": "permission_request_terminal_notice",
        "payload": {"tool_name": "Bash"},
        "reason": "Reviewing this",
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(
        payload["response"]["value"],
        "HOL Guard: reviewing Claude approval for Bash. Reviewing this."
    );

    req.cli = Some(json!({"which": "not-a-name", "payload": {}}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn artifact_id_kind_names_the_artifact_an_event_belongs_to() {
    let mut req = request("artifact_id");
    req.cli = Some(json!({
        "canonical_harness": "codex",
        "payload": {"source_scope": "project", "tool_name": "shell"},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(payload["response"]["value"], "codex:project:shell");

    // No tool name: the event name scopes the id, lowercased.
    req.cli = Some(json!({
        "canonical_harness": "codex",
        "payload": {"hook_event_name": "preToolUse"},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], "codex:project:pretooluse");

    // Neither: the bare hook fallback.
    req.cli = Some(json!({"canonical_harness": "codex", "payload": {}}));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], "codex:project:hook");
}

#[test]
fn artifact_id_kind_folds_claude_tools_through_the_builtin_split() {
    let mut req = request("artifact_id");
    req.harness = "claude".to_owned();
    req.cli = Some(json!({
        "canonical_harness": "claude-code",
        "payload": {"source_scope": "user", "tool_name": "Bash"},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], "claude-code:user:Bash");

    req.cli = Some(json!({
        "canonical_harness": "claude-code",
        "payload": {"source_scope": "user", "tool_name": "mcp__linear__issue"},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(
        payload["response"]["value"],
        "claude-code:user:mcp:mcp__linear__issue"
    );
}

#[test]
fn artifact_id_kind_requires_the_canonical_harness() {
    let mut req = request("artifact_id");
    req.cli = Some(json!({"payload": {"tool_name": "shell"}}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn terminal_policy_action_kind_answers_whether_an_approval_could_still_matter() {
    let mut req = request("terminal_policy_action");
    req.cli = Some(json!({
        "evaluation": {"artifacts": [{"policy_action": "block"}]},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], true);

    // A reviewable action still has a question worth asking.
    req.cli = Some(json!({
        "evaluation": {"artifacts": [{"policy_action": "review"}]},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], false);
}

#[test]
fn terminal_policy_action_kind_requires_an_evaluation_object() {
    let mut req = request("terminal_policy_action");
    req.cli = Some(json!({"evaluation": "block"}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn cursor_after_shell_observed_kind_answers_whether_the_command_already_ran() {
    let mut req = request("cursor_after_shell_observed");
    req.cli = Some(json!({
        "payload": {"event": "afterShellExecution", "duration": 4},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], true);

    // A before-event carries no report of a finished command.
    req.cli = Some(json!({
        "payload": {"event": "beforeShellExecution", "command": "ls"},
    }));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], false);
}

#[test]
fn cursor_after_shell_observed_kind_requires_a_payload_object() {
    let mut req = request("cursor_after_shell_observed");
    req.cli = Some(json!({"payload": "afterShellExecution"}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn cursor_observer_event_kind_answers_what_a_proof_is_attested_under() {
    let mut req = request("cursor_observer_event");
    req.cli = Some(json!({"payload": {"hook_event_name": "beforeMCPExecution"}}));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], "afterMCPExecution");

    // A payload naming no event Guard observes falls back to the shell event.
    req.cli = Some(json!({"payload": {}}));
    let payload = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload");
    assert_eq!(payload["response"]["value"], "afterShellExecution");
}

#[test]
fn cursor_observer_event_kind_requires_a_payload_object() {
    let mut req = request("cursor_observer_event");
    req.cli = Some(json!({"payload": "beforeMCPExecution"}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}
