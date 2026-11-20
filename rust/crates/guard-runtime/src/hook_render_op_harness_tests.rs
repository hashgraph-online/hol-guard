//! `cli_hook_emit` reads and the Cursor and Hermes render kinds.

use super::*;
use serde_json::json;

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

#[test]
fn hermes_bridge_names_the_document_and_the_exit_status() {
    let mut req = request("hermes_bridge");
    req.harness = "hermes".to_owned();
    req.cli = Some(json!({"response": {"policy_action": "review", "reason": "recursive delete"}}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    let payload = result.payload.expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(
        payload["response"]["document"],
        json!({"decision": "block", "reason": "recursive delete"})
    );
    assert_eq!(payload["response"]["exit_code"], json!(2));
}

#[test]
fn hermes_bridge_uses_the_recorded_text_when_a_block_has_no_reason() {
    let mut req = request("hermes_bridge");
    req.harness = "hermes".to_owned();
    req.cli = Some(json!({"response": {"decision": "block"}}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    let payload = result.payload.expect("payload");
    assert_eq!(
        payload["response"]["document"],
        json!({"decision": "block", "reason": "HOL Guard blocked this action"})
    );
    assert_eq!(payload["response"]["exit_code"], json!(2));
}

#[test]
fn hermes_bridge_rejects_a_request_with_no_response() {
    let mut req = request("hermes_bridge");
    req.harness = "hermes".to_owned();
    req.cli = Some(json!({}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn cli_hook_emit_reads_the_answer_or_reports_why_not() {
    let mut req = request("cli_hook_emit");
    req.harness = "devin".to_owned();
    req.cli = Some(json!({
        "event_name": "PreToolUse",
        "response_json": r#"{"policy_action":"block","reason":"denied"}"#,
    }));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    let payload = result.payload.expect("payload");
    assert_eq!(payload["outcome"], "document");
    assert_eq!(payload["response"]["exit_code"], 2);
    assert_eq!(payload["response"]["stderr"], "denied");

    req.cli = Some(json!({"event_name": "PreToolUse", "response_json": "[]"}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.code, "native_hook_render_unrenderable");
    req.cli = Some(json!({"event_name": "PreToolUse"}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.code, "native_hook_render_invalid");
}

#[test]
fn cli_hook_emit_reads_an_answer_larger_than_the_render_budget() {
    // The answer travels as escaped JSON text, so a reason past the shared
    // render budget must still reach the resident and render.
    let reason = "\"x\"".repeat(guard_contracts::HOOK_RENDER_MAX_BYTES / 2);
    let response_json = serde_json::to_string(&json!({
        "policy_action": "block", "reason": reason,
    }))
    .expect("answer");
    let mut req = request("cli_hook_emit");
    req.harness = "cursor".to_owned();
    req.cli = Some(json!({"event_name": "PreToolUse", "response_json": response_json}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    assert_eq!(
        result.payload.expect("payload")["response"]["policy_action"],
        "block"
    );

    req.cli = Some(json!({
        "event_name": "PreToolUse",
        "response_json": "x".repeat(guard_contracts::HOOK_RENDER_CLI_EMIT_MAX_BYTES),
    }));
    assert_eq!(
        evaluate_hook_render_request(&req).unwrap_err(),
        "native_hook_render_too_large"
    );
}
