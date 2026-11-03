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
fn cli_hook_emit_refuses_a_document_larger_than_a_response() {
    // A character the answer carries as two bytes is written `\u00e9` in the
    // printed document and escaped a second time when that document travels
    // as a JSON string, so it leaves as seven - against the six the same
    // character costs in the canonical request the budget is measured on.
    // An answer well inside the answer budget can therefore render a document
    // no caller could ever read.
    let reason = "\u{e9}".repeat(600_000);
    let response_json = serde_json::to_string(&json!({
        "policy_action": "block", "reason": reason,
    }))
    .expect("answer");
    let mut req = request("cli_hook_emit");
    req.harness = "cursor".to_owned();
    req.cli = Some(json!({
        "event_name": "PreToolUse",
        "response_json": response_json.clone(),
        "document": true,
    }));
    // The request budget is read off the canonical serialization, not the
    // answer's own bytes, so measure the premise the way the op does: this
    // request is one the op accepts, and only its document is too large.
    crate::package_authority_op::request_digest_with_limit(
        &req,
        guard_contracts::hook_render_max_bytes("cli_hook_emit"),
    )
    .expect("the request stays inside its own budget");
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_hook_render_document_too_large");

    // The same answer still names its verdict for a caller that prints its
    // own document: only the document the resident writes is bounded here.
    req.cli = Some(json!({
        "event_name": "PreToolUse",
        "response_json": response_json,
    }));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok");
    assert_eq!(
        result.payload.expect("payload")["response"]["policy_action"],
        "block"
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

#[path = "hook_render_op_redaction_tests.rs"]
mod redaction;

/// The `cli_hook_emit` answer for a caller that prints the resident's
/// document.
fn printed(harness: &str, event_name: &str, response_json: &str, home_dir: Option<&str>) -> Value {
    let mut req = request("cli_hook_emit");
    req.harness = harness.to_owned();
    let mut params = json!({
        "event_name": event_name, "response_json": response_json, "document": true,
    });
    if let Some(home_dir) = home_dir {
        params["home_dir"] = json!(home_dir);
    }
    req.cli = Some(params);
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.status, "ok", "{response_json}");
    let payload = result.payload.expect("payload");
    assert_eq!(payload["outcome"], "document");
    payload["response"].clone()
}

#[test]
fn cli_hook_emit_shortens_only_the_home_the_caller_names() {
    let response_json = r#"{"m":"/opt/me/x","n":"/opt/me","o":"/opt/mex/y"}"#;
    let answer = printed("codex", "Stop", response_json, Some("/opt/me//"));
    assert_eq!(
        answer["stdout"],
        "{\n  \"m\": \"~/x\",\n  \"n\": \"~\",\n  \"o\": \"/opt/mex/y\"\n}"
    );
    let answer = printed("codex", "Stop", response_json, None);
    assert_eq!(
        answer["stdout"],
        "{\n  \"m\": \"/opt/me/x\",\n  \"n\": \"/opt/me\",\n  \"o\": \"/opt/mex/y\"\n}"
    );
}

#[test]
fn cli_hook_emit_names_the_exit_status_the_harness_expects() {
    for (harness, event_name, action, exit_code) in [
        // Claude reads a hook's JSON only on exit 0, a block included.
        ("claude-code", "Stop", "block", 0),
        ("claude-code", "PreToolUse", "block", 0),
        ("codex", "PreToolUse", "block", 0),
        ("codex", "UserPromptSubmit", "block", 0),
        ("codex", "Stop", "block", 1),
        ("pi", "PostToolUse", "sandbox-required", 1),
        ("cursor", "PreToolUse", "require-reapproval", 2),
        ("cursor", "PreToolUse", "allow", 0),
        ("opencode", "PreToolUse", "block", 1),
        ("superagent", "PreToolUse", "warn", 0),
        ("unlisted", "PreToolUse", "block", 1),
    ] {
        let response_json = format!(r#"{{"policy_action":"{action}"}}"#);
        let answer = printed(harness, event_name, &response_json, None);
        assert_eq!(answer["exit_code"], exit_code, "{harness} {event_name}");
        assert_eq!(answer["policy_action"], action);
        let stdout = format!("{{\n  \"policy_action\": \"{action}\"\n}}");
        assert_eq!(answer["stdout"], stdout);
    }
}

#[test]
fn cli_hook_emit_without_document_answers_as_before() {
    // A caller that prints its own document reads the policy action alone.
    let mut req = request("cli_hook_emit");
    req.harness = "codex".to_owned();
    req.cli = Some(json!({"event_name": "Stop", "response_json": r#"{"policy_action":"block"}"#}));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(
        result.payload.expect("payload")["response"],
        json!({"policy_action": "block"})
    );
    // A bridge-rendered harness keeps its bridge's output with or without it.
    let answer = printed(
        "devin",
        "PreToolUse",
        r#"{"policy_action":"block","reason":"denied"}"#,
        None,
    );
    assert_eq!(answer["exit_code"], 2);
    assert_eq!(answer["stderr"], "denied");
    // A colliding surrogate-plane character cannot be printed faithfully.
    req.cli = Some(json!({
        "event_name": "Stop", "response_json": "{\"m\":\"\u{f0000}\\udcff\"}", "document": true,
    }));
    let result = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(result.code, "native_hook_render_unrenderable");
}

#[test]
fn a_large_cursor_edge_still_fits_its_route_budget() {
    // The route sends the edge result the daemon already produced, and a
    // native response may be far larger than an ordinary render request. A
    // valid large edge that did not fit would drop the probe back to an
    // ordinary review and lose its containment route, so the kind carries a
    // budget of its own.
    let mut req = request("cursor_shell_route");
    req.harness = "cursor".to_owned();
    req.cli = Some(json!({
        "payload": {"tool_name": "Bash"},
        "edge": {
            "harness": "cursor",
            "event_name": "PreToolUse",
            "containment_route": "none",
            "result": {"reason": "x".repeat(guard_contracts::HOOK_RENDER_MAX_BYTES)},
        },
    }));
    crate::package_authority_op::request_digest_with_limit(
        &req,
        guard_contracts::HOOK_RENDER_MAX_BYTES,
    )
    .expect_err("the ordinary budget is too small for this edge");
    crate::package_authority_op::request_digest_with_limit(
        &req,
        guard_contracts::hook_render_max_bytes("cursor_shell_route"),
    )
    .expect("the route's own budget holds it");
}

#[test]
fn a_large_daemon_reply_still_fits_the_bridge_budget() {
    // The bridge kinds carry the whole daemon reply they render, and a native
    // response may be far larger than an ordinary render request. Refusing a
    // valid large reply would turn an allow the daemon already reached into a
    // fail-closed refusal of a permitted call, so the kinds carry a budget of
    // their own.
    for kind in ["hermes_bridge", "muse_bridge"] {
        let mut req = request(kind);
        req.harness = kind.trim_end_matches("_bridge").to_owned();
        req.cli = Some(json!({
            "event_name": "PreToolUse",
            "response": {
                "policy_action": "allow",
                "reason": "x".repeat(guard_contracts::HOOK_RENDER_MAX_BYTES),
            },
        }));
        crate::package_authority_op::request_digest_with_limit(
            &req,
            guard_contracts::HOOK_RENDER_MAX_BYTES,
        )
        .expect_err("the ordinary budget is too small for this reply");
        crate::package_authority_op::request_digest_with_limit(
            &req,
            guard_contracts::hook_render_max_bytes(kind),
        )
        .expect("the bridge's own budget holds it");
    }
}
