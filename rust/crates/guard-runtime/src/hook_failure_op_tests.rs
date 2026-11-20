use serde_json::{json, Value};

use super::dispatch;

const REASON: &str = "Guard could not finish.";

fn answer(harness: &str, event_name: &str) -> (Value, i64) {
    let result = dispatch(&json!({
        "harness": harness,
        "event_name": event_name,
        "reason": REASON,
    }))
    .expect("a well-formed request");
    let document = result["document"].as_str().expect("document");
    assert!(!document.ends_with('\n'));
    (
        serde_json::from_str(document).expect("a JSON document"),
        result["exit_code"].as_i64().expect("exit code"),
    )
}

#[test]
fn grok_observe_events_answer_with_an_empty_document() {
    for event in [
        "SessionStart",
        "post_tool_use",
        "Permission-Denied",
        " SubagentStop ",
    ] {
        let result = dispatch(&json!({"harness": "grok", "event_name": event, "reason": REASON}))
            .expect("a well-formed request");
        assert_eq!(result["document"], "{}");
        assert_eq!(result["exit_code"], 0);
    }
}

#[test]
fn grok_denies_in_the_decision_envelope() {
    let (payload, code) = answer("grok", "PreToolUse");
    assert_eq!(payload, json!({"decision": "deny", "reason": REASON}));
    assert_eq!(code, 0);
}

#[test]
fn hermes_blocks_with_exit_two() {
    let (payload, code) = answer("hermes", "PreToolUse");
    assert_eq!(payload, json!({"decision": "block", "reason": REASON}));
    assert_eq!(code, 2);
}

#[test]
fn copilot_denies_a_tool_and_a_permission_request() {
    let (tool, code) = answer("copilot", "PreToolUse");
    assert_eq!(
        tool,
        json!({"permissionDecision": "deny", "permissionDecisionReason": REASON})
    );
    assert_eq!(code, 0);
    let (permission, code) = answer("copilot", "PermissionRequest");
    assert_eq!(
        permission,
        json!({"behavior": "deny", "message": REASON, "interrupt": false})
    );
    assert_eq!(code, 0);
}

#[test]
fn a_prompt_gets_the_prompt_envelope_and_exit_zero() {
    let (payload, code) = answer("kimi", "UserPromptSubmit");
    assert_eq!(payload["decision"], "block");
    assert_eq!(payload["reason_code"], "native_prompt_unavailable");
    assert_eq!(code, 0);
}

#[test]
fn an_observation_event_never_authorizes_anything() {
    let (payload, code) = answer("kimi", "PostToolUse");
    assert_eq!(payload["continue"], true);
    assert_eq!(
        payload["hookSpecificOutput"]["hookEventName"],
        "PostToolUse"
    );
    assert_eq!(code, 0);
    let (copilot, _) = answer("copilot", "PostToolUse");
    assert_eq!(copilot, json!({"permissionDecision": "allow"}));
}

#[test]
fn muse_denies_in_the_envelope_and_others_exit_two() {
    let (muse, code) = answer("muse", "PreToolUse");
    assert_eq!(muse["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(code, 0);
    let (_, code) = answer("zcode", "PreToolUse");
    assert_eq!(code, 2);
}

#[test]
fn a_permission_request_v2_denies_and_other_harnesses_use_the_generic_envelope() {
    let (payload, code) = answer("copilot", "PermissionRequestV2");
    assert_eq!(payload["behavior"], "deny");
    assert_eq!(payload["interrupt"], false);
    assert!(payload.get("permissionDecision").is_none());
    assert_eq!(code, 0);
    let (cursor, code) = answer("cursor", "PreToolUse");
    assert_eq!(cursor["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(code, 2);
}

#[test]
fn the_document_is_ascii_only() {
    let result = dispatch(&json!({
        "harness": "kimi",
        "event_name": "PreToolUse",
        "reason": "caf\u{e9} \u{1f512}",
    }))
    .expect("a well-formed request");
    let document = result["document"].as_str().expect("document");
    assert!(document.is_ascii());
    assert!(document.contains("\\u00e9"));
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(dispatch(&json!({"harness": "kimi", "event_name": "Stop"})).is_err());
    assert!(dispatch(&json!({"harness": 1, "event_name": "Stop", "reason": "x"})).is_err());
    assert!(dispatch(&json!(["kimi"])).is_err());
}

#[test]
fn no_bounded_harness_can_turn_an_outage_into_an_allow() {
    for harness in [
        "copilot", "grok", "hermes", "openclaw", "kimi", "zcode", "devin", "pi", "omp",
    ] {
        let (payload, _) = answer(harness, "PreToolUse");
        let decisions = [
            payload.get("decision"),
            payload.get("permissionDecision"),
            payload
                .get("hookSpecificOutput")
                .and_then(|nested| nested.get("permissionDecision")),
        ];
        assert!(!decisions.contains(&Some(&json!("allow"))), "{harness}");
        assert!(
            decisions
                .iter()
                .any(|value| matches!(value, Some(Value::String(text)) if text == "deny" || text == "block")),
            "{harness}"
        );
    }
}

#[test]
fn a_stderr_harness_refuses_only_where_something_would_run() {
    let ask = |event: &str| {
        dispatch(&json!({"harness": "muse", "event_name": event, "reason": REASON, "stderr": true}))
            .expect("a well-formed request")
    };
    for event in ["PreToolUse", "PermissionRequest", "user_prompt-submit"] {
        assert_eq!(
            ask(event),
            json!({"document": "", "stderr": REASON, "exit_code": 2}),
            "{event}"
        );
    }
    for event in ["PostToolUse", "SessionStart", "Stop"] {
        assert_eq!(
            ask(event),
            json!({"document": "", "stderr": "", "exit_code": 0}),
            "{event}"
        );
    }
    assert!(dispatch(
        &json!({"harness": "muse", "event_name": "Stop", "reason": REASON, "stderr": "yes"})
    )
    .is_err());
    assert!(dispatch(
        &json!({"harness": "muse", "event_name": "Stop", "reason": REASON, "other": true})
    )
    .is_err());
}
