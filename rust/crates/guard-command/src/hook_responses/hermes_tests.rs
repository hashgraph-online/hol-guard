use super::*;
use serde_json::json;

fn object(value: Value) -> Object {
    value.as_object().cloned().expect("object")
}

#[test]
fn a_reply_with_no_readable_verdict_is_a_block() {
    let (action, reason) = policy_from_response(&object(json!({})));
    assert_eq!(action, "block");
    assert_eq!(reason, BLOCK_REASON);
}

#[test]
fn an_ask_permission_decision_stops_the_call() {
    let response = object(json!({
        "hookSpecificOutput": {"permissionDecision": "ask", "permissionDecisionReason": "confirm"},
    }));
    let (document, exit_code) = bridge_response(&response);
    assert_eq!(document["decision"], json!("block"));
    assert_eq!(document["reason"], json!("confirm"));
    assert_eq!(exit_code, 2);
}

#[test]
fn an_allowed_reply_exits_zero() {
    let response = object(json!({"decision": "allow", "reason": "cleared"}));
    let (document, exit_code) = bridge_response(&response);
    assert_eq!(
        document,
        object(json!({"decision": "allow", "reason": "cleared"}))
    );
    assert_eq!(exit_code, 0);
}

#[test]
fn a_policy_action_is_read_when_no_decision_is_stated() {
    let response = object(json!({"policy_action": "require-reapproval", "message": "re-approve"}));
    let (action, reason) = policy_from_response(&response);
    assert_eq!(action, "require-reapproval");
    assert_eq!(reason, "re-approve");
    assert!(should_exit_block(&action));
}

#[test]
fn a_warn_is_not_a_stop() {
    assert!(!should_exit_block("warn"));
    assert_eq!(native_decision("warn", "noted")["decision"], json!("allow"));
}

#[test]
fn an_unrecognized_policy_action_blocks_on_both_channels() {
    for action in ["deny", "pause", "Allow", "BLOCK"] {
        let response = object(json!({"policy_action": action}));
        let (document, exit_code) = bridge_response(&response);
        assert_eq!(document["decision"], json!("block"), "{action}");
        assert_eq!(exit_code, 2, "{action}");
    }
}
