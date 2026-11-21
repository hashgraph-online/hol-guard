//! What one inline approval answer means, and the block a refusal produces.

use guard_contracts::McpInlineApprovalReplyQueryV1;
use serde_json::{json, Value};

fn answer(payload: Value) -> Value {
    super::reply(&McpInlineApprovalReplyQueryV1 {
        payload,
        tool_name: "write_file".to_string(),
        server_name: "files".to_string(),
    })
}

fn accepted(decision: &str) -> Value {
    json!({"action": "accept", "content": {"decision": decision}})
}

#[test]
fn an_approved_prompt_allows_the_call_without_a_block() {
    let answer = answer(accepted("approve"));
    assert_eq!(answer["inline_approval"], "allow");
    assert_eq!(answer["block"], Value::Null);
}

#[test]
fn a_refused_prompt_blocks_the_call_it_was_raised_for() {
    let answer = answer(accepted("deny"));
    assert_eq!(answer["inline_approval"], "denied");
    assert_eq!(answer["block"]["decision_source"], "inline-denied");
    assert_eq!(answer["block"]["event_decision"], "deny-inline");
    assert_eq!(
        answer["block"]["reason"],
        "HOL Guard blocked tool call write_file from files."
    );
}

#[test]
fn an_answer_that_is_not_a_decision_blocks_with_its_own_reason() {
    let invalid = "HOL Guard blocked tool call write_file from files because inline approval \
                   returned an invalid response.";
    for payload in [
        accepted("maybe"),
        json!({"action": "accept"}),
        json!({"action": "accept", "content": "approve"}),
        // The proxy reduces every answer to a mapping first, so a payload that
        // is not one never reads as a prompt that was not raised.
        json!("accept"),
        Value::Null,
    ] {
        let answer = answer(payload);
        assert_eq!(answer["inline_approval"], "denied");
        assert_eq!(answer["block"]["decision_source"], "inline-invalid");
        assert_eq!(answer["block"]["event_decision"], "deny-inline-invalid");
        assert_eq!(answer["block"]["reason"], invalid);
    }
}

#[test]
fn a_prompt_that_was_not_answered_falls_through_to_the_queue() {
    for payload in [
        json!({"action": "cancel"}),
        json!({"action": "cancel", "reason": "timeout"}),
        json!({"action": "decline", "content": {"decision": "approve"}}),
    ] {
        let answer = answer(payload);
        assert_eq!(answer["inline_approval"], "fallthrough");
        assert_eq!(answer["block"], Value::Null);
    }
}
