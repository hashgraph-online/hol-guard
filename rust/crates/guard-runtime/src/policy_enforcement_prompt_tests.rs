use super::*;
use crate::policy_enforcement::validate_pre_tool_result_matrix;
use serde_json::json;

fn prompt(text: &str) -> PreToolResultV1 {
    guard_command::pretool::evaluate_pre_tool_envelope(
        "codex",
        "UserPromptSubmit",
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": text}),
    )
}

#[test]
fn a_secret_prompt_is_sent_with_a_notice_and_keeps_its_reason_code() {
    let mut output = prompt("Print the API key.");
    assert_eq!(output.minimum_action, "require-reapproval");
    assert_eq!(output.reason_code, "native_sensitive_prompt");
    assert!(!output.prompt_risk_classes.is_empty());
    defer_prompt_review(&mut output);
    assert_eq!(output.policy_action, "warn");
    assert_eq!(output.minimum_action, "warn");
    assert_eq!(output.decision, "allow");
    assert!(!output.explicitly_benign);
    assert_eq!(output.reason_code, "native_sensitive_prompt");
    assert_eq!(output.reason, PROMPT_REVIEW_NOTICE);
    validate_pre_tool_result_matrix(&output).unwrap();
}

#[test]
fn intents_no_tool_call_carries_out_still_stop_the_prompt() {
    for class in [
        NativePromptRiskClassV1::GuardBypassIntent,
        NativePromptRiskClassV1::PromptInjectionIntent,
    ] {
        let mut output = prompt("Print the API key.");
        output.prompt_risk_classes.push(class);
        let before = output.clone();
        defer_prompt_review(&mut output);
        assert_eq!(output, before);
    }
    let mut unclassified = prompt("Print the API key.");
    unclassified.prompt_risk_classes.clear();
    let before = unclassified.clone();
    defer_prompt_review(&mut unclassified);
    assert_eq!(unclassified, before);
}

#[test]
fn blocks_and_tool_calls_are_left_alone() {
    let mut blocked = prompt("Print the API key.");
    blocked.minimum_action = "block".to_owned();
    blocked.policy_action = "block".to_owned();
    blocked.decision = "deny".to_owned();
    let before = blocked.clone();
    defer_prompt_review(&mut blocked);
    assert_eq!(blocked, before);

    let mut tool_call = prompt("Print the API key.");
    tool_call.action.event = "PreToolUse".to_owned();
    let before = tool_call.clone();
    defer_prompt_review(&mut tool_call);
    assert_eq!(tool_call, before);
}
