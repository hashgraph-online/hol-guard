//! The proxy's need loop: which decision the native prompt is answered about.

use guard_command::effect_decision::GuardAction;
use serde_json::Map;

use super::*;
use crate::mcp_tool_policy_decision::Current;

fn decision(source: &str) -> Decision {
    Decision::plain(Current {
        action: GuardAction::Review,
        source: source.to_owned(),
        signals: vec!["Opens an external site.".to_owned()],
        summary: "browser navigation".to_owned(),
        risk_categories: vec!["browser_navigation".to_owned()],
    })
}

fn input(catalog_state: &str, mode: &str) -> McpToolPolicyProxyInputV1 {
    McpToolPolicyProxyInputV1 {
        catalog_state: catalog_state.to_owned(),
        mode: mode.to_owned(),
        package_present: false,
        asks_for_approval: true,
        inline_available: false,
        tool_name: "navigate".to_owned(),
        inline_approval: None,
    }
}

/// `_allow_after_native_prompt` for OpenCode: the saved policy's own decision
/// stays blocked after the prompt, every other source allows.
fn opencode(tool: &McpToolFactsV1) -> Option<bool> {
    Some(tool.source != "policy")
}

fn route(payload: &Value) -> &Value {
    &payload["route"]["route"]
}

#[test]
fn the_catalog_gates_replacement_answers_the_native_prompt() {
    let mut pending = decision("policy");
    pending.pending = Some(Map::new());

    let payload = proxy_payload(&input("pending", "enforce"), &pending, opencode);

    // The gate replaced the policy source before the route ran, so the prompt
    // reads the replacement and the call forwards instead of queueing.
    assert_eq!(payload["gate"]["disable"], json!(true));
    assert_eq!(route(&payload)["kind"], json!("allow_and_forward"));
    assert_eq!(route(&payload)["decision_source"], json!("native-approved"));
}

#[test]
fn the_observe_mode_override_answers_the_native_prompt() {
    let mut pending = decision("policy");
    pending.pending = Some(Map::new());
    pending.current_action = Some(GuardAction::Review);

    let payload = proxy_payload(&input("complete", "observe"), &pending, opencode);

    assert_eq!(payload["gate"]["disable"], json!(false));
    // The override carries the enforced action the runtime derives for it, so
    // the caller never recomputes one from the decision it is handed.
    assert_eq!(
        payload["route"]["decision_override"],
        json!({
            "action": "review",
            "source": "observe-current-policy",
            "policy_action": "review",
        })
    );
    assert_eq!(route(&payload)["decision_source"], json!("native-approved"));
}

#[test]
fn a_policy_decision_the_prompt_refuses_still_queues() {
    let payload = proxy_payload(&input("complete", "enforce"), &decision("policy"), opencode);

    assert_eq!(route(&payload)["kind"], json!("queue"));
}

#[test]
fn a_harness_that_cannot_answer_leaves_the_need_standing() {
    let payload = proxy_payload(&input("complete", "enforce"), &decision("policy"), |_| None);

    assert_eq!(payload["route"]["need"], json!("native_prompt"));
}
