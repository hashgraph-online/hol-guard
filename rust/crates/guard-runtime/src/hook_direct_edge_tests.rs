use super::{edge, post_edge, pre_edge};
use crate::hook_direct::{post_tool_answer, pre_tool_answer, HookDirectDefer};
use serde_json::{json, Value};

#[test]
fn only_a_verdict_the_daemon_passes_through_is_answered() {
    for (decision, minimum_action) in [
        ("allow", "allow"),
        ("allow", "warn"),
        ("deny", "block"),
        ("deny", "sandbox-required"),
    ] {
        let answered = pre_tool_answer(&edge(decision, minimum_action), false).unwrap();
        assert_eq!(answered["result"]["minimum_action"], minimum_action);
    }
    for (decision, minimum_action) in [
        ("deny", "review"),
        ("deny", "require-reapproval"),
        ("allow", "review"),
        ("allow", "require-reapproval"),
        ("allow", "block"),
        ("deny", "warn"),
        ("deny", "allow"),
    ] {
        assert_eq!(
            pre_tool_answer(&edge(decision, minimum_action), false),
            Err(HookDirectDefer::NotAllow),
            "{decision} {minimum_action}"
        );
    }
    let mut missing_response: Value = serde_json::from_slice(&edge("allow", "allow")).unwrap();
    missing_response
        .as_object_mut()
        .unwrap()
        .remove("harness_response");
    assert_eq!(
        pre_tool_answer(&serde_json::to_vec(&missing_response).unwrap(), false),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(b"not json", false),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn a_block_the_daemon_can_offer_to_repair_defers() {
    // The daemon adds its repair link to this denial.
    let repairable = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_control_authority_block",
    }));
    assert_eq!(
        pre_tool_answer(&repairable, false),
        Err(HookDirectDefer::NotAllow)
    );
    let other = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_destructive",
    }));
    assert!(pre_tool_answer(&other, false).is_ok());
}

#[test]
fn a_claude_code_sandbox_requirement_defers_to_contained_execution() {
    // The daemon rewrites this Claude Code denial into a contained run.
    assert_eq!(
        pre_tool_answer(&edge("deny", "sandbox-required"), true),
        Err(HookDirectDefer::NotAllow)
    );
    assert!(pre_tool_answer(&edge("deny", "block"), true).is_ok());
    assert!(pre_tool_answer(&edge("deny", "sandbox-required"), false).is_ok());
}

#[test]
fn every_reviewed_post_tool_use_is_answered() {
    let blocked = json!({ "decision": "block", "minimum_action": "block" });
    let answered = post_tool_answer(&post_edge(blocked.clone())).unwrap();
    assert_eq!(answered["result"], blocked);
    assert_eq!(
        post_tool_answer(&post_edge(json!("allow"))),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        post_tool_answer(&edge("allow", "allow")),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(
            &post_edge(json!({ "decision": "allow", "minimum_action": "allow" })),
            false
        ),
        Err(HookDirectDefer::EdgeFailed)
    );
}
