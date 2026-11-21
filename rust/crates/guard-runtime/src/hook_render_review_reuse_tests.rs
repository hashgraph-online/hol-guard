use super::{decode, evaluate_hook_render_request, json, request};

#[test]
fn a_settled_retry_has_the_harness_response_and_reuse_status() {
    for (outcome, decision, reuse_status) in [
        ("allowed", "allow", "accepted"),
        ("blocked", "deny", "blocked"),
    ] {
        let mut req = request("review_reuse");
        req.cli = Some(json!({
            "outcome": outcome,
            "verdict": {
                "minimum_action": "review",
                "policy_action": "review",
                "reason": "Review this action.",
                "padding": "x".repeat(512 * 1024),
            },
        }));
        let result =
            decode(evaluate_hook_render_request(&req).expect("reply is within the render budget"));
        assert_eq!(result.status, "ok");
        let payload = result.payload.expect("reply payload");
        let response = &payload["response"];
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"],
            decision
        );
        assert_eq!(response["approval_reuse_status"], reuse_status);
        if outcome == "blocked" {
            assert_eq!(response["prompted"], false);
            assert_eq!(response["reason_code"], "native_review_user_block");
        }
    }
}

#[test]
fn an_unsettled_retry_has_no_reply() {
    let mut req = request("review_reuse");
    req.cli = Some(json!({"outcome": "review", "verdict": {"minimum_action": "review"}}));

    let result = decode(evaluate_hook_render_request(&req).expect("reply"));

    assert_eq!(result.code, "native_hook_render_invalid");
    assert!(result.payload.is_none());
}
