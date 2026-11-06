//! Oh My Pi `github` lookups: their output is a network read's output.

use super::*;

#[test]
fn proved_github_lookup_output_is_released_without_lowering_scans_or_floors() {
    let request_for = |input: Value| {
        let mut request = post_request(json!({
            "hook_event_name": "PostToolUse", "tool_call_id": "call-github-1",
            "tool_name": "github", "tool_input": input,
            "tool_response": {"content": [{"type": "text", "text": "3 pull requests"}]},
            "is_error": false
        }));
        request.harness = "omp".into();
        request
    };
    let request = request_for(json!({
        "op": "search_prs",
        "repo": "example-org/example-repo",
        "query": "is:pr metrics OR analytics"
    }));
    // The authority reads the lookup as a request to GitHub, so its result is
    // a network read's output, not a tool nothing recognizes.
    assert_eq!(
        super::super::eval_output::bounded_output_action(&request),
        Some(PreToolActionTypeV1::Network)
    );
    let effective = policy("allow");
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        guard_hook_core::review_post_tool(&request),
    )
    .unwrap();
    assert_eq!(result.decision, "allow", "{}", result.reason_code);
    assert_eq!(result.model_output_action, "allow_original");
    // The installed network setting still decides, and a scan that denies the
    // output still denies it.
    let mut reviewed = effective.clone();
    reviewed.new_network_domain_action = "review".into();
    let held = apply_post_tool_policy(
        &snapshot(reviewed),
        &request,
        GuardHookPayloadKindV2::Inline,
        guard_hook_core::review_post_tool(&request),
    )
    .unwrap();
    assert_ne!(held.model_output_action, "allow_original");
    let denied = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("source_secret_match", "sensitive output"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    // A mutation, an unlisted argument and a repository that is not a plain
    // owner/name are not the proved lookup.
    for input in [
        json!({"op": "pr_create", "repo": "example-org/example-repo", "query": "x"}),
        json!({"op": "search_prs", "repo": "example-org/example-repo", "path": "src"}),
        json!({"op": "search_prs", "repo": "https://example.com/x", "query": "x"}),
    ] {
        assert!(
            super::super::eval_output::bounded_output_action(&request_for(input.clone())).is_none(),
            "{input}"
        );
    }
}
