//! What a `PostToolUse` verdict can still do to output the harness already
//! delivered.
//!
//! Claude Code runs `PostToolUse` after a built-in tool's result has reached
//! the model. Its `decision: "block"` adds Guard's reason to the conversation;
//! it does not take the result back. A verdict that names `block` as the
//! model-output action would record a withholding that never happened, so the
//! edge keeps the denial and its reason code and records that no model-output
//! action applies. See `docs/guard/claude-code-post-tool.md`.

use guard_contracts::HookReviewResponseV1;

/// Harnesses whose `PostToolUse` cannot withhold a delivered built-in result.
const DELIVERED_BEFORE_REVIEW: [&str; 1] = ["claude-code"];

/// Record what the harness can enforce on output it already delivered.
///
/// Runs after `seal_output_mask`, so Guard still masks the output in its own
/// records and evidence.
pub(crate) fn settle(harness: &str, response: &mut HookReviewResponseV1) {
    if DELIVERED_BEFORE_REVIEW.contains(&harness) && response.model_output_action == "block" {
        response.model_output_action = "not_applicable".to_owned();
    }
}

#[cfg(test)]
mod tests {
    use guard_contracts::GuardHookEdgeResultV2;
    use serde_json::json;

    fn post_tool(harness: &str) -> GuardHookEdgeResultV2 {
        // Synthetic token shape only; the scanner flags its prefix.
        let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
        let mut envelope = crate::edge::tests::envelope(
            "PostToolUse",
            json!({
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "printenv EXAMPLE"},
                "tool_response": {"stdout": token, "stderr": "", "interrupted": false},
            }),
        );
        envelope.harness = harness.to_owned();
        let bytes = crate::edge::tests::evaluate_isolated(envelope).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn a_claude_post_tool_denial_records_no_withheld_output() {
        let edge = post_tool("claude-code");
        assert_eq!(edge.result["decision"], "deny");
        assert_eq!(edge.result["model_output_action"], "not_applicable");
        assert_eq!(edge.result["output_masked"], true);
        assert_eq!(edge.receipt.decision, "deny");
        assert_eq!(edge.receipt.model_output_action, "not_applicable");
    }

    #[test]
    fn a_harness_that_can_withhold_output_keeps_the_block() {
        let edge = post_tool("codex");
        assert_eq!(edge.result["decision"], "deny");
        assert_eq!(edge.receipt.model_output_action, "block");
    }
}
