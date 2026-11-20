//! What a `PostToolUse` verdict can still do to output the harness already
//! delivered.
//!
//! Claude Code runs `PostToolUse` after a built-in tool's result has reached
//! the model. Its `decision: "block"` adds Guard's reason to the conversation;
//! it neither takes the result back nor swaps in a reviewed excerpt. A verdict
//! that names `block` or `replace_with_reviewed_excerpt` as the model-output
//! action would record a withholding or replacement that never happened, so
//! the edge keeps the decision and its reason code and records that no
//! model-output action applies. See `docs/guard/claude-code-post-tool.md`.
//!
//! Codex replaces a blocked tool result with Guard's reason, so it can
//! withhold output but cannot show a reviewed excerpt in its place. An
//! excerpt verdict is recorded as the withholding Codex performs. See
//! `docs/guard/codex-hook-boundaries.md`.

use guard_contracts::HookReviewResponseV1;

/// Harnesses whose `PostToolUse` cannot withhold or replace a delivered
/// built-in result.
const DELIVERED_BEFORE_REVIEW: [&str; 1] = ["claude-code"];

/// Model-output actions that only a harness able to change the result can
/// carry out.
const WITHHOLDING_ACTIONS: [&str; 2] = ["block", "replace_with_reviewed_excerpt"];

/// Harnesses whose `PostToolUse` block reply replaces the tool result with
/// Guard's reason and nothing else.
const REASON_REPLACES_RESULT: [&str; 1] = ["codex"];

/// What the model reads in place of output too large to scan in full, where
/// the harness shows only Guard's reason.
pub(crate) const OVERSIZED_OUTPUT_WITHHELD: &str =
    "HOL Guard withheld this output because it was too large to scan in full within local limits.";

/// Record what the harness can enforce on output it already delivered.
///
/// Runs after `seal_output_mask`, so Guard still masks the output in its own
/// records and evidence. A Codex excerpt turned into a withholding is sealed
/// again, since `block` always masks.
pub(crate) fn settle(harness: &str, response: &mut HookReviewResponseV1) {
    if DELIVERED_BEFORE_REVIEW.contains(&harness)
        && WITHHOLDING_ACTIONS.contains(&response.model_output_action.as_str())
    {
        response.model_output_action = "not_applicable".to_owned();
    } else if REASON_REPLACES_RESULT.contains(&harness)
        && response.model_output_action == "replace_with_reviewed_excerpt"
    {
        // The reply carries the reason only, so the excerpt never reaches the
        // model; the original is withheld instead.
        response.model_output_action = "block".to_owned();
        response.reason = Some(OVERSIZED_OUTPUT_WITHHELD.to_owned());
        response.reviewed_excerpt = None;
        // A withheld result is masked output; the mask sealed for the
        // excerpt verdict no longer describes it.
        response.seal_output_mask();
    }
}

#[cfg(test)]
mod tests {
    use guard_contracts::GuardHookEdgeResultV2;
    use serde_json::json;

    fn post_tool(harness: &str) -> GuardHookEdgeResultV2 {
        // Synthetic token shape only; the scanner flags its prefix.
        let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
        post_tool_with(harness, token)
    }

    fn post_tool_with(harness: &str, stdout: String) -> GuardHookEdgeResultV2 {
        let mut envelope = crate::edge::tests::envelope(
            "PostToolUse",
            json!({
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "printenv EXAMPLE"},
                "tool_response": {"stdout": stdout, "stderr": "", "interrupted": false},
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

    #[test]
    fn an_oversized_claude_result_records_no_replaced_output() {
        // Clean output past the scan limit gets a reviewed excerpt where the
        // harness can show one; Claude Code already has the original.
        let edge = post_tool_with("claude-code", oversized());
        assert_eq!(edge.result["reason_code"], "output_too_large");
        assert_eq!(edge.result["model_output_action"], "not_applicable");
        assert_eq!(edge.receipt.model_output_action, "not_applicable");
    }

    #[test]
    fn an_oversized_codex_result_records_the_withholding_codex_performs() {
        // Codex shows the model Guard's reason in place of a blocked result,
        // so no excerpt reaches it and the reason must not promise one.
        let edge = post_tool_with("codex", oversized());
        assert_eq!(edge.result["reason_code"], "output_too_large");
        assert_eq!(edge.result["model_output_action"], "block");
        assert_eq!(edge.result["output_masked"], true);
        assert_eq!(edge.result["reason"], super::OVERSIZED_OUTPUT_WITHHELD);
        assert!(edge
            .result
            .get("reviewed_excerpt")
            .is_none_or(|v| v.is_null()));
        assert_eq!(edge.receipt.model_output_action, "block");
    }

    /// Clean output past the scan limit, `guard_rules::MAX_OUTPUT_CHARS`,
    /// which this crate does not depend on.
    fn oversized() -> String {
        "x".repeat(5 * 1024 * 1024 + 1)
    }
}
