//! Claude Code `PostToolUse` replies.
//!
//! Claude Code runs `PostToolUse` after a built-in tool's result has reached
//! the model, and its `decision: "block"` only adds Guard's reason to the
//! conversation. A flagged result is therefore described as already
//! delivered, never as blocked or withheld. See
//! `docs/guard/claude-code-post-tool.md`.

use serde_json::json;

use super::{object, text_or, Object};

/// What Claude Code and its model are told about a flagged, delivered result.
pub(super) const POST_TOOL_DELIVERED_REASON: &str = "HOL Guard flagged this tool output as sensitive after Claude Code had already received it, so Guard could not withhold it. Do not repeat, quote, summarize or store the sensitive parts.";

/// Render a flagged Claude Code `PostToolUse` result.
pub(super) fn post_tool_flagged(response: &Object) -> Object {
    let reason_code = text_or(response, "reason_code", "native_hook_edge_block");
    object(vec![
        ("decision", json!("block")),
        ("reason", json!(POST_TOOL_DELIVERED_REASON)),
        ("continue", json!(true)),
        ("stopReason", json!(POST_TOOL_DELIVERED_REASON)),
        ("policy_action", json!("block")),
        ("risk_summary", json!(POST_TOOL_DELIVERED_REASON)),
        ("model_output_action", json!("not_applicable")),
        ("notice", json!("warning")),
        ("reason_code", json!(reason_code)),
        (
            "hookSpecificOutput",
            json!({
                "hookEventName": "PostToolUse",
                "additionalContext": POST_TOOL_DELIVERED_REASON,
            }),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::POST_TOOL_DELIVERED_REASON;
    use crate::hook_responses::{post_tool, Object};

    fn denied(reason: &str) -> Object {
        json!({
            "decision": "deny",
            "model_output_action": "not_applicable",
            "policy_action": "block",
            "reason": reason,
            "reason_code": "output_secret_match",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn a_flagged_claude_result_is_described_as_already_delivered() {
        let reply = post_tool(
            "claude-code",
            &denied("HOL Guard blocked this output because it contains sensitive content."),
        );
        assert_eq!(reply["decision"], "block");
        assert_eq!(reply["continue"], true);
        assert_eq!(reply["reason"], POST_TOOL_DELIVERED_REASON);
        assert_eq!(reply["model_output_action"], "not_applicable");
        assert_eq!(reply["reason_code"], "output_secret_match");
        assert_eq!(
            reply["hookSpecificOutput"]["additionalContext"],
            POST_TOOL_DELIVERED_REASON
        );
        let text = serde_json::to_string(&reply).unwrap();
        assert!(!text.contains("blocked this output"));
    }

    #[test]
    fn other_harnesses_keep_the_native_block_reply() {
        let reason = "HOL Guard blocked this output because it contains sensitive content.";
        let reply = post_tool("codex", &denied(reason));
        assert_eq!(reply["reason"], reason);
        assert_eq!(reply["model_output_action"], "block");
    }
}
