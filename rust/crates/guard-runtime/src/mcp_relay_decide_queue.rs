//! The proxy route of a decided call, and its approval-queue route under
//! `blocked_request_mode = "safe-alternative"`.
//!
//! A call that is neither allowed nor blocked takes the `queue` route, and
//! `_queue_approval_center_response` answers it by the blocked-request mode.
//! Under `safe-alternative` (the default) the proxy blocks the call with the
//! safe-alternative guidance, records the `policy-safe-alternative` block
//! receipt and leaves a silent inbox row (`record_unprompted_review`), which
//! the agent's answer never names. The resident answers that block, and the
//! daemon's evidence drain writes the receipt and the inbox row from the
//! queued evidence, as for any other block.
//!
//! Under `ask` the proxy first consults the native prompt and the client's
//! inline elicitation. The resident answers the native prompt from the
//! decision alone, and the route names the inline prompt as a need, which the
//! relay gathers by raising it on the client and deciding the call again with
//! the answer (`mcp_relay_decide_inline.rs`). An approved prompt forwards,
//! and may first save the allow it granted; a denied or invalid one blocks;
//! and a prompt that falls through, or a client that offers none, queues the
//! call's approval request (`mcp_relay_decide_ask.rs`). A binding whose
//! configs do not agree on the mode or the receipt redaction level defers
//! either way.

use super::{inline, Routed, ROUTE_UNSUPPORTED};
use crate::blocked_request_mode::safe_alternative_reason;
use crate::mcp_tool_policy_decision::Decision;
use serde_json::{json, Value};

/// `blocked_request_mode`, under which the queue route blocks in place.
const SAFE_ALTERNATIVE_MODE: &str = "safe-alternative";
/// The decision source `_queue_approval_center_response` records.
pub(super) const SAFE_ALTERNATIVE_SOURCE: &str = "policy-safe-alternative";
/// The one fact the relay gathers itself, by raising the client's prompt.
const INLINE_NEED: &str = "inline_approval";
/// The one forward that also saves the allow it was granted.
const INLINE_APPROVED_SOURCE: &str = "inline-approved";

/// The proxy route for a decided call, when it is a forward, a block, a
/// queue or an observe-forward, or a forward that first claims the pending
/// saved approval. The caller takes out the observe-mode downgrade first,
/// and passes the answer to the inline prompt it already raised.
pub(super) fn route(
    proxy: &Value,
    decision: &Decision,
    inline_answer: Option<inline::Reply>,
) -> Result<Routed, &'static str> {
    if proxy["gate"].get("disable") == Some(&Value::Bool(true)) {
        return Err(ROUTE_UNSUPPORTED);
    }
    let routed = &proxy["route"];
    if !routed["decision_override"].is_null() {
        return Err(ROUTE_UNSUPPORTED);
    }
    if let Some(need) = routed["need"].as_str() {
        // The inline prompt is the one fact the relay gathers; every other
        // need is a fact only the Python proxy holds.
        if need != INLINE_NEED {
            return Err(ROUTE_UNSUPPORTED);
        }
        return Ok(Routed::Elicit);
    }
    if !routed["need"].is_null() {
        return Err(ROUTE_UNSUPPORTED);
    }
    let route = &routed["route"];
    let text = |key: &str| route.get(key).and_then(Value::as_str).map(str::to_owned);
    let pending = decision.pending.is_some();
    match route.get("kind").and_then(Value::as_str) {
        Some("stored_block") if !pending => Ok(Routed::StoredBlock),
        Some("terminal") if !pending => Ok(Routed::Terminal {
            policy_action: text("policy_action").ok_or(ROUTE_UNSUPPORTED)?,
        }),
        Some("queue") if !pending => Ok(Routed::Queue {
            policy_action: text("policy_action").ok_or(ROUTE_UNSUPPORTED)?,
        }),
        // `mode = "observe"`, after its downgrade (`mcp_relay_decide_observe.rs`).
        Some("observe_forward") if !pending => Ok(Routed::ObserveForward),
        // The inline prompt denied the call, or answered it invalidly; the
        // reply the relay classified tells the block's reason apart.
        Some("inline_denied") if !pending => Ok(Routed::InlineDenied {
            source: inline_answer
                .and_then(inline::Reply::block_source)
                .ok_or(ROUTE_UNSUPPORTED)?,
        }),
        Some("allow_and_forward") => {
            let source = text("decision_source").ok_or(ROUTE_UNSUPPORTED)?;
            let policy_action = text("policy_action").ok_or(ROUTE_UNSUPPORTED)?;
            let remember = match route.get("remember") {
                Some(Value::Bool(false)) => false,
                // Only the forward an inline prompt approved saves the allow,
                // and `composio_requires_action_review` turns that off for the
                // tools whose every call is reviewed.
                Some(Value::Bool(true)) if source == INLINE_APPROVED_SOURCE => true,
                _ => return Err(ROUTE_UNSUPPORTED),
            };
            // `approval_decision=decision if route["pass_approval_decision"]`:
            // a pending decision is claimed before the forward.
            match (pending, route.get("pass_approval_decision")) {
                (false, _) => Ok(Routed::Forward {
                    source,
                    policy_action,
                    remember,
                }),
                (true, Some(Value::Bool(true))) => Ok(Routed::Claim {
                    source,
                    policy_action,
                }),
                _ => Err(ROUTE_UNSUPPORTED),
            }
        }
        _ => Err(ROUTE_UNSUPPORTED),
    }
}

/// The queue route as the bound blocked-request mode answers it: a
/// safe-alternative block, or a deferral for any other mode.
pub(super) fn safe_alternative(
    blocked_request_mode: Option<&str>,
    redaction_level: Option<&str>,
    policy_action: String,
) -> Result<Routed, &'static str> {
    match (blocked_request_mode, redaction_level) {
        (Some(SAFE_ALTERNATIVE_MODE), Some(level)) => Ok(Routed::SafeAlternative {
            policy_action,
            redaction_level: level.to_owned(),
        }),
        _ => Err(ROUTE_UNSUPPORTED),
    }
}

/// The message and data of `_queue_approval_center_response`'s
/// safe-alternative block.
pub(super) fn safe_alternative_block(
    tool: &str,
    server: &str,
    signals: &[String],
) -> (String, Value) {
    let reason = format!(
        "HOL Guard blocked tool call {tool} from {server}. {}",
        signals.join(" ")
    );
    (
        safe_alternative_reason(&reason, None, None),
        json!({
            "approvalRequests": [],
            "guardPolicyAction": "block",
            "transportOutcome": "not-forwarded",
        }),
    )
}

#[cfg(test)]
#[path = "mcp_relay_decide_queue_tests.rs"]
mod tests;
