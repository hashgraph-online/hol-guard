//! The client's inline approval prompt, which the queue route consults under
//! `blocked_request_mode = "ask"` before it queues the call.
//!
//! `ElicitationMcpGuardProxy` raises an `elicitation/create` request on the
//! client that declared the `elicitation` capability in its `initialize`, and
//! classifies the answer: an `accept` carrying `decision = "approve"` allows
//! the call, one carrying `deny` blocks it, anything else is an invalid
//! answer that blocks it with its own reason, and a client that offers no
//! prompt falls through to the approval queue.
//!
//! The relay owns the transport, so the resident answers the first decide
//! with the prompt's params and the relay raises it; the answer comes back on
//! the next decide of the same call, which routes it. The counter in the
//! request id belongs to the transport, which holds it per session, and the
//! message is built from the decision the proxy would have prompted with:
//! `_apply_decision_override` replaces only a decision's action and source,
//! so the summary is the one the policy produced either way.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use guard_contracts::McpInlineApprovalV1;

/// The answer the relay classified one inline prompt into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reply {
    /// `_approval_allows`.
    Allow,
    /// `_approval_denies`.
    Denied,
    /// `_approval_invalid`, which blocks with its own reason.
    Invalid,
    /// No prompt was raised, so the route queues the call.
    Fallthrough,
}

impl Reply {
    /// `_inline_approval_kind`, which reports a denial and an invalid answer
    /// alike; the relay keeps them apart for the block's reason.
    pub(crate) fn contract(self) -> McpInlineApprovalV1 {
        match self {
            Reply::Allow => McpInlineApprovalV1::Allow,
            Reply::Denied | Reply::Invalid => McpInlineApprovalV1::Denied,
            Reply::Fallthrough => McpInlineApprovalV1::Fallthrough,
        }
    }

    /// `_inline_approval_deny_result`'s decision source for a block.
    pub(crate) fn block_source(self) -> Option<&'static str> {
        match self {
            Reply::Denied => Some(DENIED_SOURCE),
            Reply::Invalid => Some(INVALID_SOURCE),
            _ => None,
        }
    }

    /// Classify one `elicitation/create` response as the proxy does.
    pub(crate) fn classify(response: &Value) -> Reply {
        Reply::classify_payload(&approval_payload(response))
    }

    /// Classify an answer the caller already reduced to its payload, which the
    /// proxy does for a prompt it timed out or saw no answer to at all.
    pub(crate) fn classify_payload(payload: &Value) -> Reply {
        if payload.get("action").and_then(Value::as_str) != Some(ACCEPT) {
            // A cancel, a decline, an error or a timeout: `_approval_denies`
            // and `_approval_invalid` both read `accept` first, so the prompt
            // falls through to the approval queue instead of blocking.
            return Reply::Fallthrough;
        }
        let Some(content) = payload.get("content").and_then(Value::as_object) else {
            return Reply::Invalid;
        };
        match content.get(DECISION).and_then(Value::as_str) {
            Some(APPROVE) => Reply::Allow,
            Some(DENY) => Reply::Denied,
            _ => Reply::Invalid,
        }
    }
}

/// `_approval_denies` reads `action == "accept"`.
const ACCEPT: &str = "accept";
const DECISION: &str = "decision";
const APPROVE: &str = "approve";
const DENY: &str = "deny";
/// `_inline_approval_deny_result`'s sources.
pub(crate) const DENIED_SOURCE: &str = "inline-denied";
pub(crate) const INVALID_SOURCE: &str = "inline-invalid";

/// `_approval_payload`: the result of an answered prompt, and a cancel for an
/// error, a missing result or a result that is not an object.
fn approval_payload(response: &Value) -> Value {
    match response.get("result") {
        Some(Value::Object(result)) => Value::Object(result.clone()),
        _ => json!({"action": "cancel"}),
    }
}

/// `_inline_approval_request`'s params, which the relay sends under the id it
/// counts itself.
pub(crate) fn prompt(server_name: &str, tool_name: &str, summary: &str) -> Value {
    json!({
        "mode": "form",
        "message": format!(
            "HOL Guard intercepted {server_name}.{tool_name}. {summary} Approve this exact call?"
        ),
        "requestedSchema": {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["approve", "deny"],
                    "enumNames": ["Approve", "Deny"],
                    "description": "Approve or reject this exact tool call.",
                }
            },
            "required": ["decision"],
        },
    })
}

/// `_inline_approval_deny_result`'s reason for a blocked call.
pub(crate) fn block_message(source: &str, tool: &str, server: &str) -> String {
    if source == INVALID_SOURCE {
        format!(
            "HOL Guard blocked tool call {tool} from {server} because inline approval returned \
             an invalid response."
        )
    } else {
        format!("HOL Guard blocked tool call {tool} from {server}.")
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_inline_tests.rs"]
mod tests;
