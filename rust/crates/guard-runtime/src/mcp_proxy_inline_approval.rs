//! The answer a client gave to one inline approval prompt.
//!
//! The relay already classifies this answer for the calls it routes itself
//! (`mcp_relay_decide_inline`). The proxy raises the same prompt over its own
//! transport, so it asks here rather than reading the answer a second time:
//! one classifier decides what an approval reply means, and the block a
//! refused or malformed answer produces is described here too.

use guard_contracts::McpInlineApprovalReplyQueryV1;
use serde_json::{json, Value};

use crate::mcp_relay_decide::inline::{block_message, Reply, INVALID_SOURCE};

/// `_inline_approval_deny_result`'s event decision for a refused answer.
const DENIED_EVENT: &str = "deny-inline";
/// Its event decision for an answer that is not a decision at all.
const INVALID_EVENT: &str = "deny-inline-invalid";

pub(crate) fn reply(query: &McpInlineApprovalReplyQueryV1) -> Value {
    // `_approval_invalid` reads anything that is not a mapping as invalid. The
    // proxy reduces every answer to a mapping before it asks, so this only
    // keeps a malformed one from reading as a prompt that was never raised.
    let classified = if query.payload.is_object() {
        Reply::classify_payload(&query.payload)
    } else {
        Reply::Invalid
    };
    json!({
        "inline_approval": classified.contract(),
        "block": classified.block_source().map(|source| {
            json!({
                "decision_source": source,
                "event_decision": if source == INVALID_SOURCE { INVALID_EVENT } else { DENIED_EVENT },
                "reason": block_message(source, &query.tool_name, &query.server_name),
            })
        }),
    })
}

#[cfg(test)]
#[path = "mcp_proxy_inline_approval_tests.rs"]
mod tests;
