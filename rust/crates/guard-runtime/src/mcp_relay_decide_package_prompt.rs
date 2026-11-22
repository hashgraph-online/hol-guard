//! The client's inline prompt for a package call under `ask`.
//!
//! The proxy sends a package call through `_route_tool_call` before
//! `_handle_package_request`, and that route raises the client's inline
//! elicitation for a tool decision it would otherwise queue or observe. An
//! answer of Allow saves the tool's artifact allow (`allow_tool_call` with
//! `remember`), then hands the call to the package lane with the source
//! `inline-approved`, which records the package's own remembered allow on the
//! forward. The resident does the same: it saves the tool allow, then decides
//! the call once more with the approval marked, so the second pass reads the
//! saved row and records the forward as the proxy does.

use super::{
    ask, settle, Admitted, Answer, McpRelayDecideRequestV1, Resolved, IDENTITY_FAILED,
    ROUTE_UNSUPPORTED,
};
use crate::local_mcp_grant_identity::composio_requires_action_review;
use crate::mcp_relay_receipt::remember::{save_now, Allow};
use crate::mcp_tool_policy_decision::Decision;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{McpInlineApprovalV1, McpToolPolicyProxyInputV1};
use serde_json::{json, Value};

/// The decision source of a forward the inline prompt approved.
pub(super) const INLINE_SOURCE: &str = "inline-approved";
/// The sentinel `decide_once` returns to be run again with the marked request.
pub(super) const AGAIN: &str = "mcp_relay_prompt_again";
/// The tool allow the approval saves could not be written.
const REMEMBER_FAILED: &str = "mcp_relay_remember_failed";
/// The fact the route names when the client's inline elicitation answers.
const INLINE_APPROVAL: &str = "inline_approval";

/// An inline approval already acted on, which the second pass records.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Remembered {
    /// Whether the forward saves the package's own allow: every approval but a
    /// provider action whose calls are each reviewed.
    pub(crate) remember: bool,
    /// The tool decision's signals the receipt keeps.
    pub(crate) signals: Vec<String>,
    /// The tool decision's risk categories the receipt keeps.
    pub(crate) risk_categories: Vec<String>,
}

/// An Allow answer to the package call's prompt.
///
/// Under the approval gate the remembered write is refused, and the proxy
/// queues the call with the tool policy's action instead, as it does for a
/// plain call. Otherwise the tool allow is saved now and `again` holds the
/// request the call is decided once more with.
pub(super) fn approved(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    policy_store: &PolicySnapshotStore,
    again: &mut Option<McpRelayDecideRequestV1>,
) -> Result<Answer, &'static str> {
    let remember = !composio_requires_action_review(&request.build.tool_name);
    if remember {
        let artifact = &resolved.identity.artifact;
        if ask::remembered_write_refused(&request.guard_home, artifact)? {
            // `queue()` with the route's `tool_policy_action`; the prompt is
            // only raised under `ask`, so the row is written before the block.
            let payload = route_payload(request, resolved, Some(McpInlineApprovalV1::Allow));
            let policy_action = payload["route"]["tool_policy_action"]
                .as_str()
                .ok_or(ROUTE_UNSUPPORTED)?
                .to_owned();
            let routed = ask::queue(request, admitted, resolved, policy_action)?;
            return settle(request, resolved, routed, None, policy_store);
        }
        let allow = Allow {
            harness: &artifact.harness,
            artifact_id: &artifact.artifact_id,
            artifact_hash: resolved
                .identity
                .artifact_hash
                .as_deref()
                .ok_or(IDENTITY_FAILED)?,
            command: artifact.command.as_deref(),
            workspace: None,
        };
        if !save_now(&request.guard_home, &allow) {
            return Err(REMEMBER_FAILED);
        }
    }
    let mut marked = request.clone();
    marked.inline.remembered = Some(Remembered {
        remember,
        signals: resolved.decision.signals.clone(),
        risk_categories: resolved.decision.risk_categories.clone(),
    });
    *again = Some(marked);
    Err(AGAIN)
}

/// Whether the proxy raises the client's inline elicitation for a package call
/// under `ask` before its package lane runs.
///
/// The proxy sends a package call through `_route_tool_call` before
/// `_handle_package_request`, and that route raises the client's inline
/// elicitation for a tool decision it would otherwise queue or observe.
///
/// The native prompt raises nothing. `_allow_after_native_prompt` reads the
/// decision's source, and the `package` route it leads to hands
/// `_handle_package_request` a tool decision that handler never reads: it
/// resolves the tool authority afresh and composes the package lane from that,
/// which is the lane this resident runs. A call no prompt answers falls
/// through to the queue or the observed forward, which the lane takes too.
///
/// The route is asked as for a plain call: a package call reaches the same
/// prompts on the same decision, and only a saved package block, which skips
/// them, comes first.
pub(super) fn prompts(request: &McpRelayDecideRequestV1, resolved: &Resolved) -> bool {
    route_payload(request, resolved, None)["route"]["need"] == INLINE_APPROVAL
}

/// The tool route of this call as a plain call, given the prompt's answer.
fn route_payload(
    request: &McpRelayDecideRequestV1,
    resolved: &Resolved,
    inline_approval: Option<McpInlineApprovalV1>,
) -> Value {
    let call = Call {
        catalog_state: &request.catalog_state,
        mode: &resolved.mode,
        tool_name: &request.build.tool_name,
        harness: &request.build.harness,
        inline_available: request.inline.available,
    };
    call.route(&resolved.decision, inline_approval)
}

/// What the tool route reads of the call besides its decision.
pub(super) struct Call<'a> {
    pub(super) catalog_state: &'a str,
    pub(super) mode: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) harness: &'a str,
    pub(super) inline_available: bool,
}

impl Call<'_> {
    /// The route `_route_tool_call` takes under `ask`, as for a plain call.
    pub(super) fn route(
        &self,
        decision: &Decision,
        inline_approval: Option<McpInlineApprovalV1>,
    ) -> Value {
        let input = McpToolPolicyProxyInputV1 {
            catalog_state: self.catalog_state.to_owned(),
            mode: self.mode.to_owned(),
            package_present: false,
            asks_for_approval: true,
            inline_available: self.inline_available && self.harness != ask::OPENCODE,
            tool_name: self.tool_name.to_owned(),
            inline_approval,
        };
        crate::mcp_tool_policy_proxy::proxy_payload(&input, decision, |tool| {
            Some(ask::native_prompt_allows(self.harness, tool))
        })
    }

    /// Whether the route raises the client's inline elicitation.
    pub(super) fn prompts(&self, decision: &Decision) -> bool {
        self.route(decision, None)["route"]["need"] == INLINE_APPROVAL
    }
}

/// Mark the forward a remembered approval led to, as `_record_package_forward`
/// records it: the source `inline-approved`, the tool decision's signals and
/// risk categories, and the `remember` flag the drain saves the package allow
/// from.
pub(super) fn mark_forward(remembered: &Remembered, record: &mut Value) {
    record["decision_source"] = json!(INLINE_SOURCE);
    if !remembered.signals.is_empty() {
        record["package"]["signals"] = json!(remembered.signals);
    }
    record["package"][crate::mcp_relay_receipt::package::RISK_KEY] =
        json!(remembered.risk_categories);
    if remembered.remember {
        record["remember"] = json!(true);
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_prompt_tests.rs"]
mod tests;
