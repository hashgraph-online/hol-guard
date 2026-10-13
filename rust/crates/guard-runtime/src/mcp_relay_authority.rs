//! The `tools/call` decision seam of the native MCP relay.
//!
//! The relay owns transport only. Each `tools/call` is handed to a
//! `RelayAuthority`, which either answers it (block, approval required,
//! repair) or forwards it bound to the catalog authority it was decided
//! against. The authority that ships with the transport is
//! `PendingNativeAuthority`: until the fused native decision op lands it
//! answers every call with the proxy's fail-closed "no native decision"
//! response, so the relay can never forward a call nobody decided.

use serde_json::{json, Map, Value};

use crate::mcp_relay_catalog::{CatalogSnapshot, RelayCatalog};

const BLOCKED_CODE: i64 = -32001;
const NO_DECISION: &str = "HOL Guard could not obtain a native decision for this tool call.";
const SYNC_FAILED: &str =
    "HOL Guard could not synchronize the MCP server notification stream before this tool call.";

/// A `tools/call` the authority allowed, bound to the catalog it saw.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ForwardTicket {
    /// The exact request to write to the child.
    pub(crate) message: Value,
    /// The catalog authority the decision was made against.
    pub(crate) expected: CatalogSnapshot,
}

/// The authority's answer for one `tools/call`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ToolCallVerdict {
    /// Reply to the host without contacting the child.
    Respond(Value),
    /// Forward to the child once the catalog still matches. Only the native
    /// decision op (and the relay tests) construct it.
    #[cfg_attr(not(test), allow(dead_code))]
    Forward(ForwardTicket),
}

/// Decides `tools/call` requests; the relay never decides one itself.
pub(crate) trait RelayAuthority {
    /// Decide one `tools/call` whose `params` is an object.
    fn decide(
        &mut self,
        message: &Value,
        params: &Map<String, Value>,
        catalog: &RelayCatalog,
    ) -> ToolCallVerdict;

    /// The catalog changed between the decision and the write.
    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value;

    /// Record a forwarded call's outcome and return the host response.
    fn complete(&mut self, ticket: ForwardTicket, response: Value) -> Value;
}

/// Fail-closed authority used until the native decision op is wired in.
#[derive(Debug, Default)]
pub(crate) struct PendingNativeAuthority;

impl RelayAuthority for PendingNativeAuthority {
    fn decide(
        &mut self,
        message: &Value,
        params: &Map<String, Value>,
        _catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        ToolCallVerdict::Respond(no_decision_response(message.get("id"), params))
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        let params = ticket
            .message
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        no_decision_response(ticket.message.get("id"), &params)
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        response
    }
}

/// The tool name a blocked response names (`params.name`, else `unknown`).
pub(crate) fn tool_name(params: &Map<String, Value>) -> String {
    params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

/// `_blocked_tool_response`.
pub(crate) fn blocked_response(
    id: Option<&Value>,
    tool_name: &str,
    reason: Option<&str>,
    data: Option<Value>,
) -> Value {
    let message = reason.map_or_else(
        || format!("Guard blocked tool call for {tool_name}."),
        str::to_owned,
    );
    let mut error = json!({"code": BLOCKED_CODE, "message": message});
    if let Some(data) = data.filter(truthy) {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id.cloned().unwrap_or(Value::Null), "error": error})
}

/// The response for a call without a native decision.
pub(crate) fn no_decision_response(id: Option<&Value>, params: &Map<String, Value>) -> Value {
    blocked_response(
        id,
        &tool_name(params),
        Some(NO_DECISION),
        Some(json!({"approvalRequests": [], "guardPolicyAction": "block"})),
    )
}

/// The response when the child stream could not be synchronized first.
pub(crate) fn sync_failed_response(id: Option<&Value>, params: &Map<String, Value>) -> Value {
    blocked_response(
        id,
        &tool_name(params),
        Some(SYNC_FAILED),
        Some(json!({"approvalRequests": [], "guardPolicyAction": "require-reapproval"})),
    )
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Object(map) => !map.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
    }
}
