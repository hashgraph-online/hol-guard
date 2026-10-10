//! `McpProxyDecide` resident op.
//!
//! Rust owns every authoritative decision of the MCP proxy: the `tools/list`
//! catalog state machine, tool-call routing, boundary revalidation and package
//! composition. Python frames the stream, supplies facts and renders the
//! response. A malformed request is a bound error result; nothing falls back
//! to Python.

use guard_contracts::{
    McpProxyDecisionRequestV1, McpProxyDecisionResultV1, McpProxyQueryV1,
    MCP_PROXY_DECISION_MAX_BYTES, MCP_PROXY_DECISION_REQUEST_SCHEMA,
    MCP_PROXY_DECISION_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;
use crate::{mcp_proxy_catalog as catalog, mcp_proxy_package as package};
use crate::{mcp_proxy_postclaim as postclaim, mcp_proxy_route as route};

const INVALID: &str = "native_mcp_proxy_decision_invalid";
const SCHEMA_MISMATCH: &str = "native_mcp_proxy_decision_schema_mismatch";

fn request_digest(request: &McpProxyDecisionRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, MCP_PROXY_DECISION_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn decide(query: &McpProxyQueryV1) -> Value {
    match query {
        McpProxyQueryV1::CatalogEvent(query) => catalog::catalog_event(query),
        McpProxyQueryV1::SavedAllowGate(query) => catalog::saved_allow_gate(query),
        McpProxyQueryV1::BoundaryFailure(query) => postclaim::boundary_failure(query),
        McpProxyQueryV1::ToolPostclaim(query) => postclaim::tool_postclaim(query),
        McpProxyQueryV1::PackagePostclaim(query) => postclaim::package_postclaim(query),
        McpProxyQueryV1::PackagePrecheck(query) => package::package_precheck(query),
        McpProxyQueryV1::PackageCompose(query) => package::package_compose(query),
        McpProxyQueryV1::RouteToolCall(query) => route::route_tool_call(query),
        McpProxyQueryV1::ObserveToolForward(query) => route::observe_tool_forward(query),
        McpProxyQueryV1::EvidenceItem(query) => postclaim::evidence_item(query),
    }
}

pub(crate) fn evaluate_mcp_proxy_decision(
    request: &McpProxyDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, payload) = if request.schema != MCP_PROXY_DECISION_REQUEST_SCHEMA {
        ("error", SCHEMA_MISMATCH, Value::Null)
    } else if request.request_id.len() > 128 {
        ("error", INVALID, Value::Null)
    } else {
        ("ok", "ok", decide(&request.query))
    };
    crate::encode_response(&McpProxyDecisionResultV1 {
        schema: MCP_PROXY_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}
