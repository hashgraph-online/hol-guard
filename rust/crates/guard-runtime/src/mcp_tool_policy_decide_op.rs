//! `McpToolPolicyDecide` - resident op owning the non-package MCP tool-call
//! policy composition: current floors, provider/account review, temporary
//! choices, saved reuse, claim disposition and fresh post-claim authority.
//!
//! The op is pure and observation driven (see `guard_contracts`): it names the
//! next effect Python must run, and decides once every result is observed.
//! Python never recomputes a verdict; an `error` result or an unreachable
//! resident must be treated as a fail-closed block by the caller.

use guard_contracts::{
    McpToolPolicyDecideRequestV1, McpToolPolicyDecideResultV1, MCP_TOOL_POLICY_DECIDE_MAX_BYTES,
    MCP_TOOL_POLICY_DECIDE_MAX_OBSERVATIONS, MCP_TOOL_POLICY_DECIDE_REQUEST_SCHEMA,
    MCP_TOOL_POLICY_DECIDE_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::mcp_tool_policy_decision::Decision;
use crate::mcp_tool_policy_flow::{evaluate_pass, Ctx, Flow, Pass, Phase, Stop};
use crate::mcp_tool_policy_revalidate::revalidate;

const ERR_INVALID: &str = "native_mcp_tool_policy_decide_request_invalid";
const ERR_SCHEMA: &str = "native_mcp_tool_policy_decide_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_mcp_tool_policy_decide_request_too_large";

fn request_digest(request: &McpToolPolicyDecideRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut bytes = Vec::with_capacity(2048);
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| ERR_INVALID)?;
    if bytes.len() > MCP_TOOL_POLICY_DECIDE_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn decide(request: &McpToolPolicyDecideRequestV1) -> Flow<Decision> {
    if request.schema != MCP_TOOL_POLICY_DECIDE_REQUEST_SCHEMA {
        return Err(Stop::Fail(ERR_SCHEMA));
    }
    if request.observations.len() > MCP_TOOL_POLICY_DECIDE_MAX_OBSERVATIONS {
        return Err(Stop::Fail(ERR_TOO_LARGE));
    }
    let ctx = Ctx {
        observations: &request.observations,
    };
    match evaluate_pass(
        &ctx,
        &request.subject,
        Phase::Initial,
        request.claim_saved_approval,
    )? {
        Pass::Final(decision) => Ok(*decision),
        Pass::Claimed { row, disposition } => revalidate(&ctx, &request.subject, &row, disposition),
    }
}

fn result(
    request: &McpToolPolicyDecideRequestV1,
    request_sha256: String,
    status: &str,
    code: &str,
    payload: Option<Value>,
) -> Result<Vec<u8>, String> {
    crate::resident_protocol::encode_response(&McpToolPolicyDecideResultV1 {
        schema: MCP_TOOL_POLICY_DECIDE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

pub(crate) fn evaluate_mcp_tool_policy_decide_request(
    request: &McpToolPolicyDecideRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest failures are this op's own typed error result, not a transport
    // error (which the resident would redact to invalid-json).
    let digest = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => return result(request, String::new(), "error", code, None),
    };
    match decide(request) {
        Ok(decision) => result(request, digest, "ok", "ok", Some(decision.to_value())),
        Err(Stop::Need(need)) => result(request, digest, "need", "need", Some(need)),
        Err(Stop::Fail(code)) => result(request, digest, "error", code, None),
    }
}

#[cfg(test)]
#[path = "mcp_tool_policy_decide_op_tests.rs"]
mod tests;
