//! `McpToolEvidence` — resident op owning MCP tool-call risk presentation and
//! the portal firewall projection.
//!
//! Pure (no IO). `risk` extracts categories, signals and summary text;
//! `firewall` projects `mcp_server`/`tool_call` artifacts into the portal
//! evidence and legacy identity metadata. Python transports DTOs only.
//! Failures are typed `error` results: the caller must treat them as an
//! unavailable authority, never as "no risk" or "no firewall".

use guard_command::mcp_skill_firewall::evaluate_firewall_evidence;
use guard_command::mcp_tool_signals::evaluate_risk_evidence;
use guard_contracts::{
    McpToolEvidenceRequestV1, McpToolEvidenceResultV1, MCP_TOOL_EVIDENCE_MAX_BYTES,
    MCP_TOOL_EVIDENCE_REQUEST_SCHEMA, MCP_TOOL_EVIDENCE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;

const ERR_INVALID: &str = "native_mcp_tool_evidence_invalid";
const ERR_SCHEMA: &str = "native_mcp_tool_evidence_schema_mismatch";
const ERR_SUBOP: &str = "native_mcp_tool_evidence_unknown_subop";
const ERR_TOO_LARGE: &str = "native_mcp_tool_evidence_request_too_large";

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
fn request_digest(request: &McpToolEvidenceRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(1024);
    write_canonical_json_with_limit(&material, &mut canonical, usize::MAX)
        .map_err(|_| ERR_INVALID)?;
    if canonical.len() > MCP_TOOL_EVIDENCE_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

fn evaluate(request: &McpToolEvidenceRequestV1) -> Result<Value, &'static str> {
    if request.schema != MCP_TOOL_EVIDENCE_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    // Exactly the input the subop reads: a request carrying the other
    // subop's input (or neither) is malformed, not silently ignored.
    match (request.subop.as_str(), &request.risk, &request.firewall) {
        ("risk", Some(input), None) => evaluate_risk_evidence(input),
        ("firewall", None, Some(input)) => evaluate_firewall_evidence(input),
        ("risk" | "firewall", _, _) => Err(ERR_INVALID),
        _ => Err(ERR_SUBOP),
    }
}

pub(crate) fn evaluate_mcp_tool_evidence(
    request: &McpToolEvidenceRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&McpToolEvidenceResultV1 {
                schema: MCP_TOOL_EVIDENCE_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256: String::new(),
                status: "error".to_owned(),
                code: code.to_owned(),
                payload: None,
            });
        }
    };
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::encode_response(&McpToolEvidenceResultV1 {
        schema: MCP_TOOL_EVIDENCE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

#[cfg(test)]
#[path = "mcp_tool_evidence_op_tests.rs"]
mod tests;
