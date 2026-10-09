//! `McpRuntimeEvidence` — resident op owning MCP tool-call receipt evidence.
//!
//! Pure (no IO): `runtime_action` returns the `runtimeAction` record and
//! `command_text` the displayed command string. Both were Python producers;
//! Python now transports DTOs only. Failures are typed `error` results — the
//! caller must treat them as an unavailable authority, never as empty evidence.

use guard_command::mcp_runtime_evidence::{extract_command_text, runtime_action_record};
use guard_contracts::{
    McpRuntimeEvidenceRequestV1, McpRuntimeEvidenceResultV1, MCP_RUNTIME_EVIDENCE_MAX_BYTES,
    MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA, MCP_RUNTIME_EVIDENCE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;

const ERR_INVALID: &str = "native_mcp_runtime_evidence_invalid";
const ERR_SCHEMA: &str = "native_mcp_runtime_evidence_schema_mismatch";
const ERR_SUBOP: &str = "native_mcp_runtime_evidence_unknown_subop";
const ERR_TOO_LARGE: &str = "native_mcp_runtime_evidence_request_too_large";

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
fn request_digest(request: &McpRuntimeEvidenceRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(&material, &mut canonical, usize::MAX)
        .map_err(|_| ERR_INVALID)?;
    if canonical.len() > MCP_RUNTIME_EVIDENCE_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

fn evaluate(request: &McpRuntimeEvidenceRequestV1) -> Result<Value, &'static str> {
    if request.schema != MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    let arguments = request.arguments.as_deref();
    match request.subop.as_str() {
        "runtime_action" => Ok(json!({
            "runtime_action": runtime_action_record(
                request.tool_description.as_deref(),
                arguments,
                &request.risk_categories,
                request.envelope.as_ref(),
            ),
        })),
        "command_text" => Ok(json!({
            "command_text": extract_command_text(&request.artifact_name, arguments),
        })),
        // One round trip for a receipt: display text from the arguments, the
        // runtimeAction record from description/risk/envelope (receipts never
        // fed call arguments into it).
        "receipt_evidence" => Ok(json!({
            "command_text": extract_command_text(&request.artifact_name, arguments),
            "runtime_action": runtime_action_record(
                request.tool_description.as_deref(),
                None,
                &request.risk_categories,
                request.envelope.as_ref(),
            ),
        })),
        _ => Err(ERR_SUBOP),
    }
}

pub(crate) fn evaluate_mcp_runtime_evidence(
    request: &McpRuntimeEvidenceRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&McpRuntimeEvidenceResultV1 {
                schema: MCP_RUNTIME_EVIDENCE_RESULT_SCHEMA.to_owned(),
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
    crate::encode_response(&McpRuntimeEvidenceResultV1 {
        schema: MCP_RUNTIME_EVIDENCE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

#[cfg(test)]
#[path = "mcp_runtime_evidence_op_tests.rs"]
mod tests;
