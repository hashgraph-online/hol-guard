//! `McpToolCallIdentity` - resident op that builds the MCP tool-call artifact
//! and its approval digest or context token in one pure call.
//!
//! Python ships the session and call facts as data; this op owns server and
//! tool identity, the tool-definition authority binding, firewall evidence and
//! the approval hash. Any failure is a typed `error` result the caller must
//! treat as an unavailable authority.

use guard_contracts::{
    BrowserMcpArtifactV1, McpToolApprovalHashRequestV1, McpToolCallArtifactV1,
    McpToolCallHashInputV1, McpToolCallIdentityPayloadV1, McpToolCallIdentityRequestV1,
    McpToolCallIdentityResultV1, MCP_TOOL_CALL_IDENTITY_MAX_BYTES,
    MCP_TOOL_CALL_IDENTITY_REQUEST_SCHEMA, MCP_TOOL_CALL_IDENTITY_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

use crate::mcp_tool_call_identity_build::build_artifact;

const ERR_INVALID: &str = "native_mcp_tool_call_identity_request_invalid";
const ERR_SCHEMA: &str = "native_mcp_tool_call_identity_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_mcp_tool_call_identity_request_too_large";
const ERR_HASH: &str = "native_mcp_tool_call_identity_hash_unavailable";
const ERR_RESPONSE_TOO_LARGE: &str = "native_mcp_tool_call_identity_response_too_large";

fn request_digest(request: &McpToolCallIdentityRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut bytes = Vec::with_capacity(2048);
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| ERR_INVALID)?;
    if bytes.len() > MCP_TOOL_CALL_IDENTITY_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn hash_request(
    artifact: &McpToolCallArtifactV1,
    input: &McpToolCallHashInputV1,
) -> McpToolApprovalHashRequestV1 {
    McpToolApprovalHashRequestV1 {
        artifact: BrowserMcpArtifactV1 {
            name: artifact.name.clone(),
            command: artifact.command.clone(),
            metadata: artifact.metadata.clone(),
        },
        artifact_id: artifact.artifact_id.clone(),
        config_path: artifact.config_path.clone(),
        harness: artifact.harness.clone(),
        publisher: artifact.publisher.clone(),
        source_scope: Value::String(artifact.source_scope.clone()),
        transport: artifact.transport.clone(),
        arguments: input.arguments.clone(),
        config: input.config.clone(),
        workspace: input.workspace.clone(),
        extension_control_digest: input.extension_control_digest.clone(),
    }
}

fn compose(request: &McpToolCallIdentityRequestV1) -> Result<Value, &'static str> {
    if request.schema != MCP_TOOL_CALL_IDENTITY_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    let (artifact, private) = match (&request.build, &request.artifact) {
        (Some(build), None) => build_artifact(build)?,
        (None, Some(artifact)) => (artifact.clone(), Map::new()),
        _ => return Err(ERR_INVALID),
    };
    let (artifact_hash, risk_categories) = match &request.hash {
        Some(input) => {
            let hashed =
                crate::context_digest::build_mcp_tool_approval(&hash_request(&artifact, input))
                    .map_err(|_| ERR_HASH)?;
            (Some(hashed.token_or_digest), hashed.risk_categories)
        }
        None => (None, Vec::new()),
    };
    serde_json::to_value(McpToolCallIdentityPayloadV1 {
        artifact,
        runtime_private_metadata: private,
        artifact_hash,
        risk_categories,
    })
    .map_err(|_| ERR_INVALID)
}

fn result(
    request: &McpToolCallIdentityRequestV1,
    request_sha256: String,
    status: &str,
    code: &str,
    payload: Option<Value>,
) -> Result<Vec<u8>, String> {
    crate::resident_protocol::encode_response(&McpToolCallIdentityResultV1 {
        schema: MCP_TOOL_CALL_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

pub(crate) fn evaluate_mcp_tool_call_identity_request(
    request: &McpToolCallIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let digest = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => return result(request, String::new(), "error", code, None),
    };
    match compose(request) {
        // An artifact whose schema-bearing metadata does not fit one resident
        // response is a typed refusal, not a transport encoding failure.
        Ok(payload) => result(request, digest.clone(), "ok", "ok", Some(payload)).or_else(|code| {
            if code == "native_response_too_large" {
                result(request, digest, "error", ERR_RESPONSE_TOO_LARGE, None)
            } else {
                Err(code)
            }
        }),
        Err(code) => result(request, digest, "error", code, None),
    }
}

#[cfg(test)]
#[path = "mcp_tool_call_identity_op_tests.rs"]
mod tests;
