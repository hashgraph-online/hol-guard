//! Single-request composition of the full MCP tool-call approval hash.
//!
//! `build_tool_call_hash` historically made five separate native round trips
//! (browser intent, canonical exact-argument SHA, MCP approval/content digest,
//! tool risk categories, context token). This module renders every persisted
//! component from raw artifact/argument/config material in one request; the
//! runtime dispatch arm then either returns the legacy digest row or feeds
//! `write_tool_policy_context` + `build_context_token_fields` into the shared
//! token builder, leaving Python a thin send-and-validate adapter.
//!
//! Persisted keys are byte-identical to the historical pipeline:
//! * `content_arguments` for browser artifacts is the intent projection map.
//! * Non-browser artifacts persist the raw argument value unchanged.
//! * `exact_arguments_hash` is `sha256(canonical_json(exact))` where `exact`
//!   drops volatile browser fields for mapping arguments only; JSON-string or
//!   non-mapping arguments persist verbatim, matching the legacy dict
//!   comprehension that only ran on `Mapping` inputs.
//! * `sensitive_arguments_hash` duplicates the exact hash only when
//!   `sensitive_surface_flags` is non-empty — the historical second filtering
//!   pass folded to the same filtered map.
//! * `capabilities` carry risk categories plus metadata fields; the
//!   authority/provider-hash keys appear only when present in metadata.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::browser_mcp_intent;
use crate::mcp_tool_risk;
use guard_contracts::{
    write_python_default_json, BrowserAutomationIntentV1, McpToolApprovalDigestRequestV1,
    McpToolApprovalHashRequestV1, McpToolContentDigestRequestV1,
};

/// Result shared by both paths: persisted hash plus risk categories and the
/// browser-intent flag callers persist alongside the approval row.
pub struct ToolApprovalHash {
    pub token_or_digest: String,
    pub risk_categories: Vec<String>,
    pub browser_intent_was_applied: bool,
}

/// Token-path component material — the runtime arm feeds `identity`,
/// `capabilities`, `sandbox`, `content` into `build_context_token_fields`
/// with `write_tool_policy_context` producing the policy bytes.
pub struct ToolApprovalTokenMaterial {
    pub identity: Value,
    pub capabilities: Value,
    pub sandbox: Value,
    /// The token's `content` component — the persisted content digest.
    pub content_digest: String,
    pub risk_categories: Vec<String>,
    pub browser_intent_was_applied: bool,
}

fn canonical_sha256_of(value: &Value) -> Result<String, &'static str> {
    let mut bytes = Vec::with_capacity(256);
    guard_contracts::write_canonical_json(value, &mut bytes)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn persisted_json_digest(material: &Value) -> Result<String, &'static str> {
    let mut bytes = Vec::with_capacity(512);
    write_python_default_json(material, &mut bytes)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// Persisted `content_arguments` for a browser artifact — the intent
/// projection map the historical Python block emitted.
fn browser_content_arguments(
    exact_arguments_hash: &str,
    intent: &BrowserAutomationIntentV1,
) -> Value {
    let sensitive = !intent.sensitive_surface_flags.is_empty();
    let mut map = Map::with_capacity(11 + sensitive as usize);
    map.insert("intent".to_owned(), json!(intent.intent));
    map.insert("operation".to_owned(), json!(intent.operation));
    map.insert("target_origin".to_owned(), json!(intent.target_origin));
    map.insert(
        "target_path_prefix".to_owned(),
        json!(intent.target_path_prefix),
    );
    map.insert("method".to_owned(), json!(intent.method));
    map.insert("profile_mode".to_owned(), json!(intent.profile_mode));
    map.insert(
        "mcp_server_identity_hash".to_owned(),
        json!(intent.mcp_server_identity_hash),
    );
    map.insert(
        "mcp_tool_identity_hash".to_owned(),
        json!(intent.mcp_tool_identity_hash),
    );
    map.insert("mcp_schema_hash".to_owned(), json!(intent.mcp_schema_hash));
    map.insert(
        "sensitive_surface_flags".to_owned(),
        json!(intent.sensitive_surface_flags),
    );
    map.insert(
        "exact_arguments_hash".to_owned(),
        Value::String(exact_arguments_hash.to_owned()),
    );
    if sensitive {
        map.insert(
            "sensitive_arguments_hash".to_owned(),
            Value::String(exact_arguments_hash.to_owned()),
        );
    }
    Value::Object(map)
}

/// `sha256(canonical_json(exact_arguments))`; volatile browser fields drop
/// only for mapping inputs — JSON strings and scalars persist verbatim.
fn exact_arguments_digest(arguments: &Value, volatile: &[String]) -> Result<String, &'static str> {
    match arguments {
        Value::Object(map) => {
            let mut filtered = Map::with_capacity(map.len());
            for (key, value) in map {
                if !volatile.iter().any(|drop| drop == key) {
                    filtered.insert(key.clone(), value.clone());
                }
            }
            canonical_sha256_of(&Value::Object(filtered))
        }
        _ => canonical_sha256_of(arguments),
    }
}

fn capabilities_material(
    request: &McpToolApprovalHashRequestV1,
    risk_categories: &[String],
) -> Value {
    let metadata = &request.artifact.metadata;
    let tool_catalog_fingerprint = metadata
        .get("server_fingerprint")
        .and_then(Value::as_object)
        .and_then(|fp| fp.get("tool_catalog_fingerprint"));

    let mut map = Map::with_capacity(7);
    map.insert("risk_categories".to_owned(), json!(risk_categories));
    map.insert(
        "server_identity".to_owned(),
        metadata
            .get("mcp_server_identity")
            .cloned()
            .unwrap_or(Value::Null),
    );
    map.insert(
        "tool_catalog_fingerprint".to_owned(),
        tool_catalog_fingerprint.cloned().unwrap_or(Value::Null),
    );
    map.insert(
        "tool_identity".to_owned(),
        metadata
            .get("mcp_tool_identity")
            .cloned()
            .unwrap_or(Value::Null),
    );
    map.insert(
        "transport".to_owned(),
        request
            .transport
            .as_ref()
            .map(|t| Value::String(t.clone()))
            .unwrap_or(Value::Null),
    );
    if let Some(value) = metadata.get("mcp_tool_authority_hash") {
        if !value.is_null() {
            map.insert("tool_authority_hash".to_owned(), value.clone());
        }
    }
    if let Some(value) = metadata.get("mcp_provider_catalog_hash") {
        if !value.is_null() {
            map.insert("provider_catalog_hash".to_owned(), value.clone());
        }
    }
    Value::Object(map)
}

fn identity_material(request: &McpToolApprovalHashRequestV1) -> Value {
    let resolved_executable = request
        .artifact
        .metadata
        .get("server_fingerprint")
        .and_then(Value::as_object)
        .and_then(|fp| fp.get("resolved_executable"));

    let mut map = Map::with_capacity(7);
    map.insert(
        "artifact_id".to_owned(),
        Value::String(request.artifact_id.clone()),
    );
    map.insert(
        "config_path".to_owned(),
        Value::String(request.config_path.clone()),
    );
    map.insert("harness".to_owned(), Value::String(request.harness.clone()));
    map.insert(
        "publisher".to_owned(),
        request
            .publisher
            .as_ref()
            .map(|p| Value::String(p.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert("source_scope".to_owned(), request.source_scope.clone());
    map.insert(
        "workspace".to_owned(),
        request
            .workspace
            .as_ref()
            .map(|w| Value::String(w.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "resolved_executable".to_owned(),
        resolved_executable.cloned().unwrap_or(Value::Null),
    );
    Value::Object(map)
}

/// Resolve content_arguments + content digest + risk categories once —
/// shared by the digest and token arms of the dispatch.
fn shared_material(
    request: &McpToolApprovalHashRequestV1,
) -> Result<(Value, String, Vec<String>, bool), &'static str> {
    let intent =
        browser_mcp_intent::normalize_approval_intent(&request.artifact, &request.arguments)?;
    let content_arguments = match &intent {
        Some(intent) => {
            let exact_hash =
                exact_arguments_digest(&request.arguments, &intent.volatile_fields_dropped)?;
            browser_content_arguments(&exact_hash, intent)
        }
        None => request.arguments.clone(),
    };
    let content_digest = persisted_json_digest(&json!({
        "arguments": content_arguments,
        "artifact_id": request.artifact_id,
        "config_path": request.config_path,
    }))?;
    let risk_categories = mcp_tool_risk::evaluate_tool_risk(&request.artifact, &request.arguments)?;
    Ok((
        content_arguments,
        content_digest,
        risk_categories,
        intent.is_some(),
    ))
}

/// `config` absent — render the historical `mcp_tool_approval_digest` row.
pub fn build_tool_approval_digest(
    request: &McpToolApprovalHashRequestV1,
) -> Result<ToolApprovalHash, &'static str> {
    let (content_arguments, _, risk_categories, applied) = shared_material(request)?;
    let digest_request = McpToolApprovalDigestRequestV1 {
        content: McpToolContentDigestRequestV1 {
            artifact_id: request.artifact_id.clone(),
            config_path: request.config_path.clone(),
            arguments: content_arguments,
        },
        transport: request.transport.clone(),
        server_fingerprint: request.artifact.metadata.get("server_fingerprint").cloned(),
        server_identity: request
            .artifact
            .metadata
            .get("mcp_server_identity")
            .cloned(),
        tool_identity: request.artifact.metadata.get("mcp_tool_identity").cloned(),
        authority_hash: request
            .artifact
            .metadata
            .get("mcp_tool_authority_hash")
            .cloned(),
        provider_hash: request
            .artifact
            .metadata
            .get("mcp_provider_catalog_hash")
            .cloned(),
        workspace: request.workspace.clone(),
    };
    Ok(ToolApprovalHash {
        token_or_digest: crate::mcp_decision::mcp_tool_approval_digest(&digest_request)?,
        risk_categories,
        browser_intent_was_applied: applied,
    })
}

/// `config` present — render the token components; the runtime arm composes
/// the token itself via `write_tool_policy_context` + `build_context_token_fields`.
pub fn tool_approval_token_material(
    request: &McpToolApprovalHashRequestV1,
    config: &Map<String, Value>,
) -> Result<ToolApprovalTokenMaterial, &'static str> {
    let (_, content_digest, risk_categories, applied) = shared_material(request)?;
    Ok(ToolApprovalTokenMaterial {
        identity: identity_material(request),
        capabilities: capabilities_material(request, &risk_categories),
        sandbox: json!({ "analysis": config.get("sandbox_analysis") }),
        content_digest,
        risk_categories,
        browser_intent_was_applied: applied,
    })
}
