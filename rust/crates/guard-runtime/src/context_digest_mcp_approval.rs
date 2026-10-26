//! MCP tool approval: the approval digest row or the approval-context token
//! for one tool call, shared by the context digest and the resident
//! `McpToolCallIdentity` op.

use serde_json::Value;

use super::build_context_token_fields;

/// The approval digest row (no config) or the approval-context token (config
/// present) for one MCP tool call, with its Cloud risk categories.
pub(crate) fn build_mcp_tool_approval(
    request: &guard_contracts::McpToolApprovalHashRequestV1,
) -> Result<guard_command::mcp_tool_approval::ToolApprovalHash, &'static str> {
    let Some(config) = &request.config else {
        return guard_command::mcp_tool_approval::build_tool_approval_digest(request);
    };
    let material = guard_command::mcp_tool_approval::tool_approval_token_material(request, config)?;
    let extension_control_digest = request
        .extension_control_digest
        .as_deref()
        .ok_or("native_context_component_invalid")?;
    let token = build_context_token_fields(
        &material.identity,
        &Value::String(material.content_digest.clone()),
        &material.capabilities,
        &material.sandbox,
        extension_control_digest,
        |out| {
            guard_command::mcp_tool_policy::write_tool_policy_context(
                &guard_contracts::McpToolApprovalContextRequestV1 {
                    config: config.clone(),
                    harness: request.harness.clone(),
                    artifact_id: request.artifact_id.clone(),
                    publisher: request.publisher.clone(),
                    identity: material.identity.clone(),
                    content: Value::String(material.content_digest.clone()),
                    capabilities: material.capabilities.clone(),
                    sandbox: material.sandbox.clone(),
                    extension_control_digest: extension_control_digest.to_owned(),
                },
                out,
            )
        },
    )?;
    Ok(guard_command::mcp_tool_approval::ToolApprovalHash {
        token_or_digest: token,
        risk_categories: material.risk_categories,
        browser_intent_was_applied: material.browser_intent_was_applied,
    })
}
