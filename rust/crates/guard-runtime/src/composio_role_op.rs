//! `ComposioRole` — resident op for the Composio routing contract.
//!
//! Pure: reads one MCP tool name through `mcp_tool_policy_composio`. No IO.
//!
//! The role is routing, not authority. Callers use it to decide where a call
//! goes and how much review it draws; a caller that cannot reach the resident
//! has no role and must fall back to the stricter path, never to a role it
//! worked out for itself.

use crate::mcp_tool_policy_composio::{requires_action_review, tool_role, Role};
use crate::package_authority_op::request_digest_with_limit;
use guard_contracts::{
    ComposioRoleRequestV1, ComposioRoleResultV1, COMPOSIO_ROLE_MAX_BYTES,
    COMPOSIO_ROLE_REQUEST_SCHEMA, COMPOSIO_ROLE_RESULT_SCHEMA,
};

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Discovery => "discovery",
        Role::Batch => "batch",
        Role::Workbench => "workbench",
        Role::Connections => "connections",
        Role::Unknown => "unknown",
    }
}

pub(crate) fn evaluate_composio_role_request(
    request: &ComposioRoleRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any hashing or routing work;
    // an oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, COMPOSIO_ROLE_MAX_BYTES)
        .map_err(|_| "native_composio_role_too_large".to_owned())?;
    let (status, code, role, review) = if request.schema == COMPOSIO_ROLE_REQUEST_SCHEMA {
        (
            "ok".to_owned(),
            "ok".to_owned(),
            tool_role(&request.tool_name).map(|role| role_name(role).to_owned()),
            requires_action_review(&request.tool_name),
        )
    } else {
        (
            "error".to_owned(),
            "native_composio_role_schema_mismatch".to_owned(),
            None,
            // An unreadable request names no tool, so it earns the review a
            // tool the contract cannot place would draw.
            true,
        )
    };
    crate::encode_response(&ComposioRoleResultV1 {
        schema: COMPOSIO_ROLE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        role,
        requires_action_review: review,
    })
}

#[cfg(test)]
#[path = "composio_role_op_tests.rs"]
mod tests;
