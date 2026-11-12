//! `PackageWorkspaceScope` - resident op that derives the workspace identity a
//! saved package approval is stored and matched under.
//!
//! Pure: the caller ships the artifact fields and the package execution context
//! evidence it already holds; the resident returns the portable scope and the
//! runtime scope. Deriving the key anywhere but here lets the two derivations
//! drift, and a drifted key silently stops a saved "Always allow" from
//! matching, so the user is asked again for a package they already approved.

use guard_contracts::{
    PackageWorkspaceScopeRequestV1, PackageWorkspaceScopeResultV1,
    PACKAGE_WORKSPACE_SCOPE_MAX_BYTES, PACKAGE_WORKSPACE_SCOPE_REQUEST_SCHEMA,
    PACKAGE_WORKSPACE_SCOPE_RESULT_SCHEMA,
};
use serde_json::json;

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_package_workspace_scope_request(
    request: &PackageWorkspaceScopeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, PACKAGE_WORKSPACE_SCOPE_MAX_BYTES)
        .map_err(|_| "native_package_workspace_scope_too_large".to_owned())?;
    if request.schema != PACKAGE_WORKSPACE_SCOPE_REQUEST_SCHEMA {
        return Err("native_package_workspace_scope_schema_mismatch".to_owned());
    }
    // An absent request id reaches the op as the empty string, and echoing it
    // back would hand the caller a reply it cannot bind to the request it sent.
    if request.request_id.is_empty() {
        return Err("native_package_workspace_scope_invalid".to_owned());
    }

    let context = request.execution_context.as_ref().and_then(
        guard_command::package_execution_context::package_execution_context_from_evidence,
    );

    let artifact_id = request.artifact_id.as_deref();
    let artifact_hash = request.artifact_hash.as_deref();
    let artifact_type = request.artifact_type.as_deref();

    let portable = guard_command::local_supply_chain::package_request_portable_workspace_scope(
        artifact_id,
        artifact_hash,
        artifact_type,
        context.as_ref(),
    );
    let runtime = context.as_ref().and_then(|ctx| {
        guard_command::local_supply_chain::package_request_runtime_workspace_scope(
            artifact_id,
            artifact_hash,
            artifact_type,
            ctx,
        )
    });

    crate::encode_response(&PackageWorkspaceScopeResultV1 {
        schema: PACKAGE_WORKSPACE_SCOPE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(json!({ "portable": portable, "runtime": runtime })),
    })
}

#[cfg(test)]
#[path = "package_workspace_scope_op_tests.rs"]
mod tests;
