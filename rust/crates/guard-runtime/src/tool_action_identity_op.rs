//! `ToolActionRequestIdentity` resident op: the artifact id a sensitive
//! tool-action review is saved under.
//!
//! Wraps `guard_command::tool_action_identity::tool_action_request_artifact_id`
//! and binds the reply to the request with `request_id` plus the canonical
//! request digest. Any internal failure is reported as an `error` status so the
//! Python transport fails closed; Python never derives the id itself, because a
//! second derivation would re-key approvals the user already granted.

use std::panic::{catch_unwind, AssertUnwindSafe};

use guard_command::tool_action_identity::{
    tool_action_request_artifact_id, ToolActionIdentityInputs,
};
use guard_contracts::{
    write_canonical_json_with_limit, ToolActionRequestIdentityRequestV1,
    ToolActionRequestIdentityResultV1, TOOL_ACTION_REQUEST_IDENTITY_MAX_REQUEST_BYTES,
    TOOL_ACTION_REQUEST_IDENTITY_REQUEST_SCHEMA, TOOL_ACTION_REQUEST_IDENTITY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

fn canonical_request(
    request: &ToolActionRequestIdentityRequestV1,
) -> Result<Vec<u8>, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_tool_action_identity_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(
        &material,
        &mut canonical,
        usize::MAX,
        "native_tool_action_identity_invalid",
    )
    .map_err(|_| "native_tool_action_identity_invalid")?;
    Ok(canonical)
}

fn derive(
    request: &ToolActionRequestIdentityRequestV1,
    canonical_len: usize,
) -> Result<String, &'static str> {
    if request.schema != TOOL_ACTION_REQUEST_IDENTITY_REQUEST_SCHEMA {
        return Err("native_tool_action_identity_schema_mismatch");
    }
    if canonical_len > TOOL_ACTION_REQUEST_IDENTITY_MAX_REQUEST_BYTES {
        return Err("native_tool_action_identity_request_too_large");
    }
    // The harness and scope are the artifact id's own prefix; an empty one
    // would make two different scopes collide on one key.
    if request.harness.is_empty() || request.source_scope.is_empty() {
        return Err("native_tool_action_identity_invalid");
    }
    let inputs = ToolActionIdentityInputs {
        harness: request.harness.clone(),
        source_scope: request.source_scope.clone(),
        normalized_tool_name: request.normalized_tool_name.clone(),
        command_text: request.command_text.clone(),
        action_class: request.action_class.clone(),
        shell_execution_context_hash: request.shell_execution_context_hash.clone(),
        interpreter_executable_identities: request.interpreter_executable_identities.clone(),
        script_read_identity_sha256: request.script_read_identity_sha256.clone(),
        restricted_profile_version: request.restricted_profile_version.clone(),
        pytest_config_identity_sha256: request.pytest_config_identity_sha256.clone(),
    };
    catch_unwind(AssertUnwindSafe(|| {
        tool_action_request_artifact_id(&inputs)
    }))
    .map_err(|_| "native_tool_action_identity_failed")
}

pub(crate) fn evaluate_tool_action_request_identity(
    request: &ToolActionRequestIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let canonical = canonical_request(request).map_err(str::to_owned)?;
    let request_sha256 = digest_bytes(&canonical);
    let (status, code, artifact_id) = match derive(request, canonical.len()) {
        Ok(artifact_id) => ("ok", "ok", Some(artifact_id)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&ToolActionRequestIdentityResultV1 {
        schema: TOOL_ACTION_REQUEST_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        artifact_id,
    })
}

#[cfg(test)]
#[path = "tool_action_identity_op_tests.rs"]
mod tests;
