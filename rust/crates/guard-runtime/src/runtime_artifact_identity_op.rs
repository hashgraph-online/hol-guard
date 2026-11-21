//! `RuntimeArtifactIdentity` resident op: the ids a merged prompt request and
//! a data-flow exfiltration request are saved under.
//!
//! Wraps `guard_command::runtime_artifact_identity` and binds the reply to the
//! request with `request_id` plus the canonical request digest. Any internal
//! failure is reported as an `error` status so the Python transport fails
//! closed; Python never derives either id itself, because a second derivation
//! would re-key approvals the user already granted.

use std::panic::{catch_unwind, AssertUnwindSafe};

use guard_command::runtime_artifact_identity::{data_flow_artifact_id, prompt_multi_artifact_id};
use guard_contracts::{
    write_canonical_json_with_limit, RuntimeArtifactIdentityKindV1,
    RuntimeArtifactIdentityRequestV1, RuntimeArtifactIdentityResultV1,
    RUNTIME_ARTIFACT_IDENTITY_MAX_REQUEST_BYTES, RUNTIME_ARTIFACT_IDENTITY_REQUEST_SCHEMA,
    RUNTIME_ARTIFACT_IDENTITY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

fn canonical_request(request: &RuntimeArtifactIdentityRequestV1) -> Result<Vec<u8>, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_runtime_artifact_identity_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    write_canonical_json_with_limit(
        &material,
        &mut canonical,
        usize::MAX,
        "native_runtime_artifact_identity_invalid",
    )
    .map_err(|_| "native_runtime_artifact_identity_invalid")?;
    Ok(canonical)
}

fn derive(
    request: &RuntimeArtifactIdentityRequestV1,
    canonical_len: usize,
) -> Result<String, &'static str> {
    if request.schema != RUNTIME_ARTIFACT_IDENTITY_REQUEST_SCHEMA {
        return Err("native_runtime_artifact_identity_schema_mismatch");
    }
    if canonical_len > RUNTIME_ARTIFACT_IDENTITY_MAX_REQUEST_BYTES {
        return Err("native_runtime_artifact_identity_request_too_large");
    }
    // The harness is the id's own prefix; an empty one would let two harnesses
    // collide on one approval key.
    if request.harness.is_empty() {
        return Err("native_runtime_artifact_identity_invalid");
    }
    let harness = request.harness.as_str();
    match &request.identity {
        RuntimeArtifactIdentityKindV1::PromptMulti {
            member_artifact_ids,
        } => {
            // A merged id stands for the artifacts it merges; with none there
            // is nothing for it to stand for.
            if member_artifact_ids.is_empty() {
                return Err("native_runtime_artifact_identity_invalid");
            }
            catch_unwind(AssertUnwindSafe(|| {
                prompt_multi_artifact_id(harness, member_artifact_ids)
            }))
        }
        RuntimeArtifactIdentityKindV1::DataFlow {
            source_scope,
            command_text,
            signal_ids,
        } => {
            if source_scope.is_empty() {
                return Err("native_runtime_artifact_identity_invalid");
            }
            catch_unwind(AssertUnwindSafe(|| {
                data_flow_artifact_id(harness, source_scope, command_text, signal_ids)
            }))
        }
    }
    .map_err(|_| "native_runtime_artifact_identity_failed")
}

pub(crate) fn evaluate_runtime_artifact_identity(
    request: &RuntimeArtifactIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let canonical = canonical_request(request).map_err(str::to_owned)?;
    let request_sha256 = digest_bytes(&canonical);
    let (status, code, artifact_id) = match derive(request, canonical.len()) {
        Ok(artifact_id) => ("ok", "ok", Some(artifact_id)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&RuntimeArtifactIdentityResultV1 {
        schema: RUNTIME_ARTIFACT_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        artifact_id,
    })
}

#[cfg(test)]
#[path = "runtime_artifact_identity_op_tests.rs"]
mod tests;
