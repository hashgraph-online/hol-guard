//! `ArtifactContentHash` - resident op spelling the content hash a saved
//! approval is keyed by.
//!
//! The hash itself lives in `guard_command::artifact_hash`, ported from
//! `consumer.service.artifact_hash`. This op exists so the callers that still
//! spelled it in Python stop doing so: an approval key computed beside the
//! store is a key a caller could spell differently, and a different spelling
//! silently misses every approval the user already granted.
//!
//! The artifacts arrive raw. The hash reads the artifact's own redaction of
//! its arguments, url and metadata, so a caller that redacted first would
//! hand the resident a different artifact than the one the approval covers.

use guard_command::artifact_hash::artifact_hash;
use guard_contracts::{
    ArtifactContentHashRequestV1, ArtifactContentHashResultV1, ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS,
    ARTIFACT_CONTENT_HASH_MAX_BYTES, ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA,
    ARTIFACT_CONTENT_HASH_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_artifact_content_hash_request(
    request: &ArtifactContentHashRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, ARTIFACT_CONTENT_HASH_MAX_BYTES)
        .map_err(|_| "native_artifact_content_hash_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&ArtifactContentHashResultV1 {
        schema: ARTIFACT_CONTENT_HASH_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &ArtifactContentHashRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA {
        return Some("native_artifact_content_hash_schema_mismatch");
    }
    if request.artifacts.len() > ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS {
        return Some("native_artifact_content_hash_too_many_artifacts");
    }
    None
}

/// One hash per requested artifact, in the request's order.
pub(crate) fn evaluate_request(request: &ArtifactContentHashRequestV1) -> Value {
    let content_hashes: Vec<Value> = request
        .artifacts
        .iter()
        .map(|artifact| Value::String(artifact_hash(artifact)))
        .collect();
    serde_json::json!({ "content_hashes": content_hashes })
}

#[cfg(test)]
#[path = "artifact_content_hash_op_tests.rs"]
mod tests;
