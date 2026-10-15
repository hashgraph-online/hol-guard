//! `ConsumerArtifactProject` - resident projection of consumer artifact
//! evidence for `guard run`, `guard scan` and inventory refresh.
//!
//! Python reads the store and the harness. This op decides what that evidence
//! means: the capability snapshot and its delta, the artifact diff, the
//! history and provenance context, the receipt summaries, the incident copy
//! and the per-artifact result rows. Every query is pure and answers with a
//! bound, digest-checked reply or a stable error code; there is no partial
//! answer for Python to complete.

use guard_contracts::{
    ConsumerArtifactProjectQueryV1, ConsumerArtifactProjectRequestV1,
    ConsumerArtifactProjectResultV1, CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA,
    CONSUMER_ARTIFACT_PROJECT_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::consumer_evidence::artifact_evidence;
use crate::consumer_result::{artifact_result, incident_context, removed_result};

const REQUEST_INVALID: &str = "native_consumer_artifact_project_request_invalid";
const SCHEMA_MISMATCH: &str = "native_consumer_artifact_project_schema_mismatch";

pub(crate) fn evaluate_consumer_artifact_project_request(
    request: &ConsumerArtifactProjectRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA {
        return Err(SCHEMA_MISMATCH.to_owned());
    }
    crate::resident_protocol::encode_response(&ConsumerArtifactProjectResultV1 {
        schema: CONSUMER_ARTIFACT_PROJECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(project(&request.query).map_err(str::to_owned)?),
    })
}

fn request_digest(request: &ConsumerArtifactProjectRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request).map_err(|_| REQUEST_INVALID.to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| REQUEST_INVALID.to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn project(query: &ConsumerArtifactProjectQueryV1) -> Result<Value, &'static str> {
    let body = |value: Result<Value, serde_json::Error>| -> Result<Value, &'static str> {
        value.map_err(|_| REQUEST_INVALID)
    };
    match query {
        ConsumerArtifactProjectQueryV1::ArtifactEvidence(query) => {
            artifact_evidence(&body(serde_json::to_value(query))?)
        }
        ConsumerArtifactProjectQueryV1::ArtifactResult(query) => {
            artifact_result(&body(serde_json::to_value(query))?)
        }
        ConsumerArtifactProjectQueryV1::RemovedResult(query) => {
            removed_result(&body(serde_json::to_value(query))?)
        }
        ConsumerArtifactProjectQueryV1::IncidentContext(query) => {
            incident_context(&body(serde_json::to_value(query))?)
        }
    }
}

#[cfg(test)]
#[path = "consumer_artifact_project_op_tests.rs"]
mod tests;
