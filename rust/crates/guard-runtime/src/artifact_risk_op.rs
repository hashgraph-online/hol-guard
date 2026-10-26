//! `ArtifactRisk` — every risk signal for one Guard artifact in one reply:
//! the typed signals, their V2 projection and the summary.
//!
//! A malformed artifact or an unavailable secret-path classification is an
//! error reply, which the caller raises on; it never answers fewer signals.
//! A payload over `PACK_THRESHOLD_BYTES` crosses back gzip-packed, as large
//! requests do, so an artifact naming many hosts still fits the transport.

use std::io::Write;

use base64ct::{Base64, Encoding};
use flate2::{write::GzEncoder, Compression};
use guard_contracts::{
    ArtifactRiskRequestV1, ArtifactRiskResultV1, ARTIFACT_RISK_REQUEST_SCHEMA,
    ARTIFACT_RISK_RESULT_SCHEMA,
};

pub(crate) fn evaluate_artifact_risk_request(
    request: &ArtifactRiskRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != ARTIFACT_RISK_REQUEST_SCHEMA {
        return Err("native_artifact_risk_schema_mismatch".to_owned());
    }
    let payload = guard_command::artifact_risk::artifact_risk(&request.artifact)
        .map_err(|code| format!("native_{code}"))?;
    let payload = pack_large_payload(payload)?;
    crate::resident_protocol::encode_response(&ArtifactRiskResultV1 {
        schema: ARTIFACT_RISK_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

const PACK_THRESHOLD_BYTES: usize = 128 * 1024;

fn pack_large_payload(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let bytes = serde_json::to_vec(&payload)
        .map_err(|_| "native_artifact_risk_reply_invalid".to_owned())?;
    if bytes.len() <= PACK_THRESHOLD_BYTES {
        return Ok(payload);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&bytes)
        .map_err(|_| "native_artifact_risk_reply_invalid".to_owned())?;
    let packed = encoder
        .finish()
        .map_err(|_| "native_artifact_risk_reply_invalid".to_owned())?;
    Ok(serde_json::json!({"packed_json_gzip_v1": Base64::encode_string(&packed)}))
}

fn request_digest(request: &ArtifactRiskRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_artifact_risk_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_artifact_risk_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

#[cfg(all(test, unix))]
#[path = "artifact_risk_op_tests.rs"]
mod tests;
