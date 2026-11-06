//! Artifact risk signal contract.
//!
//! The resident derives every risk signal for one Guard artifact: the typed
//! signals, their product-facing V2 projection and the human summary. The
//! caller sends only the artifact's launch definition and the metadata keys
//! the derivation reads; it never supplies a signal or a verdict.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const ARTIFACT_RISK_REQUEST_SCHEMA: &str = "guard-artifact-risk-request.v1";
/// Schema discriminator for the result.
pub const ARTIFACT_RISK_RESULT_SCHEMA: &str = "guard-artifact-risk-result.v1";
/// Capability advertised by the runtime when `artifact_risk` is available.
pub const ARTIFACT_RISK_FEATURE: &str = "artifact-risk-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRiskRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// `{name, command, url, args, metadata}`, or that object packed as
    /// `{packed_json_gzip_v1, decoded_bytes}` when it is large.
    pub artifact: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRiskResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `{signals, signals_v2, summary}`.
    #[serde(default)]
    pub payload: Value,
}
