//! Request/result contract for the `RuntimeArtifactIdentity` resident op.
//!
//! Two runtime artifact ids share this op: the merged prompt request and the
//! data-flow exfiltration request. Both are keys a saved approval is stored
//! under, so the resident derives them and Python only transports the result,
//! bound to the request by `request_id` plus the canonical `request_sha256`.

use serde::{Deserialize, Serialize};

pub const RUNTIME_ARTIFACT_IDENTITY_FEATURE: &str = "runtime-artifact-identity-v1";
pub const RUNTIME_ARTIFACT_IDENTITY_REQUEST_SCHEMA: &str =
    "guard-runtime-artifact-identity-request.v1";
pub const RUNTIME_ARTIFACT_IDENTITY_RESULT_SCHEMA: &str =
    "guard-runtime-artifact-identity-result.v1";
/// Largest request the op accepts; longer input fails closed.
pub const RUNTIME_ARTIFACT_IDENTITY_MAX_REQUEST_BYTES: usize = 256 * 1024;

/// Which identity the request asks for. The two carry different material, so
/// they are separate variants rather than one payload with optional fields:
/// a data-flow request can never be answered with a prompt key by accident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeArtifactIdentityKindV1 {
    /// `_merged_prompt_runtime_artifact`: the ids of the prompt artifacts
    /// being merged, in whatever order they were collected.
    PromptMulti { member_artifact_ids: Vec<String> },
    /// `_runtime_data_flow_artifact`: the action's command text and the
    /// detector's signal ids, in detection order.
    DataFlow {
        source_scope: String,
        command_text: String,
        signal_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactIdentityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub harness: String,
    pub identity: RuntimeArtifactIdentityKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// Hex SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    pub code: String,
    /// `GuardArtifact.artifact_id`; present only when `ok`.
    pub artifact_id: Option<String>,
}
