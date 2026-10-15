//! `ConsumerArtifactProject` - wire contract for the resident consumer
//! artifact projection op.
//!
//! The consumer evaluation (`guard run`, `guard scan`, inventory refresh) reads
//! the store and the harness in Python. The resident owns what the evidence
//! means: the capability snapshot and its delta against the previous snapshot,
//! the artifact diff, the local history and provenance context, the incident
//! copy shown for a decision, the receipt fields and the per-artifact result
//! projection, and the approval-context components. Every query is pure: no
//! IO, no SQLite. Python sends every field explicitly (nulls included) so the
//! request digest it binds matches the resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CONSUMER_ARTIFACT_PROJECT_REQUEST_SCHEMA: &str =
    "guard-consumer-artifact-project-request.v1";
/// Schema discriminator for the result.
pub const CONSUMER_ARTIFACT_PROJECT_RESULT_SCHEMA: &str =
    "guard-consumer-artifact-project-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONSUMER_ARTIFACT_PROJECT_FEATURE: &str = "consumer-artifact-project-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactProjectRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: ConsumerArtifactProjectQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsumerArtifactProjectQueryV1 {
    /// Capability snapshot and delta, diff, history and provenance.
    ArtifactEvidence(Box<ConsumerArtifactEvidenceQueryV1>),
    /// Result row of a detected artifact.
    ArtifactResult(Box<ConsumerArtifactResultQueryV1>),
    /// Receipt strings and result row of a removed artifact.
    RemovedResult(Box<ConsumerRemovedResultQueryV1>),
    /// Incident copy for one artifact decision.
    IncidentContext(Box<ConsumerIncidentQueryV1>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactEvidenceQueryV1 {
    /// Raw artifact fields and the metadata keys the capability and incident
    /// logic read (`env_keys`, request and prompt summaries, hook identity).
    pub artifact: Value,
    /// The serialized artifact the diff compares against the snapshot.
    pub current_payload: Value,
    /// The key order of `current_payload`, which orders `changed_fields`.
    pub payload_keys: Vec<String>,
    pub current_hash: String,
    /// The stored snapshot of the previous run, or `null` when first seen.
    pub previous_snapshot: Value,
    /// The stored capability snapshot, or `null`.
    pub previous_capabilities: Value,
    /// Inventory item, receipt decision counts, event names of the artifact
    /// and the cached advisories of its publisher.
    pub history: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactResultQueryV1 {
    pub harness: String,
    pub artifact: Value,
    /// The evidence payload this artifact's evidence query returned.
    pub evidence: Value,
    /// `to_artifact_projection()` of the authoritative decision.
    pub projection: Value,
    pub verdict: Value,
    pub scanner_action: Value,
    /// The runtime decision composition answer.
    pub runtime: Value,
    pub signals: Vec<Value>,
    pub risk_signals: Vec<Value>,
    pub risk_summary: Value,
    pub approval_context_hash: String,
    pub effective_workspace: Value,
    pub policy_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerRemovedResultQueryV1 {
    pub harness: String,
    pub artifact_id: String,
    pub previous: Value,
    pub previous_hash: String,
    pub projection: Value,
    pub runtime: Value,
    pub signals: Vec<Value>,
    pub risk_signals: Vec<Value>,
    pub has_runtime_authority: bool,
    pub dashboard_detail: Value,
    pub approval_context_hash: String,
    pub effective_workspace: Value,
    pub policy_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerIncidentQueryV1 {
    pub harness: String,
    /// The artifact fields the copy reads, or `null` for a removed artifact.
    pub artifact: Value,
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_type: Value,
    pub source_scope: Value,
    pub config_path: Value,
    pub changed_fields: Vec<String>,
    pub policy_action: String,
    pub launch_target: Value,
    pub risk_summary: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactProjectResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_consumer_artifact_project_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
