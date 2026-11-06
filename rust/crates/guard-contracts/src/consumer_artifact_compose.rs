//! `ConsumerArtifactCompose` — wire contract for the resident consumer
//! artifact decision composition op.
//!
//! The consumer evaluation (`guard run`, `guard scan`, inventory refresh)
//! gathers evidence in Python: detected artifacts, capability deltas, store
//! history, provenance, saved-decision lookups and context tokens. The
//! resident decides: it scores the artifact, composes the current policy
//! action, validates saved approvals against the exact context token,
//! evaluates saved/claimed approval reuse and the trusted-request override,
//! applies runtime-detector authority, and returns the composition trace.
//! Every query is pure: no IO, no SQLite. Python must send every field
//! explicitly (nulls included) so the request digest it binds matches the
//! resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA: &str =
    "guard-consumer-artifact-compose-request.v1";
/// Schema discriminator for the result.
pub const CONSUMER_ARTIFACT_COMPOSE_RESULT_SCHEMA: &str =
    "guard-consumer-artifact-compose-result.v1";
/// Capability advertised by the runtime when this operation is available.
///
/// v3 adds the `LowTrustFloor` query. A resident still advertising v2 would
/// refuse that query while answering the rest, which is how a fresh low-trust
/// artifact could be composed with no review floor, so the capability moves
/// with the query set rather than the request schema.
pub const CONSUMER_ARTIFACT_COMPOSE_FEATURE: &str = "consumer-artifact-compose-v3";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactComposeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: ConsumerArtifactComposeQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsumerArtifactComposeQueryV1 {
    /// Score the artifact and compose its current policy action.
    CurrentAction(Box<ConsumerCurrentActionQueryV1>),
    /// Compose saved/claimed reuse, override and runtime authority.
    RuntimeDecision(Box<ConsumerRuntimeDecisionQueryV1>),
    /// Compose and build its canonical decision in one resident request.
    RuntimeAuthoritative(Box<ConsumerRuntimeAuthoritativeQueryV1>),
    /// Decide the registry trust review floor of a fresh artifact.
    LowTrustFloor(Box<ConsumerLowTrustFloorQueryV1>),
}

/// The facts the review floor for a low registry trust score is decided from.
///
/// Python holds the registry lookup because it is network IO with an on-disk
/// cache; every judgement around it is made here. The resident decides whether
/// the artifact qualifies at all, resolves the `low_trust_artifact` action from
/// the sent configuration, compares the score against the threshold and writes
/// the signal. A first query leaves `trust_score` null: the answer asks for the
/// score only when the floor would otherwise apply, so a configured, settled or
/// unscored artifact still costs no lookup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerLowTrustFloorQueryV1 {
    pub risk_action_config: crate::RiskActionConfigV1,
    /// The harness the artifact was detected in; `null` when unknown.
    pub harness: Value,
    pub artifact_type: Value,
    pub artifact_id: String,
    pub artifact_name: String,
    /// Per-artifact or publisher override; a configured artifact keeps it.
    pub configured_action: Value,
    /// The artifact is first seen or changed, so its action is decided now.
    pub fresh_decision: bool,
    /// The registry trust score, or `null` when it has not been looked up.
    pub trust_score: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerRuntimeAuthoritativeQueryV1 {
    pub runtime: ConsumerRuntimeDecisionQueryV1,
    pub signals: Value,
}

/// One structured risk signal of the scored artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerSignalV1 {
    pub severity: i64,
    pub confidence: f64,
    pub explanation: String,
    pub family: String,
    pub evidence_source: String,
}

/// One capability delta against the previously approved snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerDeltaV1 {
    pub delta_type: String,
    pub severity: i64,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerCurrentActionQueryV1 {
    /// The artifact disappeared from the harness: no body to score.
    pub removed: bool,
    pub artifact_type: Value,
    /// Per-artifact or publisher override; `null` when none is configured.
    pub configured_action: Value,
    /// Adapter-provided `guard_default_action` metadata (request artifacts).
    pub guard_default_action: Value,
    pub first_seen: bool,
    pub changed: bool,
    /// Caller-supplied default action; `null` when absent or unknown.
    pub effective_default_action: Value,
    pub config_changed_hash_action: Value,
    pub config_default_action: Value,
    /// `null` when the adapter emits no skill-directory identity marker.
    pub skill_directory_identity_reusable: Option<bool>,
    pub signals: Vec<ConsumerSignalV1>,
    pub deltas: Vec<ConsumerDeltaV1>,
    pub provenance_source_kind: String,
    pub publisher_trust: String,
    pub prior_approvals: i64,
    pub prior_incidents: i64,
    /// The `low_trust_artifact` action for a first-seen or changed artifact
    /// whose registry trust score is low; omitted (null) otherwise, so
    /// requests without it keep their digest.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub low_trust_action: Value,
}

/// The fields of a resolved saved policy decision that authority reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerSavedDecisionV1 {
    pub action: Value,
    pub artifact_hash: Value,
    pub scope: Value,
    pub fresh_local_approval: Value,
    pub durable_exact_approval: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerRuntimeDecisionQueryV1 {
    pub current_action: Value,
    pub configured_action: Value,
    /// Mapped scoring action; `null` for a removed artifact.
    pub scanner_action: Value,
    pub raw_scoring_recommendation: Value,
    pub skill_directory_identity_reusable: Option<bool>,
    pub approval_context_hash: String,
    pub saved_decision: Option<ConsumerSavedDecisionV1>,
    /// The lookup skipped a saved row whose local integrity failed.
    pub ignored_local_integrity: bool,
    /// Store diagnosis for an invalidated saved approval; only consulted when
    /// the lookup found neither a decision nor an integrity failure.
    pub diagnosed_reason: Option<String>,
    /// Exact context hash of a freshly resolved trusted request, if any.
    pub trusted_request_override_hash: Value,
    /// Exact context hash of a consumed saved-approval claim, if any.
    pub claimed_saved_approval_hash: Value,
    /// Exact context hash of a retained saved-approval claim, if any.
    pub retained_saved_approval_hash: Value,
    /// Native qualification of the claimed approval (fresh/durable flags).
    pub saved_approval_qualification: Value,
    /// Raw runtime-detector `composition` object; `null` when absent.
    pub runtime_detector_composition: Value,
    pub runtime_detector_block_reason: Option<String>,
    /// Serialized runtime-detector risk signals, already de-duplicated.
    pub runtime_signals: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsumerArtifactComposeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_consumer_artifact_compose_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
