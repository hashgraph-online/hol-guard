//! `AibomReportSummaries` — wire contract for the resident op that counts an
//! AIBOM report's layers, trust coverage and drift.
//!
//! The rows travel as the projection the grammar actually reads, not as whole
//! inventory records. A layer count looks at an item's kind, its risk level,
//! its drift state and three metadata keys; nothing else in a stored item
//! changes an answer, and the findings and sources are only ever measured by
//! how many there are. Sending the projection keeps a large report inside the
//! request budget and keeps scan detail out of a message that does not need
//! it.
//!
//! Every field is always present on the wire. A request field that could be
//! omitted would digest differently on each side of the call and the reply
//! would never bind to the request that asked for it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Resident feature advertising this op.
pub const AIBOM_REPORT_SUMMARIES_FEATURE: &str = "aibom-report-summaries-v1";

/// Canonical request budget. A report of a few thousand artifacts fits well
/// inside it.
pub const AIBOM_REPORT_SUMMARIES_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on a request's measured rows: every finding and source count
/// across all of its snapshots together. The counts stand in for rows the
/// caller did not send, so an unbounded total would be an unbounded
/// allocation, however small the request.
pub const AIBOM_REPORT_SUMMARIES_MAX_ROWS: u64 = 1_000_000;

/// Request schema identifier.
pub const AIBOM_REPORT_SUMMARIES_REQUEST_SCHEMA: &str = "guard-aibom-report-summaries-request.v1";

/// Result schema identifier.
pub const AIBOM_REPORT_SUMMARIES_RESULT_SCHEMA: &str = "guard-aibom-report-summaries-result.v1";

/// One inventory item, projected to what the summaries read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AibomSummaryItemV1 {
    /// `GuardAgentInventoryItem.item_kind`; picks the layer and trust eligibility.
    pub item_kind: String,
    /// `GuardAgentInventoryItem.risk_level`; `critical` and `high` are high risk.
    pub risk_level: String,
    /// `GuardAgentInventoryItem.drift_state`; an unknown state is counted nowhere.
    pub drift_state: String,
    /// `metadata["trustResolution"]`, or null. An object is trust coverage.
    pub trust_resolution: Value,
    /// `metadata["sourceLinks"]`, or null. A non-empty array counts once per link.
    pub source_links: Value,
    /// `metadata["sourceOfTruth"]`, or null. An object counts once, and only
    /// when the item carries no links.
    pub source_of_truth: Value,
}

/// One inventory snapshot, projected to what the summaries read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AibomSummarySnapshotV1 {
    /// The snapshot's items.
    pub items: Vec<AibomSummaryItemV1>,
    /// How many findings the snapshot carries; the summaries read the number only.
    pub finding_count: u64,
    /// How many inventory sources the snapshot carries; the number only, again.
    pub source_count: u64,
    /// `GuardAgentInventoryDrift.state` for each drift row, in order.
    pub drift_states: Vec<String>,
}

/// Request for the three summaries of one report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AibomReportSummariesRequestV1 {
    /// Must equal [`AIBOM_REPORT_SUMMARIES_REQUEST_SCHEMA`].
    pub schema: String,
    /// Caller-chosen identifier the reply echoes.
    pub request_id: String,
    /// Timestamp the layer summary reports as `generatedAt`.
    pub generated_at: String,
    /// The report's snapshots.
    pub snapshots: Vec<AibomSummarySnapshotV1>,
}

/// Reply carrying `layer_summary`, `trust` and `drift`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AibomReportSummariesResultV1 {
    /// Always [`AIBOM_REPORT_SUMMARIES_RESULT_SCHEMA`].
    pub schema: String,
    /// Echo of the request's identifier.
    pub request_id: String,
    /// Digest of the canonical request this reply answers.
    pub request_sha256: String,
    /// `ok` for a reply the caller may read.
    pub status: String,
    /// `ok` for a reply the caller may read.
    pub code: String,
    /// The three summaries, under `layer_summary`, `trust` and `drift`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
