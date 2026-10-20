//! `PolicyDocumentDecide` - wire contract for deciding one event against the
//! compiled rows of a policy document.
//!
//! `policy check` and `policy test` answer the same question the runtime
//! answers from the store: which rule decides this event, and why did every
//! other rule lose. Those two answers must not be able to disagree, so the
//! precedence, expiry and exact-match rules live in the runtime and the
//! document path asks for them rather than reimplementing them.
//!
//! The op is pure: it reads the rows the caller supplies and never opens the
//! store, the keyring or a policy file.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA: &str =
    "guard-policy-document-decision-request.v1";
/// Schema discriminator for the result.
pub const POLICY_DOCUMENT_DECISION_RESULT_SCHEMA: &str = "guard-policy-document-decision-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const POLICY_DOCUMENT_DECISION_FEATURE: &str = "policy-document-decision-v1";
/// Largest canonical request serialization the op will accept. It stays below
/// `MAX_NATIVE_REQUEST_BYTES` so the resident envelope still fits one frame.
pub const POLICY_DOCUMENT_DECISION_MAX_BYTES: usize = 6 * 1024 * 1024 - 64 * 1024;
/// Most compiled rows one call may decide against. `guard explain` builds its
/// document from every remembered decision on the device, and that table is
/// unbounded, so this ceiling sits far above any hand-written document; the
/// byte limit above is what a real request runs into first.
pub const POLICY_DOCUMENT_DECISION_MAX_ROWS: usize = 16384;
/// Matched rows above which the document is reported as too ambiguous to
/// decide. The runtime store lookup applies the same ceiling.
pub const POLICY_DOCUMENT_MATCH_LIMIT: usize = 256;

/// One compiled row: the persisted decision plus the rule that produced it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentRowV1 {
    pub rule_id: String,
    pub harness: String,
    pub scope: String,
    pub action: String,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// The event to decide. `artifact` and `tool` are mutually exclusive; the
/// runtime derives the artifact id of a tool family from `tool`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentEventV1 {
    pub harness: String,
    #[serde(default)]
    pub artifact: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub workspace: Option<String>,
    /// Evaluation time; `now` is used when the event does not carry one.
    #[serde(default)]
    pub at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentDecisionRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub rows: Vec<PolicyDocumentRowV1>,
    pub event: PolicyDocumentEventV1,
    pub now: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_policy_document_decision_*` failure codes.
    pub code: String,
    /// The Explain document: `effect`, `ruleId`, `ambiguous`,
    /// `matchLimitExceeded`, `tiedRuleIds`, `candidates` and `lookup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
