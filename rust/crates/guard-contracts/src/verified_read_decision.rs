//! Request/result contract for the `VerifiedReadDecision` resident op.
//!
//! The verified GitHub public read asks here whether its proven read may run
//! silently. The verified workspace read asks the same question, but it runs in
//! the resident already and composes its decision there, so it never crosses
//! this wire. The host transports the decision and never re-derives it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERIFIED_READ_DECISION_FEATURE: &str = "verified-read-decision-v1";
pub const VERIFIED_READ_DECISION_REQUEST_SCHEMA: &str = "guard-verified-read-decision-request.v1";
pub const VERIFIED_READ_DECISION_RESULT_SCHEMA: &str = "guard-verified-read-decision-result.v1";
/// Largest request the op accepts; longer input fails closed. The request
/// carries two short identifiers, so this is generous by a wide margin.
pub const VERIFIED_READ_DECISION_MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Which verified read is asking. The workspace read composes its own decision
/// inside `verified-read-execute-v1`, so the only read that still asks over the
/// wire is the GitHub one, whose operation ref is fixed by the executor: there
/// is nothing for the host to supply and nothing it could get wrong.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedReadDecisionKindV1 {
    /// `verified_github_reads._decision`.
    GithubPublicRead {},
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadDecisionRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The proof's binding digest. Everything else about the proof is fixed by
    /// the executor that produced it, so the digest is the whole variable.
    pub binding_digest: String,
    pub read: VerifiedReadDecisionKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// Hex SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    pub code: String,
    /// `effect_decision_to_payload` output; present only when `ok`.
    pub decision: Option<Value>,
}
