//! Trusted-local-tool grant shape contract.
//!
//! Eligibility says a command *may* carry a reusable grant. This contract
//! covers what that grant is allowed to be: which targets and durations the
//! approval card may offer, and, once the user picks a pair, the selector the
//! grant is filed under, when it expires and the policy row that records it.
//!
//! The caller sends the approval request's filed scanner evidence and the raw
//! pick; it never derives a selector, an expiry or a decision of its own. The
//! same selector derivation answers the read side in
//! `policy_lookup_local_tool_grant`, so a grant is always looked up under the
//! id it was written to.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const LOCAL_TOOL_GRANT_REQUEST_SCHEMA: &str = "guard-local-tool-grant-request.v1";
/// Schema discriminator for the result.
pub const LOCAL_TOOL_GRANT_RESULT_SCHEMA: &str = "guard-local-tool-grant-result.v1";
/// Capability advertised by the runtime when `local_tool_grant` is available.
pub const LOCAL_TOOL_GRANT_FEATURE: &str = "local-tool-grant-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalToolGrantRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The approval request's `scanner_evidence`, exactly as it was filed. It
    /// is untrusted input: any shape at all answers "not eligible" rather than
    /// failing the op.
    #[serde(default)]
    pub scanner_evidence: Value,
    /// The pick to turn into a grant. Absent when the caller only needs the
    /// options the approval card may offer.
    #[serde(default)]
    pub selection: Option<LocalToolGrantSelectionRequestV1>,
}

/// One user pick, as it arrived from the approval surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalToolGrantSelectionRequestV1 {
    /// The harness the recorded policy row belongs to.
    pub harness: String,
    /// The chosen target, unvalidated: any JSON value the surface sent.
    #[serde(default)]
    pub target: Value,
    /// The chosen duration, unvalidated.
    #[serde(default)]
    pub duration: Value,
    /// The resolution timestamp an expiry is measured from.
    pub now: String,
    /// The reason recorded with the policy row.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalToolGrantResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `{approval, selection, refusal}`. `approval` is the card payload, or
    /// `null` when the evidence carries no eligible grant. `selection` is the
    /// derived grant and its policy row, or `null` when none was asked for or
    /// the pick was refused. `refusal` names why a pick was refused.
    pub payload: Value,
}
