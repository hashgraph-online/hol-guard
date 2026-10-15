//! `ApprovalProofDecide` — wire contract for the resident approval-proof op.
//!
//! The Python store selects saved approval rows; the resident decides what a
//! selected row proves. Every query is pure: no IO, no SQLite. The caller sends
//! the selected row(s) verbatim and presents the boolean/disposition answer.
//! There is no Python evaluator, so any transport failure must be handled by
//! the caller as "no proof".

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const APPROVAL_PROOF_REQUEST_SCHEMA: &str = "guard-approval-proof-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_PROOF_RESULT_SCHEMA: &str = "guard-approval-proof-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_PROOF_FEATURE: &str = "approval-proof-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProofRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: ApprovalProofQueryV1,
}

/// One proof question. `claim_disposition` values are `consumed` or
/// `retained`; any other string is treated as no disposition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalProofQueryV1 {
    /// What a successful claim does to the selected `allow` row.
    ClaimDisposition { decision: Map<String, Value> },
    /// Whether a claim-time lookup outcome keeps a consumed claim usable.
    LookupPreservesClaim {
        #[serde(default)]
        reason_code: Option<String>,
    },
    /// Whether the row is exact, fresh, local proof for this tool call.
    FreshToolApproval {
        #[serde(default)]
        decision: Option<Map<String, Value>>,
        harness: String,
        artifact_id: String,
        artifact_hash: String,
    },
    /// Whether a consumed claim may lower a fresh review for this tool call.
    FreshClaimAllowsReapproval {
        #[serde(default)]
        claim_disposition: Option<String>,
        #[serde(default)]
        reason_code: Option<String>,
        #[serde(default)]
        decision: Option<Map<String, Value>>,
        harness: String,
        artifact_id: String,
        artifact_hash: String,
    },
    /// Whether the claimed row still authorizes the post-claim review.
    PostclaimReviewAuthorized {
        #[serde(default)]
        claim_disposition: Option<String>,
        #[serde(default)]
        claimed_decision: Option<Map<String, Value>>,
        #[serde(default)]
        current_decision: Option<Map<String, Value>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProofResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_approval_proof_*` failure code.
    pub code: String,
    /// `{accepted, claim_disposition}` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
