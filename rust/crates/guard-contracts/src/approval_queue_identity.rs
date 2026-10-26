//! `ApprovalQueueIdentity` - wire contract for the resident op that derives the
//! approval queue identity of one or more requests.
//!
//! The op is pure (no IO, no SQLite). The caller ships the narrowed request
//! fields; the resident returns the normalized identity key, the action
//! identity and the queue group id used to deduplicate pending approvals.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_QUEUE_IDENTITY_REQUEST_SCHEMA: &str = "guard-approval-queue-identity-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_QUEUE_IDENTITY_RESULT_SCHEMA: &str = "guard-approval-queue-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_QUEUE_IDENTITY_FEATURE: &str = "approval-queue-identity-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_QUEUE_IDENTITY_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most requests one call may identify.
pub const APPROVAL_QUEUE_IDENTITY_MAX_ITEMS: usize = 1024;

/// One approval request, narrowed to the fields its queue identity reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalQueueIdentityItemV1 {
    #[serde(default)]
    pub launch_target: Option<String>,
    pub harness: String,
    #[serde(default)]
    pub workspace: Option<String>,
    pub artifact_id: String,
    /// The stored action envelope when it is a JSON object.
    #[serde(default)]
    pub envelope: Option<Value>,
    /// The browser intent when the request carries one.
    #[serde(default)]
    pub browser_intent: Option<Value>,
    /// An identity the request already carries; empty counts as absent.
    #[serde(default)]
    pub action_identity: Option<String>,
    /// A queue group the request already carries; empty counts as absent.
    #[serde(default)]
    pub queue_group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalQueueIdentityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub items: Vec<ApprovalQueueIdentityItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalQueueIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_queue_identity_*` failure codes.
    pub code: String,
    /// `{"items": [{"identity_key", "action_identity", "queue_group_id"}]}`,
    /// in request order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
