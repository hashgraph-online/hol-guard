//! `CommandCapability` - wire contract for the resident op that verifies the
//! signed, revocable capability guarding Guard Cloud's remote commands, and
//! authorizes one leased job against it.
//!
//! The capability is an HMAC-signed envelope stored in the local sync state.
//! It names the device and workspace it was issued for, the operations it
//! grants, and when it expires. Until this op existed, `command_capability.py`
//! verified that signature and every binding itself, so the Python edge
//! decided whether a remote command could run at all. That is authority, not
//! transport: a caller that reached the Python helper could authorize a job
//! the runtime would have refused.
//!
//! The op answers both questions in one round trip, because every caller that
//! authorizes a job verifies the capability first. The caller supplies the
//! stored envelope, the local signing key, the device binding it resolved and
//! the replay rows it holds; the runtime performs every comparison and returns
//! the verdict. Issuing, revoking and recording remain the caller's writes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const COMMAND_CAPABILITY_REQUEST_SCHEMA: &str = "guard-command-capability-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_CAPABILITY_RESULT_SCHEMA: &str = "guard-command-capability-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_CAPABILITY_FEATURE: &str = "command-capability-v1";
/// Largest canonical request serialization the op will accept.
pub const COMMAND_CAPABILITY_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Replay rows one request may carry. The store keeps far fewer; a caller
/// holding more is refused rather than answered from a truncated history.
pub const COMMAND_CAPABILITY_MAX_REPLAY_ITEMS: usize = 4096;
/// The only capability envelope version this runtime accepts.
pub const COMMAND_CAPABILITY_VERSION: i64 = 1;
/// Longest life a signed capability may claim between issue and expiry.
pub const COMMAND_CAPABILITY_MAX_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;
/// Clock skew allowed on a capability's issue time before it reads as future.
pub const COMMAND_CAPABILITY_ISSUE_SKEW_SECONDS: i64 = 5 * 60;
/// Furthest ahead a leased job's expiry may sit from the decision instant.
pub const COMMAND_JOB_MAX_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

/// Operations a capability may grant that only read local state.
pub const READ_ONLY_COMMAND_OPERATIONS: &[&str] = &[
    "guard.packageShims.status",
    "guard.packageShims.test",
    "guard.packageShims.audit",
    "guard.app.status",
    "guard.app.updateCheck",
];
/// Operations that change state but are confirmed locally before they run.
pub const LOCAL_CONFIRMATION_COMMAND_OPERATIONS: &[&str] =
    &["guard.packageShims.remove", "guard.app.remove"];
/// Operations that change state and need a local approval unless the remote
/// side stepped the user up for them.
pub const STATE_CHANGING_COMMAND_OPERATIONS: &[&str] = &[
    "guard.packageShims.repair",
    "guard.packageShims.sync",
    "guard.packageShims.install",
    "guard.app.repair",
    "guard.app.connect",
    "guard.app.update",
    "guard.review.syncPolicyMemory",
];
/// State-changing operations whose remote step-up stands in for the local
/// approval. Empty: no operation currently qualifies.
pub const REMOTE_STEP_UP_COMMAND_OPERATIONS: &[&str] = &[];

/// Whether this runtime still recognizes `operation` as something a signed
/// grant can carry. A grant naming anything else is projected away rather
/// than honored, so a stale capability cannot outlive the operation it named.
pub fn command_operation_is_classified(operation: &str) -> bool {
    READ_ONLY_COMMAND_OPERATIONS.contains(&operation)
        || LOCAL_CONFIRMATION_COMMAND_OPERATIONS.contains(&operation)
        || STATE_CHANGING_COMMAND_OPERATIONS.contains(&operation)
}

/// Whether running `operation` needs a local approval before it may proceed.
pub fn command_operation_requires_local_approval(operation: &str) -> bool {
    STATE_CHANGING_COMMAND_OPERATIONS.contains(&operation)
        && !REMOTE_STEP_UP_COMMAND_OPERATIONS.contains(&operation)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandCapabilityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The signed envelope read from the store, or null when none is stored.
    #[serde(default)]
    pub capability: Value,
    /// Base64 of the local policy integrity secret the envelope was signed
    /// with, or null when the store holds no key.
    #[serde(default)]
    pub integrity_key_b64: Option<String>,
    /// Identifier of that key, compared against the envelope's `keyId`.
    #[serde(default)]
    pub integrity_key_id: Option<String>,
    /// The DPoP device the capability must name.
    #[serde(default)]
    pub device_id: Option<String>,
    /// The workspace the capability must name.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// The code the caller hit resolving that binding, raised in the same
    /// place the binding itself is checked.
    #[serde(default)]
    pub oauth_error: Option<String>,
    /// The instant the decision is made at, as an ISO-8601 timestamp.
    pub now: String,
    /// The leased job to authorize. Null asks only about the capability.
    #[serde(default)]
    pub job: Value,
    /// The schema version each operation's payload must declare.
    #[serde(default)]
    pub schema_versions: BTreeMap<String, Value>,
    /// Replay rows recorded for jobs already admitted.
    #[serde(default)]
    pub replay_items: Vec<Value>,
    /// A job identity to test against `replay_items` on its own, for a caller
    /// that authorizes its own operation and only needs the replay answer.
    /// Null asks nothing.
    #[serde(default)]
    pub replay_identity: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandCapabilityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_capability_*` codes.
    pub code: String,
    /// The capability verdict, its projected grants, and the job verdict when
    /// one was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
