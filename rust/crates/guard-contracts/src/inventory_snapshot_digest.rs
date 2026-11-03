//! `InventorySnapshotDigest` — wire contract for the resident op that computes
//! an inventory snapshot's content identity.
//!
//! A snapshot's digest is what decides whether an inventory changed. It is not
//! a hash of the snapshot as observed: observation timestamps, durations and
//! attestation blocks are dropped first, nested lists are ordered, and items,
//! findings and sources are each sorted by their own key, so two scans of an
//! unchanged machine agree. That whole grammar lives in
//! `inventory_fingerprints`, pinned by `inventory_fingerprint_parity.json`.
//!
//! The snapshot travels whole. Unlike the evidence op there is nothing to
//! batch: a digest over part of an inventory is not a digest of it, so a
//! snapshot too large for the request bound fails rather than being hashed
//! anywhere else.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const INVENTORY_SNAPSHOT_DIGEST_REQUEST_SCHEMA: &str =
    "guard-inventory-snapshot-digest-request.v1";
/// Schema discriminator for the result.
pub const INVENTORY_SNAPSHOT_DIGEST_RESULT_SCHEMA: &str =
    "guard-inventory-snapshot-digest-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const INVENTORY_SNAPSHOT_DIGEST_FEATURE: &str = "inventory-snapshot-digest-v1";
/// Largest canonical request serialization the op will accept.
///
/// Held under [`MAX_NATIVE_REQUEST_BYTES`](crate::MAX_NATIVE_REQUEST_BYTES),
/// which the transport enforces on the frame before this op ever sees it. A
/// bound above that would be unreachable: a snapshot between the two would be
/// refused as a malformed frame instead of being told its own size is why.
pub const INVENTORY_SNAPSHOT_DIGEST_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySnapshotDigestRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The harness the snapshot describes.
    pub agent_type: String,
    /// The runtime version recorded with the snapshot, or `null`.
    #[serde(default)]
    pub runtime_version: Option<String>,
    /// The snapshot's items, as the dataclass fields the digest reads. Fields
    /// the mirror does not name ride along so a default and an absent value
    /// stay distinguishable.
    #[serde(default)]
    pub items: Vec<Value>,
    /// The snapshot's findings, in the same form.
    #[serde(default)]
    pub findings: Vec<Value>,
    /// The snapshot's sources, in the same form.
    #[serde(default)]
    pub sources: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySnapshotDigestResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_inventory_snapshot_digest_*` codes.
    pub code: String,
    /// `{"digest": "<64 hex characters>"}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
