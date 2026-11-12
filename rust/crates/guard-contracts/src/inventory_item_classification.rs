//! `InventoryItemClassification` - wire contract for the resident op that
//! decides what an inventory item is.
//!
//! Six deterministic readings of one artifact's metadata settle its kind, the
//! capabilities it declares, its risk level, the content hash that identifies
//! it, and which evidence keys a skill may keep. Every one of them is a
//! protection decision: an item whose risk level silently reads `info`, or
//! whose documented capabilities survive without evidence that matches the
//! body Guard hashed, is a weaker inventory than the scan actually found.
//! `guard_command::inventory_item_metadata` already owns the grammar, pinned
//! by `testdata/inventory_item_metadata_parity.json`, so Python asks for the
//! answers instead of keeping a second copy of the rules.
//!
//! A scan asks once for every artifact it detected: the entries ride together
//! so an inventory of a few hundred artifacts costs one round trip.
//!
//! The answer carries the metadata changes as key edits rather than as a
//! rewritten object, so the caller's own insertion order survives a scan.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const INVENTORY_ITEM_CLASSIFICATION_REQUEST_SCHEMA: &str =
    "guard-inventory-item-classification-request.v1";
/// Schema discriminator for the result.
pub const INVENTORY_ITEM_CLASSIFICATION_RESULT_SCHEMA: &str =
    "guard-inventory-item-classification-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const INVENTORY_ITEM_CLASSIFICATION_FEATURE: &str = "inventory-item-classification-v1";
/// Largest canonical request serialization the op will accept.
///
/// Held under [`MAX_NATIVE_REQUEST_BYTES`](crate::MAX_NATIVE_REQUEST_BYTES),
/// which the transport enforces on the frame before this op ever sees it. A
/// bound above that would be unreachable: a batch between the two would be
/// refused as a malformed frame instead of being told its own size is why.
pub const INVENTORY_ITEM_CLASSIFICATION_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most entries one request may carry. A scan covering more than this asks
/// again with the next batch rather than growing the request unbounded.
pub const INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES: usize = 512;

/// One detected artifact, as much of it as the six readings need.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryItemClassificationEntryV1 {
    /// The artifact's identity, which rides into the semantic fingerprint.
    pub artifact_id: String,
    /// The native artifact category the kind and capabilities are read from.
    pub artifact_type: String,
    /// The artifact's display name, which also rides into the fingerprint.
    pub name: String,
    /// The artifact's metadata after the filesystem readings the caller owns.
    pub metadata: Map<String, Value>,
    /// The hash of Guard's own full read of the primary document, when the
    /// artifact has one. Absent and `null` both mean there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryItemClassificationRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The artifacts to classify, in the caller's order.
    pub entries: Vec<InventoryItemClassificationEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryItemClassificationResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_inventory_item_classification_*` codes.
    pub code: String,
    /// `{"items": [{"item_kind": "skill", "capability_categories": [...],
    /// "risk_level": "info", "content_hash": "sha256:...",
    /// "metadata_removals": [...], "metadata_updates": {...}}, ...]}`, one
    /// entry per requested artifact, in the order the request listed them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
