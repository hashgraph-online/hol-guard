//! `InventorySourceEvidence` - wire contract for the resident op that reads an
//! inventory item's source of truth off the filesystem.
//!
//! Two readings decide what a snapshot records about where an item really
//! comes from: the content hash of its primary document, and, when its config
//! path is a symlink, where that link leads. Both walk paths the user did not
//! write and both must stay inside the roots the caller names, so the resident
//! does the walking and hands back fingerprints rather than raw local paths.
//!
//! The answer also names the instruction role an overlay's configured path
//! stands for - the `AGENTS.md` of a workspace, a `.cursor/rules` file, a
//! document under `docs/security` - because that reading is the same grammar
//! the discovery walk already applies, and a second copy of it would let the
//! role a scan records drift from the role discovery assigned.
//!
//! A snapshot asks once for the whole detection: the entries ride together so
//! an inventory of a few hundred artifacts costs one round trip rather than
//! one per artifact.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA: &str =
    "guard-inventory-source-evidence-request.v1";
/// Schema discriminator for the result.
pub const INVENTORY_SOURCE_EVIDENCE_RESULT_SCHEMA: &str =
    "guard-inventory-source-evidence-result.v1";
/// Capability advertised by the runtime when this operation is available.
///
/// The version marks what the answer carries, not the schema. A v2 resident
/// derives an artifact's item kind and answers with it, so a v2 client sends
/// no kind of its own; a v1 resident refuses an entry without that field, and
/// a client that cannot spell it must not be routed to one. A v3 resident also
/// reads the instruction role an overlay's configured path names, which a v2
/// answer leaves out entirely.
pub const INVENTORY_SOURCE_EVIDENCE_FEATURE: &str = "inventory-source-evidence-v3";
/// Same wire schema, before the resident answered the instruction role. Still
/// advertised so a client built against it keeps its inventory.
pub const INVENTORY_SOURCE_EVIDENCE_PREVIOUS_FEATURE: &str = "inventory-source-evidence-v2";
/// Same wire schema, before the resident owned the item-kind mapping. Still
/// advertised for the same reason.
pub const INVENTORY_SOURCE_EVIDENCE_FIRST_FEATURE: &str = "inventory-source-evidence-v1";
/// Largest canonical request serialization the op will accept.
pub const INVENTORY_SOURCE_EVIDENCE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most entries one request may carry. A detection covering more than this
/// asks again with the next batch rather than growing the request unbounded.
pub const INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES: usize = 512;

/// One artifact's identity, as much of it as the two readings need.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySourceEvidenceEntryV1 {
    /// The harness the artifact belongs to, used to spell the source link id.
    pub harness: String,
    /// The snapshot's own kind for the artifact, as a client built before the
    /// op derived it spells the field.
    ///
    /// The op now maps the kind from `artifact_type` and answers with it, so a
    /// current caller leaves the field out. The field stays accepted because
    /// an older client still sends it and `deny_unknown_fields` would cost
    /// that pairing its whole inventory. Nothing reads it.
    ///
    /// It is optional rather than defaulted so that an absent field stays
    /// absent when the request is re-serialized: the reply binds the caller by
    /// the digest of that serialization, and an empty string written where the
    /// caller sent no key at all would leave every answer unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_kind: Option<String>,
    /// The artifact type, which decides whether a primary document hash is
    /// defined at all: only `skill` and `instruction` carry one.
    pub artifact_type: String,
    /// The artifact's configured path. An entry without one still gets an
    /// answer, with both readings absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// The same path as the harness wrote it, when the caller had to anchor a
    /// relative one to reach the filesystem.
    ///
    /// Only the instruction role reads it. A role is a reading of the path a
    /// harness configured, so a relative `notes.md` names no role wherever the
    /// scan happens to run; classifying the anchored path instead would let
    /// the working directory's own components - a scan started inside
    /// `docs/security`, or `.cursor/rules` - hand that role to a document
    /// whose configured path never named it. The two readings that walk the
    /// filesystem keep using `config_path`, which is the only one that
    /// resolves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySourceEvidenceRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The user's home directory: one of the safe roots, and the directory
    /// every redacted path is spelled relative to.
    pub home_dir: String,
    /// The workspace being scanned, when there is one. It is the preferred
    /// safe root and it changes how a relative link target is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// Whether the caller wants source-of-truth metadata at all.
    pub include_symlinks: bool,
    /// Whether a link leading outside the safe roots is followed rather than
    /// recorded as blocked.
    pub follow_unsafe_symlinks: bool,
    /// The artifacts to read, in the caller's order.
    pub entries: Vec<InventorySourceEvidenceEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventorySourceEvidenceResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_inventory_source_evidence_*` codes.
    pub code: String,
    /// `{"evidence": [{"item_kind": "overlay", "source_of_truth": {...}|null,
    /// "primary_content_hash": "sha256:..."|null,
    /// "instruction_role": "agents_md"|null}, ...]}`, one entry per requested
    /// artifact, in the order the request listed them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
