//! `ExtensionControlAuthority` - wire contract for the resident op that
//! verifies the authenticated extension-control authority kept in the guard
//! store.
//!
//! The authority is a committed snapshot, its chain of authenticated
//! transitions, the trusted catalog manifests and the managed-controls
//! activation, all bound by a per-home authentication key and a vault anchor.
//! The resident reads and verifies every one of them; nothing it reads is
//! trusted in Python. The key and the anchor live in the OS-keyring-facing
//! credential store, so the transport reads them and ships them here along
//! with the clock.
//!
//! The op never writes. When a read finds work only a writer may do --
//! restoring the last-good export, resuming or abandoning a prepared
//! transition, or committing a catalog migration -- it answers with an
//! `action` naming that work and the authenticated inputs it needs. The caller
//! performs it under the exclusive authority lease and repeats the read. It
//! may answer `{"need": "current_manifest"}` when the request carried only the
//! manifest digest and the full manifest is required.
//!
//! Each request names one `op` and carries only the fields that op reads.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const EXTENSION_CONTROL_AUTHORITY_REQUEST_SCHEMA: &str =
    "guard-extension-control-authority-request.v1";
/// Schema discriminator for the result.
pub const EXTENSION_CONTROL_AUTHORITY_RESULT_SCHEMA: &str =
    "guard-extension-control-authority-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const EXTENSION_CONTROL_AUTHORITY_FEATURE: &str = "extension-control-authority-v1";
/// Largest canonical request the resident accepts. A request carries at most
/// two catalog manifests, one fingerprint per catalog target.
pub const EXTENSION_CONTROL_AUTHORITY_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlAuthorityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the resolved guard home.
    pub guard_home: String,
    /// `read`, `read_composed`, `sync_manifest`, `compose_managed`,
    /// `managed_activation`, `managed_revision`, `load_manifest`,
    /// `validate_chain` or `anchor`.
    pub op: String,
    /// Authority authentication key bytes (base64url, no padding); absent
    /// when the credential store holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_b64: Option<String>,
    /// The anchor exactly as the credential store returned it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_digest: Option<String>,
    /// The trusted target manifest of the current catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_manifest: Option<BTreeMap<String, String>>,
    /// SHA-256 of the current manifest's canonical JSON, sent instead of the
    /// manifest when the caller does not yet know the read needs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_manifest_sha256: Option<String>,
    /// `compose_managed`: the manifest the controls were last bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_manifest: Option<BTreeMap<String, String>>,
    /// `read`: the caller holds a registry for `catalog_digest`, so a stored
    /// authority under another catalog may be rebound to it.
    #[serde(default)]
    pub migration: bool,
    /// `read` / `sync_manifest`: the caller holds the exclusive lease and may
    /// commit.
    #[serde(default)]
    pub allow_migration: bool,
    /// `read`: the caller already attempted the named writer action, so the
    /// read reports the state it leaves instead of asking again.
    #[serde(default)]
    pub restore_attempted: bool,
    #[serde(default)]
    pub resume_attempted: bool,
    #[serde(default)]
    pub rollback_attempted: bool,
    /// `sync_manifest` / `compose_managed`: the authority view to work on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<Value>,
    /// `managed_activation` / `managed_revision`: the decoded state value.
    /// `managed_activation` checks it against `catalog_digest`, or against
    /// the catalog the state names when that is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    /// `validate_chain`: the committed head to validate up to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlAuthorityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_extension_control_authority_*` codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
