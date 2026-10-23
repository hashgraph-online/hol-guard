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
//! The op never writes. The `commit_plan`, `resume_plan`, `rollback_plan`,
//! `bootstrap_plan`, `migrate_plan` and `restore_plan` ops decide a writer's
//! next step -- the checks a commit, bootstrap, catalog migration or
//! last-good restore must pass, the records it seals, and whether a prepared
//! transition is resumed, committed or abandoned -- and the caller performs
//! that step under the exclusive authority lease. `seal_anchor` and
//! `seal_manifest` seal the anchor and catalog manifest records it stores,
//! and `seal_managed_revision` and `seal_managed_activation` the managed
//! controls publication epoch and activation. When a read finds work only a writer may do --
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
///
/// Held under [`MAX_NATIVE_REQUEST_BYTES`](crate::MAX_NATIVE_REQUEST_BYTES),
/// which the transport enforces on the frame before this op ever sees it. A
/// bound above that would be unreachable: a request between the two would be
/// refused as a malformed frame instead of being told its own size is why.
pub const EXTENSION_CONTROL_AUTHORITY_MAX_BYTES: usize = 6 * 1024 * 1024 - 64 * 1024;

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
    /// `validate_chain`, `history`, `commit_plan`, `resume_plan`,
    /// `rollback_plan`, `bootstrap_plan`, `migrate_plan`, `restore_plan`,
    /// `seal_anchor`, `seal_manifest`, `seal_managed_revision`,
    /// `seal_managed_activation` or `anchor`.
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
    /// `resume_plan`: the prepared transition to resume.
    /// `rollback_plan`: the committed head the prepared transition sits on.
    /// `seal_anchor`: the revision the anchor pins.
    /// `seal_managed_revision`: the managed publication epoch to seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_digest: Option<String>,
    /// `seal_anchor`: `prepared`, `anchored` or `committed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// The caller's clock, as Python's `datetime.now(timezone.utc).isoformat()`
    /// spells it, for the plan ops and `seal_manifest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// `history`: how many prior snapshots to list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// `commit_plan`: the mutation the caller's proof was validated against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<ExtensionControlCommitV1>,
    /// `migrate_plan`: the rebinding a read's `migrate_catalog` action named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_migration: Option<ExtensionControlCatalogMigrationV1>,
    /// `seal_managed_activation`: the verified policy to activate on the
    /// authority committed under `catalog_digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_activation: Option<ExtensionControlManagedActivationV1>,
}

/// A verified managed-controls policy and the local authority it activates
/// on. The resident builds, acknowledges and seals the activation record.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlManagedActivationV1 {
    /// The signed bundle's `bundleHash`, `bundleVersion`, `workspaceId`,
    /// `payloadHash`, `issuedAt` and `expiresAt` as received, and `payload`
    /// carrying only the payload's `metadata`.
    pub bundle: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_mode: Option<String>,
    /// The policy's signed Cloud layer, when it has one, as `layers_to_json`
    /// values.
    pub signed_cloud_layers: Value,
    pub rule_targets: Value,
    pub delegated_targets: Value,
    pub base_revision: i64,
    pub base_snapshot_digest: String,
    pub managed_revision: i64,
    pub negotiated_capabilities: Vec<String>,
}

/// A catalog migration as the read's `migrate_catalog` action named it: the
/// committed head it starts from and the layers rebound to `catalog_digest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlCatalogMigrationV1 {
    pub previous_revision: i64,
    pub previous_catalog_digest: String,
    pub layers: Value,
    /// Authenticated installed-release replacement of the same active selection.
    /// Ordinary catalog migrations cannot change the active pack record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_upgrade: Option<Value>,
}

/// One requested extension-control commit. The identities are sent as the
/// caller received them; the resident keys them into private hashes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlCommitV1 {
    pub actor_id: String,
    pub idempotency_key: String,
    pub nonce: String,
    pub proof_id: String,
    /// The digest the commit proof was granted for. The plan recomputes it
    /// from these layers, identities and `expected_revision` and refuses a
    /// commit it does not match.
    pub mutation_digest: String,
    /// The requested layers, serialized as `layers_to_json` writes them.
    pub layers_json: String,
    pub expected_revision: i64,
    /// The activated command pack record, when the commit activates one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_record_digest: Option<String>,
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
