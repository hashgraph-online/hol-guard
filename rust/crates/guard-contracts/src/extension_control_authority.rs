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
//! that step under the exclusive authority lease. `write_anchor` writes an
//! anchor the store has earned into the credential vault, and
//! `seal_managed_revision` and `seal_managed_activation` seal the managed
//! controls publication epoch and activation, `apply_policy` activates a
//! verified policy bundle, `apply_review_memory` publishes Cloud Review
//! policy memory and `clear_policy` removes the cached remote policy
//! authority. When a read finds work only a writer may do --
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
/// Capability advertised when the `restore` and `roll_back` writer ops are
/// available.
pub const EXTENSION_CONTROL_AUTHORITY_WRITES_FEATURE: &str =
    "extension-control-authority-writes-v1";
/// Capability advertised when the `bootstrap`, `commit_prepare`, `resume`,
/// `migrate` and `write_manifest` writer ops are available.
pub const EXTENSION_CONTROL_AUTHORITY_COMMIT_FEATURE: &str =
    "extension-control-authority-commit-v1";
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
    /// `bootstrap`, `commit_prepare`, `resume`, `migrate`, `write_manifest`,
    /// `queue_change`, `apply_policy`, `apply_review_memory`, `clear_policy`,
    /// `write_anchor`, `seal_managed_revision`, `seal_managed_activation` or `anchor`.
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
    /// `write_anchor`: the revision the anchor pins.
    /// `queue_change`: the committed head whose change event is queued.
    /// `seal_managed_revision`: the managed publication epoch to seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_digest: Option<String>,
    /// `rollback_plan`: the transition digest of the prepared row the caller
    /// wrote itself and then failed to anchor. That row has no retry window to
    /// wait out: the request that would retry it is the caller, and it has
    /// already given up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_transition_digest: Option<String>,
    /// `write_anchor`: `anchored` or `committed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// The caller's clock, as Python's `datetime.now(timezone.utc).isoformat()`
    /// spells it, for the plan ops and `write_manifest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// `resume`: the pending cloud-event capacity the change event is queued
    /// under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_queue_limit: Option<i64>,
    /// `resume` from the commit that prepared the row: the hashed proof the
    /// commit consumes in the same transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
    /// `resume` from a retry of a commit that found its own prepared row: the
    /// proof the retry settles in the transaction that applies the verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_proof: Option<ExtensionControlRetryProofV1>,
    /// `history`: how many prior snapshots to list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// `commit_plan`: the mutation the caller's proof was validated against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<ExtensionControlCommitV1>,
    /// `migrate_plan` / `migrate`: the rebinding a read's `migrate_catalog`
    /// action named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_migration: Option<ExtensionControlCatalogMigrationV1>,
    /// `migrate`: what the migration event records beside the rebinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_record: Option<ExtensionControlMigrationRecordV1>,
    /// `write_manifest`: replace the manifest recorded for `catalog_digest`
    /// instead of recording its first one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_replace: Option<bool>,
    /// `resume` of a row whose commit activates a command pack: what the
    /// caller read from the protected store for the resident to check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_finish: Option<ExtensionControlPackFinishV1>,
    /// `commit_prepare` of a commit that activates a command pack: the
    /// staged activation and the protected state it was staged against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_reserve: Option<ExtensionControlPackReserveV1>,
    /// `seal_managed_activation`: the verified policy to activate on the
    /// authority committed under `catalog_digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_activation: Option<ExtensionControlManagedActivationV1>,
    /// `reset`: why the authority is reset, and whether the catalog
    /// manifests the lost key authenticated go with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<ExtensionControlResetV1>,
    /// `clear_policy`: the remote policy authority a clear removes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_clear: Option<ExtensionControlPolicyClearV1>,
    /// `apply_policy`: the verified policy bundle an activation writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_apply: Option<ExtensionControlPolicyApplyV1>,
    /// `apply_review_memory`: the Cloud Review policy memory a publish writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_memory: Option<ExtensionControlReviewMemoryV1>,
}

/// `apply_review_policy_memory_state`. The caller verifies and seals the
/// memory rules; the resident replaces the remote policy decisions with
/// them and writes the memory cursor state in one transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlReviewMemoryV1 {
    /// The memory registry, policy version and acknowledgement, as JSON text
    /// by `sync_state` key.
    #[serde(default)]
    pub payloads: BTreeMap<String, String>,
    /// The remote policy decisions that replace the stored ones, each in
    /// `policy_decisions` column order.
    #[serde(default)]
    pub rows: Vec<Vec<Value>>,
}

/// An authority reset: the rows whose chain cannot be verified are archived
/// under `reason` and removed so a fresh authority can be bootstrapped.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlResetV1 {
    pub reason: String,
    /// The key that authenticated the catalog manifests was lost.
    pub drop_manifest: bool,
}

/// `apply_policy_bundle_authority`. The caller verifies the bundle, seals the
/// managed state and encodes every payload first; the resident writes them
/// in one transaction only while the authority snapshot and each
/// `sync_state` value the caller read are unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPolicyApplyV1 {
    /// The authority snapshot the caller read; both absent when there was
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_snapshot_digest: Option<String>,
    /// The `sync_state` text the caller read, by key; `None` when the key
    /// was absent.
    #[serde(default)]
    pub observed: BTreeMap<String, Option<String>>,
    /// The `sync_state` payloads the activation writes, as JSON text by key.
    #[serde(default)]
    pub payloads: BTreeMap<String, String>,
    /// Removes the managed-controls activation and its negotiated
    /// capabilities: the bundle carries no managed controls.
    #[serde(default)]
    pub retire_managed: bool,
    /// The remote policy decisions that replace the stored ones, each in
    /// `policy_decisions` column order.
    #[serde(default)]
    pub rows: Vec<Vec<Value>>,
    /// The custom-extension continuity the activation carries, as the
    /// `apply_custom_extension_continuity` store method takes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<serde_json::Map<String, Value>>,
}

/// `clear_policy_bundle_authority`. Without `managed_revision` the resident
/// answers the publication epoch the clear moves to and the acknowledgement
/// stored now, and writes nothing. With it, the clear is written only while
/// the authority snapshot, that epoch and that acknowledgement are still the
/// ones the caller published from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPolicyClearV1 {
    /// The authority snapshot the caller read before the clear; both absent
    /// when there was none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_snapshot_digest: Option<String>,
    /// The publication epoch the plan answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_revision: Option<i64>,
    /// The `policy_bundle_ack` text the plan answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_ack: Option<String>,
    /// The `sync_state` payloads the clear writes, as JSON text by key.
    #[serde(default)]
    pub payloads: BTreeMap<String, String>,
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

/// What a committed catalog migration records: the provenance the caller
/// settled before the store transaction opened, the older writer the store is
/// handed back to when the migration is a downgrade, and the controls it
/// retires.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlMigrationRecordV1 {
    pub provenance: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downgraded_from: Option<String>,
    #[serde(default)]
    pub retired_target_ids: Vec<String>,
}

/// The protected state a command-pack activation is checked against. The
/// caller reads it from the policy-integrity store and writes the lifecycle
/// floor the resident names; the resident authenticates and decides.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPackFinishV1 {
    /// The command-pack verifier key, base64url without padding.
    pub key_b64: String,
    /// The protected lifecycle floor record, when one is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
    /// The active pack security record, when one is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// The retained evidence a link sealed before lifecycle binding needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_evidence: Option<Value>,
}

impl std::fmt::Debug for ExtensionControlPackFinishV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionControlPackFinishV1")
            .field("security", &self.security.is_some())
            .field("legacy_evidence", &self.legacy_evidence.is_some())
            .finish_non_exhaustive()
    }
}

/// The proof a commit retry settles with the verdict on its own prepared row:
/// recorded as consumed when the row commits, released when it is abandoned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlRetryProofV1 {
    /// The hashed proof identifier the commit plan named.
    pub proof_hash: String,
    /// The mutation digest the proof was validated against.
    pub mutation_digest: String,
}

/// A staged command-pack activation to reserve with the prepared row, and
/// the protected state the caller read for the resident to check it against.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPackReserveV1 {
    /// The command-pack verifier key, base64url without padding.
    pub key_b64: String,
    /// The protected lifecycle floor record, when one is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
    /// The active pack security record, when one is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// The sealed activation record.
    pub record_json: String,
    pub record_digest: String,
    pub record_mac: String,
    /// The active record the activation extends; none over a baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub lifecycle_before: String,
    pub lifecycle_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_digest: Option<String>,
    /// Unix seconds the activation is admitted at.
    pub admitted_at: i64,
}

impl std::fmt::Debug for ExtensionControlPackReserveV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionControlPackReserveV1")
            .field("record_digest", &self.record_digest)
            .field("previous_digest", &self.previous_digest)
            .field("admitted_at", &self.admitted_at)
            .finish_non_exhaustive()
    }
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
