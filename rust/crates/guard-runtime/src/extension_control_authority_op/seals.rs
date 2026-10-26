//! The records a writer seals outside a commit: the bootstrap snapshot, a
//! catalog migration, a last-good restore, the vault anchor and the trusted
//! catalog manifest.
//!
//! Like the commit plans, these ops never write. Each answers with what the
//! caller stores under the exclusive authority lease, or a `tampered` fault
//! carrying the message the Python writer raised for the refusal.

use std::path::Path;

use guard_contracts::ExtensionControlAuthorityRequestV1;
use serde_json::{json, Map, Value};

use super::layers::{
    layers_from_json, layers_from_values, layers_to_json, validate_serialized_layers,
};
use super::plans::{plan, sealed, with_pack};
use super::records::{
    authenticated_record, canonical, exact_int, field, private_hash, py_eq, query_row, row_int,
    row_text, snapshot_pack_binding, tampered, verify_record, Anchor, Phase, Res, ANCHOR_PURPOSE,
    CATALOG_MANIFEST_PURPOSE, SNAPSHOT_PURPOSE, TRANSITION_PURPOSE,
};
use super::Ctx;

/// The owner-only copy of the latest committed snapshot beside `guard.db`.
const LAST_GOOD_FILE_NAME: &str = "extension-control-last-good.json";
const LAST_GOOD_SCHEMA: &str = "guard.extension-control-last-good.v1";
const MAX_EXPORT_BYTES: usize = 1024 * 1024;
const EXPORT_FIELDS: [&str; 5] = [
    "revision",
    "catalog_digest",
    "layers_json",
    "previous_digest",
    "committed_at",
];
/// The actors a writer names when it commits on the store's own behalf.
const MIGRATION_ACTOR: &str = "trusted-catalog-migration";
const RESTORE_ACTOR: &str = "trusted-store-restore";

fn require_key(key: Option<&[u8]>) -> Res<&[u8]> {
    key.ok_or_else(|| tampered("extension control authentication key missing"))
}

/// `anchor_to_json`.
pub(super) fn anchor_json(anchor: &Anchor, key: &[u8]) -> Res<String> {
    let Value::Object(payload) = anchor.to_value() else {
        return Err(tampered("invalid authority anchor"));
    };
    let (record, digest, mac) = authenticated_record(&payload, key, ANCHOR_PURPOSE)?;
    canonical(&json!({ "record": record, "digest": digest, "mac": mac }))
}

/// `seal_anchor`: the anchor the caller writes to the credential store.
pub(super) fn seal_anchor_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let key = require_key(key)?;
    let (Some(revision), Some(snapshot_digest), Some(phase)) = (
        request.revision.filter(|revision| *revision >= 0),
        request
            .snapshot_digest
            .as_deref()
            .filter(|digest| digest.chars().count() == 64),
        request.phase.as_deref().and_then(Phase::parse),
    ) else {
        return Err(tampered("invalid authority anchor"));
    };
    let anchor = Anchor {
        revision,
        snapshot_digest: snapshot_digest.to_owned(),
        phase,
    };
    Ok(json!({ "anchor_json": anchor_json(&anchor, key)? }))
}

/// `seal_manifest`: the record `_write_catalog_manifest` stores for the
/// current catalog's trusted target manifest.
pub(super) fn seal_manifest_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let key = require_key(key)?;
    let (Some(catalog_digest), Some(manifest), Some(recorded_at)) = (
        request.catalog_digest.as_deref(),
        request.current_manifest.as_ref(),
        request.now.as_deref(),
    ) else {
        return Err(tampered("invalid extension control catalog manifest"));
    };
    let manifest_json = canonical(&json!(manifest))?;
    let record = sealed(
        json!({
            "catalog_digest": catalog_digest,
            "manifest_json": manifest_json,
            "recorded_at": recorded_at,
        }),
        key,
        CATALOG_MANIFEST_PURPOSE,
    )?;
    Ok(json!({
        "manifest_json": manifest_json,
        "recorded_at": recorded_at,
        "record": record,
    }))
}

/// `_count_controls`: zero for layers that do not decode.
fn count_controls(layers_json: &str) -> usize {
    layers_from_json(layers_json)
        .map(|layers| layers.iter().map(|layer| layer.controls.len()).sum())
        .unwrap_or(0)
}

/// The private hashes of a commit the store makes on its own behalf.
fn trusted_hashes(actor: &str, reference: &str, key: &[u8]) -> Value {
    json!({
        "actor": private_hash(actor, key, "actor"),
        "idempotency": private_hash(reference, key, "idempotency"),
        "nonce": private_hash(reference, key, "nonce"),
    })
}

fn transition_payload(
    revision: i64,
    previous_digest: &Value,
    snapshot_digest: &Value,
    catalog_digest: &str,
    hashes: &Value,
    created_at: &str,
) -> Value {
    json!({
        "revision": revision,
        "previous_revision": revision - 1,
        "previous_digest": previous_digest,
        "snapshot_digest": snapshot_digest,
        "catalog_digest": catalog_digest,
        "actor_id_hash": hashes["actor"],
        "idempotency_key_hash": hashes["idempotency"],
        "nonce_hash": hashes["nonce"],
        "created_at": created_at,
        "phase": Phase::Prepared.as_str(),
    })
}

/// `_verified_last_good_export`: the export's verified snapshot fields, or
/// `None` for an export that is absent, unreadable or does not verify.
fn verified_export(guard_home: &str, key: &[u8]) -> Option<Map<String, Value>> {
    let home = std::fs::canonicalize(Path::new(guard_home)).ok()?;
    let read =
        guard_secure_fs::read_bounded(&home.join(LAST_GOOD_FILE_NAME), MAX_EXPORT_BYTES).ok()?;
    let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(&read.bytes) else {
        return None;
    };
    if !py_eq(field(&raw, "schema"), &json!(LAST_GOOD_SCHEMA)) {
        return None;
    }
    let (Some(snapshot_json), Some(digest), Some(mac)) = (
        field(&raw, "snapshot_json").as_str(),
        field(&raw, "snapshot_digest").as_str(),
        field(&raw, "snapshot_mac").as_str(),
    ) else {
        return None;
    };
    let mut payload = verify_record(snapshot_json, digest, mac, key, SNAPSHOT_PURPOSE).ok()?;
    if EXPORT_FIELDS
        .iter()
        .any(|name| !py_eq(field(&payload, name), field(&raw, name)))
    {
        return None;
    }
    exact_int(field(&payload, "revision")).filter(|revision| *revision >= 0)?;
    if !["catalog_digest", "layers_json", "committed_at"]
        .iter()
        .all(|name| field(&payload, name).is_string())
    {
        return None;
    }
    payload.insert("snapshot_json".to_owned(), json!(snapshot_json));
    payload.insert("snapshot_digest".to_owned(), json!(digest));
    payload.insert("snapshot_mac".to_owned(), json!(mac));
    Some(payload)
}

impl Ctx<'_> {
    fn now(&self) -> Res<&str> {
        self.request
            .now
            .as_deref()
            .ok_or_else(|| tampered("invalid extension control writer request"))
    }

    /// `bootstrap_plan`: the empty revision-zero snapshot of a new authority.
    pub(super) fn bootstrap_plan(&self) -> Res<Value> {
        let key = self.require_key()?;
        let catalog_digest = self.catalog_digest()?;
        let committed_at = self.now()?;
        if self.snapshot_row()?.is_some() {
            return Err(tampered("extension control authority already exists"));
        }
        let layers_json = layers_to_json(&[])?;
        let snapshot = sealed(
            json!({
                "revision": 0,
                "catalog_digest": catalog_digest,
                "layers_json": layers_json,
                "previous_digest": null,
                "committed_at": committed_at,
            }),
            key,
            SNAPSHOT_PURPOSE,
        )?;
        Ok(plan(
            "bootstrap",
            Map::from_iter([
                ("layers_json".to_owned(), json!(layers_json)),
                ("committed_at".to_owned(), json!(committed_at)),
                ("snapshot".to_owned(), snapshot),
            ]),
        ))
    }

    /// `migrate_plan`: the records `_migrate_extension_control_catalog`
    /// commits for the rebinding a read named.
    pub(super) fn migrate_plan(&self) -> Res<Value> {
        let key = self.require_key()?;
        let catalog_digest = self.catalog_digest()?;
        let created_at = self.now()?;
        let migration = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered("invalid extension control catalog migration"))?;
        let layers_json = layers_to_json(&layers_from_values(&migration.layers)?)?;
        validate_serialized_layers(&layers_json)?;
        let source = self.snapshot_row()?;
        let previous_digest = match &source {
            Some(row)
                if row_text(row, "catalog_digest")? == migration.previous_catalog_digest
                    && row_int(row, "revision")? == migration.previous_revision =>
            {
                row_text(row, "snapshot_digest")?
            }
            _ => {
                return Err(tampered(
                    "extension control catalog migration source changed",
                ))
            }
        };
        let revision = migration.previous_revision + 1;
        let source_row = source
            .as_ref()
            .ok_or_else(|| tampered("migration source missing"))?;
        let pack_digest = self.installed_upgrade_digest(source_row)?;
        let retained = snapshot_pack_binding(source_row, key)?;
        let reference = format!(
            "catalog-migration:{}:{catalog_digest}:{}",
            migration.previous_catalog_digest, migration.previous_revision
        );
        let hashes = trusted_hashes(MIGRATION_ACTOR, &reference, key);
        let snapshot_payload = json!({
            "revision": revision,
            "catalog_digest": catalog_digest,
            "layers_json": layers_json,
            "previous_digest": previous_digest,
            "committed_at": created_at,
        });
        let snapshot = sealed(
            with_pack(
                snapshot_payload,
                pack_digest.as_deref().or(retained.as_deref()),
            ),
            key,
            SNAPSHOT_PURPOSE,
        )?;
        let transition = sealed(
            with_pack(
                transition_payload(
                    revision,
                    &json!(previous_digest),
                    &snapshot["digest"],
                    catalog_digest,
                    &hashes,
                    created_at,
                ),
                pack_digest.as_deref(),
            ),
            key,
            TRANSITION_PURPOSE,
        )?;
        Ok(plan(
            "migrate",
            Map::from_iter([
                ("revision".to_owned(), json!(revision)),
                ("previous_digest".to_owned(), json!(previous_digest)),
                ("created_at".to_owned(), json!(created_at)),
                ("layers_json".to_owned(), json!(layers_json)),
                ("hashes".to_owned(), hashes),
                ("snapshot".to_owned(), snapshot),
                ("transition".to_owned(), transition),
                ("command_pack_record_digest".to_owned(), json!(pack_digest)),
            ]),
        ))
    }

    /// `restore_plan`: `_restore_last_good_authority`. The export restores
    /// the snapshot row only when it verifies, matches the committed vault
    /// anchor exactly and the row is missing; a missing baseline transition
    /// is sealed so the chain validates from the restored head.
    pub(super) fn restore_plan(&self) -> Res<Value> {
        let key = self.require_key()?;
        let restored_at = self.now()?;
        let skip = || Ok(plan("skip", Map::new()));
        let Some(anchor) = self
            .anchor()?
            .filter(|anchor| anchor.phase == Phase::Committed)
        else {
            return skip();
        };
        let Some(exported) = verified_export(&self.request.guard_home, key) else {
            return skip();
        };
        let revision = exact_int(field(&exported, "revision")).unwrap_or(-1);
        let snapshot_digest = field(&exported, "snapshot_digest")
            .as_str()
            .unwrap_or_default();
        if revision != anchor.revision || snapshot_digest != anchor.snapshot_digest {
            return skip();
        }
        if self.snapshot_row()?.is_some() {
            return skip();
        }
        let text = |name: &str| {
            field(&exported, name)
                .as_str()
                .unwrap_or_default()
                .to_owned()
        };
        let (catalog_digest, layers_json, committed_at) = (
            text("catalog_digest"),
            text("layers_json"),
            text("committed_at"),
        );
        let previous_digest = field(&exported, "previous_digest").clone();
        let mut fields = Map::from_iter([
            ("revision".to_owned(), json!(revision)),
            ("catalog_digest".to_owned(), json!(catalog_digest)),
            ("layers_json".to_owned(), json!(layers_json)),
            ("previous_digest".to_owned(), previous_digest.clone()),
            (
                "snapshot".to_owned(),
                json!({
                    "json": text("snapshot_json"),
                    "digest": snapshot_digest,
                    "mac": text("snapshot_mac"),
                }),
            ),
            ("committed_at".to_owned(), json!(committed_at)),
            ("restored_at".to_owned(), json!(restored_at)),
            (
                "control_count".to_owned(),
                json!(count_controls(&layers_json)),
            ),
        ]);
        let baseline_exists = query_row(
            self.connection,
            "select 1 from extension_control_authority_transition where revision = ?",
            [revision],
        )?
        .is_some();
        if revision > 0 && !baseline_exists {
            if !previous_digest.is_string() {
                return skip();
            }
            // The baseline's created_at equals the restored snapshot's
            // committed_at, so chain validation accepts the pair.
            let reference = format!("restored-baseline:{revision}:{snapshot_digest}");
            let hashes = trusted_hashes(RESTORE_ACTOR, &reference, key);
            let mut payload = transition_payload(
                revision,
                &previous_digest,
                &json!(snapshot_digest),
                &catalog_digest,
                &hashes,
                &committed_at,
            );
            payload["restored_baseline"] = json!(true);
            fields.insert(
                "baseline".to_owned(),
                json!({
                    "hashes": hashes,
                    "transition": sealed(payload, key, TRANSITION_PURPOSE)?,
                }),
            );
        }
        Ok(plan("restore", fields))
    }
}
