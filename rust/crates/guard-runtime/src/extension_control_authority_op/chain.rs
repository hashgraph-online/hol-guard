//! The authenticated transition chain behind a committed snapshot, the
//! pending transition above it, and the catalog-migration history it records.

use std::collections::BTreeSet;

use guard_command::extension_control::ExtensionControlLayer;
use rusqlite::params;
use serde_json::{json, Value};

use super::layers::{
    layers_from_json, layers_to_values, validate_layers, validate_serialized_layers,
};
use super::records::{
    field, fields_match, private_hash, py_eq, query_row, query_rows, row_int, row_str, row_text,
    tampered, verify_record, Phase, Res, Row, SNAPSHOT_PURPOSE, TRANSITION_PURPOSE,
};
use super::Ctx;

const MIGRATED_EVENT: &str = "extension_control_authority_catalog_migrated";

impl Ctx<'_> {
    /// `_pending_transition`.
    pub(super) fn pending_transition(&self, revision: i64) -> Res<Option<Row>> {
        query_row(
            self.connection,
            "select * from extension_control_authority_transition where revision = ?",
            params![revision],
        )
    }

    /// `_validate_transition_chain`.
    pub(super) fn validate_transition_chain(
        &self,
        revision: i64,
        current_snapshot_digest: &str,
    ) -> Res<()> {
        let key = self.require_key()?;
        let rows = query_rows(
            self.connection,
            "select * from extension_control_authority_transition order by revision",
            [],
        )?;
        let mut committed = Vec::new();
        for row in rows {
            if row_str(&row, "phase")? == Phase::Committed.as_str() {
                committed.push(row);
            }
        }
        let revisions = committed
            .iter()
            .map(|row| row_int(row, "revision"))
            .collect::<Res<Vec<_>>>()?;
        let first = revisions.first().copied().unwrap_or(revision + 1);
        let expected: Vec<i64> = if first <= revision {
            (first..=revision).collect()
        } else {
            Vec::new()
        };
        if revisions != expected || (revision > 0 && revisions.is_empty()) {
            return Err(tampered("extension control transition gap"));
        }
        if first > 1 && !is_restored_baseline(&committed[0], key)? {
            return Err(tampered("extension control transition gap"));
        }
        let mut prior_snapshot_digest: Option<String> = None;
        for row in &committed {
            let row_revision = row_int(row, "revision")?;
            let previous_revision = row_int(row, "previous_revision")?;
            if previous_revision != row_revision - 1 {
                return Err(tampered("extension control transition chain mismatch"));
            }
            let layers_json = row_str(row, "layers_json")?;
            validate_serialized_layers(&layers_json)?;
            let snapshot = verify_record(
                &row_str(row, "snapshot_json")?,
                &row_str(row, "snapshot_digest")?,
                &row_str(row, "snapshot_mac")?,
                key,
                SNAPSHOT_PURPOSE,
            )?;
            let Some(Value::String(previous_digest)) = snapshot.get("previous_digest").cloned()
            else {
                return Err(tampered("extension control transition chain mismatch"));
            };
            if prior_snapshot_digest
                .as_ref()
                .is_some_and(|prior| *prior != previous_digest)
            {
                return Err(tampered("extension control transition chain mismatch"));
            }
            let catalog_digest = row_str(row, "catalog_digest")?;
            let created_at = row_str(row, "created_at")?;
            let snapshot_digest = row_str(row, "snapshot_digest")?;
            if !fields_match(
                &snapshot,
                &[
                    ("revision", Some(json!(row_revision))),
                    ("catalog_digest", Some(json!(catalog_digest))),
                    ("layers_json", Some(json!(layers_json))),
                    ("previous_digest", Some(json!(previous_digest))),
                    ("committed_at", Some(json!(created_at))),
                ],
            ) {
                return Err(tampered("extension control transition snapshot mismatch"));
            }
            validate_layers(&layers_from_json(&layers_json)?, &catalog_digest)?;
            let transition = verify_record(
                &row_str(row, "transition_json")?,
                &row_str(row, "transition_digest")?,
                &row_str(row, "transition_mac")?,
                key,
                TRANSITION_PURPOSE,
            )?;
            if !fields_match(
                &transition,
                &[
                    ("revision", Some(json!(row_revision))),
                    ("previous_revision", Some(json!(previous_revision))),
                    ("previous_digest", Some(json!(previous_digest))),
                    ("snapshot_digest", Some(json!(snapshot_digest))),
                    ("catalog_digest", Some(json!(catalog_digest))),
                    ("actor_id_hash", Some(json!(row_str(row, "actor_id_hash")?))),
                    (
                        "idempotency_key_hash",
                        Some(json!(row_str(row, "idempotency_key_hash")?)),
                    ),
                    ("nonce_hash", Some(json!(row_str(row, "nonce_hash")?))),
                    ("created_at", Some(json!(created_at))),
                    ("phase", Some(json!(Phase::Prepared.as_str()))),
                ],
            ) {
                return Err(tampered("extension control transition field mismatch"));
            }
            prior_snapshot_digest = Some(snapshot_digest);
        }
        if prior_snapshot_digest.is_some_and(|prior| prior != current_snapshot_digest) {
            return Err(tampered("extension control transition head mismatch"));
        }
        Ok(())
    }

    /// `_is_catalog_migration`.
    fn is_catalog_migration(
        &self,
        revision: i64,
        migrated_from: &str,
        migrated_to: &str,
    ) -> Res<bool> {
        if revision <= 0 {
            return Ok(false);
        }
        let Some(row) = query_row(
            self.connection,
            "select idempotency_key_hash from extension_control_authority_transition where revision = ?",
            params![revision],
        )?
        else {
            return Ok(false);
        };
        let reference = format!(
            "catalog-migration:{migrated_from}:{migrated_to}:{}",
            revision - 1
        );
        Ok(row_str(&row, "idempotency_key_hash")?
            == private_hash(&reference, self.require_key()?, "idempotency"))
    }

    /// `_catalog_migration_oscillates`.
    pub(super) fn migration_oscillates(
        &self,
        revision: i64,
        migrated_from: &str,
        migrated_to: &str,
    ) -> Res<bool> {
        Ok(
            self.is_catalog_migration(revision, migrated_from, migrated_to)?
                && self.is_catalog_migration(revision - 1, migrated_to, migrated_from)?,
        )
    }

    /// `_ensure_catalog_migrated_event`, minus the write: the migration event
    /// a protected read still owes the store, if any. The caller records it.
    pub(super) fn catalog_migrated_backfill(
        &self,
        revision: i64,
        catalog_digest: &str,
        layers: &[ExtensionControlLayer],
    ) -> Res<Option<Value>> {
        if revision < 1 {
            return Ok(None);
        }
        let Some(current) = query_row(
            self.connection,
            "select previous_revision, catalog_digest, layers_json from extension_control_authority_transition \
             where revision = ?",
            params![revision],
        )?
        else {
            return Ok(None);
        };
        if row_str(&current, "catalog_digest")? != catalog_digest {
            return Ok(None);
        }
        let previous_revision = row_int(&current, "previous_revision")?;
        let Some(previous) = query_row(
            self.connection,
            "select catalog_digest, layers_json from extension_control_authority_transition where revision = ?",
            params![previous_revision],
        )?
        else {
            return Ok(None);
        };
        let previous_catalog_digest = row_str(&previous, "catalog_digest")?;
        if previous_catalog_digest == catalog_digest {
            return Ok(None);
        }
        let previous_targets: BTreeSet<String> =
            layers_from_json(&row_str(&previous, "layers_json")?)?
                .iter()
                .flat_map(|layer| {
                    layer
                        .controls
                        .iter()
                        .map(|control| control.target.target_id.clone())
                })
                .collect();
        let current_targets: BTreeSet<&str> = layers
            .iter()
            .flat_map(|layer| {
                layer
                    .controls
                    .iter()
                    .map(|control| control.target.target_id.as_str())
            })
            .collect();
        let retired: Vec<&String> = previous_targets
            .iter()
            .filter(|target| !current_targets.contains(target.as_str()))
            .collect();
        if self.migration_event_recorded(revision)? {
            return Ok(None);
        }
        Ok(Some(json!({
            "previous_revision": previous_revision,
            "revision": revision,
            "previous_catalog_digest": previous_catalog_digest,
            "catalog_digest": catalog_digest,
            "layers": layers_to_values(layers),
            "retired_targets": retired,
        })))
    }

    /// `already_recorded`.
    fn migration_event_recorded(&self, revision: i64) -> Res<bool> {
        let rows = query_rows(
            self.connection,
            "select payload_json from guard_events where event_name = ?",
            params![MIGRATED_EVENT],
        )?;
        for row in rows {
            let text = row_text(&row, "payload_json")?;
            if let Ok(Value::Object(recorded)) = serde_json::from_str::<Value>(&text) {
                if py_eq(field(&recorded, "revision"), &json!(revision)) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// `_is_restored_baseline`.
fn is_restored_baseline(row: &Row, key: &[u8]) -> Res<bool> {
    let payload = verify_record(
        &row_str(row, "transition_json")?,
        &row_str(row, "transition_digest")?,
        &row_str(row, "transition_mac")?,
        key,
        TRANSITION_PURPOSE,
    )?;
    Ok(payload.get("restored_baseline") == Some(&Value::Bool(true)))
}
