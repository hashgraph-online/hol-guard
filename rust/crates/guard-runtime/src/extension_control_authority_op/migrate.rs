//! `migrate`: the resident commits a catalog migration itself.
//!
//! This is `_migrate_extension_control_catalog` for a rebinding that activates
//! no command pack. The plan is taken inside the immediate transaction that
//! writes the prepared row, the anchored anchor is sealed into the credential
//! vault and read back, and the second transaction moves the snapshot, commits
//! the row and records the migration event before the committed anchor is
//! sealed. A plan that reserves a command pack is refused: its activation
//! journal stays with the caller.
//!
//! The caller settles the migration's provenance before the op opens a store
//! transaction, so a slow provenance lookup never holds the write lock.

use std::cell::RefCell;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlMigrationRecordV1};
use rusqlite::params;
use serde_json::{json, Value};

use super::chain::MIGRATED_EVENT;
use super::layers::layers_from_values;
use super::records::{canonical, degraded, store_fault, tampered, Anchor, Phase, Res};
use super::resume::immediate;
use super::seals::anchor_json;
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};

const INVALID_MIGRATION: &str = "invalid extension control catalog migration";
const REGRESSED_EVENT: &str = "extension_control_authority_catalog_regressed";

pub(super) fn migrate_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let Some(connection) = open_writer(request)? else {
        return Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    };
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    let outcome = ctx.migrate_catalog();
    let events = ctx.events.take();
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

fn text(value: &Value) -> Res<&str> {
    value.as_str().ok_or_else(|| tampered(INVALID_MIGRATION))
}

fn int(value: &Value) -> Res<i64> {
    value.as_i64().ok_or_else(|| tampered(INVALID_MIGRATION))
}

/// `build_catalog_migration_payload`: the migration event, and the regression
/// row when the migration hands the store back to an older writer.
fn migration_events(
    request: &ExtensionControlAuthorityRequestV1,
    record: &ExtensionControlMigrationRecordV1,
    revision: i64,
) -> Res<(String, Option<String>)> {
    let migration = request
        .catalog_migration
        .as_ref()
        .ok_or_else(|| tampered(INVALID_MIGRATION))?;
    let catalog_digest = request
        .catalog_digest
        .as_deref()
        .ok_or_else(|| tampered(INVALID_MIGRATION))?;
    let layers = layers_from_values(&migration.layers)?;
    let retired = &record.retired_target_ids;
    let mut payload = json!({
        "previous_revision": migration.previous_revision,
        "revision": revision,
        "previous_catalog_digest": migration.previous_catalog_digest,
        "catalog_digest": catalog_digest,
        "layer_count": layers.len(),
        "control_count": layers.iter().map(|layer| layer.controls.len()).sum::<usize>(),
        "retired_target_count": retired.len(),
        "retired_target_ids": retired,
        "provenance": record.provenance,
    });
    let Some(downgraded_from) = record.downgraded_from.as_deref() else {
        return Ok((canonical(&payload)?, None));
    };
    let regression = json!({
        "previous_writer_version": downgraded_from,
        "writer_version": record.provenance["writer_version"],
        "retired_target_count": retired.len(),
        "retired_target_ids": retired,
    });
    payload["regression"] = regression.clone();
    let mut row = json!({
        "revision": revision,
        "previous_catalog_digest": migration.previous_catalog_digest,
        "catalog_digest": catalog_digest,
    });
    for (name, value) in regression.as_object().into_iter().flatten() {
        row[name] = value.clone();
    }
    Ok((canonical(&payload)?, Some(canonical(&row)?)))
}

impl Ctx<'_> {
    fn migrate_catalog(&self) -> Res<Value> {
        let key = self.require_key()?;
        let record = self
            .request
            .migration_record
            .as_ref()
            .ok_or_else(|| tampered(INVALID_MIGRATION))?;
        let previous_revision = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered(INVALID_MIGRATION))?
            .previous_revision;
        // `migrate_plan` seals the revision after the source head; the event
        // is built first so nothing after the first anchor can refuse it.
        let events = migration_events(self.request, record, previous_revision + 1)?;
        let reply = immediate(self.connection, || self.prepare_migration())?;
        let plan = &reply["plan"];
        let revision = int(&plan["revision"])?;
        if revision != previous_revision + 1 {
            return Err(tampered(INVALID_MIGRATION));
        }
        let snapshot_digest = text(&plan["snapshot"]["digest"])?.to_owned();
        let anchored = Anchor {
            revision,
            snapshot_digest: snapshot_digest.clone(),
            phase: Phase::Anchored,
        };
        self.write_anchor(&anchor_json(&anchored, key)?)?;
        immediate(self.connection, || self.commit_migration(plan, &events))?;
        let committed = Anchor {
            revision,
            snapshot_digest,
            phase: Phase::Committed,
        };
        let sealed = anchor_json(&committed, key)?;
        self.write_anchor(&sealed)?;
        // Best effort, as in `_export_last_good_authority`.
        let _ = self.export_last_good(&committed);
        Ok(json!({
            "resumed": {
                "revision": revision,
                "catalog_digest": self.catalog_digest()?,
            },
            "anchor_json": sealed,
        }))
    }

    fn prepare_migration(&self) -> Res<Value> {
        let reply = self.migrate_plan()?;
        let plan = &reply["plan"];
        if plan["outcome"] != "migrate" {
            return Err(tampered(INVALID_MIGRATION));
        }
        if !plan["command_pack_record_digest"].is_null() {
            return Err(tampered(
                "installed command pack migration binding mismatch",
            ));
        }
        let migration = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered(INVALID_MIGRATION))?;
        let hashes = &plan["hashes"];
        let (snapshot, transition) = (&plan["snapshot"], &plan["transition"]);
        self.connection
            .execute(
                "insert into extension_control_authority_transition (
                    revision, previous_revision, phase, actor_id_hash, idempotency_key_hash,
                    nonce_hash, catalog_digest, layers_json, snapshot_json, snapshot_digest,
                    snapshot_mac, transition_json, transition_digest, transition_mac, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    int(&plan["revision"])?,
                    migration.previous_revision,
                    Phase::Prepared.as_str(),
                    text(&hashes["actor"])?,
                    text(&hashes["idempotency"])?,
                    text(&hashes["nonce"])?,
                    self.catalog_digest()?,
                    text(&plan["layers_json"])?,
                    text(&snapshot["json"])?,
                    text(&snapshot["digest"])?,
                    text(&snapshot["mac"])?,
                    text(&transition["json"])?,
                    text(&transition["digest"])?,
                    text(&transition["mac"])?,
                    text(&plan["created_at"])?,
                ],
            )
            .map_err(store_fault)?;
        Ok(reply)
    }

    fn commit_migration(&self, plan: &Value, events: &(String, Option<String>)) -> Res<()> {
        let migration = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered(INVALID_MIGRATION))?;
        let revision = int(&plan["revision"])?;
        let created_at = text(&plan["created_at"])?;
        let previous_digest = text(&plan["previous_digest"])?;
        let snapshot = &plan["snapshot"];
        self.connection
            .execute(
                "update extension_control_authority_transition set phase = ? where revision = ?",
                params![Phase::Anchored.as_str(), revision],
            )
            .map_err(store_fault)?;
        let updated = self
            .connection
            .execute(
                "update extension_control_authority_snapshot
                 set revision = ?, catalog_digest = ?, layers_json = ?, previous_digest = ?,
                     snapshot_json = ?, snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
                 where singleton = 1 and revision = ? and snapshot_digest = ?",
                params![
                    revision,
                    self.catalog_digest()?,
                    text(&plan["layers_json"])?,
                    previous_digest,
                    text(&snapshot["json"])?,
                    text(&snapshot["digest"])?,
                    text(&snapshot["mac"])?,
                    created_at,
                    migration.previous_revision,
                    previous_digest,
                ],
            )
            .map_err(store_fault)?;
        if updated != 1 {
            return Err(tampered("extension control catalog migration conflict"));
        }
        self.connection
            .execute(
                "update extension_control_authority_transition
                 set phase = ?, committed_at = ? where revision = ?",
                params![Phase::Committed.as_str(), created_at, revision],
            )
            .map_err(store_fault)?;
        let (payload, regression) = events;
        let insert = |name: &str, payload: &str| {
            self.connection
                .execute(
                    "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                    params![name, payload, created_at],
                )
                .map_err(store_fault)
        };
        insert(MIGRATED_EVENT, payload)?;
        if let Some(regression) = regression {
            insert(REGRESSED_EVENT, regression)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod tests;
