//! Writer ops the resident carries out itself.
//!
//! `restore` and `roll_back` take the same decision `restore_plan` and
//! `rollback_plan` answer with, then apply it in the same immediate
//! transaction, so nothing can change between the verdict and the write. The
//! caller still holds the exclusive authority lease and invalidates its own
//! caches afterwards; neither op touches the vault anchor.

use std::cell::RefCell;
use std::time::Duration;

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use super::records::{canonical, degraded, store_fault, tampered, Phase, Res};
use super::resume::immediate;
use super::schema;
use super::{fault_value, Ctx, INVALID, STORE_UNAVAILABLE};
use crate::guard_store_write_cache::{open_read_write_cached, CachedConnection};
use crate::local_store_read::{require_store_path, table_exists};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const RESTORED_EVENT: &str = "extension_control_authority_restored";

/// The store a writer op writes, with the authority schema it writes
/// ensured, or the reply the op answers with when it cannot be opened or its
/// schema is not one this runtime writes. A pack reservation moves the
/// marker to the pack schema its record names.
pub(super) fn open_writer(
    request: &ExtensionControlAuthorityRequestV1,
) -> Result<Result<CachedConnection, Value>, String> {
    let unavailable = || Ok(Err(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new())));
    let store_path = require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| INVALID.to_owned())?;
    if !store_path.exists() {
        return unavailable();
    }
    let Ok(connection) = open_read_write_cached(&store_path) else {
        return unavailable();
    };
    if connection.busy_timeout(BUSY_TIMEOUT).is_err() {
        return unavailable();
    }
    let wanted = schema::wanted_version(
        request
            .pack_reserve
            .as_ref()
            .map(|reserve| reserve.record_json.as_str()),
    );
    if let Err(fault) = immediate(&connection, || schema::ensure_schema(&connection, wanted)) {
        return Ok(Err(fault_value(&fault, Vec::new())));
    }
    Ok(Ok(connection))
}

pub(super) fn with_writable_store(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let unavailable = || Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    let connection = match open_writer(request)? {
        Ok(connection) => connection,
        Err(reply) => return Ok(reply),
    };
    if connection.execute_batch("BEGIN IMMEDIATE").is_err() {
        return unavailable();
    }
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    let outcome = match request.op.as_str() {
        "restore" => ctx.restore(),
        "roll_back" => ctx.roll_back(),
        _ => Err(tampered("unsupported extension control authority op")),
    };
    let events = ctx.events.take();
    let outcome = outcome.and_then(|payload| {
        connection
            .execute_batch("COMMIT")
            .map(|()| payload)
            .map_err(store_fault)
    });
    if outcome.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

fn text<'a>(plan: &'a Value, name: &str) -> Res<&'a str> {
    plan[name]
        .as_str()
        .ok_or_else(|| tampered("invalid extension control authority plan"))
}

fn int(plan: &Value, name: &str) -> Res<i64> {
    plan[name]
        .as_i64()
        .ok_or_else(|| tampered("invalid extension control authority plan"))
}

fn record<'a>(plan: &'a Value, name: &str) -> Res<(&'a str, &'a str, &'a str)> {
    let record = &plan[name];
    Ok((
        text(record, "json")?,
        text(record, "digest")?,
        text(record, "mac")?,
    ))
}

impl Ctx<'_> {
    /// `_restore_last_good_authority`: re-create the snapshot row, and the
    /// baseline transition it needs, from a verified export that matches the
    /// committed vault anchor. Answers the restored revision and control
    /// count, or `null` when the plan skipped.
    pub(super) fn restore(&self) -> Res<Value> {
        let reply = self.restore_plan()?;
        let plan = &reply["plan"];
        if plan["outcome"] != json!("restore") {
            return Ok(json!({ "restored": null }));
        }
        let revision = int(plan, "revision")?;
        let control_count = int(plan, "control_count")?;
        let catalog_digest = text(plan, "catalog_digest")?;
        let layers_json = text(plan, "layers_json")?;
        let committed_at = text(plan, "committed_at")?;
        let restored_at = text(plan, "restored_at")?;
        let previous_digest = plan["previous_digest"].as_str();
        let (snapshot_json, snapshot_digest, snapshot_mac) = record(plan, "snapshot")?;
        insert_snapshot(
            self.connection,
            revision,
            catalog_digest,
            layers_json,
            previous_digest,
            (snapshot_json, snapshot_digest, snapshot_mac),
            committed_at,
        )?;
        let baseline = &plan["baseline"];
        if !baseline.is_null() {
            let hashes = &baseline["hashes"];
            let (transition_json, transition_digest, transition_mac) =
                record(baseline, "transition")?;
            // The baseline's created_at equals the snapshot's committed_at,
            // which chain validation requires of the pair.
            self.connection
                .execute(
                    "insert into extension_control_authority_transition (
                        revision, previous_revision, phase, actor_id_hash, idempotency_key_hash,
                        nonce_hash, catalog_digest, layers_json, snapshot_json, snapshot_digest,
                        snapshot_mac, transition_json, transition_digest, transition_mac,
                        created_at, committed_at
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        revision,
                        revision - 1,
                        Phase::Committed.as_str(),
                        text(hashes, "actor")?,
                        text(hashes, "idempotency")?,
                        text(hashes, "nonce")?,
                        catalog_digest,
                        layers_json,
                        snapshot_json,
                        snapshot_digest,
                        snapshot_mac,
                        transition_json,
                        transition_digest,
                        transition_mac,
                        committed_at,
                        restored_at,
                    ],
                )
                .map_err(store_fault)?;
        }
        let payload = canonical(&json!({
            "revision": revision,
            "control_count": control_count,
            "source": "last-good-export",
        }))?;
        self.connection
            .execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                params![RESTORED_EVENT, payload, restored_at],
            )
            .map_err(store_fault)?;
        Ok(json!({
            "restored": { "revision": revision, "control_count": control_count },
        }))
    }

    /// `_roll_back_abandoned_transition`: remove the prepared transition the
    /// vault anchor never moved past, its command-pack reservation and its
    /// unconsumed proofs. Answers whether the row was removed.
    pub(super) fn roll_back(&self) -> Res<Value> {
        let reply = self.rollback_plan()?;
        let plan = &reply["plan"];
        if plan["outcome"] != json!("abandon") {
            return Ok(json!({ "rolled_back": false }));
        }
        let revision = int(plan, "revision")?;
        let removed = self
            .connection
            .execute(
                "delete from extension_control_authority_transition where revision = ?",
                [revision],
            )
            .map_err(store_fault)?;
        if removed != 1 {
            return Err(tampered("idempotent transition state mismatch"));
        }
        let journal = table_exists(self.connection, "extension_command_pack_pending")
            .map_err(|_| degraded(STORE_UNAVAILABLE))?;
        if journal {
            self.connection
                .execute(
                    "delete from extension_command_pack_pending where control_revision = ?",
                    [revision],
                )
                .map_err(store_fault)?;
        }
        self.connection
            .execute(
                "delete from extension_control_authority_proof \
                 where transition_revision = ? and consumed_at is null",
                [revision],
            )
            .map_err(store_fault)?;
        Ok(json!({ "rolled_back": true }))
    }
}

fn insert_snapshot(
    connection: &Connection,
    revision: i64,
    catalog_digest: &str,
    layers_json: &str,
    previous_digest: Option<&str>,
    (snapshot_json, snapshot_digest, snapshot_mac): (&str, &str, &str),
    committed_at: &str,
) -> Res<()> {
    connection
        .execute(
            "insert into extension_control_authority_snapshot (
                singleton, revision, catalog_digest, layers_json, previous_digest,
                snapshot_json, snapshot_digest, snapshot_mac, committed_at
            ) values (1, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                revision,
                catalog_digest,
                layers_json,
                previous_digest,
                snapshot_json,
                snapshot_digest,
                snapshot_mac,
                committed_at,
            ],
        )
        .map_err(store_fault)?;
    Ok(())
}

#[cfg(test)]
#[path = "writes_tests.rs"]
mod tests;
