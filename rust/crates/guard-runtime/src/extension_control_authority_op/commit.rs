//! `commit_prepare`: `commit_plan`, and for a fresh commit the proof
//! reservation and the prepared transition, in one immediate transaction.
//! `bootstrap`: `bootstrap_plan` and the revision-zero snapshot it seals, then
//! the committed anchor. `write_manifest`: the sealed catalog manifest record,
//! inserted or replaced in one immediate transaction.
//!
//! The plan is taken inside the transaction that writes it, so no other
//! writer can take the revision in between. Any verdict but `prepare` comes
//! back as `commit_plan` answers it, with nothing written. A commit that
//! activates a command pack is prepared by the caller, which reserves the pack
//! activation in the same transaction as the row.

use std::cell::RefCell;

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::params;
use serde_json::{json, Value};

use super::records::{degraded, store_fault, tampered, Anchor, Phase, Res};
use super::resume::immediate;
use super::seals::{anchor_json, seal_manifest_op};
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};

const INVALID_PLAN: &str = "invalid extension control authority plan";

pub(super) fn commit_prepare_op(
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
    let outcome = immediate(&connection, || ctx.prepare_commit());
    let events = ctx.events.take();
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

pub(super) fn bootstrap_op(
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
    let outcome = ctx.bootstrap();
    let events = ctx.events.take();
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

pub(super) fn write_manifest_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let Some(connection) = open_writer(request)? else {
        return Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    };
    let outcome = immediate(&connection, || {
        write_manifest(&connection, request, key)?;
        Ok(json!({ "written": true }))
    });
    Ok(outcome.unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

/// `_write_catalog_manifest`: seal the manifest and record it, refusing a
/// replacement that finds no manifest to replace.
fn write_manifest(
    connection: &rusqlite::Connection,
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<()> {
    let sealed = seal_manifest_op(request, key)?;
    let catalog_digest = request
        .catalog_digest
        .as_deref()
        .ok_or_else(|| tampered(INVALID_PLAN))?;
    let record = &sealed["record"];
    let manifest_json = text(&sealed["manifest_json"])?;
    let (record_json, record_digest) = (text(&record["json"])?, text(&record["digest"])?);
    let (record_mac, recorded_at) = (text(&record["mac"])?, text(&sealed["recorded_at"])?);
    let row = params![
        manifest_json,
        record_json,
        record_digest,
        record_mac,
        recorded_at,
        catalog_digest
    ];
    if request.manifest_replace == Some(true) {
        let updated = connection
            .execute(
                "update extension_control_catalog_manifest
                 set manifest_json = ?, record_json = ?, record_digest = ?, record_mac = ?,
                     recorded_at = ?
                 where catalog_digest = ?",
                row,
            )
            .map_err(store_fault)?;
        if updated != 1 {
            return Err(tampered("extension control catalog manifest conflict"));
        }
        return Ok(());
    }
    connection
        .execute(
            "insert into extension_control_catalog_manifest (
                manifest_json, record_json, record_digest, record_mac, recorded_at, catalog_digest
             ) values (?, ?, ?, ?, ?, ?)",
            row,
        )
        .map_err(store_fault)?;
    Ok(())
}

fn text(value: &Value) -> Res<&str> {
    value.as_str().ok_or_else(|| tampered(INVALID_PLAN))
}

fn int(value: &Value) -> Res<i64> {
    value.as_i64().ok_or_else(|| tampered(INVALID_PLAN))
}

impl Ctx<'_> {
    /// `_bootstrap_extension_control_authority` once the caller holds a key.
    fn bootstrap(&self) -> Res<Value> {
        let key = self.require_key()?;
        let catalog_digest = self.catalog_digest()?;
        let digest = immediate(self.connection, || {
            let reply = self.bootstrap_plan()?;
            let plan = &reply["plan"];
            let snapshot = &plan["snapshot"];
            self.connection
                .execute(
                    "insert into extension_control_authority_snapshot (
                        singleton, revision, catalog_digest, layers_json, previous_digest,
                        snapshot_json, snapshot_digest, snapshot_mac, committed_at
                    ) values (1, 0, ?, ?, null, ?, ?, ?, ?)",
                    params![
                        catalog_digest,
                        text(&plan["layers_json"])?,
                        text(&snapshot["json"])?,
                        text(&snapshot["digest"])?,
                        text(&snapshot["mac"])?,
                        text(&plan["committed_at"])?,
                    ],
                )
                .map_err(store_fault)?;
            Ok(text(&snapshot["digest"])?.to_owned())
        })?;
        let anchor = Anchor {
            revision: 0,
            snapshot_digest: digest,
            phase: Phase::Committed,
        };
        let sealed = anchor_json(&anchor, key)?;
        self.write_anchor(&sealed)?;
        Ok(json!({
            "resumed": { "revision": 0, "catalog_digest": catalog_digest },
            "anchor_json": sealed,
        }))
    }

    fn prepare_commit(&self) -> Res<Value> {
        let mut reply = self.commit_plan()?;
        let commit = self
            .request
            .commit
            .as_ref()
            .ok_or_else(|| tampered("invalid extension control commit request"))?;
        if reply["plan"]["outcome"] != "prepare" || commit.pack_record_digest.is_some() {
            return Ok(reply);
        }
        let plan = &reply["plan"];
        let revision = int(&plan["revision"])?;
        let created_at = text(&plan["created_at"])?;
        let hashes = &plan["hashes"];
        let (snapshot, transition) = (&plan["snapshot"], &plan["transition"]);
        self.connection
            .execute(
                "insert into extension_control_authority_proof (
                    proof_id_hash, mutation_digest, transition_revision, reserved_at
                ) values (?, ?, ?, ?)",
                params![
                    text(&hashes["proof"])?,
                    commit.mutation_digest,
                    revision,
                    created_at
                ],
            )
            .map_err(store_fault)?;
        self.connection
            .execute(
                "insert into extension_control_authority_transition (
                    revision, previous_revision, phase, actor_id_hash, idempotency_key_hash,
                    nonce_hash, catalog_digest, layers_json, snapshot_json, snapshot_digest,
                    snapshot_mac, transition_json, transition_digest, transition_mac, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    revision,
                    int(&plan["previous_revision"])?,
                    Phase::Prepared.as_str(),
                    text(&hashes["actor"])?,
                    text(&hashes["idempotency"])?,
                    text(&hashes["nonce"])?,
                    self.catalog_digest()?,
                    commit.layers_json,
                    text(&snapshot["json"])?,
                    text(&snapshot["digest"])?,
                    text(&snapshot["mac"])?,
                    text(&transition["json"])?,
                    text(&transition["digest"])?,
                    text(&transition["mac"])?,
                    created_at,
                ],
            )
            .map_err(store_fault)?;
        reply["plan"]["prepared"] = json!(true);
        Ok(reply)
    }
}

#[cfg(test)]
#[path = "commit_tests.rs"]
mod tests;
