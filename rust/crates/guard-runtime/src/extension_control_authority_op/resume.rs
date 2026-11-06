//! `resume`: the resident finishes a prepared transition itself.
//!
//! This is `_apply_resumed_transition`.
//! The verdict `resume_plan` answers with is taken again inside the immediate
//! transaction that applies it, so nothing changes between the two. Once the
//! rows commit, the committed anchor is sealed into the credential vault and
//! read back, the last-good export refreshed, and the change event queued.
//!
//! A commit finishes its own freshly anchored row the same way, naming the
//! proof it reserved so the proof is consumed in that transaction.
//!
//! A row whose commit would activate a command pack comes back `pack_bound`
//! with nothing written unless the caller sent the protected pack state
//! (`pack_finish`). With it, the pending activation is installed in the same
//! transaction as the row; a lifecycle floor that has not moved yet, or legacy
//! evidence the link needs, comes back owed with nothing written.
//!
//! A commit retry that found its own prepared row resumes it here as well,
//! naming its proof (`retry_proof`): the proof is recorded as consumed in the
//! transaction that applies a committed verdict, released with an abandoned
//! row, and a row the retry's view already shows committed only queues its
//! change event.
//!
//! A catalog migration that activates a command pack is finished here too:
//! the request carries its `migration_record`, the migration event is recorded
//! in the transaction that commits the row, and no change event is queued, as
//! for any other migration.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use guard_command::extension_control::{ControlState, ControlTargetKind};
use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::layers::{layers_from_json, validate_serialized_layers};
use super::pack_finish::PackStep;
use super::plans::Resume;
use super::records::{
    canonical, degraded, query_row, row_int, row_str, row_value, store_fault, tampered, Anchor,
    Phase, Res, Row,
};
use super::seals::{
    anchor_json, EXPORT_FIELDS, LAST_GOOD_FILE_NAME, LAST_GOOD_SCHEMA, MAX_EXPORT_BYTES,
};
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};
use crate::encrypted_secret_store::{atomic_write_bytes, EncryptedFileSecretStore};
use crate::guard_store_receipt_events::add_guard_event;
use crate::local_store_read::table_exists;

const ANCHOR_REF_SUFFIX: &str = ":anchor";
const CHANGE_SCHEMA: &str = "guard.extension-control-authority-change.v1";
/// `GuardStore`'s default pending cloud-event capacity.
const DEFAULT_EVENT_QUEUE_LIMIT: i64 = 1000;
const STATE_MISMATCH: &str = "idempotent transition state mismatch";
const CONCURRENT_UPDATE: &str = "extension control authority concurrent update";

/// What the immediate transaction did with the row.
enum Applied {
    Absent,
    Abandoned,
    /// Committing the row activates a command pack; nothing was written.
    PackBound(Value),
    /// The pack activation needs the caller first; nothing was written.
    PackOwed(Value),
    /// The row and snapshot are committed; the anchor and event are owed.
    Committed(Row),
    /// The retry's view already shows the row committed; its proof is
    /// settled and its change event queued.
    Current(Row),
}

pub(super) fn resume_op(
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
    let outcome = ctx.resume_transition();
    let events = ctx.events.take();
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

/// Runs `apply` in one immediate transaction: its answer commits, its fault
/// rolls back.
pub(super) fn immediate<T>(connection: &Connection, apply: impl FnOnce() -> Res<T>) -> Res<T> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| degraded(STORE_UNAVAILABLE))?;
    let outcome = apply().and_then(|value| {
        connection
            .execute_batch("COMMIT")
            .map(|()| value)
            .map_err(store_fault)
    });
    if outcome.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    outcome
}

/// `Path.resolve()` of the Guard home, which names its vault secrets.
pub(super) fn resolved_home(guard_home: &str) -> PathBuf {
    let home = Path::new(guard_home);
    std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf())
}

/// `_anchor_ref`.
pub(super) fn anchor_ref(resolved_home: &Path) -> String {
    let digest = hex::encode(Sha256::digest(resolved_home.to_string_lossy().as_bytes()));
    format!("extension-control:{}{ANCHOR_REF_SUFFIX}", &digest[..20])
}

impl Ctx<'_> {
    fn resume_transition(&self) -> Res<Value> {
        let key = self.require_key()?;
        let revision = self
            .request
            .revision
            .ok_or_else(|| tampered("extension control transition head mismatch"))?;
        let row = match immediate(self.connection, || self.apply_resume(revision))? {
            Applied::Absent => return Ok(json!({ "resumed": null, "outcome": "absent" })),
            Applied::Abandoned => return Ok(json!({ "resumed": null, "outcome": "abandon" })),
            Applied::PackBound(pack) => {
                return Ok(json!({
                    "resumed": null,
                    "outcome": "commit_pending",
                    "pack_bound": true,
                    "command_pack_record_digest": pack,
                }));
            }
            Applied::PackOwed(mut owed) => {
                owed["resumed"] = Value::Null;
                owed["outcome"] = json!("commit_pending");
                return Ok(owed);
            }
            Applied::Current(row) => {
                return Ok(json!({
                    "resumed": {
                        "revision": revision,
                        "catalog_digest": row_str(&row, "catalog_digest")?,
                    },
                    "outcome": "current",
                }));
            }
            Applied::Committed(row) => row,
        };
        let anchor = Anchor {
            revision,
            snapshot_digest: row_str(&row, "snapshot_digest")?,
            phase: Phase::Committed,
        };
        let sealed = anchor_json(&anchor, key)?;
        self.write_anchor(&sealed)?;
        // Best effort, as in `_export_last_good_authority`.
        let _ = self.export_last_good(&anchor);
        if self.request.migration_record.is_none() {
            immediate(self.connection, || self.queue_change_event(&row))?;
        }
        Ok(json!({
            "resumed": {
                "revision": revision,
                "catalog_digest": row_str(&row, "catalog_digest")?,
            },
            "anchor_json": sealed,
        }))
    }

    fn apply_resume(&self, revision: i64) -> Res<Applied> {
        let Some((row, outcome, pack)) = self.resume_verdict(revision)? else {
            return Ok(Applied::Absent);
        };
        let proof_hash = self.request.proof_hash.as_deref();
        // The commit that prepared the row holds the lease and has just
        // anchored it, so any other verdict means the row moved underneath it.
        if proof_hash.is_some() && !matches!(outcome, Resume::CommitPending) {
            return Err(tampered(CONCURRENT_UPDATE));
        }
        let journal = table_exists(self.connection, "extension_command_pack_pending")
            .map_err(|_| degraded(STORE_UNAVAILABLE))?;
        match outcome {
            Resume::Abandon => {
                let removed = self
                    .connection
                    .execute(
                        "delete from extension_control_authority_transition where revision = ?",
                        [revision],
                    )
                    .map_err(store_fault)?;
                if removed != 1 {
                    return Err(tampered(STATE_MISMATCH));
                }
                if let Some(retry) = &self.request.retry_proof {
                    self.connection
                        .execute(
                            "delete from extension_control_authority_proof
                             where proof_id_hash = ? and transition_revision = ?",
                            params![retry.proof_hash, revision],
                        )
                        .map_err(store_fault)?;
                }
                if journal {
                    self.connection
                        .execute(
                            "delete from extension_command_pack_pending where control_revision = ?",
                            [revision],
                        )
                        .map_err(store_fault)?;
                }
                return Ok(Applied::Abandoned);
            }
            Resume::CommitPending => {
                let reserved = journal
                    && query_row(
                        self.connection,
                        "select 1 from extension_command_pack_pending where control_revision = ?",
                        [revision],
                    )?
                    .is_some();
                if !pack.is_null() || reserved {
                    if self.request.pack_finish.is_none() {
                        return Ok(Applied::PackBound(pack));
                    }
                    match self.finish_pack(&row, &pack)? {
                        PackStep::Finished => {}
                        PackStep::FloorOwed { before, after } => {
                            return Ok(Applied::PackOwed(json!({
                                "pack_floor_owed": { "before": before, "after": after },
                            })));
                        }
                        PackStep::LegacyOwed => {
                            return Ok(Applied::PackOwed(json!({ "pack_legacy_owed": true })));
                        }
                    }
                }
                validate_serialized_layers(&row_str(&row, "layers_json")?)?;
                let updated = self
                    .connection
                    .execute(
                        "update extension_control_authority_snapshot
                         set revision = ?, catalog_digest = ?, layers_json = ?,
                             previous_digest = snapshot_digest, snapshot_json = ?,
                             snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
                         where singleton = 1 and revision = ?",
                        params![
                            revision,
                            row_str(&row, "catalog_digest")?,
                            row_str(&row, "layers_json")?,
                            row_str(&row, "snapshot_json")?,
                            row_str(&row, "snapshot_digest")?,
                            row_str(&row, "snapshot_mac")?,
                            row_str(&row, "created_at")?,
                            row_int(&row, "previous_revision")?,
                        ],
                    )
                    .map_err(store_fault)?;
                if updated != 1 {
                    return Err(tampered(STATE_MISMATCH));
                }
                self.mark_committed(revision)?;
                if let Some(proof_hash) = proof_hash {
                    self.consume_proof(proof_hash, revision, &row_str(&row, "created_at")?)?;
                }
                self.record_migration(&row)?;
            }
            Resume::MarkCommitted => self.mark_committed(revision)?,
            Resume::Finish => {}
            Resume::Current => {
                if self.request.retry_proof.is_none() {
                    return Err(tampered("invalid extension control authority plan"));
                }
                self.settle_retry_proof(revision)?;
                self.queue_change_event(&row)?;
                return Ok(Applied::Current(row));
            }
        }
        self.settle_retry_proof(revision)?;
        Ok(Applied::Committed(row))
    }

    /// Records a retry's proof as consumed by the row at `revision`: inserted
    /// when the plan found it unrecorded, stamped once when it was reserved.
    fn settle_retry_proof(&self, revision: i64) -> Res<()> {
        let Some(retry) = &self.request.retry_proof else {
            return Ok(());
        };
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered("invalid extension control resume request"))?;
        let settled = self
            .connection
            .execute(
                "insert into extension_control_authority_proof (
                    proof_id_hash, mutation_digest, transition_revision, reserved_at, consumed_at
                 ) values (?, ?, ?, ?, ?)
                 on conflict(proof_id_hash) do update
                 set consumed_at = coalesce(consumed_at, excluded.consumed_at)
                 where transition_revision = excluded.transition_revision",
                params![retry.proof_hash, retry.mutation_digest, revision, now, now],
            )
            .map_err(store_fault)?;
        if settled != 1 {
            return Err(tampered("extension control authority proof state conflict"));
        }
        Ok(())
    }

    fn mark_committed(&self, revision: i64) -> Res<()> {
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered("invalid extension control resume request"))?;
        self.connection
            .execute(
                "update extension_control_authority_transition
                 set phase = ?, committed_at = ? where revision = ?",
                params![Phase::Committed.as_str(), now, revision],
            )
            .map_err(store_fault)?;
        Ok(())
    }

    /// Marks the commit's reserved proof consumed, once.
    fn consume_proof(&self, proof_hash: &str, revision: i64, consumed_at: &str) -> Res<()> {
        let updated = self
            .connection
            .execute(
                "update extension_control_authority_proof set consumed_at = ?
                 where proof_id_hash = ? and transition_revision = ? and consumed_at is null",
                params![consumed_at, proof_hash, revision],
            )
            .map_err(store_fault)?;
        if updated != 1 {
            return Err(tampered("extension control authority proof state conflict"));
        }
        Ok(())
    }

    /// `_write_and_verify_anchor` into the owner-only vault, which every
    /// Guard process reads first.
    pub(super) fn write_anchor(&self, sealed: &str) -> Res<()> {
        let home = resolved_home(&self.request.guard_home);
        let secret_ref = anchor_ref(&home);
        let mut vault = EncryptedFileSecretStore::new(&home);
        vault
            .set_secret(&secret_ref, sealed)
            .map_err(|_| degraded("extension control credential store unavailable"))?;
        if vault.get_secret(&secret_ref).as_deref() != Some(sealed) {
            return Err(tampered("extension control anchor read-back mismatch"));
        }
        Ok(())
    }

    /// `_export_last_good_authority` for the committed anchor just written.
    pub(super) fn export_last_good(&self, anchor: &Anchor) -> Res<()> {
        let Some(snapshot) = self.snapshot_row()? else {
            return Ok(());
        };
        if row_str(&snapshot, "snapshot_digest")? != anchor.snapshot_digest
            || row_int(&snapshot, "revision")? != anchor.revision
        {
            return Ok(());
        }
        let mut payload = Map::new();
        payload.insert("schema".to_owned(), json!(LAST_GOOD_SCHEMA));
        for name in ["snapshot_json", "snapshot_digest", "snapshot_mac"] {
            payload.insert(name.to_owned(), json!(row_str(&snapshot, name)?));
        }
        for name in EXPORT_FIELDS {
            let value = row_value(&snapshot, name)?
                .ok_or_else(|| degraded("authority record is not encodable"))?;
            payload.insert(name.to_owned(), value);
        }
        let encoded = canonical(&Value::Object(payload))?;
        if encoded.len() > MAX_EXPORT_BYTES {
            return Ok(());
        }
        let path = Path::new(&self.request.guard_home).join(LAST_GOOD_FILE_NAME);
        atomic_write_bytes(&path, encoded.as_bytes(), 0o600)
            .map_err(|_| degraded("extension control last-good export failed"))
    }

    /// `_queue_extension_control_change_event`.
    fn queue_change_event(&self, row: &Row) -> Res<()> {
        let revision = row_int(row, "revision")?;
        let occurred_at = row_str(row, "created_at")?;
        let layers = layers_from_json(&row_str(row, "layers_json")?)?;
        let controls = || layers.iter().flat_map(|layer| layer.controls.iter());
        let disabled = |kind: ControlTargetKind| {
            controls()
                .filter(|control| {
                    control.state == ControlState::Disabled && control.target.kind == kind
                })
                .count()
        };
        let payload = json!({
            "schema": CHANGE_SCHEMA,
            "action": "authority.changed",
            "revision": revision,
            "previousRevision": row_int(row, "previous_revision")?,
            "layerKinds": layers.iter().map(|layer| layer.kind.as_str()).collect::<Vec<_>>(),
            "globalLockdown": layers.iter().any(|layer| layer.global_lockdown),
            "disabledExtensionCount": disabled(ControlTargetKind::Extension),
            "disabledPermissionCount": disabled(ControlTargetKind::Permission),
            "blockSource": "extension-control-authority",
        });
        let policy_key = format!("extension-controls:{revision}");
        let fingerprint = hex::encode(Sha256::digest(
            format!("policy.changed:{policy_key}:{occurred_at}").as_bytes(),
        ));
        let event = json!({
            "schemaVersion": "guard.event.v1",
            "eventId": format!("guard-event-{}", &fingerprint[..32]),
            "idempotencyKey": format!("policy.changed:{policy_key}:{occurred_at}"),
            "eventType": "policy.changed",
            "source": "policy",
            "occurredAt": occurred_at,
            "workspaceId": self.cloud_workspace_id()?,
            "deviceId": null,
            "payload": payload,
        });
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered("invalid extension control resume request"))?;
        let limit = self
            .request
            .event_queue_limit
            .unwrap_or(DEFAULT_EVENT_QUEUE_LIMIT)
            .max(1);
        add_guard_event(self.connection, &event, limit, now)
            .map_err(|_| degraded(STORE_UNAVAILABLE))
    }

    /// `_cloud_workspace_id_from_connection`.
    fn cloud_workspace_id(&self) -> Res<Option<String>> {
        let Some(row) = query_row(
            self.connection,
            "select payload_json from sync_state where state_key = 'oauth_local_credentials'",
            [],
        )?
        else {
            return Ok(None);
        };
        let Ok(Value::Object(payload)) = serde_json::from_str(&row_str(&row, "payload_json")?)
        else {
            return Ok(None);
        };
        Ok(payload
            .get("workspace_id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .map(str::to_owned))
    }
}

#[cfg(test)]
#[path = "resume_tests.rs"]
mod tests;
