//! The writer's decisions: what a commit checks and seals, and whether a
//! prepared transition is resumed, committed or abandoned.
//!
//! These ops read the store and never write it. Each answers with a `plan`
//! naming the step the caller performs under the exclusive authority lease;
//! a refusal is a `tampered` fault carrying the message the Python writer
//! raised for it.

use rusqlite::params;
use serde_json::{json, Map, Value};

use super::layers::{layers_from_json, validate_serialized_layers};
use super::records::{
    authenticated_record, degraded, field, fields_match, private_hash, query_row, row_int,
    row_py_int, row_str, row_text, snapshot_pack_binding, tampered, verify_record, Anchor, Fault,
    Phase, Res, Row, SNAPSHOT_PURPOSE, TRANSITION_PURPOSE,
};
use super::{Ctx, View, PROTECTED, RECOVERY_REQUIRED};
use crate::extension_control_proof::{mutation_digest, Mutation};
use crate::policy_bundle_time::from_isoformat;

/// A request that died after preparing its transition may be retried with
/// the same single-use proof, which needs the prepared row and its proof
/// reservation to survive. Only rows older than this are abandoned, unless
/// the caller names the row as its own: a request that failed in process
/// takes its row back at once rather than refuse every other save.
const ABANDONED_TRANSITION_GRACE_MICROS: i64 = 300 * 1_000_000;

/// What resuming a prepared transition comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resume {
    /// The anchor never moved: discard the row and its pack reservation.
    Abandon,
    /// The anchor moved and the snapshot did not: commit the row.
    CommitPending,
    /// The snapshot moved and the row is not marked committed yet.
    MarkCommitted,
    /// The row and snapshot are committed; only the final anchor is owed.
    Finish,
    /// The authority already serves this revision.
    Current,
}

impl Resume {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Abandon => "abandon",
            Self::CommitPending => "commit_pending",
            Self::MarkCommitted => "mark_committed",
            Self::Finish => "finish",
            Self::Current => "current",
        }
    }
}

/// The request a prepared transition must have been prepared for.
struct Expected {
    catalog_digest: String,
    layers_json: String,
    actor_hash: String,
    idempotency_hash: String,
    nonce_hash: String,
    expected_revision: i64,
}

impl Expected {
    /// The row's own request, for a resume no caller asked for.
    fn of_row(row: &Row) -> Res<Self> {
        Ok(Self {
            catalog_digest: row_str(row, "catalog_digest")?,
            layers_json: row_str(row, "layers_json")?,
            actor_hash: row_str(row, "actor_id_hash")?,
            idempotency_hash: row_str(row, "idempotency_key_hash")?,
            nonce_hash: row_str(row, "nonce_hash")?,
            expected_revision: row_int(row, "previous_revision")?,
        })
    }
}

/// `_row_optional_str`.
fn row_optional_str(row: &Row, name: &str) -> Res<Option<String>> {
    match row.get(name) {
        Some(rusqlite::types::Value::Null) => Ok(None),
        _ => row_str(row, name).map(Some),
    }
}

fn utc_micros(text: &str) -> Option<i64> {
    from_isoformat(text)?.utc_micros()
}

pub(super) fn sealed(payload: Value, key: &[u8], purpose: &str) -> Res<Value> {
    let Value::Object(payload) = payload else {
        return Err(degraded("authority record is not encodable"));
    };
    let (record, digest, mac) = authenticated_record(&payload, key, purpose)?;
    Ok(json!({ "json": record, "digest": digest, "mac": mac }))
}

pub(super) fn with_pack(mut payload: Value, pack_record_digest: Option<&str>) -> Value {
    if let (Some(digest), Value::Object(fields)) = (pack_record_digest, &mut payload) {
        fields.insert("command_pack_record_digest".to_owned(), json!(digest));
    }
    payload
}

pub(super) fn plan(outcome: &str, fields: Map<String, Value>) -> Value {
    let mut plan = fields;
    plan.insert("outcome".to_owned(), json!(outcome));
    json!({ "plan": plan })
}

impl Ctx<'_> {
    pub(super) fn anchor(&self) -> Res<Option<Anchor>> {
        let key = self.require_key()?;
        self.request
            .anchor_json
            .as_deref()
            .map(|text| super::records::parse_anchor(text, key))
            .transpose()
    }

    pub(super) fn snapshot_row(&self) -> Res<Option<Row>> {
        query_row(
            self.connection,
            "select * from extension_control_authority_snapshot where singleton = 1",
            [],
        )
    }

    /// `_resume_idempotent_transition`, up to the writes it performs, with
    /// the command-pack record digest the authenticated transition binds
    /// (null when it binds none).
    fn resume(
        &self,
        row: &Row,
        expected: &Expected,
        current: Option<&View>,
    ) -> Res<(Resume, Value)> {
        let key = self.require_key()?;
        validate_serialized_layers(&expected.layers_json)?;
        if row_int(row, "previous_revision")? != expected.expected_revision
            || row_str(row, "catalog_digest")? != expected.catalog_digest
            || row_str(row, "layers_json")? != expected.layers_json
            || row_str(row, "actor_id_hash")? != expected.actor_hash
            || row_str(row, "idempotency_key_hash")? != expected.idempotency_hash
            || row_str(row, "nonce_hash")? != expected.nonce_hash
        {
            return Err(tampered("idempotency key request mismatch"));
        }
        let snapshot = self
            .snapshot_row()?
            .ok_or_else(|| tampered("extension control authority snapshot missing"))?;
        let previous_revision = row_int(row, "previous_revision")?;
        let revision = row_int(row, "revision")?;
        let snapshot_revision = row_int(&snapshot, "revision")?;
        let previous_digest = if snapshot_revision == previous_revision {
            row_str(&snapshot, "snapshot_digest")?
        } else if snapshot_revision == revision {
            row_optional_str(&snapshot, "previous_digest")?
                .ok_or_else(|| tampered("idempotent transition chain mismatch"))?
        } else {
            return Err(tampered("idempotent transition revision mismatch"));
        };
        let created_at = row_str(row, "created_at")?;
        let snapshot_digest = row_str(row, "snapshot_digest")?;
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
                ("revision", Some(json!(revision))),
                ("previous_revision", Some(json!(previous_revision))),
                ("previous_digest", Some(json!(previous_digest))),
                ("snapshot_digest", Some(json!(snapshot_digest))),
                ("catalog_digest", Some(json!(expected.catalog_digest))),
                ("actor_id_hash", Some(json!(expected.actor_hash))),
                (
                    "idempotency_key_hash",
                    Some(json!(expected.idempotency_hash)),
                ),
                ("nonce_hash", Some(json!(expected.nonce_hash))),
                ("created_at", Some(json!(created_at))),
                ("phase", Some(json!(Phase::Prepared.as_str()))),
            ],
        ) {
            return Err(tampered("idempotent transition authentication mismatch"));
        }
        let pack = field(&transition, "command_pack_record_digest").clone();
        if !(pack.is_null() || pack.is_string()) {
            return Err(tampered("idempotent transition authentication mismatch"));
        }
        let sealed_snapshot = verify_record(
            &row_str(row, "snapshot_json")?,
            &snapshot_digest,
            &row_str(row, "snapshot_mac")?,
            key,
            SNAPSHOT_PURPOSE,
        )?;
        if !fields_match(
            &sealed_snapshot,
            &[
                ("revision", Some(json!(revision))),
                ("catalog_digest", Some(json!(expected.catalog_digest))),
                ("layers_json", Some(json!(expected.layers_json))),
                ("previous_digest", Some(json!(previous_digest))),
                ("committed_at", Some(json!(created_at))),
            ],
        ) {
            return Err(tampered("idempotent snapshot authentication mismatch"));
        }
        let anchor = self
            .anchor()?
            .ok_or_else(|| tampered("extension control authority anchor missing"))?;
        let phase = row_str(row, "phase")?;
        if snapshot_revision == previous_revision
            && anchor.revision == previous_revision
            && anchor.snapshot_digest == previous_digest
            && anchor.phase == Phase::Committed
            && phase == Phase::Prepared.as_str()
        {
            return Ok((Resume::Abandon, pack));
        }
        if anchor.revision == revision
            && anchor.snapshot_digest == snapshot_digest
            && matches!(anchor.phase, Phase::Anchored | Phase::Committed)
        {
            let outcome = if snapshot_revision == previous_revision {
                Resume::CommitPending
            } else if phase != Phase::Committed.as_str() {
                Resume::MarkCommitted
            } else {
                Resume::Finish
            };
            return Ok((outcome, pack));
        }
        if current.is_some_and(|view| view.health == PROTECTED && view.revision == revision) {
            return Ok((Resume::Current, pack));
        }
        Err(tampered("idempotent transition state mismatch"))
    }

    /// `resume_plan`: resume the prepared transition at `revision` for the
    /// request it was prepared for.
    pub(super) fn resume_plan(&self) -> Res<Value> {
        let revision = self
            .request
            .revision
            .ok_or_else(|| tampered("extension control transition head mismatch"))?;
        let Some((_, outcome, pack)) = self.resume_verdict(revision)? else {
            return Ok(plan("absent", Map::new()));
        };
        Ok(plan(
            outcome.as_str(),
            Map::from_iter([
                ("revision".to_owned(), json!(revision)),
                ("command_pack_record_digest".to_owned(), pack),
            ]),
        ))
    }

    /// The prepared row at `revision`, what resuming it for its own request
    /// comes to and the command pack it binds; `None` when there is no row.
    /// A commit retry sends the view it read, so a row that view already
    /// shows committed comes back `current`, as in `commit_plan`.
    pub(super) fn resume_verdict(&self, revision: i64) -> Res<Option<(Row, Resume, Value)>> {
        let Some(row) = self.pending_transition(revision)? else {
            return Ok(None);
        };
        let current = match (&self.request.retry_proof, &self.request.view) {
            (Some(_), Some(_)) => Some(View::from_value(self.request.view.as_ref())?),
            _ => None,
        };
        let (outcome, pack) = self.resume(&row, &Expected::of_row(&row)?, current.as_ref())?;
        Ok(Some((row, outcome, pack)))
    }

    /// `rollback_plan`: `_roll_back_abandoned_transition`. The prepared row
    /// above the committed head is abandoned only when the anchor never
    /// moved past that head and the row outlived its retry window, or the
    /// caller names it as its own failed write; anything else keeps it for
    /// its own retry or explicit recovery.
    pub(super) fn rollback_plan(&self) -> Res<Value> {
        let keep = || Ok(plan("keep", Map::new()));
        let (Some(revision), Some(snapshot_digest), Some(now)) = (
            self.request.revision,
            self.request.snapshot_digest.as_deref(),
            self.request.now.as_deref().and_then(utc_micros),
        ) else {
            return Err(tampered("invalid extension control rollback request"));
        };
        let Ok(Some(anchor)) = self.anchor() else {
            return keep();
        };
        if anchor.revision != revision
            || anchor.snapshot_digest != snapshot_digest
            || anchor.phase != Phase::Committed
        {
            return keep();
        }
        let Some(pending) = self.pending_transition(revision + 1)? else {
            return keep();
        };
        // `_prepared_row_is_stale`: an unreadable clock keeps the row.
        let stale = utc_micros(&row_str(&pending, "created_at")?).is_some_and(|created| {
            now.saturating_sub(created) >= ABANDONED_TRANSITION_GRACE_MICROS
        });
        // A commit that failed before anchoring its own row abandons it at
        // once. Waiting out the retry window would refuse every save in the
        // meantime, and only a writer lease would ever clear it afterwards.
        let own = self
            .request
            .own_transition_digest
            .as_deref()
            .is_some_and(|digest| {
                row_str(&pending, "transition_digest").is_ok_and(|row| row == digest)
            });
        if (!stale && !own) || !self.pending_carries_no_authority(&pending)? {
            return keep();
        }
        Ok(plan(
            "abandon",
            Map::from_iter([("revision".to_owned(), json!(revision + 1))]),
        ))
    }

    /// Whether the prepared row above the committed head carries no authority
    /// of its own: the vault anchor still pins the committed snapshot below
    /// it, and the row authenticates as a prepare that anchor never moved
    /// past. Such a row decides nothing the device enforces, so a reader that
    /// cannot remove it may still serve the committed view, and a writer may
    /// not take the revision it holds.
    ///
    /// A transition that fails to authenticate as that shape is not one a
    /// caller may discount: it is left for its own retry or for explicit
    /// recovery.
    pub(super) fn pending_carries_no_authority(&self, pending: &Row) -> Res<bool> {
        if row_str(pending, "phase")? != Phase::Prepared.as_str() {
            return Ok(false);
        }
        match Expected::of_row(pending).and_then(|expected| self.resume(pending, &expected, None)) {
            Ok((Resume::Abandon, _)) => Ok(true),
            Ok(_) | Err(Fault::Tampered(_)) => Ok(false),
            Err(fault) => Err(fault),
        }
    }
}

#[path = "commit_plan.rs"]
mod commit_plan;
