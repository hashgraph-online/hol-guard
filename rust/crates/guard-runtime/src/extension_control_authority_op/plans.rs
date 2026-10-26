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
        let Some(row) = self.pending_transition(revision)? else {
            return Ok(plan("absent", Map::new()));
        };
        let (outcome, pack) = self.resume(&row, &Expected::of_row(&row)?, None)?;
        Ok(plan(
            outcome.as_str(),
            Map::from_iter([
                ("revision".to_owned(), json!(revision)),
                ("command_pack_record_digest".to_owned(), pack),
            ]),
        ))
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

    /// `commit_plan`: the checks `commit_extension_control_layers` makes
    /// under the lease, and the records it seals when they pass.
    pub(super) fn commit_plan(&self) -> Res<Value> {
        let key = self.require_key()?;
        let catalog_digest = self.catalog_digest()?;
        let (Some(commit), Some(created_at)) =
            (self.request.commit.as_ref(), self.request.now.as_deref())
        else {
            return Err(tampered("invalid extension control commit request"));
        };
        let current = View::from_value(self.request.view.as_ref())?;
        validate_serialized_layers(&commit.layers_json)?;
        // The proof was granted for one mutation digest. Recompute it from the
        // layers and identities this plan seals, so a grant cannot commit
        // anything other than what was approved.
        let layers = layers_from_json(&commit.layers_json)?;
        let sealed_digest = mutation_digest(&Mutation {
            previous_revision: commit.expected_revision,
            catalog_digest,
            layers: &layers,
            actor_id: &commit.actor_id,
            idempotency_key: &commit.idempotency_key,
            nonce: &commit.nonce,
        })
        .map_err(|_| tampered("invalid extension control commit request"))?;
        if sealed_digest != commit.mutation_digest {
            return Err(tampered("extension control proof does not match mutation"));
        }
        let actor_hash = private_hash(&commit.actor_id, key, "actor");
        let idempotency_hash = private_hash(&commit.idempotency_key, key, "idempotency");
        let nonce_hash = private_hash(&commit.nonce, key, "nonce");
        let proof_hash = private_hash(&commit.proof_id, key, "proof");
        let hashes = json!({
            "actor": actor_hash,
            "idempotency": idempotency_hash,
            "nonce": nonce_hash,
            "proof": proof_hash,
        });
        let proof = query_row(
            self.connection,
            "select * from extension_control_authority_proof where proof_id_hash = ?",
            params![proof_hash],
        )?;
        let replay = query_row(
            self.connection,
            "select * from extension_control_authority_transition where idempotency_key_hash = ?",
            params![idempotency_hash],
        )?;
        if let Some(proof) = &proof {
            let Some(replay) = &replay else {
                return Err(tampered("extension control authority proof replay"));
            };
            // The grant names the one mutation it was issued for and the one
            // row that reserved it. A grant that names anything else is not
            // this transition's, whatever state that transition is in.
            if row_text(proof, "mutation_digest")? != commit.mutation_digest
                || row_py_int(proof, "transition_revision")? != row_int(replay, "revision")?
            {
                return Err(tampered("extension control authority proof state conflict"));
            }
            let phase = Phase::parse(&row_text(replay, "phase")?)
                .ok_or_else(|| degraded("invalid extension control authority phase"))?;
            // A committed row whose grant was spent is a second use of a
            // commit that already returned. A committed row whose grant is
            // still unspent is this caller's own commit, finished for it by a
            // read that met the sealed head while the call that prepared it
            // was still in flight. Refusing that as a replay would strand the
            // caller: its commit never returned, and the grant it holds is the
            // only one it has. It falls through to `resume`, which checks the
            // row against this request's own identity and layers and settles
            // the grant, so the single use is spent exactly once either way.
            if phase == Phase::Committed && row_optional_str(proof, "consumed_at")?.is_some() {
                return Err(tampered("extension control authority proof replay"));
            }
        }
        if let Some(replay) = &replay {
            let expected = Expected {
                catalog_digest: catalog_digest.to_owned(),
                layers_json: commit.layers_json.clone(),
                actor_hash: actor_hash.clone(),
                idempotency_hash: idempotency_hash.clone(),
                nonce_hash: nonce_hash.clone(),
                expected_revision: commit.expected_revision,
            };
            let (outcome, pack) = self.resume(replay, &expected, Some(&current))?;
            return Ok(plan(
                outcome.as_str(),
                Map::from_iter([
                    ("revision".to_owned(), json!(row_int(replay, "revision")?)),
                    ("command_pack_record_digest".to_owned(), pack),
                    ("proof_recorded".to_owned(), json!(proof.is_some())),
                    ("hashes".to_owned(), hashes),
                ]),
            ));
        }
        if current.health == RECOVERY_REQUIRED && !self.request.rollback_attempted {
            // A different request abandoned its prepared transition before
            // anchoring it; a read that may roll it back lets this one proceed.
            return Ok(plan("reread", Map::new()));
        }
        if current.health != PROTECTED {
            return Err(tampered("extension control authority unavailable"));
        }
        if current.revision != commit.expected_revision {
            return Err(tampered("extension control authority revision conflict"));
        }
        // Another request's prepared row already holds the revision this
        // commit would write. A read that may roll it back lets this one
        // proceed; once such a read has run and the row is still there, it is
        // a live transition this request must not take. The served view no
        // longer reports that row -- an unanchored prepare decides nothing,
        // and reporting it would stop every command on the device -- so the
        // occupied revision is checked here rather than read off the health
        // the caller was handed.
        if self.pending_transition(current.revision + 1)?.is_some() {
            if self.request.rollback_attempted {
                return Err(tampered("extension control authority unavailable"));
            }
            return Ok(plan("reread", Map::new()));
        }
        let seen = |sql: &str, value: &str| -> Res<bool> {
            Ok(query_row(self.connection, sql, params![value])?.is_some())
        };
        if seen(
            "select 1 from extension_control_authority_transition where nonce_hash = ?",
            &nonce_hash,
        )? {
            return Err(tampered("extension control authority nonce replay"));
        }
        if seen(
            "select 1 from extension_control_authority_proof where proof_id_hash = ?",
            &proof_hash,
        )? {
            return Err(tampered("extension control authority proof replay"));
        }
        let source = self
            .snapshot_row()?
            .ok_or_else(|| tampered("extension control authority snapshot missing"))?;
        let previous_digest = row_text(&source, "snapshot_digest")?;
        let revision = current.revision + 1;
        let pack = commit.pack_record_digest.as_deref();
        let retained = snapshot_pack_binding(&source, key)?;
        let snapshot = sealed(
            with_pack(
                json!({
                    "revision": revision,
                    "catalog_digest": catalog_digest,
                    "layers_json": commit.layers_json,
                    "previous_digest": previous_digest,
                    "committed_at": created_at,
                }),
                pack.or(retained.as_deref()),
            ),
            key,
            SNAPSHOT_PURPOSE,
        )?;
        let transition = sealed(
            with_pack(
                json!({
                    "revision": revision,
                    "previous_revision": current.revision,
                    "previous_digest": previous_digest,
                    "snapshot_digest": snapshot["digest"],
                    "catalog_digest": catalog_digest,
                    "actor_id_hash": actor_hash,
                    "idempotency_key_hash": idempotency_hash,
                    "nonce_hash": nonce_hash,
                    "created_at": created_at,
                    "phase": Phase::Prepared.as_str(),
                }),
                pack,
            ),
            key,
            TRANSITION_PURPOSE,
        )?;
        Ok(plan(
            "prepare",
            Map::from_iter([
                ("revision".to_owned(), json!(revision)),
                ("previous_revision".to_owned(), json!(current.revision)),
                ("previous_digest".to_owned(), json!(previous_digest)),
                ("created_at".to_owned(), json!(created_at)),
                ("hashes".to_owned(), hashes),
                ("snapshot".to_owned(), snapshot),
                ("transition".to_owned(), transition),
            ]),
        ))
    }
}
