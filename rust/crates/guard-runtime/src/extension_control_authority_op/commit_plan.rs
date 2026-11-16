//! `commit_plan`: what a commit checks under the lease and the records it
//! seals when those checks pass.

use super::*;

impl Ctx<'_> {
    /// `commit_plan`: the checks `commit_extension_control_layers` makes
    /// under the lease, and the records it seals when they pass.
    pub(in super::super) fn commit_plan(&self) -> Res<Value> {
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
