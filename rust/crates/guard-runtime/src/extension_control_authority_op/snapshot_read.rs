//! The authority read: the stored snapshot verified against the vault
//! anchor, and the catalog migration a read across catalogs resumes or asks
//! for.

use super::*;

impl Ctx<'_> {
    /// `_read_extension_control_authority_locked`, after the caller ensured
    /// the schema and read the key and the raw anchor.
    pub(super) fn read(&self, catalog_digest: &str, mode: ReadMode) -> Res<Read> {
        let anchor = match (self.key, self.request.anchor_json.as_deref()) {
            (Some(key), Some(text)) => match parse_anchor(text, key) {
                Ok(anchor) => Some(anchor),
                Err(_) => return Ok(Read::View(View::bare(DEGRADED, 0, catalog_digest))),
            },
            _ => None,
        };
        let row = query_row(
            self.connection,
            "select * from extension_control_authority_snapshot where singleton = 1",
            [],
        )?;
        let (row, anchor) = match (row, anchor) {
            (None, None) => return Ok(Read::View(View::bare(UNENROLLED, 0, catalog_digest))),
            // The database was re-created while the vault still holds the key
            // and anchor: the last-good export may restore the exact snapshot.
            (None, Some(anchor)) if self.key.is_some() && !self.request.restore_attempted => {
                return Ok(Read::Action(json!({
                    "action": "restore_last_good",
                    "anchor": anchor.to_value(),
                })));
            }
            (Some(row), Some(anchor)) if self.key.is_some() => (row, anchor),
            _ => return Ok(Read::View(View::bare(TAMPERED, 0, catalog_digest))),
        };
        match self.read_snapshot(catalog_digest, mode, &row, &anchor) {
            Err(Fault::Tampered(_)) => Ok(Read::View(View::bare(TAMPERED, 0, catalog_digest))),
            other => other,
        }
    }

    fn read_snapshot(
        &self,
        catalog_digest: &str,
        mode: ReadMode,
        row: &Row,
        anchor: &Anchor,
    ) -> Res<Read> {
        let key = self.require_key()?;
        let revision = row_py_int(row, "revision")?;
        let stored_catalog_digest = row_text(row, "catalog_digest")?;
        let mut validation_catalog_digest = catalog_digest;
        if stored_catalog_digest != catalog_digest {
            if layers_from_json(&row_text(row, "layers_json")?)?.is_empty() {
                // No layers means nothing is bound to a catalog, so the
                // authority is served as-is instead of committing an empty
                // revision whenever another catalog reads the same home.
                validation_catalog_digest = &stored_catalog_digest;
            } else {
                return self.read_across_catalogs(
                    catalog_digest,
                    &stored_catalog_digest,
                    revision,
                    mode,
                );
            }
        }
        let snapshot_digest = row_text(row, "snapshot_digest")?;
        let layers_json = row_text(row, "layers_json")?;
        let payload = verify_record(
            &row_text(row, "snapshot_json")?,
            &snapshot_digest,
            &row_text(row, "snapshot_mac")?,
            key,
            SNAPSHOT_PURPOSE,
        )?;
        if !fields_match(
            &payload,
            &[
                ("revision", Some(json!(revision))),
                ("catalog_digest", Some(json!(stored_catalog_digest))),
                ("layers_json", Some(json!(layers_json))),
                ("previous_digest", row_value(row, "previous_digest")?),
                ("committed_at", Some(json!(row_text(row, "committed_at")?))),
            ],
        ) {
            return Err(tampered("extension control snapshot field mismatch"));
        }
        validate_serialized_layers(&layers_json)?;
        let layers = layers_from_json(&layers_json)?;
        validate_layers(&layers, validation_catalog_digest)?;
        let recovery = || {
            Ok(Read::View(View::bare(
                RECOVERY_REQUIRED,
                revision,
                catalog_digest,
            )))
        };
        if anchor.revision != revision || anchor.snapshot_digest != snapshot_digest {
            let pending = self.pending_transition(revision + 1)?;
            let interrupted = match &pending {
                Some(pending)
                    if anchor.phase == Phase::Anchored && anchor.revision == revision + 1 =>
                {
                    anchor.snapshot_digest == row_str(pending, "snapshot_digest")?
                }
                _ => false,
            };
            if !interrupted {
                return Err(tampered("extension control authority rollback detected"));
            }
            // The commit sealed the anchor and then died before the row said
            // so. Nothing here is left for a person to decide: `resume_plan`
            // re-verifies the prepared row's transition record and sealed
            // snapshot under the authority key, pins every field of both, and
            // the anchor authenticates the same digest independently, so the
            // revision that was already authorised is finished rather than
            // held. Only a shape that proof cannot settle still reports
            // `recovery-required`, which is what the explicit recovery verb is
            // for. Without this the authority stays unhealthy for good: the
            // abandoned-row rollback needs the anchor to still sit on the
            // committed head, and this anchor has moved past it, so every
            // later command is blocked until a person runs that verb.
            //
            // A commit retrying its own request is the one caller this is not
            // for: it settles that row under the single-use proof it still
            // holds, and finishing the row out from under it would leave that
            // proof reserved against a committed transition, which reads as a
            // replay. It is the only caller that asks for a read with
            // `rollback_attempted` already set, which is how it says the
            // prepared row is its own; a read that set the flag by rolling a
            // row back cannot be here, since that shape leaves the anchor on
            // the committed head and this one has moved past it.
            if !self.request.rollback_attempted && !self.request.resume_attempted {
                return Ok(Read::Action(json!({
                    "action": "resume_pending",
                    "revision": revision + 1,
                    "current_revision": revision,
                    "stored_catalog_digest": &stored_catalog_digest,
                })));
            }
            return recovery();
        }
        if let Some(pending) = self.pending_transition(revision + 1)? {
            if !self.request.rollback_attempted {
                return Ok(Read::Action(json!({
                    "action": "roll_back_abandoned",
                    "revision": revision,
                    "snapshot_digest": row_str(row, "snapshot_digest")?,
                    "anchor": anchor.to_value(),
                })));
            }
            // The caller asked and the row is still here: either its own retry
            // window has not run out, or the caller reads under a shared lease
            // and cannot write at all. Neither says anything about the
            // authority this read already authenticated. A prepare the anchor
            // never moved past carries nothing the device enforces, so the
            // committed snapshot below it is served and the row is left to the
            // next writer, which holds the lock exclusively and discards it
            // once its window closes. Reporting recovery here instead would
            // stop every command on the device -- with no approval to offer,
            // since there is no decision left to make -- until a writer
            // happened to run. A pending row of any other shape is a state
            // this read may not discount, and still needs explicit recovery.
            if !self.pending_carries_no_authority(&pending)? {
                return recovery();
            }
        }
        if anchor.phase != Phase::Committed {
            // The anchor already seals this revision and this digest: the
            // commit got as far as sealing its head and died before the row
            // and the anchor said the revision was closed. That is the same
            // interrupted commit as above, caught one step later, when the
            // snapshot row had already advanced to the sealed revision. The
            // proof is no weaker here than there: the sealed snapshot was
            // verified under the authority key and every field of it pinned
            // against the row before this point, and `resume_plan` verifies
            // the prepared row's transition record independently before it
            // settles anything, so finishing the phase authorises nothing the
            // anchor had not already authorised. A prepared anchor is left
            // alone, since nothing has sealed a head for it to finish.
            if anchor.phase == Phase::Anchored
                && !self.request.rollback_attempted
                && !self.request.resume_attempted
            {
                return Ok(Read::Action(json!({
                    "action": "resume_pending",
                    "revision": revision,
                    "current_revision": revision,
                    "stored_catalog_digest": &stored_catalog_digest,
                })));
            }
            return recovery();
        }
        self.validate_transition_chain(revision, &row_str(row, "snapshot_digest")?)?;
        if let Some(event) = self.catalog_migrated_backfill(revision, catalog_digest, &layers)? {
            self.record_event(event);
        }
        Ok(Read::View(View {
            health: PROTECTED.to_owned(),
            revision,
            catalog_digest: catalog_digest.to_owned(),
            layers,
            managed_revision: 0,
        }))
    }

    /// The stored authority is bound to another catalog: resume the prepared
    /// migration to this one, rebind in memory, or ask the caller to migrate.
    fn read_across_catalogs(
        &self,
        catalog_digest: &str,
        stored_catalog_digest: &str,
        revision: i64,
        mode: ReadMode,
    ) -> Res<Read> {
        if !mode.migration {
            return Err(tampered("extension control catalog digest changed"));
        }
        if mode.allow_migration && !self.request.resume_attempted {
            if let Some(pending) = self.pending_transition(revision + 1)? {
                if row_str(&pending, "catalog_digest")? == catalog_digest {
                    return Ok(Read::Action(json!({
                        "action": "resume_pending",
                        "revision": revision + 1,
                        "current_revision": revision,
                        "stored_catalog_digest": stored_catalog_digest,
                    })));
                }
            }
        }
        let source = ReadMode {
            migration: false,
            allow_migration: true,
        };
        let previous = match self.read(stored_catalog_digest, source)? {
            Read::View(view) if view.health == PROTECTED => view,
            Read::View(_) => {
                return Err(tampered(
                    "extension control catalog migration source unavailable",
                ))
            }
            other => return Ok(other),
        };
        // Two runtimes with different catalogs sharing a home would otherwise
        // commit a revision on every read, migrating the authority back and
        // forth faster than a dashboard draft can be applied.
        let oscillates = mode.allow_migration
            && self.migration_oscillates(revision, catalog_digest, stored_catalog_digest)?;
        // The source read serves the committed view while a prepare that
        // decides nothing still holds the next revision. Migrating now would
        // insert a second transition at that occupied revision, so the
        // migration waits for the writer that discards the row and the read
        // is served rebound in memory meanwhile.
        let next_occupied =
            mode.allow_migration && self.pending_transition(revision + 1)?.is_some();
        let Some(current_manifest) = self.current_manifest() else {
            return Ok(Read::NeedManifest);
        };
        let (layers, retired_targets) =
            self.rebound_catalog_layers(&previous, catalog_digest, current_manifest)?;
        if !mode.allow_migration || oscillates || next_occupied {
            return Ok(Read::View(View {
                catalog_digest: catalog_digest.to_owned(),
                layers,
                ..previous
            }));
        }
        Ok(Read::Action(catalog::migrate_action(
            &previous,
            catalog_digest,
            &layers,
            &retired_targets,
        )))
    }
}
