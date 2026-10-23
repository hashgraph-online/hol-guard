//! `ExtensionControlAuthority` - resident op that reads and verifies the
//! authenticated extension-control authority in the guard store.
//!
//! Every read happens in one read-only transaction. The op never writes: work
//! only a writer may do comes back as an `action`, together with the
//! authenticated inputs it needs, and the caller performs it under the
//! exclusive authority lease before asking again. The writer's own decisions
//! come back the same way, as the `plan` a `*_plan` op answers with. A read that ends on a
//! verdict also reports the catalog-migration events it found missing, which
//! the caller records.
//!
//! A failure the Python store reported as `ExtensionControlAuthorityError`
//! comes back as `{"fault": "tampered"}`; any other failure, which the Python
//! readers turned into a degraded view, as `{"fault": "degraded"}`.

mod catalog;
mod chain;
mod history;
mod installed_upgrade;
#[cfg(test)]
mod installed_upgrade_tests;
mod layers;
mod managed;
mod managed_seals;
#[cfg(test)]
mod managed_seals_tests;
#[cfg(test)]
mod managed_tests;
mod plans;
#[cfg(test)]
mod plans_tests;
pub(crate) mod records;
mod seals;
#[cfg(test)]
mod seals_tests;
#[cfg(test)]
mod tests;
mod view;

use std::cell::RefCell;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    ExtensionControlAuthorityRequestV1, ExtensionControlAuthorityResultV1,
    EXTENSION_CONTROL_AUTHORITY_MAX_BYTES, EXTENSION_CONTROL_AUTHORITY_REQUEST_SCHEMA,
    EXTENSION_CONTROL_AUTHORITY_RESULT_SCHEMA,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::local_store_read::{open_read_only, require_store_path};
use crate::package_authority_op::request_digest_with_limit;
use layers::{layers_from_json, validate_layers, validate_serialized_layers, Manifest};
use records::{
    degraded, fields_match, parse_anchor, query_row, row_py_int, row_str, row_text, row_value,
    tampered, verify_record, Anchor, Fault, Phase, Res, Row, SNAPSHOT_PURPOSE,
};
use view::View;

const INVALID: &str = "native_extension_control_authority_invalid";
const STORE_UNAVAILABLE: &str = "extension control authority store unavailable";

pub(super) const PROTECTED: &str = "protected";
const UNENROLLED: &str = "unenrolled";
const TAMPERED: &str = "tampered";
/// The caller resolves this to acknowledged or unacknowledged degraded mode.
const DEGRADED: &str = "degraded";
const RECOVERY_REQUIRED: &str = "recovery-required";

pub(crate) fn evaluate_extension_control_authority_request(
    request: &ExtensionControlAuthorityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, EXTENSION_CONTROL_AUTHORITY_MAX_BYTES)
        .map_err(|_| "native_extension_control_authority_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ExtensionControlAuthorityResultV1 {
        schema: EXTENSION_CONTROL_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn evaluate(request: &ExtensionControlAuthorityRequestV1) -> Result<Value, String> {
    if request.schema != EXTENSION_CONTROL_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_extension_control_authority_schema_mismatch".to_owned());
    }
    let key = match request.key_b64.as_deref() {
        Some(encoded) => Some(Zeroizing::new(
            Base64UrlUnpadded::decode_vec(encoded).map_err(|_| INVALID.to_owned())?,
        )),
        None => None,
    };
    let key = key.as_deref().map(Vec::as_slice);
    let outcome = match request.op.as_str() {
        "anchor" => anchor_op(request, key),
        "managed_activation" => managed::activation_op(request, key),
        "managed_revision" => managed::revision_op(request, key),
        "seal_anchor" => seals::seal_anchor_op(request, key),
        "seal_manifest" => seals::seal_manifest_op(request, key),
        "seal_managed_revision" => managed_seals::seal_revision_op(request, key),
        "seal_managed_activation" => managed_seals::seal_activation_op(request, key),
        "read" | "read_composed" | "sync_manifest" | "compose_managed" | "load_manifest"
        | "validate_chain" | "history" | "commit_plan" | "resume_plan" | "rollback_plan"
        | "bootstrap_plan" | "migrate_plan" | "restore_plan" => {
            return with_store(request, key);
        }
        _ => return Err(INVALID.to_owned()),
    };
    Ok(outcome.unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

fn fault_value(fault: &Fault, events: Vec<Value>) -> Value {
    let (kind, reason) = match fault {
        Fault::Tampered(reason) => ("tampered", reason),
        Fault::Degraded(reason) => ("degraded", reason),
    };
    json!({ "fault": kind, "reason": reason, "events": events })
}

fn anchor_op(request: &ExtensionControlAuthorityRequestV1, key: Option<&[u8]>) -> Res<Value> {
    let (Some(text), Some(key)) = (request.anchor_json.as_deref(), key) else {
        return Err(tampered("invalid authority anchor"));
    };
    Ok(json!({ "anchor": parse_anchor(text, key)?.to_value() }))
}

fn with_store(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let store_path = require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| INVALID.to_owned())?;
    let unavailable = || Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    let connection = match open_read_only(&store_path) {
        Ok(Some(connection)) => connection,
        Ok(None) | Err(_) => return unavailable(),
    };
    if connection.execute_batch("BEGIN").is_err() {
        return unavailable();
    }
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    let outcome = ctx.dispatch();
    let events = ctx.events.take();
    // Read-only: ending the transaction only releases the snapshot.
    let _ = connection.execute_batch("ROLLBACK");
    Ok(match outcome {
        Ok(mut payload) => {
            payload["events"] = Value::Array(events);
            payload
        }
        Err(fault) => fault_value(&fault, events),
    })
}

pub(super) struct Ctx<'a> {
    pub(super) connection: &'a Connection,
    key: Option<&'a [u8]>,
    pub(super) request: &'a ExtensionControlAuthorityRequestV1,
    events: RefCell<Vec<Value>>,
}

/// How far one `_read_extension_control_authority_locked` call may go.
#[derive(Debug, Clone, Copy)]
struct ReadMode {
    /// The caller holds a registry for the requested catalog.
    migration: bool,
    allow_migration: bool,
}

enum Read {
    View(View),
    /// Writer work the caller performs before asking again.
    Action(Value),
    /// The read needs the full current catalog manifest, not its digest.
    NeedManifest,
}

impl Read {
    fn into_value(self) -> Value {
        match self {
            Self::View(view) => json!({ "view": view.to_value() }),
            Self::Action(action) => json!({ "action": action }),
            Self::NeedManifest => json!({ "need": "current_manifest" }),
        }
    }
}

impl Ctx<'_> {
    fn require_key(&self) -> Res<&[u8]> {
        self.key
            .ok_or_else(|| tampered("extension control authentication key missing"))
    }

    fn catalog_digest(&self) -> Res<&str> {
        self.request
            .catalog_digest
            .as_deref()
            .ok_or_else(|| tampered("extension control catalog digest missing"))
    }

    /// The current manifest when the request carried it in full.
    pub(super) fn current_manifest(&self) -> Option<&Manifest> {
        self.request.current_manifest.as_ref()
    }

    pub(super) fn record_event(&self, event: Value) {
        self.events.borrow_mut().push(event);
    }

    fn dispatch(&self) -> Res<Value> {
        match self.request.op.as_str() {
            "read" => {
                let mode = ReadMode {
                    migration: self.request.migration,
                    allow_migration: self.request.allow_migration,
                };
                Ok(self.read(self.catalog_digest()?, mode)?.into_value())
            }
            "sync_manifest" => self.sync_manifest(View::from_value(self.request.view.as_ref())?),
            "compose_managed" => self.compose_managed(
                View::from_value(self.request.view.as_ref())?,
                self.request.previous_manifest.as_ref(),
            ),
            "read_composed" => self.read_composed(ReadMode {
                migration: self.request.migration,
                allow_migration: self.request.allow_migration,
            }),
            "load_manifest" => {
                Ok(json!({ "manifest": self.load_manifest(self.catalog_digest()?)? }))
            }
            "validate_chain" => {
                let (Some(revision), Some(snapshot_digest)) = (
                    self.request.revision,
                    self.request.snapshot_digest.as_deref(),
                ) else {
                    return Err(tampered("extension control transition head mismatch"));
                };
                self.validate_transition_chain(revision, snapshot_digest)?;
                Ok(json!({ "ok": true }))
            }
            "history" => self.history(),
            "commit_plan" => self.commit_plan(),
            "resume_plan" => self.resume_plan(),
            "rollback_plan" => self.rollback_plan(),
            "bootstrap_plan" => self.bootstrap_plan(),
            "migrate_plan" => self.migrate_plan(),
            "restore_plan" => self.restore_plan(),
            _ => Err(tampered("unsupported extension control authority op")),
        }
    }

    /// `_read_extension_control_authority_locked`, after the caller ensured
    /// the schema and read the key and the raw anchor.
    fn read(&self, catalog_digest: &str, mode: ReadMode) -> Res<Read> {
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
            return recovery();
        }
        if self.pending_transition(revision + 1)?.is_some() {
            if !self.request.rollback_attempted {
                return Ok(Read::Action(json!({
                    "action": "roll_back_abandoned",
                    "revision": revision,
                    "snapshot_digest": row_str(row, "snapshot_digest")?,
                    "anchor": anchor.to_value(),
                })));
            }
            return recovery();
        }
        if anchor.phase != Phase::Committed {
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
        let Some(current_manifest) = self.current_manifest() else {
            return Ok(Read::NeedManifest);
        };
        let (layers, retired_targets) =
            self.rebound_catalog_layers(&previous, catalog_digest, current_manifest)?;
        if !mode.allow_migration || oscillates {
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
