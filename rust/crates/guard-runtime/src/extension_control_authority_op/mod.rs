//! `ExtensionControlAuthority` - resident op that reads and verifies the
//! authenticated extension-control authority in the guard store.
//!
//! Every read happens in one read-only transaction. A read never writes: work
//! only a writer may do comes back as an `action`, together with the
//! authenticated inputs it needs, and the caller has it done under the
//! exclusive authority lease before asking again. The writer's own decisions
//! come back the same way, as the `plan` a `*_plan` op answers with; `restore`,
//! `roll_back` and `resume` apply theirs here (see `writes` and `resume`). A read that ends on a
//! verdict also reports the catalog-migration events it found missing, which
//! the caller records.
//!
//! A failure the Python store reported as `ExtensionControlAuthorityError`
//! comes back as `{"fault": "tampered"}`; any other failure, which the Python
//! readers turned into a degraded view, as `{"fault": "degraded"}`.

mod catalog;
mod chain;
mod change_event;
mod command_marker;
#[cfg(test)]
mod command_marker_tests;
mod commit;
mod earned_anchor;
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
mod migrate;
mod migration_event;
mod pack_finish;
mod pack_reserve;
mod plans;
#[cfg(test)]
mod plans_tests;
mod policy_apply;
mod policy_clear;
mod private_state;
#[cfg(test)]
mod private_state_tests;
pub(crate) mod records;
mod reset;
mod resume;
mod review_memory;
mod schema;
#[cfg(test)]
mod schema_tests;
mod seals;
#[cfg(test)]
mod seals_tests;
mod snapshot_read;
#[cfg(test)]
mod tests;
mod view;
mod writes;

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
        "seal_managed_revision" => managed_seals::seal_revision_op(request, key),
        "seal_managed_activation" => managed_seals::seal_activation_op(request, key),
        "read" | "read_composed" | "sync_manifest" | "compose_managed" | "load_manifest"
        | "validate_chain" | "history" | "commit_plan" | "resume_plan" | "rollback_plan"
        | "bootstrap_plan" | "migrate_plan" | "restore_plan" | "write_anchor" => {
            return with_store(request, key);
        }
        "restore" | "roll_back" => return writes::with_writable_store(request, key),
        "commit_prepare" => return commit::commit_prepare_op(request, key),
        "resume" => return resume::resume_op(request, key),
        "queue_change" => return change_event::queue_change_op(request, key),
        "apply_policy" => return policy_apply::apply_policy_op(request, key),
        "apply_review_memory" => return review_memory::apply_review_memory_op(request, key),
        "clear_policy" => return policy_clear::clear_policy_op(request, key),
        "migrate" => return migrate::migrate_op(request, key),
        "bootstrap" => return commit::bootstrap_op(request, key),
        "write_manifest" => return commit::write_manifest_op(request, key),
        "reset" => return reset::reset_op(request),
        "abandon_bootstrap" => return reset::abandon_bootstrap_op(request),
        "record_migration" => return migration_event::record_migration_op(request),
        "write_private_state" => {
            return Ok(private_state::write_private_state_op(request)
                .unwrap_or_else(|code| json!({ "error": code })));
        }
        "write_command_marker" => {
            return Ok(command_marker::write_command_marker_op(request, key)
                .unwrap_or_else(|code| json!({ "error": code })));
        }
        _ => return Err(INVALID.to_owned()),
    };
    Ok(outcome.unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

fn fault_value(fault: &Fault, events: Vec<Value>) -> Value {
    let (kind, reason) = match fault {
        Fault::Tampered(reason) => ("tampered", reason),
        Fault::Degraded(reason) => ("degraded", reason),
        Fault::Pack(reason) => ("pack", reason),
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
            "write_anchor" => self.write_earned_anchor(),
            _ => Err(tampered("unsupported extension control authority op")),
        }
    }
}
