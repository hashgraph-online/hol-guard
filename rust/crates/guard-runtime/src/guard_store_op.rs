//! `GuardStore` — resident op owning request-path persistence over
//! `guard.db`. Each call opens the store, applies the same connection pragmas
//! as the Python store, runs one method in a single SQLite transaction,
//! finalizes trigger-written outbox payload hashes, commits, and reports the
//! outbox generation when rows changed.
//!
//! Process-local concerns (the storage-access lock, wake notification,
//! permission repair, fatal-store recovery, wall-clock timestamps) stay with
//! the Python caller, which passes every timestamp in the request.

use std::time::Duration;

use guard_contracts::{
    GuardStoreRequestV1, GuardStoreResultV1, GUARD_STORE_MAX_REQUEST_BYTES,
    GUARD_STORE_REQUEST_SCHEMA, GUARD_STORE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::guard_store_args::Args;
use crate::guard_store_clients as clients;
use crate::guard_store_cmd_activity as activity;
use crate::guard_store_cmd_api as api;
use crate::guard_store_cmd_feedback as feedback;
use crate::guard_store_cmd_lifecycle as lifecycle;
use crate::guard_store_cmd_maintenance as maintenance;
use crate::guard_store_cmd_privacy as privacy;
use crate::guard_store_db::{exec, query_all, query_one, text, StoreError, StoreResult};
use crate::guard_store_inventory as inventory;
use crate::guard_store_outbox_binding::{
    count_recoverable_unbound, load_binding, normalized_binding, reassign_quarantined,
    refresh_same_subject,
};
use crate::guard_store_outbox_identity::payload_digest;
use crate::guard_store_outbox_queries as queries;
use crate::guard_store_outbox_reads as reads;
use crate::guard_store_outbox_recover::recover_sequences;
use crate::guard_store_outbox_requeue::{repair_rejected_correlation, requeue_method};
use crate::guard_store_sessions as sessions;
use crate::guard_store_storage_maintenance as storage_maintenance;

const MAX_BUSY_TIMEOUT_MS: u64 = 600_000;
const CACHE_SIZE_KIB: i64 = 256 * 1024;
const MMAP_SIZE_BYTES: i64 = 1024 * 1024 * 1024;

fn request_digest(request: &GuardStoreRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_guard_store_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, GUARD_STORE_MAX_REQUEST_BYTES)
        .map_err(|_| "native_guard_store_request_too_large")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_guard_store_request(
    request: &GuardStoreRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, payload, generation) = match evaluate(request) {
        Ok((payload, generation)) => ("ok".to_owned(), "ok".to_owned(), Some(payload), generation),
        Err(error) => {
            let payload = Some(json!({ "message": error.message() }));
            ("error".to_owned(), error.code().to_owned(), payload, None)
        }
    };
    crate::encode_response(&GuardStoreResultV1 {
        schema: GUARD_STORE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
        outbox_generation: generation,
    })
}

fn evaluate(request: &GuardStoreRequestV1) -> StoreResult<(Value, Option<i64>)> {
    let invalid = |code| Err(StoreError::Invalid(code));
    if request.schema != GUARD_STORE_REQUEST_SCHEMA {
        return invalid("native_guard_store_schema_mismatch");
    }
    if request.request_id.is_empty()
        || request.source.is_empty()
        || !(1..=MAX_BUSY_TIMEOUT_MS).contains(&request.busy_timeout_ms)
    {
        return invalid("native_guard_store_invalid");
    }
    let path =
        crate::local_store_read::require_store_path(&request.store_path, &request.guard_home)
            .map_err(|_| StoreError::Invalid("native_guard_store_path_invalid"))?;
    let kind = match method_kind(&request.method) {
        Some(kind) => kind,
        None => return invalid("native_guard_store_method_unknown"),
    };
    let writes = kind == Kind::Write;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_millis(request.busy_timeout_ms))?;
    apply_pragmas(&connection)?;
    let initial_changes = connection.total_changes();
    match kind {
        Kind::Write => connection.execute_batch("BEGIN IMMEDIATE")?,
        Kind::Snapshot => connection.execute_batch("BEGIN")?,
        Kind::Read => {}
    }
    let args = Args(&request.args);
    let outcome = dispatch(&connection, &request.source, &request.method, &args);
    let payload = match outcome {
        Ok(payload) => payload,
        Err(error) => {
            if kind != Kind::Read {
                let _ = connection.execute_batch("ROLLBACK");
            }
            return Err(error);
        }
    };
    if kind == Kind::Snapshot {
        connection.execute_batch("ROLLBACK")?;
    } else {
        finalize_and_commit(&connection, writes)?;
    }
    let generation = (connection.total_changes() > initial_changes)
        .then(|| outbox_generation(&connection))
        .transpose()?;
    Ok((payload, generation))
}

fn apply_pragmas(connection: &Connection) -> StoreResult<()> {
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if journal.eq_ignore_ascii_case("wal") {
        connection.execute_batch("pragma synchronous=NORMAL")?;
    }
    connection.execute_batch(&format!(
        "pragma cache_size=-{CACHE_SIZE_KIB}; pragma mmap_size={MMAP_SIZE_BYTES};"
    ))?;
    Ok(())
}

/// Finalize empty trigger-written payload digests, then commit.
fn finalize_and_commit(connection: &Connection, in_transaction: bool) -> StoreResult<()> {
    let pending = query_one(
        connection,
        "select 1 as present from guard_review_outbox_events where payload_hash = '' limit 1",
        &[],
    )?
    .is_some();
    if pending && !in_transaction {
        connection.execute_batch("BEGIN IMMEDIATE")?;
    }
    if pending {
        finalize_payload_hashes(connection)?;
    }
    if in_transaction || pending {
        connection.execute_batch("COMMIT")?;
    }
    Ok(())
}

fn finalize_payload_hashes(connection: &Connection) -> StoreResult<()> {
    let null = Value::Null;
    let rows = query_all(
        connection,
        "select stream_sequence, payload_json, oauth_source, oauth_subject_hash, \
         workspace_id, machine_id, machine_installation_id \
         from guard_review_outbox_events where payload_hash = ''",
        &[],
    )?;
    for row in &rows {
        let field = |name: &str| row.get(name).unwrap_or(&null);
        let digest = payload_digest(
            text(row, "payload_json"),
            [
                field("oauth_source"),
                field("oauth_subject_hash"),
                field("workspace_id"),
                field("machine_id"),
                field("machine_installation_id"),
            ],
        );
        exec(
            connection,
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            &[Value::from(digest), field("stream_sequence").clone()],
        )?;
    }
    Ok(())
}

fn outbox_generation(connection: &Connection) -> StoreResult<i64> {
    let table = query_one(
        connection,
        "select 1 as present from sqlite_master \
         where type = 'table' and name = 'guard_review_outbox_wake_state'",
        &[],
    )?;
    if table.is_none() {
        return Ok(0);
    }
    Ok(query_one(
        connection,
        "select generation from guard_review_outbox_wake_state where singleton = 1",
        &[],
    )?
    .map_or(0, |row| crate::guard_store_db::int(&row, "generation")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    /// Several reads inside one deferred transaction for a consistent view.
    Snapshot,
    Write,
}

fn method_kind(method: &str) -> Option<Kind> {
    Some(match method {
        "review_event_outbox_status"
        | "list_ready_review_events"
        | "list_review_event_snapshots"
        | "get_review_event_oauth_binding"
        | "count_recoverable_unbound_review_events"
        | "list_pending_review_request_ids"
        | "command_activity_by_request_correlation"
        | "is_exact_command_activity_pre_replay"
        | "command_activity_rollups_are_reconciled"
        | "count_command_shadow_observations"
        | "get_guard_session"
        | "list_guard_sessions"
        | "get_guard_operation"
        | "list_guard_operations"
        | "get_guard_operation_for_approval_request"
        | "list_guard_operation_items"
        | "get_guard_client_attachment"
        | "list_guard_client_attachments"
        | "has_guard_surface_open"
        | "get_artifact_snapshot"
        | "list_artifact_snapshots"
        | "list_artifact_inventory"
        | "find_artifact_inventory_item"
        | "get_artifact_capability"
        | "run_storage_housekeeping" => Kind::Read,
        "list_command_activity_page"
        | "command_activity_analytics"
        | "list_command_activity_invalidations"
        | "command_activity_diagnostics"
        | "list_command_shadow_observations" => Kind::Snapshot,
        "refresh_review_event_outbox_binding_for_identity"
        | "refresh_review_event_outbox_binding"
        | "reassign_quarantined_review_events"
        | "acknowledge_review_events"
        | "retry_review_events"
        | "quarantine_review_event"
        | "requeue_pending_review_events"
        | "requeue_pending_review_events_with_marker"
        | "repair_rejected_review_correlation"
        | "recover_review_snapshot_sequences"
        | "record_command_activity"
        | "probe_command_activity_persistence"
        | "transition_command_activity"
        | "record_command_activity_persistence_failure"
        | "record_command_activity_observation_conflict"
        | "maintain_command_activity"
        | "rebuild_command_activity_rollups"
        | "record_command_activity_feedback"
        | "clear_command_activity_evidence"
        | "upsert_guard_session"
        | "upsert_guard_operation"
        | "add_guard_operation_item"
        | "attach_guard_client"
        | "renew_guard_client_attachment"
        | "record_guard_surface_open"
        | "save_artifact_snapshot"
        | "delete_artifact_snapshot"
        | "record_artifact_diff"
        | "record_inventory_artifact"
        | "mark_inventory_removed"
        | "save_artifact_capability"
        | "upsert_provenance_cache"
        | "next_aibom_trust_attestation_sequence"
        | "maintain_storage" => Kind::Write,
        _ => return None,
    })
}

fn dispatch(
    connection: &Connection,
    source: &str,
    method: &str,
    args: &Args,
) -> StoreResult<Value> {
    match method {
        "review_event_outbox_status" => queries::status(connection, source, args),
        "list_ready_review_events" => reads::list_ready(connection, source, args),
        "list_review_event_snapshots" => reads::list_snapshots(connection, source, args),
        "list_pending_review_request_ids" => {
            queries::list_pending_request_ids(connection, source, args)
        }
        "get_review_event_oauth_binding" => Ok(load_binding(connection, source)?.map_or(
            Value::Null,
            |binding| {
                json!({
                    "oauth_source": source,
                    "oauth_subject_hash": binding.subject_hash,
                    "workspace_id": binding.workspace_id,
                    "machine_id": binding.machine_id,
                    "machine_installation_id": binding.installation_id,
                })
            },
        )),
        "count_recoverable_unbound_review_events" => {
            Ok(json!(count_recoverable_unbound(connection, source)?))
        }
        "refresh_review_event_outbox_binding" => {
            Ok(json!(refresh_same_subject(connection, source)?))
        }
        "refresh_review_event_outbox_binding_for_identity" => {
            let supplied = normalized_binding([
                args.str("oauth_subject_hash")?,
                args.str("workspace_id")?,
                args.str("machine_id")?,
                args.str("machine_installation_id")?,
            ])?;
            match load_binding(connection, source)? {
                Some(current) if current == supplied => {
                    Ok(json!(refresh_same_subject(connection, source)?))
                }
                _ => Ok(json!(0)),
            }
        }
        "reassign_quarantined_review_events" => Ok(json!(reassign_quarantined(
            connection,
            source,
            args.str("approved_source")?,
            args.str("approved_workspace_id")?,
            args.flag("only_unbound")?,
        )?)),
        "acknowledge_review_events" => queries::acknowledge_method(connection, source, args),
        "retry_review_events" => queries::retry_events(connection, source, args),
        "quarantine_review_event" => queries::quarantine_event(connection, source, args),
        "requeue_pending_review_events" => requeue_method(connection, source, args, false),
        "requeue_pending_review_events_with_marker" => {
            requeue_method(connection, source, args, true)
        }
        "repair_rejected_review_correlation" => {
            repair_rejected_correlation(connection, source, args)
        }
        "recover_review_snapshot_sequences" => recover_sequences(connection, source, args),
        "record_command_activity" => activity::record_command_activity(connection, args),
        "probe_command_activity_persistence" => activity::probe_persistence(connection, args),
        "transition_command_activity" => lifecycle::transition(connection, args),
        "record_command_activity_persistence_failure" => {
            lifecycle::persistence_failure(connection, args)
        }
        "record_command_activity_observation_conflict" => {
            lifecycle::observation_conflict(connection, args)
        }
        "command_activity_by_request_correlation" => {
            lifecycle::activity_by_correlation(connection, args)
        }
        "is_exact_command_activity_pre_replay" => lifecycle::is_exact_pre_replay(connection, args),
        "maintain_command_activity" => maintenance::maintain(connection, args),
        "rebuild_command_activity_rollups" => maintenance::rebuild_rollups(connection, args),
        "command_activity_rollups_are_reconciled" => {
            maintenance::rollups_are_reconciled(connection)
        }
        "list_command_activity_page" => api::list_page(connection, args),
        "command_activity_analytics" => api::analytics(connection, args),
        "record_command_activity_feedback" => feedback::record_feedback(connection, args),
        "list_command_activity_invalidations" => feedback::list_invalidations(connection, args),
        "clear_command_activity_evidence" => privacy::clear_evidence(connection),
        "command_activity_diagnostics" => privacy::diagnostics(connection, args),
        "count_command_shadow_observations" => privacy::count_shadow(connection),
        "list_command_shadow_observations" => privacy::list_shadow(connection, args),
        "upsert_guard_session" => sessions::upsert_session(connection, args),
        "get_guard_session" => sessions::get_session(connection, args),
        "list_guard_sessions" => sessions::list_sessions(connection, args),
        "upsert_guard_operation" => sessions::upsert_operation(connection, args),
        "get_guard_operation" => sessions::get_operation(connection, args),
        "list_guard_operations" => sessions::list_operations(connection, args),
        "get_guard_operation_for_approval_request" => {
            sessions::operation_for_approval_request(connection, args)
        }
        "add_guard_operation_item" => sessions::add_operation_item(connection, args),
        "list_guard_operation_items" => sessions::list_operation_items(connection, args),
        "attach_guard_client" => clients::attach_client(connection, args),
        "renew_guard_client_attachment" => clients::renew_attachment(connection, args),
        "get_guard_client_attachment" => clients::get_attachment(connection, args),
        "list_guard_client_attachments" => clients::list_attachments(connection, args),
        "record_guard_surface_open" => clients::record_surface_open(connection, args),
        "has_guard_surface_open" => clients::has_surface_open(connection, args),
        "save_artifact_snapshot" => inventory::save_snapshot(connection, args),
        "get_artifact_snapshot" => inventory::get_snapshot(connection, args),
        "list_artifact_snapshots" => inventory::list_snapshots(connection, args),
        "delete_artifact_snapshot" => inventory::delete_snapshot(connection, args),
        "record_artifact_diff" => inventory::record_diff(connection, args),
        "record_inventory_artifact" => inventory::record_inventory_artifact(connection, args),
        "mark_inventory_removed" => inventory::mark_removed(connection, args),
        "list_artifact_inventory" => inventory::list_inventory(connection, args),
        "find_artifact_inventory_item" => inventory::find_inventory_item(connection, args),
        "save_artifact_capability" => inventory::save_capability(connection, args),
        "get_artifact_capability" => inventory::get_capability(connection, args),
        "upsert_provenance_cache" => inventory::upsert_provenance(connection, args),
        "next_aibom_trust_attestation_sequence" => {
            inventory::next_attestation_sequence(connection, args)
        }
        "maintain_storage" => storage_maintenance::maintain(connection, args),
        "run_storage_housekeeping" => storage_maintenance::housekeeping(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}
