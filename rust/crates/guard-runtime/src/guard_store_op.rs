//! `GuardStore` — resident op owning request-path persistence over
//! `guard.db`. Each call opens the store (reusing a kept connection to the
//! same file), applies the same connection pragmas
//! as the Python store, runs one method in a single SQLite transaction,
//! finalizes trigger-written outbox payload hashes, commits, and reports the
//! outbox generation when rows changed.
//!
//! Process-local concerns (the storage-access lock, wake notification,
//! permission repair, fatal-store recovery, wall-clock timestamps) stay with
//! the caller, which passes every timestamp in the request.

use std::time::Duration;

use guard_contracts::{
    GuardStoreRequestV1, GuardStoreResultV1, GUARD_STORE_MAX_REQUEST_BYTES,
    GUARD_STORE_REQUEST_SCHEMA, GUARD_STORE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::guard_store_advisory_cache as advisory_cache;
use crate::guard_store_approval_backfill;
use crate::guard_store_approval_metadata as approval_metadata;
use crate::guard_store_approval_page_reads as approval_pages;
use crate::guard_store_approval_queue::queue_blocked_approvals;
use crate::guard_store_approval_queue_result as queue_result;
use crate::guard_store_approval_reads as approval_reads;
use crate::guard_store_approval_resolve::{
    resolve_approval_request, resolve_harness_native_approval_request,
    resolve_matching_duplicate_requests,
};
use crate::guard_store_approval_sweep::resolve_matching_approval_requests;
use crate::guard_store_approval_write::{add_approval_request, add_native_review_approval_request};
use crate::guard_store_args::Args;
use crate::guard_store_claude_review::add_claude_native_review_approval_request;
use crate::guard_store_clients as clients;
use crate::guard_store_cmd_activity as activity;
use crate::guard_store_cmd_api as api;
use crate::guard_store_cmd_feedback as feedback;
use crate::guard_store_cmd_lifecycle as lifecycle;
use crate::guard_store_cmd_maintenance as maintenance;
use crate::guard_store_cmd_privacy as privacy;
use crate::guard_store_composio_catalog as composio_catalog;
use crate::guard_store_connect as connect;
use crate::guard_store_connector_context as connector_context;
use crate::guard_store_db::{exec, query_all, query_one, text, StoreError, StoreResult};
use crate::guard_store_inventory as inventory;
use crate::guard_store_local_cli as local_cli;
use crate::guard_store_local_cli_catalog as local_cli_catalog;
use crate::guard_store_local_cli_grants as local_cli_grants;
use crate::guard_store_local_cli_inventory as local_cli_inventory;
use crate::guard_store_local_mcp_declarations as local_mcp_declarations;
use crate::guard_store_local_mcp_observation as local_mcp;
use crate::guard_store_mcp_provider_reads as mcp_provider_reads;
use crate::guard_store_mcp_workflow_reads as mcp_workflow_reads;
use crate::guard_store_native_receipts as native_receipts;
use crate::guard_store_native_review_consume as native_review_consume;
use crate::guard_store_observed_mcp as observed_mcp;
use crate::guard_store_outbox_binding::{
    count_recoverable_unbound, load_binding, normalized_binding, reassign_quarantined,
    refresh_same_subject,
};
use crate::guard_store_outbox_identity::payload_digest;
use crate::guard_store_outbox_queries as queries;
use crate::guard_store_outbox_reads as reads;
use crate::guard_store_outbox_recover::recover_sequences;
use crate::guard_store_outbox_requeue::{repair_rejected_correlation, requeue_method};
use crate::guard_store_policy_source_context::policy_source_contexts;
use crate::guard_store_policy_upsert::upsert_policy;
use crate::guard_store_receipt_reads as receipt_reads;
use crate::guard_store_receipt_rollups as receipt_rollups;
use crate::guard_store_receipt_writes as receipt_writes;
use crate::guard_store_sessions as sessions;
use crate::guard_store_silent_review::add_silent_native_review_approval_request;
use crate::guard_store_state_ops as state_ops;
use crate::guard_store_storage_maintenance as storage_maintenance;
use crate::guard_store_temporary_mcp::apply_temporary_mcp_grant;
use crate::guard_store_tool_call_evidence as tool_call_evidence;
use crate::guard_store_wfcap_wire as wfcap;

pub(crate) const MAX_BUSY_TIMEOUT_MS: u64 = 600_000;
const CACHE_SIZE_KIB: i64 = 256 * 1024;
const MMAP_SIZE_BYTES: i64 = 1024 * 1024 * 1024;

/// The digest never covers policy-integrity key bytes: a reply, log or
/// diagnostic that carries the digest reveals nothing about the key. The
/// caller drops the same arguments before computing its own digest, exactly as
/// the policy-integrity rows request does.
const UNDIGESTED_ARGS: [&str; 1] = ["integrity_key_b64"];

fn request_digest(request: &GuardStoreRequestV1) -> Result<String, &'static str> {
    let mut material = serde_json::to_value(request).map_err(|_| "native_guard_store_invalid")?;
    if let Some(args) = material.get_mut("args").and_then(Value::as_object_mut) {
        for field in UNDIGESTED_ARGS {
            args.remove(field);
        }
    }
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, GUARD_STORE_MAX_REQUEST_BYTES)
        .map_err(|_| "native_guard_store_request_too_large")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

#[cfg(test)]
pub(crate) fn evaluate_guard_store_request(
    request: &GuardStoreRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_guard_store_request_with_owner(request, None)
}

pub(crate) fn evaluate_guard_store_request_with_owner(
    request: &GuardStoreRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let outcome = match owner {
        Some(owner) => evaluate_with_owner(request, Some(owner)),
        None => evaluate(request),
    };
    let (status, code, payload, generation) = match outcome {
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

pub(crate) fn evaluate(request: &GuardStoreRequestV1) -> StoreResult<(Value, Option<i64>)> {
    evaluate_with_owner(request, None)
}

fn evaluate_with_owner(
    request: &GuardStoreRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> StoreResult<(Value, Option<i64>)> {
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
    // A warm call reuses a kept connection: reopening parsed the whole schema
    // on every call (see `guard_store_write_cache`).
    let connection = crate::guard_store_write_cache::open_read_write_cached(&path)?;
    connection.busy_timeout(Duration::from_millis(request.busy_timeout_ms))?;
    apply_pragmas(&connection)?;
    // A total read only writes for the one-time rebuild a migration requests;
    // every other call stays lock-free.
    let args = Args(&request.args);
    let kind = if (request.method == "count_receipts"
        && kind == Kind::Read
        && receipt_rollups::rebuild_pending(&connection)?)
        || (connect::is_state_read(&request.method)
            && connect::read_persists_expiry(&connection, &args)?)
    {
        Kind::Write
    } else {
        kind
    };
    let writes = kind == Kind::Write;
    let initial_changes = connection.total_changes();
    match kind {
        Kind::Write => connection.execute_batch("BEGIN IMMEDIATE")?,
        Kind::Snapshot => connection.execute_batch("BEGIN")?,
        Kind::Read => {}
    }
    let outcome = dispatch(
        &connection,
        &request.source,
        &request.guard_home,
        &request.method,
        &args,
        owner,
    );
    let payload = match outcome {
        Ok(payload) => payload,
        Err(error) => {
            if kind != Kind::Read {
                let _ = connection.execute_batch("ROLLBACK");
            }
            guard_store_approval_backfill::settle(false);
            return Err(error);
        }
    };
    if kind == Kind::Snapshot {
        connection.execute_batch("ROLLBACK")?;
    } else {
        let committed = finalize_and_commit(&connection, writes);
        guard_store_approval_backfill::settle(committed.is_ok());
        committed?;
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
        | "list_receipts"
        | "observed_mcp_history"
        | "list_receipts_since_rowid"
        | "latest_receipt_rowid"
        | "get_receipt"
        | "get_receipt_for_approval_request"
        | "get_latest_receipt"
        | "receipt_decision_counts"
        | "run_storage_housekeeping"
        | "count_receipts"
        | "artifact_latest_diff"
        | "oauth_sources_list"
        | "read_local_cli_grant"
        | "read_local_cli_command_catalog"
        | "read_local_cli_command_states"
        | "list_local_cli_items"
        | "list_cached_advisories"
        | "policy_source_contexts"
        | "matching_native_review_block" => Kind::Read,
        "list_command_activity_page"
        | "command_activity_analytics"
        | "list_command_activity_invalidations"
        | "command_activity_diagnostics"
        | "list_command_shadow_observations"
        | "observed_mcp_tool_actions"
        | "read_mcp_provider_choices"
        | "read_mcp_provider_authority_hash"
        | "read_local_mcp_provider_actions"
        | "read_local_mcp_workflows"
        | "read_local_mcp_skills"
        | "workflow_capability_plan"
        | "get_approval_request"
        | "list_approval_requests"
        | "list_approval_request_page"
        | "count_approval_requests"
        | "get_next_pending_request"
        | "get_approval_extension_allow_hint"
        | "approval_desktop_notified_at"
        | "oldest_approval_request_created_at" => Kind::Snapshot,
        "workflow_capability_commit" => Kind::Write,
        "consume_native_review_approval"
        | "resolve_matching_approval_requests"
        | "resolve_approval_request"
        | "resolve_one_request_only"
        | "resolve_harness_native_approval_request"
        | "apply_temporary_mcp_grant_resolution"
        | "resolve_request_with_queue_result"
        | "resolve_native_workspace_review_request"
        | "resolve_matching_duplicate_requests"
        | "mark_approval_desktop_notified"
        | "add_approval_request"
        | "queue_blocked_approvals"
        | "add_native_review_approval_request"
        | "add_silent_native_review_approval_request"
        | "add_claude_native_review_approval_request"
        | "refresh_review_event_outbox_binding_for_identity"
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
        | "add_receipt"
        | "record_tool_call_evidence"
        | "record_native_decision_receipt"
        | "set_receipt_action_envelope"
        | "update_receipt_policy_decision"
        | "update_receipt_approval_context"
        | "list_receipts_for_command_detail_backfill"
        | "receipt_summary_between"
        | "receipt_analytics"
        | "reconcile_receipt_events"
        | "maintain_storage"
        | "managed_keyring_reconcile"
        | "record_local_cli_observation"
        | "replace_local_cli_commands"
        | "merge_local_cli_commands"
        | "forget_local_cli_observation"
        | "record_connector_setup_context"
        | "local_cli_replay_allowed"
        | "prune_inactive_local_cli_observations"
        | "cache_advisories"
        | "upsert_policy" => Kind::Write,
        "find_local_mcp_observation" => Kind::Read,
        "ensure_local_mcp_observation"
        | "reconcile_remote_mcp_declarations"
        | "record_composio_discovery" => Kind::Write,
        _ if connect::is_state_read(method) => Kind::Read,
        _ if connect::handles(method) => Kind::Write,
        _ => return None,
    })
}

fn dispatch(
    connection: &Connection,
    source: &str,
    guard_home: &str,
    method: &str,
    args: &Args,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> StoreResult<Value> {
    match method {
        "upsert_policy" => upsert_policy(connection, args),
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
        "observed_mcp_tool_actions" => observed_mcp::observed_mcp_tool_actions(connection),
        "read_mcp_provider_choices" => mcp_provider_reads::provider_choices(connection),
        "read_mcp_provider_authority_hash" => {
            mcp_provider_reads::provider_authority_hash(connection)
        }
        "read_local_mcp_provider_actions" => mcp_provider_reads::provider_actions(connection, args),
        "read_local_mcp_workflows" => mcp_workflow_reads::workflow_proposals(connection, args),
        "read_local_mcp_skills" => mcp_workflow_reads::mcp_skill_page(connection, args),
        "observed_mcp_history" => observed_mcp::observed_mcp_history(connection, args),
        "read_local_cli_grant" => local_cli_grants::read_grant(connection, args),
        "read_local_cli_command_catalog" => {
            local_cli_grants::read_command_catalog(connection, args)
        }
        "read_local_cli_command_states" => local_cli_grants::read_command_states(connection, args),
        "list_local_cli_items" => local_cli_inventory::list_items(connection, args),
        "cache_advisories" => advisory_cache::cache(connection, args),
        "list_cached_advisories" => advisory_cache::list(connection, args),
        "consume_native_review_approval" => native_review_consume::consume(connection, args),
        "matching_native_review_block" => native_review_consume::matching_block(connection, args),
        "add_approval_request" => add_approval_request(connection, source, args),
        "queue_blocked_approvals" => queue_blocked_approvals(connection, source, args),
        "add_native_review_approval_request" => {
            add_native_review_approval_request(connection, source, args)
        }
        "add_silent_native_review_approval_request" => {
            add_silent_native_review_approval_request(connection, source, args)
        }
        "add_claude_native_review_approval_request" => {
            add_claude_native_review_approval_request(connection, source, args)
        }
        "workflow_capability_plan" => wfcap::plan(connection, args),
        "workflow_capability_commit" => wfcap::commit(connection, args),
        "record_local_cli_observation" => local_cli::record_observation(connection, args),
        "replace_local_cli_commands" => {
            local_cli_catalog::write_local_cli_catalog(connection, args, false)
        }
        "merge_local_cli_commands" => {
            local_cli_catalog::write_local_cli_catalog(connection, args, true)
        }
        "forget_local_cli_observation" => local_cli::forget_observation(connection, args),
        "record_connector_setup_context" => connector_context::record_context(connection, args),
        "local_cli_replay_allowed" => local_cli::replay_allowed_op(connection, args),
        "prune_inactive_local_cli_observations" => local_cli::prune_inactive(connection, args),
        "find_local_mcp_observation" => local_mcp::find_observation(connection, args),
        "ensure_local_mcp_observation" => local_mcp::ensure_observation(connection, args),
        "reconcile_remote_mcp_declarations" => {
            local_mcp_declarations::reconcile_remote_declarations(connection, args)
        }
        "record_composio_discovery" => {
            composio_catalog::record_composio_discovery(connection, args)
        }
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
        "add_receipt" => receipt_writes::add_receipt(connection, args),
        "record_tool_call_evidence" => {
            tool_call_evidence::record_tool_call_evidence(connection, args)
        }
        "record_native_decision_receipt" => {
            native_receipts::record_native_decision_receipt(connection, args)
        }
        "set_receipt_action_envelope" => receipt_writes::set_action_envelope(connection, args),
        "update_receipt_policy_decision" => {
            receipt_writes::update_policy_decision(connection, args)
        }
        "update_receipt_approval_context" => {
            receipt_writes::update_approval_context(connection, args)
        }
        "list_receipts" => receipt_reads::list_receipts(connection, args),
        "list_receipts_since_rowid" => receipt_reads::list_since_rowid(connection, args),
        "list_receipts_for_command_detail_backfill" => {
            receipt_reads::list_for_command_detail_backfill(connection, args)
        }
        "latest_receipt_rowid" => receipt_reads::latest_rowid(connection, args),
        "get_receipt" => receipt_reads::get_receipt(connection, args),
        "get_approval_request" => {
            approval_reads::get_approval_request(connection, guard_home, args, owner)
        }
        "list_approval_requests" => {
            approval_reads::list_approval_requests(connection, guard_home, args, owner)
        }
        "list_approval_request_page" => {
            approval_pages::list_approval_request_page(connection, guard_home, args)
        }
        "count_approval_requests" => approval_pages::count_approval_requests(connection, args),
        "get_next_pending_request" => {
            approval_pages::get_next_pending_request(connection, guard_home, args, owner)
        }
        "get_approval_extension_allow_hint" => {
            approval_metadata::get_approval_extension_allow_hint(connection, args)
        }
        "approval_desktop_notified_at" => {
            approval_metadata::approval_desktop_notified_at(connection, args)
        }
        "mark_approval_desktop_notified" => {
            approval_metadata::mark_approval_desktop_notified(connection, args)
        }
        "oldest_approval_request_created_at" => {
            approval_metadata::oldest_approval_request_created_at(connection, args)
        }
        "resolve_approval_request" => resolve_approval_request(connection, guard_home, args, false),
        "resolve_one_request_only" => resolve_approval_request(connection, guard_home, args, true),
        "resolve_harness_native_approval_request" => {
            resolve_harness_native_approval_request(connection, guard_home, args)
        }
        "apply_temporary_mcp_grant_resolution" => {
            apply_temporary_mcp_grant(connection, guard_home, args, owner)
        }
        "resolve_request_with_queue_result" => {
            queue_result::resolve_request_with_queue_result(connection, guard_home, args, owner)
        }
        "resolve_native_workspace_review_request" => {
            queue_result::resolve_native_workspace_review_request(
                connection, guard_home, args, owner,
            )
        }
        "resolve_matching_duplicate_requests" => {
            resolve_matching_duplicate_requests(connection, source, guard_home, args)
        }
        "resolve_matching_approval_requests" => {
            resolve_matching_approval_requests(connection, guard_home, args)
        }
        "get_receipt_for_approval_request" => {
            receipt_reads::get_for_approval_request(connection, args)
        }
        "get_latest_receipt" => receipt_reads::get_latest(connection, args),
        "count_receipts" => receipt_reads::count(connection, args),
        "policy_source_contexts" => policy_source_contexts(connection, args),
        "receipt_summary_between" => receipt_reads::summary_between(connection, args),
        "receipt_analytics" => receipt_reads::analytics(connection, args),
        "receipt_decision_counts" => receipt_reads::decision_counts(connection, args),
        "reconcile_receipt_events" => receipt_reads::reconcile_events(connection, args),
        "maintain_storage" => storage_maintenance::maintain(connection, args),
        "run_storage_housekeeping" => storage_maintenance::housekeeping(connection),
        _ if connect::handles(method) => connect::dispatch(connection, method, args),
        _ if state_ops::handles(method) => state_ops::dispatch(connection, method, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}
