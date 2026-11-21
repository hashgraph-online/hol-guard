//! The `GuardStore` method table: each method name to the function that runs
//! it inside the transaction `guard_store_op` opened.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_advisory_cache as advisory_cache;
use crate::guard_store_approval_metadata as approval_metadata;
use crate::guard_store_approval_page_reads as approval_pages;
use crate::guard_store_approval_queue::queue_blocked_approvals;
use crate::guard_store_approval_queue_result as queue_result;
use crate::guard_store_approval_reads as approval_reads;
use crate::guard_store_approval_reads::with_stored_row as stored_row;
use crate::guard_store_approval_resolve::{
    resolve_approval_request, resolve_harness_native_approval_request,
    resolve_matching_duplicate_requests,
};
use crate::guard_store_approval_sweep::resolve_matching_approval_requests;
use crate::guard_store_approval_write::{
    add_approval_request, add_native_review_approval_request, clear_approval_requests,
};
use crate::guard_store_args::Args;
use crate::guard_store_claude_review::{
    add_claude_approval_request, add_claude_native_review_approval_request,
};
use crate::guard_store_clients as clients;
use crate::guard_store_cloud_events as cloud_events;
use crate::guard_store_cmd_activity as activity;
use crate::guard_store_cmd_api as api;
use crate::guard_store_cmd_feedback as feedback;
use crate::guard_store_cmd_lifecycle as lifecycle;
use crate::guard_store_cmd_maintenance as maintenance;
use crate::guard_store_cmd_privacy as privacy;
use crate::guard_store_composio_catalog as composio_catalog;
use crate::guard_store_connect as connect;
use crate::guard_store_connector_context as connector_context;
use crate::guard_store_continuity_write as continuity_write;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_devices as devices;
use crate::guard_store_evidence as evidence;
use crate::guard_store_inventory as inventory;
use crate::guard_store_legacy_probe as legacy_probe;
use crate::guard_store_local_cli as local_cli;
use crate::guard_store_local_cli_catalog as local_cli_catalog;
use crate::guard_store_local_cli_grants as local_cli_grants;
use crate::guard_store_local_cli_inventory as local_cli_inventory;
use crate::guard_store_local_mcp_declarations as local_mcp_declarations;
use crate::guard_store_local_mcp_observation as local_mcp;
use crate::guard_store_mcp_policy_requests as mcp_policy_requests;
use crate::guard_store_mcp_provider_reads as mcp_provider_reads;
use crate::guard_store_mcp_workflow_reads as mcp_workflow_reads;
use crate::guard_store_native_receipts as native_receipts;
use crate::guard_store_native_review_consume as native_review_consume;
use crate::guard_store_observed_mcp as observed_mcp;
use crate::guard_store_outbox_binding::{
    count_recoverable_unbound, load_binding, normalized_binding, reassign_quarantined,
    refresh_same_subject,
};
use crate::guard_store_outbox_queries as queries;
use crate::guard_store_outbox_reads as reads;
use crate::guard_store_outbox_recover::recover_sequences;
use crate::guard_store_outbox_requeue::{repair_rejected_correlation, requeue_method};
use crate::guard_store_policy_clear::clear_policy_decisions;
use crate::guard_store_policy_import as policy_import;
use crate::guard_store_policy_source_context::policy_source_contexts;
use crate::guard_store_policy_upsert::upsert_policy;
use crate::guard_store_queue_live_wait::queue_with_live_wait;
use crate::guard_store_read_state as read_state;
use crate::guard_store_receipt_reads as receipt_reads;
use crate::guard_store_receipt_writes as receipt_writes;
use crate::guard_store_review_settle as review_settle;
use crate::guard_store_sessions as sessions;
use crate::guard_store_silent_review::add_silent_native_review_approval_request;
use crate::guard_store_state_ops as state_ops;
use crate::guard_store_storage_maintenance as storage_maintenance;
use crate::guard_store_temporary_mcp::apply_temporary_mcp_grant;
use crate::guard_store_tool_call_evidence as tool_call_evidence;
use crate::guard_store_wfcap_wire as wfcap;

pub(crate) fn dispatch(
    connection: &Connection,
    source: &str,
    guard_home: &str,
    method: &str,
    args: &Args,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> StoreResult<Value> {
    match method {
        "upsert_policy" => upsert_policy(connection, args),
        "clear_policy_decisions" => clear_policy_decisions(connection, args),
        "import_policy_rows" => policy_import::import_policy_rows(connection, args),
        "apply_mcp_policy_request" => policy_import::apply_mcp_policy_request(connection, args),
        "policy_rows_fingerprint" => policy_import::policy_rows_fingerprint(connection, args),
        "stage_mcp_policy_request" => mcp_policy_requests::stage(connection, args),
        "expire_mcp_policy_request" => mcp_policy_requests::expire(connection, args),
        "decline_mcp_policy_request" => mcp_policy_requests::decline(connection, args),
        "fail_mcp_policy_request" => mcp_policy_requests::fail(connection, args),
        "list_pending_mcp_policy_requests" => mcp_policy_requests::list_pending(connection, args),
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
        "receipt_redaction_bookkeeping" => {
            crate::guard_store_receipt_redaction::method(connection, source, args)
        }
        "record_policy_bundle_activation" => {
            crate::guard_store_receipt_redaction::policy_bundle_activated::method(
                connection, source, args,
            )
        }
        "record_policy_bundle_rejection" => {
            crate::guard_store_receipt_redaction::policy_bundle_rejection::method(connection, args)
        }
        "record_sync_summary" => {
            crate::guard_store_receipt_redaction::sync_summary::method(connection, args)
        }
        "repair_rejected_review_correlation" => {
            repair_rejected_correlation(connection, source, args)
        }
        "recover_review_snapshot_sequences" => recover_sequences(connection, source, args),
        "settle_rejected_review_events" => review_settle::settle(connection, source, args),
        "forget_review_rejection_counts" => {
            crate::guard_store_review_rejection_counts::forget_counts(connection, source, args)
        }
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
        "get_command_activity_persistence_health" => api::persistence_health(connection, args),
        "list_table_names" => api::table_names(connection, args),
        "record_command_activity_feedback" => feedback::record_feedback(connection, args),
        "list_command_activity_invalidations" => feedback::list_invalidations(connection, args),
        "clear_command_activity_evidence" => privacy::clear_evidence(connection),
        "add_evidence" => evidence::add(connection, args),
        "list_evidence" => evidence::list(connection, args),
        "count_evidence" => evidence::count(connection, args),
        "clear_evidence" => evidence::clear(connection, args),
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
        "observed_mcp_discovery" => {
            observed_mcp::discovery::observed_mcp_discovery(connection, args)
        }
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
        "settle_native_review_reuse" => native_review_consume::settle(connection, args),
        "record_native_admitted_call" => crate::native_admitted_call::record(connection, args),
        "native_admitted_call" => crate::native_admitted_call::lookup(connection, args),
        "add_approval_request" => queue_with_live_wait(connection, args, |args| {
            add_approval_request(connection, source, args)
        })
        .and_then(|written| stored_row(connection, guard_home, args, owner, written)),
        "queue_blocked_approvals" => queue_blocked_approvals(connection, source, args),
        "add_native_review_approval_request" => queue_with_live_wait(connection, args, |args| {
            add_native_review_approval_request(connection, source, args)
        }),
        "add_silent_native_review_approval_request" => {
            queue_with_live_wait(connection, args, |args| {
                add_silent_native_review_approval_request(connection, source, args)
            })
            .and_then(|written| stored_row(connection, guard_home, args, owner, written))
        }
        "add_claude_native_review_approval_request" => {
            add_claude_native_review_approval_request(connection, source, args)
        }
        "add_claude_approval_request" => add_claude_approval_request(connection, source, args)
            .and_then(|written| stored_row(connection, guard_home, args, owner, written)),
        "workflow_capability_plan" => wfcap::plan(connection, args),
        "workflow_capability_commit" => wfcap::commit(connection, args),
        "record_local_cli_observation" => local_cli::record_observation(connection, args),
        "apply_custom_extension_continuity" => continuity_write::apply_continuity(connection, args),
        "upsert_local_cli_grant" => continuity_write::upsert_grant(connection, args),
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
        "link_codex_live_wait" => sessions::link_codex_live_wait(connection, args),
        "get_guard_operation" => sessions::get_operation(connection, args),
        "get_mcp_policy_request" => {
            crate::guard_store_mcp_policy_requests::get_request(connection, args)
        }
        "list_guard_operations" => sessions::list_operations(connection, args),
        "get_guard_operation_for_approval_request" => {
            sessions::operation_for_approval_request(connection, args)
        }
        "get_request_resume" => crate::codex_request_resume_store::get(connection, args),
        "get_latest_request_resume" => crate::codex_request_resume_store::latest(connection, args),
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
        "read_legacy_codex_probe_receipt" => {
            legacy_probe::read_legacy_codex_probe_receipt(connection, args)
        }
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
        "pending_connector_group_rows" => {
            approval_metadata::pending_connector_group_rows(connection, args)
        }
        "connector_setup_advice" => approval_metadata::connector_setup_advice(connection, args),
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
        "settle_claimed_native_allow" => {
            crate::guard_store_claimed_native_allow::settle(connection, guard_home, args)
        }
        "settle_claimed_native_review" => {
            crate::guard_store_claimed_native_allow::settle_review(connection, guard_home, args)
        }
        "codex_live_allow_authority" => {
            crate::guard_store_codex_live_authority::op(connection, guard_home, args, owner)
        }
        "complete_codex_live_decision" => {
            crate::guard_store_codex_live_completion::complete(connection, guard_home, args, owner)
        }
        "record_codex_live_completion" => {
            crate::guard_store_codex_live_completion::record(connection, guard_home, args, owner)
        }
        "apply_signed_remote_exact_result" => {
            crate::guard_store_exact_cloud_apply::apply_signed_remote_exact_result(
                connection, guard_home, args, owner,
            )
        }
        "peek_waited_exact_cloud_package_allow" => {
            crate::guard_store_exact_cloud_package::peek(connection, args)
        }
        "consume_waited_exact_cloud_package_allow" => {
            crate::guard_store_exact_cloud_package::consume(connection, args)
        }
        "record_local_once_approval" => {
            crate::guard_store_local_once_mint::record_local_once_approval(connection, args)
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
        "mark_requests_read" => read_state::mark_read(connection, args),
        "clear_approval_requests" => clear_approval_requests(connection, args),
        "mark_request_unread" => read_state::mark_unread(connection, args),
        "get_read_state" => read_state::ids(connection, args),
        "clear_read_state" => read_state::clear(connection, args),
        "set_device_label" => devices::set_label(connection, args),
        "get_sync_payload" => crate::guard_store_sync_state::get(connection, args),
        "set_sync_payload" => crate::guard_store_sync_state::set(connection, args),
        "record_command_queue_lease_limit" => {
            crate::guard_store_sync_state::queue_lease_limit::method(connection, args)
        }
        "transition_command_queue_state" => {
            crate::guard_store_sync_state::queue_transition::method(connection, args)
        }
        "transition_cloud_review_sync_state" => {
            crate::guard_store_sync_state::review_sync_transition::method(connection, args)
        }
        "native_workspace_review_replay_marker" => {
            crate::guard_store_sync_state::review_replay_marker::read_method(connection, args)
        }
        "transition_native_workspace_review_replay_marker" => {
            crate::guard_store_sync_state::review_replay_marker::step::method(connection, args)
        }
        "workspace_review_enrollment_due" => {
            crate::guard_store_sync_state::review_enrollment::due_method(connection, args)
        }
        "record_workspace_review_enrollment" => {
            crate::guard_store_sync_state::review_enrollment::record_method(connection, args)
        }
        "rotate_installation_id" => devices::rotate(connection, args),
        "add_event" => cloud_events::add_event(connection, args),
        "set_managed_install" => crate::guard_store_managed_installs::set(connection, args),
        "get_managed_install" => crate::guard_store_managed_installs::get(connection, args),
        "get_managed_install_revision" => {
            crate::guard_store_managed_installs::revision(connection, args)
        }
        "bump_managed_install_revision" => {
            crate::guard_store_managed_installs::bump(connection, args)
        }
        "list_managed_installs" => crate::guard_store_managed_installs::list(connection, args),
        "hook_managed_install_admission" => {
            crate::guard_store_managed_installs::hook_admission(connection, args)
        }
        "list_events_after" => cloud_events::list_after(connection, args),
        "list_cloud_exceptions" => crate::policy_bundle_cloud_exceptions::list(connection, args),
        "cached_supply_chain_bundle" => {
            crate::supply_chain_bundle_cache_op::cached_bundle(connection)
        }
        "add_guard_event_v1" => cloud_events::add(connection, args),
        "list_guard_events_v1" => cloud_events::list(connection, args),
        "count_guard_events_v1" => cloud_events::count(connection, args),
        "mark_guard_events_v1_uploaded" => cloud_events::mark_uploaded(connection, args),
        "maintain_storage" => storage_maintenance::maintain(connection, args),
        "run_storage_housekeeping" => storage_maintenance::housekeeping(connection),
        _ if connect::handles(method) => connect::dispatch(connection, method, args),
        _ if state_ops::handles(method) => state_ops::dispatch(connection, method, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}
