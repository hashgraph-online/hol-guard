"""Closed field sets and bounds for exact lifecycle evidence retention."""

import re

MAX_CELL_BYTES = 256 * 1024
PART_CHARS = 2048
EVIDENCE_SCHEMA = "hol-guard.workspace-lifecycle-evidence.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ATTEMPT = re.compile(r"mixed-policy-(?:[0-9]|[12][0-9]|3[01])")
_CONTROLS = {
    "program_digest": "program_digest",
    "catalog_digest": "catalog_digest",
    "trust_digest": "trust_digest",
    "control_revision": "revision",
    "managed_control_revision": "managed_revision",
    "control_effective_digest": "effective_digest",
}
_ROW_FLAGS = {
    "review_returned",
    "request_returned",
    "request_command_bound",
    "request_scope_matches",
    "native_receipt_validated",
    "writer_admitted",
    "witness_committed",
    "witness_commit_binding_valid",
    "committed_receipt_validated",
    "request_binding_matches",
    "authority_readback_before",
    "authority_readback_after",
}
_ROW_COUNTS = {
    "review_calls",
    "capture_faults",
    "committed_row_count",
    "committed_row_count_before",
    "committed_row_count_after",
}
_ROW_TIMES = {
    "offered_ms",
    "review_entered_ms",
    "review_entered_wall_ms",
    "native_finished_ms",
    "review_returned_ms",
    "review_returned_wall_ms",
    "delivered_ms",
    "commit_observed_ms",
}
_ROW_OTHER = {
    "attempt",
    "workspace_index",
    "authority_before",
    "authority_after",
    "request_binding",
    "request_mode",
    "native_receipt",
    "committed_receipt",
    "delivered_decision",
    "witness_decision_id",
}
_REQUEST_EXTRA = {
    "actual_request_rows",
    "declared_attempts",
    "owned_offered_attempts",
    "undeclared_owned_attempts",
    "receipt_witness",
    "unowned_native_calls_excluded",
    "observation_lifecycle",
    "clock_sources",
    "receipt_bound",
    "readback_scope",
}
_WITNESS_COUNTS = {
    "native_receipts",
    "committed",
    "missing",
    "binding_mismatches",
    "writer_rejected",
    "writer_admission_unobserved",
    "pre_receipts_without_program_binding",
}
_OBSERVATION_COUNTS = {
    "duplicate_observations",
    "witness_overflow",
    "invalid_receipt_identity",
    "native_without_receipt",
    "journal_write_failures",
    "journal_write_calls",
    "journal_written_bytes",
    "journal_file_fsync_failures",
    "journal_file_fsync_calls",
    "journal_directory_sync_attempts",
}
_LIFECYCLE_COUNTS = {
    "http_requests_in_flight_at_freeze",
    "native_calls_in_flight_at_freeze",
    "http_requests_currently_in_flight",
    "native_calls_currently_in_flight",
    "late_native_calls",
    "refused_offers",
    "capture_faults",
}
_SPAN_COMMON = {"kind", "phase", "publication", "started_ms", "finished_ms", "thread_cpu_ms"}
_SPAN_FIELDS = {
    "compile": {
        "succeeded",
        "config_loads",
        "scope_loads",
        "unregistered_loads",
        "config_load_failures",
        "scope_counts_overflow",
        "config_load_wall_ms",
        "config_load_thread_cpu_ms",
        "cache_entries",
        "registered_workspaces",
    },
    "push": {"binding", "returned"},
    "transport_ack": {"binding", "validated"},
    "barrier": {"binding", "ready"},
}
_SCOPE_CHECKS = {
    "acknowledged_compile_observed",
    "all_registered_workspaces_retained",
    "compiled_cache_complete",
    "config_capture_complete",
}
_PUBLICATION_FIELDS = {"publication_rows", "publication_observer", "publication_chain", "scope_checks"}
_FACT_FIELDS = {"service_replacement", "key_change", "expiry", "fault", "fault_request", "lifecycle_clocks"}
_FAILURE_FIELDS = {"failure", "fixture_cleanup_failure", "cleanup_failures"}
_PROOF_FIELDS = {"requests"} | _PUBLICATION_FIELDS | _FACT_FIELDS | _FAILURE_FIELDS
_SERVICE_FLAGS = {
    "python_process_restarted",
    "old_publisher_stopped",
    "old_resident_contained",
    "old_service_contained",
    "old_owner_lock_released",
    "same_owned_home_identity",
    "fresh_store_and_service",
    "cold_publisher_without_ack",
    "empty_command_authority_reloaded",
}
_KEY_FLAGS = {
    "actual_key_removed",
    "mutation_withdrew_ack",
    "supported_recovery_returned",
    "empty_control_policy_preserved",
    "interactive_enrollment_exercised",
    "policy_integrity_key_migration_exercised",
}
_EXPIRY_FLAGS = {
    "expired_resident_authority",
    "short_lived_acknowledged",
    "starting_authority_authenticated",
    "authenticated_readback",
    "policy_preserved",
    "control_binding_present",
    "control_binding_preserved",
    "policy_prepare_rejected",
    "refresh_suspended",
}
_HINT_FLAGS = {
    "actual_changed_hint_observed",
    "resident_identity_forwarded",
    "content_capture_replaced",
    "clock_replaced",
    "explicit_publish_hint_sent",
}
_ACK_FLAGS = {
    "real_accepted_reply_discarded",
    "production_ack_error_observed",
    "first_error_withheld_ack",
    "subsequent_transport_forwarded",
    "successful_ack_fabricated",
}
