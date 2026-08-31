"""Compatibility test façade for native policy snapshot publication.

The test groups are split by responsibility while this historical module keeps
the original import path and pytest collection contract.
"""

from . import test_native_policy_snapshot_contract as _contract_tests
from . import test_native_policy_snapshot_persistence as _persistence_tests
from . import test_native_policy_snapshot_publisher as _publisher_tests
from . import test_native_policy_snapshot_windows as _windows_tests

test_policy_merge_never_downgrades_enforcing_posture_to_watch = (
    _contract_tests.test_policy_merge_never_downgrades_enforcing_posture_to_watch
)
test_v3_builder_derives_and_provisions_verifier_before_snapshot_push = (
    _contract_tests.test_v3_builder_derives_and_provisions_verifier_before_snapshot_push
)
test_windows_scope_aliases_share_one_digest_identity = (
    _contract_tests.test_windows_scope_aliases_share_one_digest_identity
)
test_floor_only_ack_materializes_strictly_new_generation = (
    _persistence_tests.test_floor_only_ack_materializes_strictly_new_generation
)
test_floor_recovery_requires_exact_typed_ack = _persistence_tests.test_floor_recovery_requires_exact_typed_ack
test_lost_ack_retries_identical_payload = _persistence_tests.test_lost_ack_retries_identical_payload
test_publisher_process_restart_reuses_cached_payload = (
    _persistence_tests.test_publisher_process_restart_reuses_cached_payload
)
test_renewal_failure_keeps_barrier_closed_at_expiry = (
    _persistence_tests.test_renewal_failure_keeps_barrier_closed_at_expiry
)
test_renewal_materializes_higher_generation_before_expiry = (
    _persistence_tests.test_renewal_materializes_higher_generation_before_expiry
)
test_renewal_retry_reuses_candidate_with_bounded_backoff = (
    _persistence_tests.test_renewal_retry_reuses_candidate_with_bounded_backoff
)
test_snapshot_transaction_recovers_each_persistence_boundary = (
    _persistence_tests.test_snapshot_transaction_recovers_each_persistence_boundary
)
test_auto_hook_uses_barrier_without_loading_config_per_request = (
    _publisher_tests.test_auto_hook_uses_barrier_without_loading_config_per_request
)
test_publisher_does_not_ack_snapshot_after_concurrent_mutation = (
    _publisher_tests.test_publisher_does_not_ack_snapshot_after_concurrent_mutation
)
test_publisher_rejects_mutated_ack_without_opening_barrier = (
    _publisher_tests.test_publisher_rejects_mutated_ack_without_opening_barrier
)
test_publisher_repushes_after_resident_generation_change = (
    _publisher_tests.test_publisher_repushes_after_resident_generation_change
)
test_publisher_startup_ack_and_mutation_push = _publisher_tests.test_publisher_startup_ack_and_mutation_push
test_same_generation_retries_reuse_exact_signed_snapshot_bytes = (
    _publisher_tests.test_same_generation_retries_reuse_exact_signed_snapshot_bytes
)
test_windows_cache_read_rejects_ancestor_reparse_before_open = (
    _windows_tests.test_windows_cache_read_rejects_ancestor_reparse_before_open
)
test_windows_cache_reader_closes_handle_on_all_failures = (
    _windows_tests.test_windows_cache_reader_closes_handle_on_all_failures
)
test_windows_cache_reader_verifies_and_reads_one_handle = (
    _windows_tests.test_windows_cache_reader_verifies_and_reads_one_handle
)
test_windows_open_handle_uses_disk_nonreparse_read_contract = (
    _windows_tests.test_windows_open_handle_uses_disk_nonreparse_read_contract
)
test_windows_existing_directory_reapplies_owner_and_dacl_on_same_handle = (
    _windows_tests.test_windows_existing_directory_reapplies_owner_and_dacl_on_same_handle
)
test_windows_private_descriptor_deduplicates_system_owner_ace = (
    _windows_tests.test_windows_private_descriptor_deduplicates_system_owner_ace
)

__all__ = [
    "test_auto_hook_uses_barrier_without_loading_config_per_request",
    "test_floor_only_ack_materializes_strictly_new_generation",
    "test_floor_recovery_requires_exact_typed_ack",
    "test_lost_ack_retries_identical_payload",
    "test_policy_merge_never_downgrades_enforcing_posture_to_watch",
    "test_publisher_does_not_ack_snapshot_after_concurrent_mutation",
    "test_publisher_process_restart_reuses_cached_payload",
    "test_publisher_rejects_mutated_ack_without_opening_barrier",
    "test_publisher_repushes_after_resident_generation_change",
    "test_publisher_startup_ack_and_mutation_push",
    "test_renewal_failure_keeps_barrier_closed_at_expiry",
    "test_renewal_materializes_higher_generation_before_expiry",
    "test_renewal_retry_reuses_candidate_with_bounded_backoff",
    "test_same_generation_retries_reuse_exact_signed_snapshot_bytes",
    "test_snapshot_transaction_recovers_each_persistence_boundary",
    "test_v3_builder_derives_and_provisions_verifier_before_snapshot_push",
    "test_windows_cache_read_rejects_ancestor_reparse_before_open",
    "test_windows_cache_reader_closes_handle_on_all_failures",
    "test_windows_cache_reader_verifies_and_reads_one_handle",
    "test_windows_existing_directory_reapplies_owner_and_dacl_on_same_handle",
    "test_windows_open_handle_uses_disk_nonreparse_read_contract",
    "test_windows_private_descriptor_deduplicates_system_owner_ace",
    "test_windows_scope_aliases_share_one_digest_identity",
]
