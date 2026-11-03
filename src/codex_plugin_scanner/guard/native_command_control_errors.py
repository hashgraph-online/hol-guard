"""Command-control fence failures the resident reports verbatim.

These mirror ``NATIVE_COMMAND_CONTROL_ERROR_CODES`` in
``rust/crates/guard-contracts/src/native_command_controls.rs`` exactly. A code
missing here is rewritten by ``resident_protocol::safe_error_response`` into
``native_request_invalid_json``, which hides the real admission failure from
every diagnostic that reads the wire code.

Keep them diagnostic-only: the hook bridge still rejects their error envelopes
as authoritative decisions.
"""

from __future__ import annotations

NATIVE_COMMAND_CONTROL_ERROR_CODES = frozenset(
    [
        "native_active_pack_security_binding_mismatch",
        "native_active_pack_security_invalid",
        "native_active_pack_security_program_mismatch",
        "native_command_compatibility_context_unsupported",
        "native_command_compatibility_deadline",
        "native_command_compatibility_inventory_mismatch",
        "native_command_compatibility_limit",
        "native_command_compatibility_model_unsupported",
        "native_command_compatibility_owner_invalid",
        "native_command_compatibility_permission_invalid",
        "native_command_control_authority_downgrade",
        "native_command_control_authority_epoch_reused",
        "native_command_control_authority_invalid",
        "native_command_control_authority_mac_invalid",
        "native_command_control_authority_missing",
        "native_command_control_authority_noncanonical",
        "native_command_control_authority_not_current",
        "native_command_control_authority_path_invalid",
        "native_command_control_authority_removed",
        "native_command_control_binding_invalid",
        "native_command_control_binding_removed",
        "native_command_control_digest_mismatch",
        "native_command_control_encoding_failed",
        "native_command_control_floor_invalid",
        "native_command_control_layer_invalid",
        "native_command_control_mutation_in_progress",
        "native_command_control_mutation_lock_invalid",
        "native_command_control_mutation_lock_missing",
        "native_command_control_mutation_lock_unsupported",
        "native_command_control_mutation_reused",
        "native_command_control_recovery_context_mismatch",
        "native_command_control_recovery_invalid",
        "native_command_control_recovery_missing",
        "native_command_control_revision_downgrade",
        "native_command_control_revision_reused",
        "native_command_control_target_invalid",
        "native_command_control_target_unknown",
        "native_command_encoding_failed",
        "native_command_extension_contract_invalid",
        "native_command_extension_dependency_unknown",
        "native_command_extension_duplicate",
        "native_command_matcher_digest_mismatch",
        "native_command_node_missing",
        "native_command_pack_budget_exceeded",
        "native_command_pack_cache_identity_invalid",
        "native_command_pack_cache_invalid",
        "native_command_pack_cache_noncanonical",
        "native_command_pack_cache_read_failed",
        "native_command_pack_index_invalid",
        "native_command_pack_inventory_invalid",
        "native_command_pack_link_invalid",
        "native_command_pack_rule_owner_invalid",
        "native_command_pack_selection_invalid",
        "native_command_pack_selection_missing",
        "native_command_pack_transition_mismatch",
        "native_command_permission_contract_invalid",
        "native_command_permission_dependency_invalid",
        "native_command_permission_dependency_unknown",
        "native_command_permission_duplicate",
        "native_command_program_binding_mismatch",
        "native_command_program_bounds_invalid",
        "native_command_program_bytes_exceeded",
        "native_command_program_contract_invalid",
        "native_command_program_digest_mismatch",
        "native_command_program_digest_missing",
        "native_command_program_json_invalid",
        "native_command_program_noncanonical",
        "native_command_program_shape_invalid",
        "native_command_program_version_unsupported",
        "native_command_required_forbidden_flag_conflict",
        "native_command_required_option_duplicated",
        "native_command_required_option_values_empty",
        "native_command_required_pack_missing",
        "native_command_rule_candidate_invalid",
        "native_command_rule_coverage_invalid",
        "native_command_rule_duplicate",
        "native_command_rule_owner_missing",
        "native_command_variant_coverage_invalid",
        "native_policy_snapshot_command_authority_invalid",
        "native_policy_snapshot_command_authority_not_private",
        "native_policy_snapshot_command_authority_parent_missing",
        "native_policy_snapshot_command_authority_read_failed",
        "native_policy_snapshot_command_authority_stat_failed",
        "native_policy_snapshot_command_authority_too_large",
        "native_resident_command_mutation_lock_invalid",
        "native_resident_command_mutation_lock_read_failed",
    ]
)


__all__ = ["NATIVE_COMMAND_CONTROL_ERROR_CODES"]
