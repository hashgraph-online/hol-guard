"""Bounded private-fixture evidence for a publisher error already observed.

No publisher, readiness, native-client or clock reads belong here. A retained
label explains the existing refusal; it does not prove the publisher's earlier
exception or that cached error was the only cause of an unavailable policy.
"""

from __future__ import annotations

import hashlib

from codex_plugin_scanner.guard.native_approval_errors import NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES

_MAX_LABEL_CHARS = 128
_REASON_PREFIX = "HOL Guard could not prepare the native policy safely."
_ACL_CODE = "native_policy_windows_acl_not_private"
# Exact public labels reviewed from the policy snapshot, command-control and
# native-client sources. Unknown labels retain a bounded digest, never text.
_PUBLISHER_CODES = (
    frozenset(
        {
            "attributeerror",
            "databaseerror",
            "filenotfounderror",
            "guardconfigsourceerror",
            "integrityerror",
            "interfaceerror",
            "internalerror",
            "notsupportederror",
            "operationalerror",
            "oserror",
            "permissionerror",
            "programmingerror",
            "runtimeerror",
            "timeouterror",
            "typeerror",
            "valueerror",
            "native_client_containment_failed",
            "native_client_exit_nonzero",
            "native_client_launcher_failed",
            "native_client_output_limit_exceeded",
            "native_client_output_missing",
            "native_client_pool_exhausted",
            "native_client_process_failed",
            "native_client_request_invalid",
            "native_client_start_failed",
            "native_client_status_missing",
            "native_client_stdin_unavailable",
            "native_client_stream_failed",
            "native_client_timed_out",
            "native_command_control_authority_integrity_invalid",
            "native_command_control_authority_invalid",
            "native_command_control_authority_key_changed",
            "native_command_control_authority_key_unavailable",
            "native_command_control_authority_mutation_required",
            "native_command_control_authority_path_invalid",
            "native_command_control_authority_regressed",
            "native_command_control_authority_reused",
            "native_command_control_authority_revision_exhausted",
            "native_command_control_authority_write_mismatch",
            "native_command_control_binding_changed",
            "native_command_control_binding_invalid",
            "native_command_control_catalog_mismatch",
            "native_command_control_digest_mismatch",
            "native_command_control_layer_invalid",
            "native_command_control_recovery_floor_invalid",
            "native_command_control_recovery_floor_mismatch",
            "native_command_control_recovery_invalid",
            "native_command_control_revision_regressed",
            "native_command_control_target_invalid",
            "native_command_program_artifact_invalid",
            "native_command_program_artifact_unavailable",
            "native_command_program_digest_mismatch",
            "native_policy_generation_exhausted",
            "native_policy_generation_home_invalid",
            "native_policy_generation_lock_invalid",
            "native_policy_generation_lock_timeout",
            "native_policy_generation_state_invalid",
            "native_policy_generation_state_missing",
            "native_policy_runtime_state_invalid",
            "native_policy_runtime_state_not_private",
            "native_policy_snapshot_ack_invalid",
            "native_policy_snapshot_ack_mismatch",
            "native_policy_snapshot_array_too_wide",
            "native_policy_snapshot_cache_identity_failed",
            "native_policy_snapshot_cache_integrity_invalid",
            "native_policy_snapshot_cache_invalid",
            "native_policy_snapshot_cache_missing",
            "native_policy_snapshot_cache_noncanonical",
            "native_policy_snapshot_cache_read_failed",
            "native_policy_snapshot_cache_sync_failed",
            "native_policy_snapshot_cache_write_failed",
            "native_policy_snapshot_digest_invalid",
            "native_policy_snapshot_digest_mismatch",
            "native_policy_snapshot_duplicate_key",
            "native_policy_snapshot_expired",
            "native_policy_snapshot_expiry_invalid",
            "native_policy_snapshot_generation_exhausted",
            "native_policy_snapshot_generation_invalid",
            "native_policy_snapshot_generation_lock_invalid",
            "native_policy_snapshot_generation_lock_timeout",
            "native_policy_snapshot_generation_state_identity_failed",
            "native_policy_snapshot_generation_state_invalid",
            "native_policy_snapshot_generation_state_missing",
            "native_policy_snapshot_generation_state_read_failed",
            "native_policy_snapshot_generation_state_write_failed",
            "native_policy_snapshot_identity_invalid",
            "native_policy_snapshot_integrity_invalid",
            "native_policy_snapshot_integrity_key_unavailable",
            "native_policy_snapshot_json_invalid",
            "native_policy_snapshot_key_too_large",
            "native_policy_snapshot_mode_invalid",
            "native_policy_snapshot_native_disabled",
            "native_policy_snapshot_nested_cycle",
            "native_policy_snapshot_nested_depth_exceeded",
            "native_policy_snapshot_number_invalid",
            "native_policy_snapshot_object_key_invalid",
            "native_policy_snapshot_object_too_wide",
            "native_policy_snapshot_policy_invalid",
            "native_policy_snapshot_protocol_invalid",
            "native_policy_snapshot_protocol_unsupported",
            "native_policy_snapshot_publish_failed",
            "native_policy_snapshot_push_invalid",
            "native_policy_snapshot_resident_changed",
            "native_policy_snapshot_runtime_unavailable",
            "native_policy_snapshot_schema_invalid",
            "native_policy_snapshot_scope_invalid",
            "native_policy_snapshot_serialization_failed",
            "native_policy_snapshot_string_too_large",
            "native_policy_snapshot_too_large",
            "native_policy_snapshot_transaction_conflict",
            "native_policy_snapshot_transaction_invalid",
            "native_policy_snapshot_unknown_field",
            "native_policy_snapshot_version_invalid",
            "native_policy_snapshot_workspace_capacity",
            "native_policy_verifier_key_invalid",
            "native_policy_verifier_key_mismatch",
            "native_policy_verifier_key_not_private",
            "native_policy_verifier_key_read_failed",
            "native_policy_verifier_key_stat_failed",
            "native_policy_verifier_key_sync_failed",
            "native_policy_verifier_key_write_failed",
            "native_policy_verifier_master_invalid",
            "native_policy_windows_acl_apply_failed",
            "native_policy_windows_acl_build_failed",
            "native_policy_windows_acl_unavailable",
            "native_policy_windows_acl_verify_failed",
            "native_policy_windows_handle_close_failed",
            "native_policy_windows_handle_invalid",
            "native_policy_windows_owner_sid_failed",
            "native_policy_windows_owner_sid_invalid",
            "native_policy_windows_path_invalid",
            "native_policy_windows_path_open_failed",
            "native_policy_windows_path_stat_failed",
            "native_policy_windows_replace_failed",
            "native_policy_windows_state_directory_create_failed",
            "native_policy_windows_state_directory_invalid",
            "native_policy_windows_sync_failed",
            "native_policy_windows_temporary_cleanup_failed",
            "native_policy_windows_write_failed",
            "native_policy_windows_write_too_large",
        }
    )
    | NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
)


def _label_diagnostic(value: str, start: int, end: int) -> dict[str, object]:
    # Callers establish an exact plain str before any slicing, hashing or
    # equality operation. Slice before encoding to bound even unusual inputs.
    bounded = value[start : min(end, start + _MAX_LABEL_CHARS)]
    complete = end - start <= _MAX_LABEL_CHARS
    known = complete and (bounded in _PUBLISHER_CODES or bounded == _ACL_CODE)
    parameterized = bounded.startswith(_ACL_CODE + ":")
    result: dict[str, object] = {
        "publisher_error_state": "known" if known else "parameterized" if parameterized else "unlisted",
        "publisher_error_digest": hashlib.sha256(bounded.encode("utf-8", errors="replace")).hexdigest(),
        "publisher_error_digest_complete": complete,
    }
    if known or parameterized:
        result["publisher_error_value"] = _ACL_CODE if parameterized else bounded
    return result


def publisher_error_diagnostic(value: object) -> dict[str, object]:
    """Serialize an already-read label without callbacks on custom inputs."""
    if value is None:
        return {"publisher_error_state": "absent"}
    if type(value) is not str:
        return {"publisher_error_state": "invalid_type"}
    if not value:
        return {"publisher_error_state": "absent"}
    return _label_diagnostic(value, 0, len(value))


def policy_refusal_diagnostic(reason: object) -> dict[str, object]:
    """Observe the original helper result without another publisher read."""
    result: dict[str, object] = {
        "schema": "hol-guard.policy-refusal-diagnostic.v1",
        "capture_context": "original_policy_refusal_reason",
    }
    if type(reason) is not str:
        result["publisher_error_state"] = "invalid_type"
    elif reason == _REASON_PREFIX:
        result["publisher_error_state"] = "absent"
    elif reason.startswith(_REASON_PREFIX + " ") and reason.endswith(".") and len(reason) > len(_REASON_PREFIX) + 2:
        result.update(_label_diagnostic(reason, len(_REASON_PREFIX) + 1, len(reason) - 1))
    else:
        result["publisher_error_state"] = "unrecognized_reason"
    return result
