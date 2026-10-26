"""V4 transport key sets for native approval.

Rust remains authoritative for WebAuthn parsing, cryptography, policy,
replay, and approval semantics.
"""

from __future__ import annotations

from . import native_approval_protocol as _base

NativeApprovalPhase = _base.NativeApprovalPhase

_NATIVE_PROTOCOL_VERSION = _base._NATIVE_PROTOCOL_VERSION
_NATIVE_APPROVAL_MAX_BYTES = _base._NATIVE_APPROVAL_MAX_BYTES
_NATIVE_APPROVAL_MAX_STRING_BYTES = _base._NATIVE_APPROVAL_MAX_STRING_BYTES
_NATIVE_APPROVAL_KEY_ID_HEX_LENGTH = _base._NATIVE_APPROVAL_KEY_ID_HEX_LENGTH
_MAX_APPROVAL_TTL_MS = _base._MAX_APPROVAL_TTL_MS


_CHALLENGE_V4_KEYS = frozenset(
    [
        "schema",
        "version",
        "request_id",
        "request_digest",
        "action_digest",
        "action_type",
        "operation",
        "intrinsic_action",
        "minimum_action",
        "floor_class",
        "approval_eligible",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "requested_action",
        "signing_key_id",
        "webauthn",
    ]
)
_ARTIFACT_V4_KEYS = frozenset(
    [
        "schema",
        "version",
        "request_id",
        "request_digest",
        "action_digest",
        "action_type",
        "operation",
        "intrinsic_action",
        "minimum_action",
        "floor_class",
        "approval_eligible",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "requested_action",
        "approved_action",
        "signing_key_id",
        "webauthn",
    ]
)
_RECEIPT_V4_KEYS = frozenset(
    [
        "schema",
        "version",
        "phase",
        "request_id",
        "request_digest",
        "action_digest",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "decision",
        "requested_action",
        "approved_action",
        "reason_code",
        "nonce_digest",
        "replay_claimed",
        "rp_id",
        "origin",
        "credential_id_digest",
        "algorithm",
        "authenticator_sign_count",
    ]
)


_RESULT_KEYS = _base._RESULT_KEYS
_bounded_text = _base._bounded_text
_lower_hex = _base._lower_hex
_common_fields_valid = _base._common_fields_valid
_receipt_fields_are_valid = _base._receipt_fields_are_valid
_within_approval_bound = _base._within_approval_bound
