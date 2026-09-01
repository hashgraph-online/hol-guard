"""Bounded Python boundary types for the Rust native approval protocol.

This module only validates transport shape.  It never signs, verifies, or
assigns approval semantics to a challenge or artifact.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Literal, cast

NativeApprovalPhase = Literal["validated", "consumed"]

_NATIVE_PROTOCOL_VERSION = 1
_NATIVE_REQUEST_MAX_BYTES = 6 * 1024 * 1024
_NATIVE_RESPONSE_MAX_BYTES = 2 * 1024 * 1024
_NATIVE_APPROVAL_MAX_BYTES = 64 * 1024
_NATIVE_APPROVAL_MAX_STRING_BYTES = 4 * 1024
_NATIVE_APPROVAL_MAX_REASON_BYTES = 256
_NATIVE_APPROVAL_NONCE_HEX_LENGTH = 64
_NATIVE_APPROVAL_SIGNATURE_HEX_LENGTH = 128
_NATIVE_APPROVAL_KEY_ID_HEX_LENGTH = 64
_MAX_HARNESS_BYTES = 64
_MAX_PATH_BYTES = 32 * 1024
_MAX_REQUEST_ID_BYTES = 256
_MAX_DEADLINE_BUDGET_MS = 15 * 60 * 1000
_MAX_APPROVAL_TTL_MS = 15 * 60 * 1000
_U64_MAX = (1 << 64) - 1

_CHALLENGE_REQUEST_SCHEMA = "guard-native-approval-challenge-request.v3"
_VALIDATE_REQUEST_SCHEMA = "guard-native-approval-validate-request.v3"
_CONSUME_REQUEST_SCHEMA = "guard-native-approval-consume-request.v3"
_CHALLENGE_SCHEMA = "guard-native-approval-challenge.v3"
_ARTIFACT_SCHEMA = "guard-native-approval-artifact.v3"
_RESULT_SCHEMA = "guard-native-approval-result.v3"
_RECEIPT_SCHEMA = "guard-native-approval-receipt.v3"
_ENVELOPE_SCHEMA = "guard-hook-envelope.v2"
_INTEGRITY_ALGORITHM = "ed25519"

_ACTION_TYPES = frozenset(
    [
        "command",
        "file_read",
        "file_write",
        "package",
        "mcp_tool",
        "network",
        "process_service",
        "browser",
        "config",
        "prompt",
        "harness",
        "unknown",
    ]
)
_OPERATIONS = frozenset(
    ["execute", "read", "write", "install", "call", "request", "start", "stop", "navigate", "set", "submit", "unknown"]
)
_INTRINSIC_ACTIONS = frozenset(["allow", "warn", "review", "require-reapproval"])
_APPROVABLE_FLOORS = frozenset(["review", "require-reapproval"])
_APPROVAL_ACTIONS = frozenset(["review", "require-reapproval"])

_CHALLENGE_KEYS = frozenset(
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
    ]
)
_ARTIFACT_KEYS = (_CHALLENGE_KEYS - {"signing_key_id"}) | {"approved_action", "integrity"}
_RESULT_KEYS = frozenset(["schema", "version", "authority", "receipt"])
_RECEIPT_KEYS = frozenset(
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
    ]
)
_INTEGRITY_KEYS = frozenset(["algorithm", "key_id", "signature"])

_REQUEST_ID_PATTERN = re.compile(r"[a-z0-9._-]{1,256}")
_OUTPUT_REQUEST_ID_PATTERN = re.compile(r"[a-z0-9._:-]{1,256}")
_HEX_PATTERN_CACHE: dict[int, re.Pattern[str]] = {}


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _decode_json_object(payload: bytes, *, maximum: int) -> dict[str, object] | None:
    if not payload or len(payload) > maximum:
        return None
    try:
        decoded: object = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError, TypeError):
        return None
    return decoded if type(decoded) is dict else None


def _bounded_text(value: object, *, maximum: int, nonempty: bool = True) -> bool:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def _hex_pattern(length: int) -> re.Pattern[str]:
    pattern = _HEX_PATTERN_CACHE.get(length)
    if pattern is None:
        pattern = re.compile(rf"[0-9a-f]{{{length}}}")
        _HEX_PATTERN_CACHE[length] = pattern
    return pattern


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and _hex_pattern(length).fullmatch(value) is not None


def _allowed_text(value: object, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _optional_digest(value: object) -> bool:
    return value is None or _lower_hex(value, 64)


def _request_id(value: object) -> bool:
    if not _bounded_text(value, maximum=_MAX_REQUEST_ID_BYTES):
        return False
    assert isinstance(value, str)
    return _REQUEST_ID_PATTERN.fullmatch(value) is not None


def _output_request_id(value: object) -> bool:
    if not isinstance(value, str) or _OUTPUT_REQUEST_ID_PATTERN.fullmatch(value) is None:
        return False
    return ":" not in value or (
        value.startswith("sha256:") and len(value) == len("sha256:") + 64 and _lower_hex(value[len("sha256:") :], 64)
    )


def _positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _U64_MAX


def _valid_approval_times(payload: Mapping[str, object]) -> bool:
    issued_at_ms = payload.get("issued_at_ms")
    expires_at_ms = payload.get("expires_at_ms")
    if not _positive_integer(issued_at_ms) or not _positive_integer(expires_at_ms):
        return False
    issued = cast(int, issued_at_ms)
    expires = cast(int, expires_at_ms)
    return issued < expires <= issued + _MAX_APPROVAL_TTL_MS


def _common_fields_valid(payload: Mapping[str, object], *, artifact: bool) -> bool:
    if (
        not _output_request_id(payload.get("request_id"))
        or not _lower_hex(payload.get("request_digest"), 64)
        or not _lower_hex(payload.get("action_digest"), 64)
        or not _allowed_text(payload.get("action_type"), _ACTION_TYPES)
        or not _allowed_text(payload.get("operation"), _OPERATIONS)
        or not _allowed_text(payload.get("intrinsic_action"), _INTRINSIC_ACTIONS)
        or not _allowed_text(payload.get("minimum_action"), _APPROVABLE_FLOORS)
        or payload.get("floor_class") != "approvable"
        or payload.get("approval_eligible") is not True
        or not _positive_integer(payload.get("policy_generation"))
        or not _lower_hex(payload.get("policy_digest"), 64)
        or not _lower_hex(payload.get("rule_digest"), 64)
        or not _lower_hex(payload.get("runtime_identity"), 64)
        or payload.get("runtime_protocol_version") != _NATIVE_PROTOCOL_VERSION
        or not _lower_hex(payload.get("runtime_binary_identity"), 64)
        or not _allowed_text(payload.get("requested_action"), _APPROVAL_ACTIONS)
        or not _lower_hex(payload.get("scope_contract_digest"), 64)
        or not _lower_hex(payload.get("resident_epoch"), 64)
        or not _lower_hex(payload.get("nonce"), _NATIVE_APPROVAL_NONCE_HEX_LENGTH)
        or not _valid_approval_times(payload)
    ):
        return False
    if artifact and payload.get("approved_action") != "allow":
        return False
    for key in ("runtime_package", "runtime_version", "scope_contract_version"):
        if not _bounded_text(payload.get(key), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES):
            return False
    if not _bounded_text(payload.get("harness"), maximum=_MAX_HARNESS_BYTES):
        return False
    for key in (
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_binding",
    ):
        if not _optional_digest(payload.get(key)):
            return False
    return True


def _challenge_is_valid(payload: dict[str, object]) -> bool:
    return (
        set(payload) == _CHALLENGE_KEYS
        and payload.get("schema") == _CHALLENGE_SCHEMA
        and payload.get("version") == 3
        and _common_fields_valid(payload, artifact=False)
        and _lower_hex(payload.get("signing_key_id"), _NATIVE_APPROVAL_KEY_ID_HEX_LENGTH)
    )


def _artifact_is_valid(payload: dict[str, object]) -> bool:
    integrity = payload.get("integrity")
    return (
        set(payload) == _ARTIFACT_KEYS
        and payload.get("schema") == _ARTIFACT_SCHEMA
        and payload.get("version") == 3
        and _common_fields_valid(payload, artifact=True)
        and type(integrity) is dict
        and set(integrity) == _INTEGRITY_KEYS
        and integrity.get("algorithm") == _INTEGRITY_ALGORITHM
        and _lower_hex(integrity.get("key_id"), _NATIVE_APPROVAL_KEY_ID_HEX_LENGTH)
        and _lower_hex(integrity.get("signature"), _NATIVE_APPROVAL_SIGNATURE_HEX_LENGTH)
    )


def _receipt_is_valid(payload: Mapping[str, object], *, phase: NativeApprovalPhase) -> bool:
    return (
        set(payload) == _RECEIPT_KEYS
        and payload.get("schema") == _RECEIPT_SCHEMA
        and payload.get("version") == 3
        and payload.get("phase") == phase
        and _output_request_id(payload.get("request_id"))
        and _lower_hex(payload.get("request_digest"), 64)
        and _lower_hex(payload.get("action_digest"), 64)
        and _positive_integer(payload.get("policy_generation"))
        and _lower_hex(payload.get("policy_digest"), 64)
        and _lower_hex(payload.get("rule_digest"), 64)
        and _lower_hex(payload.get("runtime_identity"), 64)
        and payload.get("runtime_protocol_version") == _NATIVE_PROTOCOL_VERSION
        and _bounded_text(payload.get("runtime_package"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)
        and _bounded_text(payload.get("runtime_version"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)
        and _lower_hex(payload.get("runtime_binary_identity"), 64)
        and _bounded_text(payload.get("harness"), maximum=_MAX_HARNESS_BYTES)
        and _optional_digest(payload.get("workspace_binding"))
        and _optional_digest(payload.get("device_binding"))
        and _optional_digest(payload.get("installation_binding"))
        and _optional_digest(payload.get("publisher_binding"))
        and _optional_digest(payload.get("artifact_binding"))
        and _bounded_text(payload.get("scope_contract_version"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)
        and _lower_hex(payload.get("scope_contract_digest"), 64)
        and _optional_digest(payload.get("scope_binding"))
        and _lower_hex(payload.get("resident_epoch"), 64)
        and _lower_hex(payload.get("nonce"), _NATIVE_APPROVAL_NONCE_HEX_LENGTH)
        and _valid_approval_times(payload)
        and payload.get("decision") == "allow"
        and _allowed_text(payload.get("requested_action"), _APPROVAL_ACTIONS)
        and payload.get("approved_action") == "allow"
        and payload.get("reason_code") == f"native_approval_{phase}"
        and _bounded_text(payload.get("reason_code"), maximum=_NATIVE_APPROVAL_MAX_REASON_BYTES)
        and _lower_hex(payload.get("nonce_digest"), 64)
        and payload.get("replay_claimed") is True
    )


def _encode_json_object(payload: Mapping[str, object], *, maximum: int) -> bytes | None:
    try:
        encoded = json.dumps(
            dict(payload),
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return None
    return encoded if 0 < len(encoded) <= maximum else None


def _within_approval_bound(payload: Mapping[str, object]) -> bool:
    return _encode_json_object(payload, maximum=_NATIVE_APPROVAL_MAX_BYTES) is not None


def decode_native_approval_challenge(payload: object) -> dict[str, object] | None:
    """Decode a privacy-safe Rust challenge without exposing raw input."""

    if type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    return dict(decoded) if _challenge_is_valid(decoded) and _within_approval_bound(decoded) else None


def decode_native_approval_artifact(payload: object) -> dict[str, object] | None:
    """Bound an external artifact; Rust remains the only signature verifier."""

    if type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    return dict(decoded) if _artifact_is_valid(decoded) and _within_approval_bound(decoded) else None


def decode_native_approval_result(
    payload: object,
    *,
    phase: NativeApprovalPhase,
) -> dict[str, object] | None:
    """Decode only the requested phase of a native receipt envelope."""

    if phase not in {"validated", "consumed"} or type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    receipt = decoded.get("receipt")
    if (
        set(decoded) != _RESULT_KEYS
        or decoded.get("schema") != _RESULT_SCHEMA
        or decoded.get("version") != 3
        or decoded.get("authority") != "rust"
        or type(receipt) is not dict
        or not _receipt_is_valid(cast(dict[str, object], receipt), phase=phase)
        or not _within_approval_bound(decoded)
    ):
        return None
    return dict(decoded)
