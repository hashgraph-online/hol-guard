"""Bounded Portal-compatible transport validators for native approval V4.

This module only validates browser-envelope shape. Rust remains authoritative
for WebAuthn parsing, cryptography, policy, replay, and approval semantics.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
from collections.abc import Mapping
from typing import cast

from . import native_approval_protocol as _base
from .native_approval_v4_portal import _proof_v4_is_valid

NativeApprovalPhase = _base.NativeApprovalPhase

_NATIVE_PROTOCOL_VERSION = _base._NATIVE_PROTOCOL_VERSION
_NATIVE_APPROVAL_MAX_BYTES = _base._NATIVE_APPROVAL_MAX_BYTES
_NATIVE_APPROVAL_MAX_STRING_BYTES = _base._NATIVE_APPROVAL_MAX_STRING_BYTES
_NATIVE_APPROVAL_KEY_ID_HEX_LENGTH = _base._NATIVE_APPROVAL_KEY_ID_HEX_LENGTH
_MAX_APPROVAL_TTL_MS = _base._MAX_APPROVAL_TTL_MS

_CHALLENGE_REQUEST_V4_SCHEMA = "guard-native-approval-challenge-request.v4"
_VALIDATE_REQUEST_V4_SCHEMA = "guard-native-approval-validate-request.v4"
_CONSUME_REQUEST_V4_SCHEMA = "guard-native-approval-consume-request.v4"
_CHALLENGE_V4_SCHEMA = "guard-native-approval-challenge.v4"
_ARTIFACT_V4_SCHEMA = "guard-native-approval-artifact.v4"
_PROOF_V4_SCHEMA = "guard-native-approval-proof.v4"
_RESULT_V4_SCHEMA = "guard-native-approval-result.v4"
_RECEIPT_V4_SCHEMA = "guard-native-approval-receipt.v4"

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
_PROOF_V4_KEYS = frozenset(["schema", "challenge", "assertion"])
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

_WEBAUTHN_CHALLENGE_KEYS = frozenset(
    ["rp_id", "origin", "credential_id", "algorithm", "challenge", "user_verification"]
)
_WEBAUTHN_ASSERTION_KEYS = frozenset(["id", "rawId", "type", "response"])
_WEBAUTHN_RESPONSE_KEYS = frozenset(["authenticatorData", "clientDataJSON", "signature", "userHandle"])
_WEBAUTHN_ALGORITHMS = frozenset([-7, -8])
_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES = 1024
_MAX_WEBAUTHN_AUTHENTICATOR_DATA_BYTES = 4 * 1024
_MAX_WEBAUTHN_CLIENT_DATA_BYTES = 16 * 1024
_MAX_WEBAUTHN_SIGNATURE_BYTES = 256
_MAX_WEBAUTHN_USER_HANDLE_BYTES = 256

_RESULT_KEYS = _base._RESULT_KEYS
_bounded_text = _base._bounded_text
_lower_hex = _base._lower_hex
_common_fields_valid = _base._common_fields_valid
_receipt_fields_are_valid = _base._receipt_fields_are_valid
_within_approval_bound = _base._within_approval_bound


def _base64url_transport(value: object, *, maximum: int) -> bool:
    """Bound a browser base64url member without interpreting its meaning."""

    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if b"=" in encoded or len(encoded) > maximum * 2 + 4:
        return False
    padded = encoded + b"=" * ((-len(encoded)) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    if not decoded or len(decoded) > maximum:
        return False
    return base64.urlsafe_b64encode(decoded).rstrip(b"=") == encoded


def _rp_id_transport(value: object) -> bool:
    if not isinstance(value, str) or not _bounded_text(value, maximum=255) or not value.isascii():
        return False
    if value.startswith("[") and value.endswith("]"):
        try:
            _ = ipaddress.IPv6Address(value[1:-1])
        except ValueError:
            return False
        return True
    try:
        _ = ipaddress.IPv4Address(value)
    except ValueError:
        pass
    else:
        return True
    if value != value.lower() or value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(
            character.isascii() and (character.islower() or character.isdigit() or character == "-")
            for character in label
        )
        for label in value.split(".")
    )


def _origin_transport(value: object) -> bool:
    parsed = _origin_parts_transport(value)
    if parsed is None:
        return False
    scheme, host = parsed
    return scheme == "https" or host in {"localhost", "127.0.0.1", "[::1]"}


def _origin_parts_transport(value: object) -> tuple[str, str] | None:
    if (
        not isinstance(value, str)
        or not _bounded_text(value, maximum=2 * 1024)
        or not value.isascii()
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        return None
    if value.startswith("http://"):
        scheme = "http"
        default_port = 80
        rest = value[len("http://") :]
    elif value.startswith("https://"):
        scheme = "https"
        default_port = 443
        rest = value[len("https://") :]
    else:
        return None
    if not rest or any(character in rest for character in "/?#@"):
        return None
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return None
        host = rest[: close + 1]
        suffix = rest[close + 1 :]
        if suffix and not suffix.startswith(":"):
            return None
        port = suffix[1:] if suffix else None
    else:
        if rest.count(":") > 1:
            return None
        host, separator, port = rest.partition(":")
        if not separator:
            port = None
    if not _rp_id_transport(host):
        return None
    if port is not None and not _valid_origin_port(port, default=default_port):
        return None
    return scheme, host


def _origin_matches_rp_transport(origin: object, rp_id: object) -> bool:
    parsed = _origin_parts_transport(origin)
    return parsed is not None and parsed[1] == rp_id


def _valid_origin_port(value: str, *, default: int) -> bool:
    canonical = value.lstrip("0") or "0"
    return (
        bool(value)
        and len(value) <= 5
        and value.isdigit()
        and value == canonical
        and 0 < int(value) <= 65_535
        and int(value) != default
    )


def _webauthn_challenge_is_valid(value: object) -> bool:
    if type(value) is not dict:
        return False
    challenge = cast(dict[str, object], value)
    credential_id = challenge.get("credential_id")
    return (
        set(challenge) == _WEBAUTHN_CHALLENGE_KEYS
        and _rp_id_transport(challenge.get("rp_id"))
        and _origin_transport(challenge.get("origin"))
        and _origin_matches_rp_transport(challenge.get("origin"), challenge.get("rp_id"))
        and _base64url_transport(credential_id, maximum=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES)
        and challenge.get("algorithm") in _WEBAUTHN_ALGORITHMS
        and _base64url_transport(challenge.get("challenge"), maximum=64)
        and challenge.get("user_verification") == "required"
    )


def _webauthn_assertion_is_valid(value: object) -> bool:
    if type(value) is not dict:
        return False
    assertion = cast(dict[str, object], value)
    response = assertion.get("response")
    if type(response) is not dict:
        return False
    response_map = cast(dict[str, object], response)
    user_handle = response_map.get("userHandle")
    return (
        set(assertion) == _WEBAUTHN_ASSERTION_KEYS
        and assertion.get("type") == "public-key"
        and _base64url_transport(assertion.get("id"), maximum=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES)
        and assertion.get("id") == assertion.get("rawId")
        and _base64url_transport(assertion.get("rawId"), maximum=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES)
        and set(response_map) == _WEBAUTHN_RESPONSE_KEYS
        and _base64url_transport(response_map.get("authenticatorData"), maximum=_MAX_WEBAUTHN_AUTHENTICATOR_DATA_BYTES)
        and _base64url_transport(response_map.get("clientDataJSON"), maximum=_MAX_WEBAUTHN_CLIENT_DATA_BYTES)
        and _base64url_transport(response_map.get("signature"), maximum=_MAX_WEBAUTHN_SIGNATURE_BYTES)
        and (user_handle is None or _base64url_transport(user_handle, maximum=_MAX_WEBAUTHN_USER_HANDLE_BYTES))
    )


def _challenge_v4_is_valid(payload: dict[str, object]) -> bool:
    return (
        set(payload) == _CHALLENGE_V4_KEYS
        and payload.get("schema") == _CHALLENGE_V4_SCHEMA
        and payload.get("version") == 4
        and _common_fields_valid(payload, artifact=False)
        and _lower_hex(payload.get("signing_key_id"), _NATIVE_APPROVAL_KEY_ID_HEX_LENGTH)
        and _webauthn_challenge_is_valid(payload.get("webauthn"))
    )


def _artifact_v4_is_valid(payload: dict[str, object]) -> bool:
    return (
        set(payload) == _ARTIFACT_V4_KEYS
        and payload.get("schema") == _ARTIFACT_V4_SCHEMA
        and payload.get("version") == 4
        and _common_fields_valid(payload, artifact=True)
        and _webauthn_assertion_is_valid(payload.get("webauthn"))
    )


def _receipt_v4_is_valid(payload: Mapping[str, object], *, phase: NativeApprovalPhase) -> bool:
    if set(payload) != _RECEIPT_V4_KEYS or not _receipt_fields_are_valid(payload, phase=phase, v4=True):
        return False
    return all(
        (
            _rp_id_transport(payload.get("rp_id")),
            _origin_transport(payload.get("origin")),
            _lower_hex(payload.get("credential_id_digest"), 64),
            payload.get("algorithm") in _WEBAUTHN_ALGORITHMS,
            isinstance(payload.get("authenticator_sign_count"), int)
            and not isinstance(payload.get("authenticator_sign_count"), bool)
            and 0 <= cast(int, payload.get("authenticator_sign_count")) <= (1 << 32) - 1,
        )
    )


def decode_native_approval_v4_challenge(payload: object) -> dict[str, object] | None:
    """Bound a Rust V4 challenge; WebAuthn semantics remain in Rust."""

    if type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    return dict(decoded) if _challenge_v4_is_valid(decoded) and _within_approval_bound(decoded) else None


def decode_native_approval_v4_artifact(payload: object) -> dict[str, object] | None:
    """Carry a browser assertion without signing or cryptographic verification."""

    if type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    return dict(decoded) if _artifact_v4_is_valid(decoded) and _within_approval_bound(decoded) else None


def decode_native_approval_v4_proof(payload: object) -> dict[str, object] | None:
    """Bound the Portal proof envelope without interpreting the assertion."""

    if type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    return dict(decoded) if _proof_v4_is_valid(decoded) and _within_approval_bound(decoded) else None


def decode_native_approval_v4_result(
    payload: object,
    *,
    phase: NativeApprovalPhase,
) -> dict[str, object] | None:
    """Bound a Rust V4 receipt and its exact lifecycle phase."""

    if phase not in {"validated", "consumed"} or type(payload) is not dict:
        return None
    decoded = cast(dict[str, object], payload)
    receipt = decoded.get("receipt")
    if (
        set(decoded) != _RESULT_KEYS
        or decoded.get("schema") != _RESULT_V4_SCHEMA
        or decoded.get("version") != 4
        or decoded.get("authority") != "rust"
        or type(receipt) is not dict
        or not _receipt_v4_is_valid(cast(dict[str, object], receipt), phase=phase)
        or not _within_approval_bound(decoded)
    ):
        return None
    return dict(decoded)
