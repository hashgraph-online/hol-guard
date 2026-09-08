"""Bounded browser proof-envelope validators for native approval V4.

This module mirrors the Portal transport shape only. Rust remains authoritative
for WebAuthn semantics, cryptography, policy, replay, and approval decisions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

from . import native_approval_protocol as _base

_NATIVE_APPROVAL_MAX_STRING_BYTES = _base._NATIVE_APPROVAL_MAX_STRING_BYTES
_MAX_APPROVAL_TTL_MS = _base._MAX_APPROVAL_TTL_MS
_lower_hex = _base._lower_hex

_CHALLENGE_V4_SCHEMA = "guard-native-approval-challenge.v4"
_PROOF_V4_SCHEMA = "guard-native-approval-proof.v4"
_CHALLENGE_V4_KEYS = _base._CHALLENGE_KEYS | {"webauthn"}
_PROOF_V4_KEYS = frozenset(["schema", "challenge", "assertion"])

_WEBAUTHN_CHALLENGE_KEYS = frozenset(
    ["rp_id", "origin", "credential_id", "algorithm", "challenge", "user_verification"]
)
_WEBAUTHN_ASSERTION_KEYS = frozenset(["id", "rawId", "type", "response"])
_WEBAUTHN_RESPONSE_KEYS = frozenset(["authenticatorData", "clientDataJSON", "signature", "userHandle"])
_WEBAUTHN_ALGORITHMS = frozenset([-7, -8])
_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES = 1024

_PORTAL_ACTION_MAX_BYTES = 128
_PORTAL_CHALLENGE_MAX_BYTES = 4 * 1024
_PORTAL_CREDENTIAL_MAX_TEXT_BYTES = 2 * 1024
_PORTAL_AUTHENTICATOR_MAX_TEXT_BYTES = 8 * 1024
_PORTAL_CLIENT_DATA_MAX_TEXT_BYTES = 22 * 1024
_PORTAL_SIGNATURE_MAX_TEXT_BYTES = 512
_PORTAL_USER_HANDLE_MAX_TEXT_BYTES = 512
_PORTAL_MAX_SAFE_INTEGER = (1 << 53) - 1


def _portal_bounded_text(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    if any(
        character.isspace() or ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F or character == "\\"
        for character in value
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def _portal_base64url(value: object, *, maximum_text_bytes: int, maximum_bytes: int | None = None) -> bool:
    if not isinstance(value, str) or not value or len(value) > maximum_text_bytes:
        return False
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None or len(value) % 4 == 1:
        return False
    return maximum_bytes is None or (len(value) * 3) // 4 <= maximum_bytes


def _portal_origin_host(value: object) -> tuple[str, str] | None:
    if not _portal_bounded_text(value, maximum=2 * 1024):
        return None
    assert isinstance(value, str)
    if value.startswith("https://"):
        scheme = "https"
        rest = value[len("https://") :]
    elif value.startswith("http://"):
        scheme = "http"
        rest = value[len("http://") :]
    else:
        return None
    if not rest or any(character in rest for character in "?#@"):
        return None
    if "/" in rest:
        authority, path = rest.split("/", 1)
        if path != "":
            return None
    else:
        authority = rest
    if not authority:
        return None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host = authority[: close + 1]
        suffix = authority[close + 1 :]
        if suffix and not suffix.startswith(":"):
            return None
        port = suffix[1:] if suffix else None
    else:
        if authority.count(":") > 1:
            return None
        host, separator, port = authority.partition(":")
        if not separator:
            port = None
    if not host or (port is not None and (not port.isdigit() or int(port) > 65_535)):
        return None
    return scheme, host


def _portal_origin_matches_rp(value: object, rp_id: object) -> bool:
    parsed = _portal_origin_host(value)
    if parsed is None or not _portal_bounded_text(rp_id, maximum=255):
        return False
    scheme, host = parsed
    assert isinstance(rp_id, str)
    if scheme == "http" and host not in {"localhost", "127.0.0.1", "[::1]"}:
        return False
    return host == rp_id


def _portal_positive_safe_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _PORTAL_MAX_SAFE_INTEGER


def _portal_optional_binding(value: object) -> bool:
    return value is None or _portal_bounded_text(value, maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)


def _portal_assertion_is_valid(value: object) -> bool:
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
        and _portal_base64url(
            assertion.get("id"),
            maximum_text_bytes=_PORTAL_CREDENTIAL_MAX_TEXT_BYTES,
            maximum_bytes=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES,
        )
        and _portal_base64url(
            assertion.get("rawId"),
            maximum_text_bytes=_PORTAL_CREDENTIAL_MAX_TEXT_BYTES,
            maximum_bytes=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES,
        )
        and set(response_map) == _WEBAUTHN_RESPONSE_KEYS
        and _portal_base64url(
            response_map.get("authenticatorData"),
            maximum_text_bytes=_PORTAL_AUTHENTICATOR_MAX_TEXT_BYTES,
            maximum_bytes=4 * 1024,
        )
        and _portal_base64url(
            response_map.get("clientDataJSON"),
            maximum_text_bytes=_PORTAL_CLIENT_DATA_MAX_TEXT_BYTES,
            maximum_bytes=16 * 1024,
        )
        and _portal_base64url(
            response_map.get("signature"),
            maximum_text_bytes=_PORTAL_SIGNATURE_MAX_TEXT_BYTES,
            maximum_bytes=256,
        )
        and (
            user_handle is None
            or _portal_base64url(
                user_handle,
                maximum_text_bytes=_PORTAL_USER_HANDLE_MAX_TEXT_BYTES,
                maximum_bytes=256,
            )
        )
    )


def _portal_challenge_identity_fields_are_valid(challenge: Mapping[str, object]) -> bool:
    return (
        set(challenge) == _CHALLENGE_V4_KEYS
        and challenge.get("schema") == _CHALLENGE_V4_SCHEMA
        and challenge.get("version") == 4
        and _portal_bounded_text(challenge.get("request_id"), maximum=256)
        and all(
            _lower_hex(challenge.get(key), 64)
            for key in (
                "request_digest",
                "action_digest",
                "policy_digest",
                "rule_digest",
                "runtime_identity",
                "runtime_binary_identity",
                "scope_contract_digest",
                "resident_epoch",
                "nonce",
                "signing_key_id",
            )
        )
    )


def _portal_challenge_action_fields_are_valid(challenge: Mapping[str, object]) -> bool:
    return (
        all(
            _portal_bounded_text(challenge.get(key), maximum=_PORTAL_ACTION_MAX_BYTES)
            for key in (
                "action_type",
                "operation",
                "intrinsic_action",
                "minimum_action",
                "floor_class",
                "requested_action",
            )
        )
        and challenge.get("approval_eligible") is True
        and _portal_positive_safe_integer(challenge.get("policy_generation"))
        and isinstance(challenge.get("runtime_protocol_version"), int)
        and not isinstance(challenge.get("runtime_protocol_version"), bool)
        and 0 < cast(int, challenge.get("runtime_protocol_version")) <= 65_535
    )


def _portal_challenge_scope_fields_are_valid(challenge: Mapping[str, object]) -> bool:
    return (
        all(
            _portal_bounded_text(challenge.get(key), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)
            for key in ("runtime_package", "runtime_version", "scope_contract_version")
        )
        and _portal_bounded_text(challenge.get("harness"), maximum=128)
        and all(
            _portal_optional_binding(challenge.get(key))
            for key in (
                "workspace_binding",
                "device_binding",
                "installation_binding",
                "publisher_binding",
                "artifact_binding",
                "scope_binding",
            )
        )
    )


def _portal_challenge_times_are_valid(challenge: Mapping[str, object]) -> bool:
    issued = challenge.get("issued_at_ms")
    expires = challenge.get("expires_at_ms")
    if not _portal_positive_safe_integer(issued) or not _portal_positive_safe_integer(expires):
        return False
    issued_at = cast(int, issued)
    expires_at = cast(int, expires)
    return issued_at < expires_at <= issued_at + _MAX_APPROVAL_TTL_MS


def _portal_webauthn_challenge_is_valid(webauthn: Mapping[str, object]) -> bool:
    return (
        set(webauthn) == _WEBAUTHN_CHALLENGE_KEYS
        and _portal_bounded_text(webauthn.get("rp_id"), maximum=255)
        and _portal_origin_matches_rp(webauthn.get("origin"), webauthn.get("rp_id"))
        and _portal_base64url(
            webauthn.get("credential_id"),
            maximum_text_bytes=_PORTAL_CREDENTIAL_MAX_TEXT_BYTES,
            maximum_bytes=_MAX_WEBAUTHN_CREDENTIAL_ID_BYTES,
        )
        and webauthn.get("algorithm") in _WEBAUTHN_ALGORITHMS
        and _portal_base64url(webauthn.get("challenge"), maximum_text_bytes=_PORTAL_CHALLENGE_MAX_BYTES)
        and webauthn.get("user_verification") == "required"
    )


def _portal_challenge_v4_is_valid(value: object) -> bool:
    if type(value) is not dict:
        return False
    challenge = cast(dict[str, object], value)
    webauthn = challenge.get("webauthn")
    return (
        type(webauthn) is dict
        and _portal_challenge_identity_fields_are_valid(challenge)
        and _portal_challenge_action_fields_are_valid(challenge)
        and _portal_challenge_scope_fields_are_valid(challenge)
        and _portal_challenge_times_are_valid(challenge)
        and _portal_webauthn_challenge_is_valid(cast(dict[str, object], webauthn))
    )


def _proof_v4_is_valid(payload: dict[str, object]) -> bool:
    return (
        set(payload) == _PROOF_V4_KEYS
        and payload.get("schema") == _PROOF_V4_SCHEMA
        and type(payload.get("challenge")) is dict
        and _portal_challenge_v4_is_valid(payload.get("challenge"))
        and type(payload.get("assertion")) is dict
        and _portal_assertion_is_valid(payload.get("assertion"))
    )
