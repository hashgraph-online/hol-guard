"""Bounded Python boundary types for the Rust native approval protocol.

This module only validates transport shape.  It never signs, verifies, or
assigns approval semantics to a challenge or artifact.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
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
_CHALLENGE_REQUEST_V4_SCHEMA = "guard-native-approval-challenge-request.v4"
_VALIDATE_REQUEST_V4_SCHEMA = "guard-native-approval-validate-request.v4"
_CONSUME_REQUEST_V4_SCHEMA = "guard-native-approval-consume-request.v4"
_CHALLENGE_V4_SCHEMA = "guard-native-approval-challenge.v4"
_ARTIFACT_V4_SCHEMA = "guard-native-approval-artifact.v4"
_PROOF_V4_SCHEMA = "guard-native-approval-proof.v4"
_RESULT_V4_SCHEMA = "guard-native-approval-result.v4"
_RECEIPT_V4_SCHEMA = "guard-native-approval-receipt.v4"
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
_CHALLENGE_V4_KEYS = _CHALLENGE_KEYS | {"webauthn"}
_ARTIFACT_V4_KEYS = (_ARTIFACT_KEYS - {"integrity"}) | {"signing_key_id", "webauthn"}
_PROOF_V4_KEYS = frozenset(["schema", "challenge", "assertion"])
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
_RECEIPT_V4_KEYS = _RECEIPT_KEYS | {
    "rp_id",
    "origin",
    "credential_id_digest",
    "algorithm",
    "authenticator_sign_count",
}
_INTEGRITY_KEYS = frozenset(["algorithm", "key_id", "signature"])

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

# The browser/Portal proof schema deliberately leaves native action labels and
# bindings opaque.  Keep that outer transport compatible, but continue to
# validate the flattened resident artifact with the strict native contract.
_PORTAL_ACTION_MAX_BYTES = 128
_PORTAL_CHALLENGE_MAX_BYTES = 4 * 1024
_PORTAL_CREDENTIAL_MAX_TEXT_BYTES = 2 * 1024
_PORTAL_AUTHENTICATOR_MAX_TEXT_BYTES = 8 * 1024
_PORTAL_CLIENT_DATA_MAX_TEXT_BYTES = 22 * 1024
_PORTAL_SIGNATURE_MAX_TEXT_BYTES = 512
_PORTAL_USER_HANDLE_MAX_TEXT_BYTES = 512
_PORTAL_MAX_SAFE_INTEGER = (1 << 53) - 1

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


def _bounded_lower_hex(value: object, *, maximum_bytes: int) -> bool:
    return (
        isinstance(value, str)
        and 2 <= len(value) <= maximum_bytes * 2
        and len(value) % 2 == 0
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


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
            character.isascii()
            and (character.islower() or character.isdigit() or character == "-")
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


def _portal_bounded_text(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    if any(
        character.isspace()
        or ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or character == "\\"
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
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= _PORTAL_MAX_SAFE_INTEGER
    )


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


def _portal_challenge_v4_is_valid(value: object) -> bool:
    if type(value) is not dict:
        return False
    challenge = cast(dict[str, object], value)
    webauthn = challenge.get("webauthn")
    if type(webauthn) is not dict:
        return False
    webauthn_map = cast(dict[str, object], webauthn)
    if (
        set(challenge) != _CHALLENGE_V4_KEYS
        or challenge.get("schema") != _CHALLENGE_V4_SCHEMA
        or challenge.get("version") != 4
        or not _portal_bounded_text(challenge.get("request_id"), maximum=256)
        or not all(
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
        or not all(
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
        or challenge.get("approval_eligible") is not True
        or not _portal_positive_safe_integer(challenge.get("policy_generation"))
        or not isinstance(challenge.get("runtime_protocol_version"), int)
        or isinstance(challenge.get("runtime_protocol_version"), bool)
        or not 0 < cast(int, challenge.get("runtime_protocol_version")) <= 65_535
        or not all(
            _portal_bounded_text(challenge.get(key), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES)
            for key in ("runtime_package", "runtime_version", "scope_contract_version")
        )
        or not _portal_bounded_text(challenge.get("harness"), maximum=128)
        or not all(
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
        or not _portal_positive_safe_integer(challenge.get("issued_at_ms"))
        or not _portal_positive_safe_integer(challenge.get("expires_at_ms"))
    ):
        return False
    issued = cast(int, challenge["issued_at_ms"])
    expires = cast(int, challenge["expires_at_ms"])
    if expires <= issued or expires - issued > _MAX_APPROVAL_TTL_MS:
        return False
    return not (
        set(webauthn_map) != _WEBAUTHN_CHALLENGE_KEYS
        or not _portal_bounded_text(webauthn_map.get("rp_id"), maximum=255)
        or not _portal_origin_matches_rp(webauthn_map.get("origin"), webauthn_map.get("rp_id"))
        or not _portal_base64url(
            webauthn_map.get("credential_id"),
            maximum_text_bytes=_PORTAL_CREDENTIAL_MAX_TEXT_BYTES,
            maximum_bytes=1024,
        )
        or webauthn_map.get("algorithm") not in _WEBAUTHN_ALGORITHMS
        or not _portal_base64url(
            webauthn_map.get("challenge"), maximum_text_bytes=_PORTAL_CHALLENGE_MAX_BYTES
        )
        or webauthn_map.get("user_verification") != "required"
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
        and _base64url_transport(
            response_map.get("authenticatorData"), maximum=_MAX_WEBAUTHN_AUTHENTICATOR_DATA_BYTES
        )
        and _base64url_transport(response_map.get("clientDataJSON"), maximum=_MAX_WEBAUTHN_CLIENT_DATA_BYTES)
        and _base64url_transport(response_map.get("signature"), maximum=_MAX_WEBAUTHN_SIGNATURE_BYTES)
        and (
            user_handle is None
            or _base64url_transport(user_handle, maximum=_MAX_WEBAUTHN_USER_HANDLE_BYTES)
        )
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


def _proof_v4_is_valid(payload: dict[str, object]) -> bool:
    return (
        set(payload) == _PROOF_V4_KEYS
        and payload.get("schema") == _PROOF_V4_SCHEMA
        and type(payload.get("challenge")) is dict
        and _portal_challenge_v4_is_valid(payload.get("challenge"))
        and type(payload.get("assertion")) is dict
        and _portal_assertion_is_valid(payload.get("assertion"))
    )


def _receipt_fields_are_valid(
    payload: Mapping[str, object], *, phase: NativeApprovalPhase, v4: bool = False
) -> bool:
    return all(
        (
            payload.get("schema") == (_RECEIPT_V4_SCHEMA if v4 else _RECEIPT_SCHEMA),
            payload.get("version") == (4 if v4 else 3),
            payload.get("phase") == phase,
            _output_request_id(payload.get("request_id")),
            _lower_hex(payload.get("request_digest"), 64),
            _lower_hex(payload.get("action_digest"), 64),
            _positive_integer(payload.get("policy_generation")),
            _lower_hex(payload.get("policy_digest"), 64),
            _lower_hex(payload.get("rule_digest"), 64),
            _lower_hex(payload.get("runtime_identity"), 64),
            payload.get("runtime_protocol_version") == _NATIVE_PROTOCOL_VERSION,
            _bounded_text(payload.get("runtime_package"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES),
            _bounded_text(payload.get("runtime_version"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES),
            _lower_hex(payload.get("runtime_binary_identity"), 64),
            _bounded_text(payload.get("harness"), maximum=_MAX_HARNESS_BYTES),
            _optional_digest(payload.get("workspace_binding")),
            _optional_digest(payload.get("device_binding")),
            _optional_digest(payload.get("installation_binding")),
            _optional_digest(payload.get("publisher_binding")),
            _optional_digest(payload.get("artifact_binding")),
            _bounded_text(payload.get("scope_contract_version"), maximum=_NATIVE_APPROVAL_MAX_STRING_BYTES),
            _lower_hex(payload.get("scope_contract_digest"), 64),
            _optional_digest(payload.get("scope_binding")),
            _lower_hex(payload.get("resident_epoch"), 64),
            _lower_hex(payload.get("nonce"), _NATIVE_APPROVAL_NONCE_HEX_LENGTH),
            _valid_approval_times(payload),
            payload.get("decision") == "allow",
            _allowed_text(payload.get("requested_action"), _APPROVAL_ACTIONS),
            payload.get("approved_action") == "allow",
            payload.get("reason_code") == (f"native_approval_v4_{phase}" if v4 else f"native_approval_{phase}"),
            _bounded_text(payload.get("reason_code"), maximum=_NATIVE_APPROVAL_MAX_REASON_BYTES),
            _lower_hex(payload.get("nonce_digest"), 64),
            payload.get("replay_claimed") is True,
        )
    )


def _receipt_is_valid(payload: Mapping[str, object], *, phase: NativeApprovalPhase) -> bool:
    if set(payload) != _RECEIPT_KEYS:
        return False
    return _receipt_fields_are_valid(payload, phase=phase)


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
