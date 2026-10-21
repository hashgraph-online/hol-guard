"""Capture local-only hook retry lineage without making it authorization."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Final, cast

_LINEAGE_VERSION: Final = 1
_MAX_IDENTIFIER_LENGTH: Final = 256
_HEX_DIGEST_LENGTH: Final = 64
_SESSION_KEYS: Final = ("session_id", "sessionId")
_THREAD_KEYS: Final = ("thread_id", "threadId", "conversation_id", "conversationId", "codex_thread_id")
_TOOL_CALL_KEYS: Final = ("tool_call_id", "toolCallId", "tool_use_id", "toolUseId", "call_id", "callId")
_TURN_KEYS: Final = ("turn_id", "turnId", "codex_turn_id")
_INVOCATION_KEYS: Final = ("invocation_id", "invocationId", "event_id", "eventId")
_PROVIDER_REQUEST_KEYS: Final = ("request_id", "requestId", "approval_request_id", "approvalRequestId")
_WORKSPACE_KEYS: Final = ("workspace", "cwd", "working_directory", "workingDirectory")
_DEVICE_KEYS: Final = ("device_id", "deviceId", "device_fingerprint", "deviceFingerprint")
_LINEAGE_KEYS: Final = frozenset(
    {
        "version",
        "source",
        "harness",
        "session_id",
        "thread_id",
        "tool_call_id",
        "turn_id",
        "invocation_id",
        "provider_request_id",
        "original_request_id",
        "workspace_sha256",
        "device_sha256",
        "action_sha256",
        "lineage_id",
    }
)


def capture_retry_lineage(
    payload: Mapping[str, object],
    *,
    harness: str,
    workspace: object | None = None,
    action_envelope: Mapping[str, object] | None = None,
    original_request_id: object | None = None,
) -> dict[str, object] | None:
    """Capture provider identifiers for local diagnostics and future reattachment.

    The returned value is deliberately not a capability or bearer token. Raw
    provider identifiers stay in local operation metadata; public continuation
    payloads must continue to expose only their existing capability fields.
    """

    harness_value, harness_valid = _identifier(harness)
    if not harness_valid or harness_value is None:
        return None
    values: dict[str, str | None] = {}
    for name, keys in (
        ("session_id", _SESSION_KEYS),
        ("thread_id", _THREAD_KEYS),
        ("tool_call_id", _TOOL_CALL_KEYS),
        ("turn_id", _TURN_KEYS),
        ("invocation_id", _INVOCATION_KEYS),
    ):
        value, valid = _payload_identifier(payload, keys)
        if not valid:
            return None
        values[name] = value
    if not any(value is not None for value in values.values()):
        return None

    provider_request, provider_request_valid = _payload_identifier(payload, _PROVIDER_REQUEST_KEYS)
    original_request, original_request_valid = (
        _identifier(original_request_id) if original_request_id is not None else (None, True)
    )
    if not provider_request_valid or not original_request_valid:
        return None

    payload_workspace, workspace_valid = _payload_identifier(payload, _WORKSPACE_KEYS)
    if not workspace_valid:
        return None
    if workspace is not None:
        workspace_value, explicit_workspace_valid = _identifier(workspace)
        if not explicit_workspace_valid or workspace_value is None:
            return None
        # Payload context is diagnostic only.  Do not let it override the
        # runtime workspace, and reject a contradictory provider claim.
        if payload_workspace is not None and payload_workspace != workspace_value:
            return None
    else:
        workspace_value = payload_workspace
    device_value, device_valid = _payload_identifier(payload, _DEVICE_KEYS)
    if not device_valid:
        return None

    lineage: dict[str, object] = {
        "version": _LINEAGE_VERSION,
        "source": "hook",
        "harness": harness_value,
    }
    lineage.update({name: value for name, value in values.items() if value is not None})
    if provider_request is not None:
        lineage["provider_request_id"] = provider_request
    if original_request is not None:
        lineage["original_request_id"] = original_request
    if workspace_value is not None:
        lineage["workspace_sha256"] = _digest_text(workspace_value)
    if device_value is not None:
        lineage["device_sha256"] = _digest_text(device_value)
    action_digest = _digest_mapping(action_envelope)
    if action_envelope is not None and action_digest is None:
        return None
    if action_digest is not None:
        lineage["action_sha256"] = action_digest
    lineage["lineage_id"] = _digest_mapping(lineage)
    return lineage


def preserve_retry_lineage(
    existing_metadata: Mapping[str, object],
    requested_metadata: Mapping[str, object],
) -> dict[str, object]:
    """Keep the first valid lineage when an operation is updated later."""

    merged = dict(requested_metadata)
    existing = existing_metadata.get("retry_lineage")
    if _valid_lineage(existing):
        merged["retry_lineage"] = dict(cast(Mapping[str, object], existing))
    return merged


def _payload_identifier(payload: Mapping[str, object], keys: tuple[str, ...]) -> tuple[str | None, bool]:
    values: list[str] = []
    for key in keys:
        if key not in payload or payload[key] is None:
            continue
        value, valid = _identifier(payload[key])
        if not valid:
            return None, False
        if value is not None and value not in values:
            values.append(value)
    if len(values) > 1:
        return None, False
    return (values[0] if values else None), True


def _identifier(value: object) -> tuple[str | None, bool]:
    if not isinstance(value, str):
        return None, False
    if not value or value != value.strip():
        return None, False
    if len(value) > _MAX_IDENTIFIER_LENGTH or any(
        ord(character) < 0x20 or ord(character) == 0x7F or 0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        return None, False
    return value, True


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_mapping(value: Mapping[str, object] | None) -> str | None:
    if value is None:
        return None
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _valid_lineage(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw) or set(raw) - _LINEAGE_KEYS:
        return False
    lineage = {cast(str, key): nested for key, nested in raw.items()}
    if type(lineage.get("version")) is not int or lineage.get("version") != _LINEAGE_VERSION:
        return False
    if lineage.get("source") != "hook":
        return False
    harness, harness_valid = _identifier(lineage.get("harness"))
    if not harness_valid or harness is None:
        return False
    provider_keys = ("session_id", "thread_id", "tool_call_id", "turn_id", "invocation_id")
    if not any(key in lineage for key in provider_keys):
        return False
    for key in (*provider_keys, "provider_request_id", "original_request_id"):
        identifier, valid = _identifier(lineage.get(key)) if key in lineage else (None, True)
        if not valid or (key in lineage and identifier is None):
            return False
    for key in ("workspace_sha256", "device_sha256", "action_sha256"):
        if key not in lineage:
            continue
        digest = lineage[key]
        if (
            not isinstance(digest, str)
            or len(digest) != _HEX_DIGEST_LENGTH
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return False
    lineage_id = lineage.get("lineage_id")
    if (
        not isinstance(lineage_id, str)
        or len(lineage_id) != _HEX_DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in lineage_id)
    ):
        return False
    unsigned = {key: nested for key, nested in lineage.items() if key != "lineage_id"}
    expected = _digest_mapping(unsigned)
    return expected is not None and hmac.compare_digest(lineage_id, expected)


__all__ = ["capture_retry_lineage", "preserve_retry_lineage"]
