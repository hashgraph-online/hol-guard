"""Bounded decoding for responses returned by the native hook runtime."""

from __future__ import annotations

from typing import cast

from .native_approval_errors import (
    NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
)

_NATIVE_ERROR_CODES = frozenset(
    {
        "native_overloaded",
        "native_frame_read_failed",
        "native_request_digest_mismatch",
        "native_request_invalid_json",
        "native_request_too_large",
        "native_response_encode_failed",
        "native_runtime_panicked",
        "native_context_digest_invalid",
        "native_context_digest_invalid_json",
        "native_context_digest_schema_mismatch",
    }
)
_NATIVE_LIFECYCLE_ERROR_CODES = NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
_NATIVE_APPROVAL_ERROR_CODES = NATIVE_APPROVAL_ERROR_CODES


def _string_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return None
    return cast(dict[str, object], value)


def native_error(payload: object) -> str | None:
    """Return a known native transport error from a strict error envelope."""

    decoded = _string_dict(payload)
    if decoded is None or set(decoded) - {"error", "retryable"}:
        return None
    error = decoded.get("error")
    if not isinstance(error, str) or error not in (
        _NATIVE_ERROR_CODES | _NATIVE_APPROVAL_ERROR_CODES | _NATIVE_LIFECYCLE_ERROR_CODES
    ):
        return None
    retryable = decoded.get("retryable")
    if retryable is not None and not isinstance(retryable, bool):
        return None
    return error


__all__ = [
    "native_error",
]
