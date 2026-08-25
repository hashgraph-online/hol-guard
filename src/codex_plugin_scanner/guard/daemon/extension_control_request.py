"""Strict request-field helpers for the Extension Control daemon API."""

from __future__ import annotations

from .extension_control_errors import ExtensionControlApiError


def required_request_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ExtensionControlApiError(400, f"invalid_{key}")
    return value


def request_needs_proof(payload: dict[str, object]) -> bool:
    return any(
        key in payload
        for key in (
            "approval_gate",
            "approval_password",
            "approval_totp_code",
            "session_nonce",
        )
    )
