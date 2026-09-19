"""Stable CLI sync output with bounded transport status metadata."""

from __future__ import annotations

from typing import cast
from urllib.error import HTTPError


def sync_failure_payload(error: BaseException, *, message: str | None = None) -> dict[str, object]:
    """Inspect explicit causes only; never consume response bodies or headers."""

    payload: dict[str, object] = {"synced": False, "error": str(error) if message is None else message}
    current: BaseException | None = error
    visited: set[int] = set()
    for _ in range(8):
        if current is None or id(current) in visited:
            break
        visited.add(id(current))
        if isinstance(current, HTTPError) and type(current.code) is int and 400 <= current.code <= 599:
            payload["http_status"] = current.code
            break
        current = current.__cause__
    return payload


def sync_success_payload(payload: dict[str, object]) -> dict[str, object]:
    """Preserve existing receipt summary fields and explicit outer values."""

    receipts = payload.get("receipts")
    if isinstance(receipts, dict):
        summary = cast(dict[str, object], receipts)
        for key in (
            "receipt_upload_status",
            "policy_validation_status",
            "policy_application_status",
            "policy_rejection_reason",
        ):
            _ = payload.setdefault(key, summary.get(key))
    return payload
