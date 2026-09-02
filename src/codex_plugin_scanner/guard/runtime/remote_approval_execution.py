"""Shared response helpers for legacy and exact remote approvals."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast


def remote_resume_confirmed(resume_metadata: dict[str, object], action: str) -> bool:
    status = _text(resume_metadata.get("continuationStatus"))
    if status is None:
        # Applying a signed decision remains authoritative when the request has
        # no resumable harness surface.
        return True
    if status in {"already_resumed", "not_applicable", "resumed"}:
        return True
    if status in {"manual_retry_required", "unsupported"} and _explicitly_not_resumable(resume_metadata):
        # The signed decision is fully applied when the harness advertises no
        # continuation transport. Retry/failure states on a supported transport
        # remain unconfirmed.
        return True
    return action == "block" and status == "blocked_not_resumed"


def _explicitly_not_resumable(resume_metadata: dict[str, object]) -> bool:
    detail = _detail(resume_metadata)
    if detail is None or detail.get("supported") is not False:
        return False
    capability = _text(resume_metadata.get("continuationCapability")) or _text(detail.get("capability"))
    return capability in {None, "retry-only", "unsupported"}


def _detail(resume_metadata: dict[str, object]) -> dict[str, object] | None:
    value = resume_metadata.get("codexResume") or resume_metadata.get("harnessResume")
    if not isinstance(value, Mapping):
        return None
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return None
    return {cast(str, key): nested for key, nested in raw.items()}


def target_string(mapping: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = _text(mapping.get(key))
        if value is not None:
            return value
    return None


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["remote_resume_confirmed", "target_string"]
