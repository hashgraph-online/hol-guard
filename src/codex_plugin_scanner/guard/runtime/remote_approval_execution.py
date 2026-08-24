"""Shared response helpers for legacy and exact remote approvals."""

from __future__ import annotations


def remote_resume_confirmed(resume_metadata: dict[str, object], action: str) -> bool:
    status = _text(resume_metadata.get("resumeStatus"))
    if status in {"already_sent", "blocked", "not_applicable", "resumed", "sent"}:
        return True
    if action != "block" or status != "skipped":
        return False
    detail = resume_metadata.get("codexResume") or resume_metadata.get("harnessResume")
    return isinstance(detail, dict) and detail.get("reason") == "blocked_not_resumed"


def target_string(mapping: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = _text(mapping.get(key))
        if value is not None:
            return value
    return None


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["remote_resume_confirmed", "target_string"]
