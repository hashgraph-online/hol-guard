"""Shared text-formatting helpers for Guard surfaces."""

from __future__ import annotations


def ensure_terminal_punctuation(message: str | None) -> str:
    """Normalize trailing terminal punctuation for user-facing copy."""

    if not message:
        return ""
    trimmed = message.strip()
    if not trimmed:
        return ""
    if trimmed.endswith((".", "!", "?")):
        return trimmed
    return f"{trimmed}."
