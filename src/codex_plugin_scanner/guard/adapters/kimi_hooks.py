"""Helpers for Kimi Code CLI hook payloads."""

from __future__ import annotations


def normalize_kimi_prompt(value: object | None) -> object | None:
    """Flatten Kimi Code's ContentPart[] prompt into a single string.

    Returns the original value unchanged if it is not a string or a list of
    text-bearing content parts, so image-only or non-standard payloads are not
    silently replaced with ``None``.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return value
    parts: list[str] = []
    for item in value:
        if isinstance(item, dict):
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts) if parts else value
