"""Shared normalization for inline harness hook payloads."""

from __future__ import annotations


def inline_hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    """Return a normalized mutable hooks object, creating one when absent."""

    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized = {
            str(hook_name): list(entries) if isinstance(entries, list) else entries
            for hook_name, entries in hooks.items()
        }
        payload["hooks"] = normalized
        return normalized
    normalized: dict[str, object] = {}
    payload["hooks"] = normalized
    return normalized
