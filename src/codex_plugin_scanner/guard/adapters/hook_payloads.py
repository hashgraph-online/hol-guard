"""Shared normalization for inline harness hook payloads."""

from __future__ import annotations


def normalize_session_and_workspace_aliases(normalized: dict[str, object]) -> None:
    """Copy camelCase/``cwd`` session and workspace aliases onto canonical keys."""

    session_id = normalized.get("session_id")
    if session_id is None and isinstance(normalized.get("sessionId"), str):
        normalized["session_id"] = normalized["sessionId"]

    workspace_root = normalized.get("workspace_root")
    if workspace_root is None and isinstance(normalized.get("workspaceRoot"), str):
        workspace_root = normalized["workspaceRoot"]
        normalized["workspace_root"] = workspace_root
    if workspace_root is None and isinstance(normalized.get("cwd"), str):
        normalized["workspace_root"] = normalized["cwd"]


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
