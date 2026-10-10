"""Bind a Cloud workspace id into a store the resident reads from disk."""

from __future__ import annotations

from codex_plugin_scanner.guard.store import GuardStore


def bind_workspace(store: GuardStore, workspace_id: str, now: str = "2026-05-19T00:00:00Z") -> None:
    """Persist the workspace id so the resident, not just this process, sees it."""

    store.set_sync_payload("oauth_local_credentials", {"workspace_id": workspace_id}, now)
