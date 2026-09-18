"""Explicit prior preference negotiation for existing optional transport tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.workspace_preferences import accept_workspace_preferences
from codex_plugin_scanner.guard.store import GuardStore

_WORKSPACE = "00000000-0000-4000-8000-000000000042"
_NOW = "2026-09-18T00:00:00Z"


def allow_optional_activity(store: GuardStore) -> None:
    """Set disposable local consent and a real accepted preference state, not a gate mock."""
    workspace_id = store.get_cloud_workspace_id() or _WORKSPACE
    previous = store.get_sync_payload("oauth_local_credentials")
    credentials = previous if isinstance(previous, dict) else {}
    store.set_sync_payload("oauth_local_credentials", {**credentials, "workspace_id": workspace_id}, _NOW)
    config = store.guard_home / "config.toml"
    assert not config.exists(), "The transport fixture must explicitly preserve any pre-existing settings."
    config.write_text('sync = true\ntelemetry = true\nreceipt_redaction_level = "full"\n')
    accepted = accept_workspace_preferences(
        store,
        {
            "contractVersion": "guard.workspace-preferences.v1",
            "workspaceId": workspace_id,
            "revision": 1,
            "updatedAt": _NOW,
            "preferences": {"syncEnabled": True, "telemetryEnabled": True, "receiptRedactionLevel": "full"},
        },
        workspace_id=workspace_id,
    )
    assert accepted is not None
