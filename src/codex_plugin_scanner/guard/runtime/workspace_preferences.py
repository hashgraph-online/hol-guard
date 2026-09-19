"""Local consent and source-bound remote preferences for optional uploads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import load_guard_config
from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..synced_policy import validated_synced_policy_bundle
from ..workspace_preference_authority import (
    CONTRACT,
    WorkspacePreferences,
    accept_workspace_preference_response,
    capture_workspace_preference_state,
    parse_workspace_preferences,
)
from .receipt_redaction import compose_receipt_redaction_level

if TYPE_CHECKING:
    from ..store import GuardStore

__all__ = ["CONTRACT", "WorkspacePreferences", "parse_workspace_preferences"]


def read_workspace_preferences(store: GuardStore) -> WorkspacePreferences | None:
    return capture_workspace_preference_state(store).preferences


def preference_sync_context(store: GuardStore) -> dict[str, object]:
    try:
        return capture_workspace_preference_state(store).sync_context()
    except (OSError, RuntimeError, ValueError, TypeError):
        return {"workspacePreferencesContract": CONTRACT}


def accept_workspace_preferences(store: GuardStore, value: object, *, workspace_id: str) -> WorkspacePreferences:
    state = capture_workspace_preference_state(store)
    if state.workspace_id != workspace_id:
        raise ValueError("workspace_preferences_scope_changed")
    result = accept_workspace_preference_response(store, state, {"workspacePreferences": value}, sent_revision=None)
    assert result.state.preferences is not None
    return result.state.preferences


def optional_upload_allowed(
    store: GuardStore, *, telemetry: bool = False, required_connection: OAuthConnectionSnapshot | None = None
) -> bool:
    """Current remote permission can restrict, but cannot grant, local consent."""
    try:
        config = load_guard_config(store.guard_home)
        if not config.sync or (telemetry and not config.telemetry):
            return False
        state = capture_workspace_preference_state(store, required_connection=required_connection)
        if not state.confirmed:
            return False
        current = state.preferences
        return (
            state.mode == "legacy"
            if current is None
            else current.sync_enabled and (not telemetry or current.telemetry_enabled)
        )
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def effective_receipt_redaction_level(
    store: GuardStore, *, required_connection: OAuthConnectionSnapshot | None = None
) -> str:
    try:
        config = load_guard_config(store.guard_home)
        signed = validated_synced_policy_bundle(store)
        current = capture_workspace_preference_state(store, required_connection=required_connection).preferences
        return compose_receipt_redaction_level(config, signed, None if current is None else current.redaction_level)
    except (OSError, RuntimeError, ValueError, TypeError):
        return "full"
