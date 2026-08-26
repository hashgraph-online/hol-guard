"""Capability proof for a Codex hook that is still waiting on Guard."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from .config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config
from .live_process_identity import process_identity_matches
from .store import GuardStore


def codex_live_hook_process_is_unavailable(metadata: Mapping[str, object]) -> bool:
    """Return true when a declared browser waiter cannot be proven live."""

    return metadata.get("codex_hook_waits_for_browser_approval") is True and not process_identity_matches(
        metadata.get("codex_browser_wait_process")
    )


def codex_live_hook_wait_deadline(
    store: GuardStore,
    *,
    operation: Mapping[str, object],
    metadata: Mapping[str, object],
) -> datetime | None:
    """Return a proven live-hook deadline, including the legacy PreToolUse bridge."""

    if str(operation.get("status") or "") != "waiting_on_approval":
        return None
    if not process_identity_matches(metadata.get("codex_browser_wait_process")):
        return None
    if metadata.get("codex_hook_waits_for_browser_approval") is True:
        explicit = _parse_timestamp(
            _first_string(metadata, ("codex_browser_wait_deadline_at", "browser_wait_deadline_at")) or ""
        )
        if explicit is not None:
            return explicit
    event_name = _first_string(metadata, ("hook_event_name", "event"))
    if event_name != "PreToolUse":
        return None
    started_at = _parse_timestamp(_first_string(operation, ("updated_at", "created_at")) or "")
    if started_at is None:
        return None
    workspace = _workspace_path(metadata)
    try:
        configured = int(load_guard_config(store.guard_home, workspace).approval_wait_timeout_seconds)
        configured = max(0, min(configured, MAX_APPROVAL_WAIT_TIMEOUT_SECONDS))
    except (OSError, TypeError, ValueError):
        configured = 120
    return started_at + timedelta(seconds=max(1, configured + 5 - 2))


def _workspace_path(metadata: Mapping[str, object]) -> Path | None:
    value = _first_string(metadata, ("workspace",))
    return Path(value) if value is not None else None


def _first_string(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
