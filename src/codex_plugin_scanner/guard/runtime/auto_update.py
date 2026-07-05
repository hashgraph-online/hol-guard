"""Auto-update check for Guard Cloud command queue daemon.

Throttled to once per AUTO_UPDATE_THROTTLE_HOURS. Only runs when the
command queue is enabled and no job was leased. Source/editable installs
are excluded by build_guard_update_status_payload's auto_updatable flag.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..cli.update_commands import build_guard_update_status_payload, run_guard_update

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore

AUTO_UPDATE_THROTTLE_HOURS = 6
AUTO_UPDATE_STATE_KEY = "guard_auto_update_state"
_LOGGER = logging.getLogger(__name__)


def maybe_auto_update(store: GuardStore, context: HarnessContext) -> None:
    """Check for available updates and self-apply if auto-update is enabled."""
    raw = store.get_sync_payload(AUTO_UPDATE_STATE_KEY)
    try:
        state: dict[str, object] = dict(raw) if isinstance(raw, dict) else {}
    except (TypeError, ValueError):
        state = {}
    last_check = state.get("last_check_at")
    if isinstance(last_check, str):
        try:
            last_dt = datetime.fromisoformat(last_check)
            elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
            if elapsed < AUTO_UPDATE_THROTTLE_HOURS * 3600:
                return
        except (ValueError, TypeError):
            pass
    now_str = datetime.now(timezone.utc).isoformat()
    try:
        status = build_guard_update_status_payload()
    except Exception:
        _LOGGER.debug("Auto-update version check failed", exc_info=True)
        state["last_check_at"] = now_str
        state["last_check_error"] = True
        store.set_sync_payload(AUTO_UPDATE_STATE_KEY, state, now_str)
        return
    state["last_check_at"] = now_str
    state["last_status"] = status
    if not status.get("auto_updatable") or status.get("blocked_reason"):
        store.set_sync_payload(AUTO_UPDATE_STATE_KEY, state, now_str)
        return
    if not status.get("update_available"):
        store.set_sync_payload(AUTO_UPDATE_STATE_KEY, state, now_str)
        return
    _LOGGER.info(
        "Auto-update: applying update %s -> %s",
        status.get("current_version"),
        status.get("latest_version"),
    )
    try:
        update_payload, exit_code = run_guard_update(
            dry_run=False,
            context=context,
            store=store,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
            now=now_str,
        )
        state["last_update_result"] = update_payload
        state["last_update_exit_code"] = exit_code
        state["last_update_at"] = now_str
    except Exception:
        _LOGGER.warning("Auto-update failed", exc_info=True)
        state["last_update_error"] = True
    finally:
        store.set_sync_payload(AUTO_UPDATE_STATE_KEY, state, now_str)
