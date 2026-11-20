"""Auto-update check for Guard Cloud command queue daemon.

Throttled to once per six hours. Only runs when the command queue is enabled
and no job was leased. Source/editable installs are excluded by
build_guard_update_status_payload's auto_updatable flag.

The native runtime owns the saved state and every decision drawn from it; this
module fetches the update status and runs the installer.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..cli.update_commands import build_guard_update_status_payload, run_guard_update
from ..native_auto_update_state import AutoUpdateStateError, native_auto_update_state

if TYPE_CHECKING:
    from ..harness_context import HarnessContext
    from ..store import GuardStore

AUTO_UPDATE_STATE_KEY = "guard_auto_update_state"
_LOGGER = logging.getLogger(__name__)


def maybe_auto_update(store: GuardStore, context: HarnessContext) -> None:
    """Check for available updates and self-apply if auto-update is enabled."""
    guard_home = Path(context.guard_home)
    now_str = datetime.now(timezone.utc).isoformat()
    try:
        begun = native_auto_update_state(guard_home, "begin", now=now_str)
    except AutoUpdateStateError:
        _LOGGER.debug("Auto-update state unavailable", exc_info=True)
        return
    if not isinstance(begun, dict) or begun.get("due") is not True:
        return
    status: dict[str, object] | None
    try:
        status = build_guard_update_status_payload(guard_home=context.guard_home)
    except Exception:
        _LOGGER.debug("Auto-update version check failed", exc_info=True)
        status = None
    try:
        decision = native_auto_update_state(guard_home, "record_check", now=now_str, status=status)
    except AutoUpdateStateError:
        _LOGGER.debug("Auto-update state unavailable", exc_info=True)
        return
    if status is None or not isinstance(decision, dict) or decision.get("apply") is not True:
        return
    latest_version = decision.get("latest_version")
    _LOGGER.info(
        "Auto-update: applying update %s -> %s",
        status.get("current_version"),
        latest_version,
    )
    update_payload: object | None = None
    exit_code: int | None = None
    try:
        update_payload, exit_code = run_guard_update(
            dry_run=False,
            context=context,
            store=store,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
            now=now_str,
            include_alpha=status.get("release_channel") == "alpha",
        )
    except Exception:
        _LOGGER.warning("Auto-update failed", exc_info=True)
        update_payload, exit_code = None, None
    try:
        native_auto_update_state(
            guard_home,
            "record_update",
            now=now_str,
            latest_version=latest_version,
            update_payload=update_payload,
            exit_code=exit_code,
        )
    except AutoUpdateStateError:
        _LOGGER.warning("Auto-update result could not be recorded", exc_info=True)
