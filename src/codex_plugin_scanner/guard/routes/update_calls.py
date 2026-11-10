"""Guard library steps the native daemon's update routes run.

The native daemon owns ``GET /v1/update/status`` and ``POST /v1/update``:
which install can update, the refusals, the Desktop hand-off and every
reply. Each call here is one library step it cannot take natively yet and
reports its outcome as data.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from ..cli.update_commands import build_guard_update_status_payload
from ..daemon.dashboard_update import (
    merge_dashboard_update_progress,
    schedule_guard_dashboard_update,
    write_desktop_update_request,
)
from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)


def status(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The install's update status, with a running update's progress when asked."""

    payload = build_guard_update_status_payload(guard_home=store.guard_home)
    if args.get("progress") is True:
        return merge_dashboard_update_progress(store.guard_home, payload)
    return payload


def handoff(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Records the dashboard's request for Desktop to open its updater."""

    try:
        write_desktop_update_request(store.guard_home, latest_version=str(args.get("latest_version") or ""))
    except OSError:
        _LOGGER.exception("desktop update handoff request could not be recorded")
        return {"recorded": False}
    return {"recorded": True}


def schedule(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Starts the detached update runner and returns its reply."""

    status_payload = args.get("status")
    pid = args.get("daemon_pid")
    port = args.get("port")
    return schedule_guard_dashboard_update(
        store.guard_home,
        daemon_pid=pid if isinstance(pid, int) else 0,
        daemon_port=port if isinstance(port, int) else 0,
        force_pypi_reinstall=args.get("force_pypi_reinstall") is True,
        include_alpha=args.get("include_alpha") is True,
        status_payload=dict(status_payload) if isinstance(status_payload, dict) else None,
    )


UPDATE_CALLS = {
    "update.status": status,
    "update.handoff": handoff,
    "update.schedule": schedule,
}
