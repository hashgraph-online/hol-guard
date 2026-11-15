"""When the installed daemon became ready, measured against the install that started it.

A first hook that times out says the daemon was not ready, not why. The daemon
journals each lifecycle step under ``<guard home>/daemon-lifecycle/`` as one
small JSON file holding an event label and a nanosecond timestamp. This module
reads those back as offsets from the moment ``install`` returned, so the
evidence shows how long a cold start took on the lane's host and which step it
spent the time in.

Only event and reason labels and the offsets are kept. Pids, ports and session
identifiers stay out of the evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

LIFECYCLE_DIRECTORY = "daemon-lifecycle"
_MAX_EVENT_BYTES = 2048
_MAX_EVENTS = 128


def _offset_ms(recorded_at_ns: int, since_ns: int) -> float:
    return round((recorded_at_ns - since_ns) / 1_000_000, 1)


def startup_timeline(guard_home: Path, *, since_ns: int, not_before_ns: int | None = None) -> dict[str, Any]:
    """Lifecycle events recorded in ``guard_home``, as offsets from ``since_ns``.

    Events recorded before ``not_before_ns`` belong to an earlier run that left
    its journal in a reused home, so they are skipped. Pass the moment ``install``
    started: the daemon it starts can report ready before ``install`` returns, so
    ``since_ns`` itself is too late a cut-off.

    ``ready_ms`` is the offset of the first ``ready`` event, or ``None`` when the
    daemon never reported ready while the lane ran.
    """

    directory = guard_home / LIFECYCLE_DIRECTORY
    events: list[dict[str, Any]] = []
    if directory.is_dir() and not directory.is_symlink():
        for path in sorted(directory.glob("*.json"))[:_MAX_EVENTS]:
            try:
                if path.is_symlink() or path.stat().st_size > _MAX_EVENT_BYTES:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            event = payload.get("event")
            recorded = payload.get("recorded_at_ns")
            if not isinstance(event, str) or type(recorded) is not int:
                continue
            if not_before_ns is not None and recorded < not_before_ns:
                continue
            entry: dict[str, Any] = {"event": event, "ms_after_install": _offset_ms(recorded, since_ns)}
            reason = payload.get("reason")
            if isinstance(reason, str):
                entry["reason"] = reason
            events.append(entry)
    events.sort(key=lambda entry: entry["ms_after_install"])
    ready = next((entry["ms_after_install"] for entry in events if entry["event"] == "ready"), None)
    return {"events": events, "ready_ms": ready}
