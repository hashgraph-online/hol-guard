"""Wait for an updated Desktop Core daemon that is still starting."""

from __future__ import annotations

import time
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..daemon.live_identity import verified_live_guard_daemon_identity

CORE_START_WAIT_SECONDS = 60.0
CORE_START_POLL_SECONDS = 0.5


def wait_for_started_core(guard_home: Path, *, minimum_version: str) -> str | None:
    """Return the daemon URL once a live daemon serves at least ``minimum_version``.

    The launch that raised the still-starting signal keeps running, so a slow
    machine only needs more time. A daemon older than the Core that was started
    never counts, because it is not the update the caller just applied.
    """

    deadline = time.monotonic() + CORE_START_WAIT_SECONDS
    while True:
        url = live_core_url(verified_live_guard_daemon_identity(guard_home), minimum_version=minimum_version)
        if url is not None:
            return url
        if time.monotonic() >= deadline:
            return None
        time.sleep(CORE_START_POLL_SECONDS)


def live_core_url(identity: dict[str, object] | None, *, minimum_version: str) -> str | None:
    if identity is None:
        return None
    url = identity.get("daemon_url")
    if not isinstance(url, str) or not url:
        return None
    try:
        serves_update = Version(str(identity.get("package_version"))) >= Version(minimum_version)
    except InvalidVersion:
        return None
    return url if serves_update else None
