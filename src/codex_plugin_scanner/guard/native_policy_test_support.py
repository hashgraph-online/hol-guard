"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .store import GuardStore


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    publisher.start()
    try:
        ready_wait_seconds = 25.0 if sys.platform == "win32" else 3.0
        if not publisher.wait_until_ready(time.monotonic() + ready_wait_seconds):
            raise AssertionError(f"native policy publisher was not ready: {publisher.last_error}")
        snapshot = publisher.current_snapshot()
        if snapshot is None:
            raise AssertionError("native policy publisher returned no ACKed snapshot")
        yield snapshot
    finally:
        publisher.close()
