"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    publisher.start()
    if not publisher.wait_until_ready(time.monotonic() + 3.0):
        raise AssertionError(f"native policy publisher was not ready: {publisher.last_error}")
    snapshot = publisher.current_snapshot()
    if snapshot is None:
        raise AssertionError("native policy publisher returned no ACKed snapshot")
    try:
        yield snapshot
    finally:
        publisher.close()
