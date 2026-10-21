# pyright: reportPrivateUsage=false
"""Publisher shutdown must confirm thread exit before releasing ownership."""

from __future__ import annotations

import threading
from pathlib import Path

import codex_plugin_scanner.guard.native_policy_snapshot as snapshots
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


def test_publisher_close_retries_join_and_retains_live_thread(tmp_path: Path) -> None:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path / "guard-home"))
    entered = threading.Event()
    release = threading.Event()

    def blocked_publication() -> None:
        entered.set()
        release.wait(timeout=10)

    thread = threading.Thread(target=blocked_publication)
    publisher._thread = thread
    key = snapshots._publisher_key(publisher.guard_home)
    thread.start()
    try:
        assert entered.wait(timeout=1)
        assert publisher.close_contained(timeout_seconds=0) is False
        assert publisher.closed is True
        assert thread.is_alive()
        with snapshots._PUBLISHER_LOCK:
            assert publisher in snapshots._PUBLISHERS[key]
        assert publisher.close_contained(timeout_seconds=0) is False
    finally:
        release.set()
        assert publisher.close_contained(timeout_seconds=1) is True
        thread.join(timeout=1)
    assert not thread.is_alive()
    with snapshots._PUBLISHER_LOCK:
        assert publisher not in snapshots._PUBLISHERS.get(key, ())
    assert publisher.close_contained(timeout_seconds=0) is True
