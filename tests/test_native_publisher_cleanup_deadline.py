"""Publisher teardown preserves unfinished ownership within one deadline."""

import threading
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshots
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def test_unfinished_publisher_stays_registered_until_recovery_close(tmp_path):
    publisher = NativePolicySnapshotPublisher(store=SimpleNamespace(guard_home=tmp_path))
    key = snapshots._publisher_key(tmp_path)
    release = threading.Event()
    owner = threading.Thread(target=lambda: release.wait(timeout=2), daemon=True)
    publisher._thread = owner
    owner.start()
    try:
        started = time.monotonic()
        assert publisher.close(deadline_monotonic=started + 0.02) is False
        assert time.monotonic() - started < 0.5
        assert publisher.closed and publisher._thread is owner
        assert publisher in snapshots._PUBLISHERS[key]
        replacement = snapshots.get_native_policy_snapshot_publisher(SimpleNamespace(guard_home=tmp_path))
        assert replacement is not publisher
        assert snapshots._PUBLISHERS[key] == {publisher, replacement}
        assert replacement.close()
    finally:
        release.set()
        owner.join(timeout=1)
        assert publisher.close(deadline_monotonic=time.monotonic() + 1)
    assert not owner.is_alive() and publisher._thread is None
    assert key not in snapshots._PUBLISHERS


@pytest.mark.parametrize("lock_name", ["condition", "registry"])
def test_close_lock_contention_does_not_renew_deadline(tmp_path, lock_name):
    publisher = NativePolicySnapshotPublisher(store=SimpleNamespace(guard_home=tmp_path))
    key = snapshots._publisher_key(tmp_path)
    acquired, release = threading.Event(), threading.Event()
    lock = publisher._condition if lock_name == "condition" else snapshots._PUBLISHER_LOCK

    def hold_lock():
        with lock:
            acquired.set()
            release.wait(timeout=2)

    owner = threading.Thread(target=hold_lock, daemon=True)
    owner.start()
    try:
        assert acquired.wait(timeout=1)
        started = time.monotonic()
        assert publisher.close(deadline_monotonic=started + 0.02) is False
        assert time.monotonic() - started < 0.5
        assert publisher in snapshots._PUBLISHERS[key]
    finally:
        release.set()
        owner.join(timeout=1)
        assert publisher.close(deadline_monotonic=time.monotonic() + 1)
    assert not owner.is_alive()
    assert key not in snapshots._PUBLISHERS
