"""Threads of one process hand Guard's advisory file locks to each other at once."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore


def _hold(store: GuardStore, path: Path, *, timeout_seconds: float, poll_seconds: float):
    return store._hold_advisory_file_lock(
        path=path,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        timeout_message="lock busy",
    )


def test_a_waiting_thread_takes_the_lock_as_soon_as_it_is_released(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    path = store.guard_home / "handoff.lock"
    held = threading.Event()
    acquired_after: list[float] = []

    def waiter(released_at: list[float]) -> None:
        held.wait(5)
        # A one-second poll would only notice the release a second later.
        with _hold(store, path, timeout_seconds=5.0, poll_seconds=1.0):
            acquired_after.append(time.monotonic() - released_at[0])

    released_at = [0.0]
    thread = threading.Thread(target=waiter, args=(released_at,))
    thread.start()
    with _hold(store, path, timeout_seconds=5.0, poll_seconds=1.0):
        held.set()
        time.sleep(0.2)
        released_at[0] = time.monotonic()
    thread.join(5)

    assert len(acquired_after) == 1
    assert acquired_after[0] < 0.5


def test_a_thread_still_times_out_while_another_holds_the_lock(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    path = store.guard_home / "handoff.lock"
    held = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with _hold(store, path, timeout_seconds=5.0, poll_seconds=0.01):
            held.set()
            release.wait(5)

    thread = threading.Thread(target=holder)
    thread.start()
    held.wait(5)
    try:
        with pytest.raises(TimeoutError, match="lock busy"), _hold(store, path, timeout_seconds=0.1, poll_seconds=0.01):
            pass
    finally:
        release.set()
        thread.join(5)
    with _hold(store, path, timeout_seconds=1.0, poll_seconds=0.01):
        pass
