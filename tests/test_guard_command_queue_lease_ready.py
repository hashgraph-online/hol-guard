from __future__ import annotations

import contextvars
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue, command_queue_drain, command_queue_lease_ready
from codex_plugin_scanner.guard.runtime.command_queue_lease_ready import (
    LEASE_READY_REUSE_SECONDS,
    lane_lease_ready_operations,
)
from codex_plugin_scanner.guard.runtime.command_queue_state import enter_command_queue_lane
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from tests.test_guard_command_queue import FakeStore

_READY = (EXACT_CLOUD_REVIEW_OPERATION,)


def _count_readiness_checks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    checks: list[int] = []

    def ready(_store: object) -> tuple[str, ...]:
        checks.append(1)
        return _READY

    monkeypatch.setattr(command_queue, "lease_ready_operations", ready)
    monkeypatch.setattr(command_queue, "lease_next_job", lambda **_kwargs: None)
    return checks


def _drain_lease(slot: int, store: FakeStore) -> None:
    def run() -> None:
        enter_command_queue_lane(command_queue_drain.review_drain_lane(slot))
        command_queue._lease_next_job(store, {})

    contextvars.Context().run(run)


def test_drain_leases_reuse_a_recent_readiness_check(tmp_path: Path, monkeypatch) -> None:
    checks = _count_readiness_checks(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(command_queue_lease_ready, "_clock", lambda: clock[0])
    store = FakeStore(tmp_path / "guard-home")

    command_queue._lease_next_job(store, {})
    for slot in range(3):
        _drain_lease(slot, store)
    assert len(checks) == 1

    clock[0] += LEASE_READY_REUSE_SECONDS
    _drain_lease(0, store)
    _drain_lease(1, store)
    assert len(checks) == 2


def test_main_lane_checks_readiness_before_every_lease(tmp_path: Path, monkeypatch) -> None:
    checks = _count_readiness_checks(monkeypatch)
    monkeypatch.setattr(command_queue_lease_ready, "_clock", lambda: 100.0)
    store = FakeStore(tmp_path / "guard-home")

    for _ in range(3):
        command_queue._lease_next_job(store, {})

    assert len(checks) == 3


def test_a_slow_drain_check_holds_up_only_its_own_home(tmp_path: Path) -> None:
    slow_home = FakeStore(tmp_path / "slow-home")
    other_home = FakeStore(tmp_path / "other-home")
    entered = threading.Event()
    release = threading.Event()

    def slow_check(_store: object) -> tuple[str, ...]:
        entered.set()
        assert release.wait(5)
        return _READY

    worker = threading.Thread(
        target=lane_lease_ready_operations, args=(slow_home,), kwargs={"drain": True, "check": slow_check}
    )
    worker.start()
    try:
        assert entered.wait(5)
        done = threading.Event()

        def other_leases() -> None:
            lane_lease_ready_operations(other_home, drain=True, check=lambda _store: _READY)
            lane_lease_ready_operations(slow_home, drain=False, check=lambda _store: _READY)
            done.set()

        threading.Thread(target=other_leases).start()
        assert done.wait(5)
    finally:
        release.set()
        worker.join(5)
