"""A resident replacement must use the existing bounded fresh-ACK barrier."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


def waiting_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[worker_module.HookWorker, NativePolicySnapshotPublisher]:
    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path))
    publisher.register_workspace(tmp_path)
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(worker_module, "native_mode", lambda: "auto")
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda store: publisher)
    worker = worker_module.HookWorker(store=publisher.store, wait_for_native_policy=False)
    publisher._snapshot = {"generation": 1, "policy_digest": "old", "runtime_identity": "runtime", "mode": "enforce"}
    publisher._record_error("native_policy_snapshot_resident_changed")
    assert publisher.current_snapshot_binding() is None
    return worker, publisher


def test_resident_change_waits_for_new_ack_instead_of_returning_an_unready_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker, publisher = waiting_worker(monkeypatch, tmp_path)
    admission_waiting = threading.Event()
    original_wait = publisher.wait_until_ready

    def wait(deadline: float) -> bool:
        admission_waiting.set()
        return original_wait(deadline)

    monkeypatch.setattr(publisher, "wait_until_ready", wait)

    def acknowledge_replacement() -> None:
        if admission_waiting.wait(1):
            with publisher._condition:
                snapshot = publisher._snapshot
                assert snapshot is not None
                publisher._snapshot = {**snapshot, "generation": 2, "policy_digest": "fresh"}
                publisher._acked = True
                publisher._last_error = None
                publisher._condition.notify_all()

    acknowledgement = threading.Thread(target=acknowledge_replacement)
    acknowledgement.start()
    try:
        binding = worker.prepare_workspace_policy(tmp_path, deadline=time.monotonic() + 0.5)
        assert binding is not None, "A retryable resident replacement must await its fresh ACK"
        assert binding["generation"] == 2
        assert binding["policy_digest"] == "fresh"
    finally:
        acknowledgement.join(timeout=2)
        publisher.close()
    assert not acknowledgement.is_alive()


@pytest.mark.parametrize("deadline", [None, 100.25, 99.0])
def test_resident_change_preserves_existing_deadline_and_never_admits_without_ack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, deadline: float | None
) -> None:
    worker, publisher = waiting_worker(monkeypatch, tmp_path)
    calls: list[float] = []
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: 100.0))

    def no_ack(wait_deadline: float) -> bool:
        calls.append(wait_deadline)
        return False

    monkeypatch.setattr(publisher, "wait_until_ready", no_ack)
    try:
        assert worker.prepare_workspace_policy(tmp_path, deadline=deadline) is None
        expected = 100.0 + worker_module._NATIVE_POLICY_READY_TIMEOUT_SECONDS
        assert calls == [expected if deadline is None else min(expected, deadline)]
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "error", ["native_policy_snapshot_runtime_unavailable", "native_command_control_binding_changed", "unknown_error"]
)
def test_other_publication_failures_still_reject_immediately(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: str
) -> None:
    worker, publisher = waiting_worker(monkeypatch, tmp_path)
    publisher._record_error(error)

    def must_not_wait(deadline: float) -> bool:
        pytest.fail("Only the exact retryable resident-change error may await a fresh ACK")

    monkeypatch.setattr(publisher, "wait_until_ready", must_not_wait)
    try:
        assert worker.prepare_workspace_policy(tmp_path, deadline=time.monotonic() + 0.5) is None
    finally:
        publisher.close()
