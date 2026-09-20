"""Initial bookkeeping finishes once before periodic workers are started."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _WorkersReachedError(Exception):
    pass


class _StopAtWait(threading.Event):
    def __init__(self) -> None:
        super().__init__()
        self.waits: list[float | None] = []

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout)
        self.set()
        return True


@pytest.mark.parametrize("replaced_start", [False, True])
def test_real_initial_maintenance_commits_before_workers_and_is_not_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replaced_start: bool
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    store = GuardStore(tmp_path / "home")
    daemon = GuardDaemonServer(store, home_dir=tmp_path / "user-home")
    daemon._lifecycle_generation = 1
    daemon._active_start_generation = 1
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)
    monkeypatch.setattr(daemon, "_reconcile_runtime_artifacts_best_effort", lambda: None)
    activity = daemon._maintain_command_activity_best_effort
    storage = daemon._maintain_storage_best_effort
    counts = {"activity": 0, "storage": 0}

    def maintain_activity() -> None:
        counts["activity"] += 1
        activity()

    def maintain_storage() -> bool:
        counts["storage"] += 1
        completed = storage()
        if replaced_start:
            daemon._lifecycle_generation += 1
        return completed

    def before_workers() -> None:
        with store._connect() as connection:
            row = connection.execute("select last_run_at from guard_storage_maintenance where singleton=1").fetchone()
        assert row is not None and row["last_run_at"] is not None
        assert counts == {"activity": 1, "storage": 1}
        raise _WorkersReachedError

    monkeypatch.setattr(daemon, "_maintain_command_activity_best_effort", maintain_activity)
    monkeypatch.setattr(daemon, "_maintain_storage_best_effort", maintain_storage)
    monkeypatch.setattr(daemon, "_publish_listen_state", before_workers)
    try:
        if replaced_start:
            with pytest.raises(RuntimeError, match="stopped during startup"):
                daemon._complete_owned_service_after_listen(1, already_locked=True)
            assert counts == {"activity": 1, "storage": 1}
            assert daemon._owned_service_ready is False
            return
        with pytest.raises(_WorkersReachedError):
            daemon._complete_owned_service_after_listen(1, already_locked=True)
        stop = _StopAtWait()
        daemon._shutdown_started = stop
        with store._connect() as observer:
            before = observer.execute("pragma data_version").fetchone()[0]
            daemon._command_activity_maintenance_loop()
            after = observer.execute("pragma data_version").fetchone()[0]
        assert before == after
        assert counts == {"activity": 1, "storage": 1}
        assert stop.waits == [3_600]
        assert daemon._initial_storage_maintenance_complete is None
    finally:
        daemon.stop()


@pytest.mark.parametrize("initial_complete, expected_wait", [(True, 3_600), (False, 5)])
def test_periodic_worker_preserves_initial_result_and_existing_retry_delay(
    initial_complete: bool, expected_wait: int
) -> None:
    daemon = object.__new__(GuardDaemonServer)
    daemon._initial_storage_maintenance_complete = initial_complete
    stop = _StopAtWait()
    daemon._shutdown_started = stop
    daemon._maintain_command_activity_best_effort = lambda: pytest.fail("repeated initial activity pass")
    daemon._maintain_storage_best_effort = lambda: pytest.fail("repeated initial storage pass")
    daemon._command_activity_maintenance_loop()
    assert stop.waits == [expected_wait]
    assert daemon._initial_storage_maintenance_complete is None
