from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_url
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime_artifact_reconciliation import RuntimeArtifactReconciliation
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_serve_publishes_listen_state_before_artifact_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    configured_home = tmp_path / "configured-home"
    reconcile_started = threading.Event()
    release_reconcile = threading.Event()

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        assert home_dir == configured_home
        reconcile_started.set()
        assert release_reconcile.wait(timeout=8)
        return RuntimeArtifactReconciliation(
            refreshed_launchers=("codex",),
            repaired_harnesses=("codex",),
            repaired_package_managers=("npm",),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        home_dir=configured_home,
        idle_timeout_seconds=0,
    )
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)

    worker = threading.Thread(target=daemon.serve, name="guard-daemon-serve-test", daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 8
        url = None
        while time.monotonic() < deadline:
            url = load_guard_daemon_url(store.guard_home)
            if url:
                break
            time.sleep(0.05)
        assert url is not None
        assert reconcile_started.wait(timeout=8)
        assert release_reconcile.is_set() is False
        records = [
            json.loads(line)
            for line in (store.guard_home / "logs" / "daemon.log").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        events = [record["event"] for record in records]
        assert "daemon_listen_ready" in events
        assert "runtime_artifact_reconciliation_completed" not in events
        refresh = daemon.refresh_command_queue_worker()
        assert refresh["running"] is False
        assert refresh["sync_running"] is False
    finally:
        release_reconcile.set()
        daemon.stop()
        worker.join(timeout=8)
        assert worker.is_alive() is False


def test_serve_stop_during_reconcile_does_not_leave_background_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    reconcile_started = threading.Event()
    release_reconcile = threading.Event()

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        del home_dir
        reconcile_started.set()
        assert release_reconcile.wait(timeout=8)
        return RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)

    worker = threading.Thread(target=daemon.serve, name="guard-daemon-stop-during-reconcile", daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if load_guard_daemon_url(store.guard_home):
                break
            time.sleep(0.05)
        assert reconcile_started.wait(timeout=8)
        daemon.stop()
        assert daemon._command_queue_worker is None
        assert daemon._server.hook_process_runner.stats()["workers"] == 0
    finally:
        release_reconcile.set()
        daemon.stop()
        worker.join(timeout=8)
        assert worker.is_alive() is False
        assert daemon._command_queue_worker is None
        assert daemon._owner_lock is None


def test_post_listen_startup_aborts_on_stale_generation_before_workers(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon._lifecycle_generation = 2
    daemon._active_start_generation = 1

    with pytest.raises(RuntimeError, match="stopped during startup"):
        daemon._complete_owned_service_after_listen(1, already_locked=True)

    assert daemon._owned_service_ready is False
    assert daemon._command_queue_worker is None


def test_post_listen_startup_aborts_when_generation_changes_during_reconcile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon._lifecycle_generation = 1
    daemon._active_start_generation = 1
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        del home_dir
        daemon._lifecycle_generation += 1
        return RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)

    with pytest.raises(RuntimeError, match="stopped during startup"):
        daemon._complete_owned_service_after_listen(1, already_locked=True)

    assert daemon._owned_service_ready is False
    assert daemon._command_queue_worker is None


def test_post_listen_startup_aborts_when_generation_changes_during_activity_maintenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon._lifecycle_generation = 1
    daemon._active_start_generation = 1
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)
    monkeypatch.setattr(
        daemon_server_module,
        "reconcile_runtime_artifacts",
        lambda _store, *, home_dir=None: RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        ),
    )

    def maintain() -> None:
        daemon._lifecycle_generation += 1

    monkeypatch.setattr(daemon, "_maintain_command_activity_best_effort", maintain)

    with pytest.raises(RuntimeError, match="stopped during startup"):
        daemon._complete_owned_service_after_listen(1, already_locked=True)

    assert daemon._owned_service_ready is False
    assert daemon._command_queue_worker is None


def test_post_listen_startup_aborts_when_generation_changes_before_background_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon._lifecycle_generation = 1
    daemon._active_start_generation = 1
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)
    monkeypatch.setattr(
        daemon_server_module,
        "reconcile_runtime_artifacts",
        lambda _store, *, home_dir=None: RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        ),
    )
    monkeypatch.setattr(daemon, "_maintain_command_activity_best_effort", lambda: None)

    def persist() -> None:
        daemon._lifecycle_generation += 1

    monkeypatch.setattr(daemon, "_persist_aibom_inventory_context", persist)

    with pytest.raises(RuntimeError, match="stopped during startup"):
        daemon._complete_owned_service_after_listen(1, already_locked=True)

    assert daemon._owned_service_ready is False
    assert daemon._command_queue_worker is None


def test_command_queue_refresh_stays_idle_until_owned_service_is_ready(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
    )
    assert daemon._owned_service_ready is False
    result = daemon.refresh_command_queue_worker()
    assert result["running"] is False
    assert result["sync_running"] is False


def test_command_queue_refresh_stays_idle_after_shutdown_starts(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
    )
    daemon._owned_service_ready = True
    daemon._shutdown_started.set()
    result = daemon.refresh_command_queue_worker()
    assert result["running"] is False
    assert result["sync_running"] is False


def test_begin_owned_service_defers_hook_workers_only_when_publishing_before_listen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home", prime_policy_integrity=False),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon._lifecycle_generation = 1
    daemon._active_start_generation = 1
    seen: list[bool] = []

    def capture_start(*, defer_backfill: bool = False) -> None:
        seen.append(defer_backfill)
        raise RuntimeError("stop-after-start-flag")

    monkeypatch.setattr(daemon._server.hook_process_runner, "start", capture_start)

    with pytest.raises(RuntimeError, match="stop-after-start-flag"):
        daemon._begin_owned_service(1, publish_before_workers=False)
    with pytest.raises(RuntimeError, match="stop-after-start-flag"):
        daemon._begin_owned_service(1, publish_before_workers=True)

    assert seen == [False, True]


def test_desktop_owned_core_executable_prefers_runtime_owner(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.dashboard_launcher import _desktop_owned_core_executable

    owner = tmp_path / "hol-guard"
    owner.write_text("#!/bin/sh\n", encoding="utf-8")
    owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(owner))
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    assert _desktop_owned_core_executable() == owner.resolve()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows files do not use POSIX execute bits")
def test_desktop_owned_core_executable_ignores_non_executable_owner(
    monkeypatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.dashboard_launcher import _desktop_owned_core_executable

    owner = tmp_path / "hol-guard"
    owner.write_text("not executable\n", encoding="utf-8")
    owner.chmod(0o644)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(owner))
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    assert _desktop_owned_core_executable() is None


def test_command_queue_refresh_does_not_block_while_startup_holds_lifecycle_lock(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    assert daemon._finish_service_lock.acquire(blocking=False)
    try:
        result = daemon.refresh_command_queue_worker()
    finally:
        daemon._finish_service_lock.release()
    assert result["running"] is False
    assert result["sync_running"] is False


def test_serve_enables_full_capacity_on_the_caller_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)
    monkeypatch.setattr(
        daemon_server_module,
        "reconcile_runtime_artifacts",
        lambda _store, *, home_dir=None: RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        ),
    )

    def stop_after_ready() -> None:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if load_guard_daemon_url(store.guard_home) and daemon._owned_service_ready:
                break
            time.sleep(0.05)
        daemon.stop()

    stopper = threading.Thread(target=stop_after_ready, name="stop-serve-after-ready", daemon=True)
    stopper.start()
    try:
        daemon.serve()
    finally:
        daemon.stop()
        stopper.join(timeout=8)
    assert stopper.is_alive() is False
    assert daemon._owned_service_ready is False
    assert daemon._owner_lock is None
