"""Test-only daemon worker isolation and composition coverage."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as guard_daemon_module
from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.runtime.cloud_policy_revision import (
    cloud_policy_store_key,
    observe_cloud_policy_revision,
    reset_cloud_policy_revisions,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_control_patching import patch_daemon_global


@pytest.mark.daemon_headless_refresh
def test_daemon_headless_refresh_stops_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    synced = threading.Event()

    def _fake_sync(*, store: GuardStore) -> dict[str, object]:
        assert store.guard_home == tmp_path / "guard-home"
        synced.set()
        return {"status": "synced"}

    patch_daemon_global(monkeypatch, "_run_headless_cloud_sync", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    daemon._headless_cloud_sync_interval_seconds = 0.05

    daemon.start()
    assert synced.wait(timeout=1)
    daemon.stop()

    assert daemon._headless_cloud_sync_thread is None


@pytest.mark.daemon_headless_refresh
def test_daemon_headless_refresh_syncs_at_once_when_cloud_policy_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    syncs: list[float] = []
    first_sync = threading.Event()
    second_sync = threading.Event()

    def _fake_sync(*, store: GuardStore) -> dict[str, object]:
        del store
        syncs.append(time.monotonic())
        (second_sync if first_sync.is_set() else first_sync).set()
        return {"status": "synced"}

    reset_cloud_policy_revisions()
    patch_daemon_global(monkeypatch, "_run_headless_cloud_sync", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    # Far longer than the test, so only the policy wake can start a second sync.
    daemon._headless_cloud_sync_interval_seconds = 600

    key = cloud_policy_store_key(store)
    daemon.start()
    try:
        assert first_sync.wait(timeout=5)
        # The first revision a lease reports is the baseline, and a response
        # that repeats it changes nothing.
        assert observe_cloud_policy_revision(key, {"item": None, "policyRevision": "v3@1000"}) is False
        assert observe_cloud_policy_revision(key, {"item": None, "policyRevision": "v3@1000"}) is False
        assert not second_sync.wait(timeout=0.3)

        assert observe_cloud_policy_revision(key, {"item": None, "policyRevision": "v4@2000"}) is True
        assert second_sync.wait(timeout=5)
        assert len(syncs) == 2
    finally:
        daemon.stop()
        reset_cloud_policy_revisions()

    assert daemon._headless_cloud_sync_thread is None


@pytest.mark.daemon_headless_refresh
def test_daemon_shutdown_wakes_the_sync_loop_before_joining_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    synced = threading.Event()

    def _fake_sync(*, store: GuardStore) -> dict[str, object]:
        del store
        synced.set()
        return {"status": "synced"}

    patch_daemon_global(monkeypatch, "_run_headless_cloud_sync", _fake_sync)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    daemon._headless_cloud_sync_interval_seconds = 600
    join_workers = daemon._join_service_background_threads
    woken_before_join: list[bool] = []

    def _join_after_slower_workers() -> bool:
        # Earlier workers can use the whole join deadline, so the idle sync
        # loop must already be on its way out when joining starts.
        woken_before_join.append(daemon._headless_cloud_sync_wake.is_set())
        return join_workers()

    daemon._join_service_background_threads = _join_after_slower_workers
    daemon.start()
    try:
        assert synced.wait(timeout=5)
    finally:
        daemon.stop()

    assert woken_before_join == [True]
    assert daemon._headless_cloud_sync_thread is None


@pytest.mark.daemon_aibom_refresh
@pytest.mark.daemon_bundle_refresh
@pytest.mark.daemon_headless_refresh
@pytest.mark.daemon_service_workers
def test_daemon_start_composes_all_background_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[str] = []

    def _start_command_queue(
        _store: GuardStore,
        existing: threading.Thread | None,
    ) -> threading.Thread | None:
        started.append("command-queue")
        return existing

    def _start_cloud_review_sync(
        _store: GuardStore,
        existing: threading.Thread | None,
        *,
        on_authority_changed: object = None,
    ) -> threading.Thread | None:
        started.append("cloud-review-sync")
        return existing

    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_aibom_inventory_refresh",
        lambda _self: started.append("aibom"),
    )
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_supply_chain_bundle_refresh",
        lambda _self: started.append("bundle"),
    )
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_headless_cloud_sync",
        lambda _self: started.append("headless"),
    )
    monkeypatch.setattr(
        guard_daemon_module.GuardDaemonServer,
        "_start_plugin_telemetry",
        lambda _self: started.append("plugin-telemetry"),
    )
    monkeypatch.setattr(
        guard_daemon_module,
        "start_command_queue_worker",
        _start_command_queue,
    )
    monkeypatch.setattr(
        guard_daemon_module,
        "start_cloud_sync_sync_worker",
        _start_cloud_review_sync,
    )
    daemon = guard_daemon_module.GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
    )

    daemon.start()
    try:
        assert started == ["headless", "bundle", "aibom", "plugin-telemetry", "command-queue", "cloud-review-sync"]
    finally:
        daemon.stop()


def test_unmarked_daemon_does_not_start_background_workers(tmp_path: Path) -> None:
    daemon = guard_daemon_module.GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=60,
    )

    daemon.start()
    try:
        assert daemon._headless_cloud_sync_thread is None
        assert daemon._bundle_refresh_thread is None
        assert daemon._aibom_refresh_thread is None
        assert daemon._plugin_telemetry_thread is None
        assert daemon._command_queue_worker is None
        assert daemon._cloud_review_sync_worker is None
    finally:
        daemon.stop()


@pytest.mark.daemon_headless_refresh
def test_headless_refresh_survives_a_store_outage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A store that cannot record the attempt must not end the sync loop.

    An install that has not signed in reaches the not-logged-in path, which
    records that outcome through the same native store. When the store is
    unavailable the recording raises, and before this the loop thread died, so
    the daemon never synced again even once the user signed in.
    """

    store = GuardStore(tmp_path / "guard-home")
    attempts: list[int] = []
    synced = threading.Event()

    def _failing_then_synced(*, store: GuardStore) -> dict[str, object]:
        attempts.append(len(attempts))
        if len(attempts) <= 2:
            raise NativeGuardStoreUnavailable(
                "Guard store native runtime unavailable (native_guard_store_unavailable)."
            )
        synced.set()
        return {"status": "synced"}

    patch_daemon_global(monkeypatch, "_run_headless_cloud_sync", _failing_then_synced)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    daemon._headless_cloud_sync_interval_seconds = 0.05
    daemon._headless_cloud_sync_backoff_seconds = 0.05

    daemon.start()
    try:
        assert synced.wait(timeout=5)
        assert len(attempts) >= 3
        assert daemon._headless_cloud_sync_thread is not None
        assert daemon._headless_cloud_sync_thread.is_alive()
    finally:
        daemon.stop()


@pytest.mark.daemon_headless_refresh
def test_headless_refresh_keeps_the_traceback_of_an_unexpected_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    attempts: list[int] = []
    synced = threading.Event()

    def _failing_then_synced(*, store: GuardStore) -> dict[str, object]:
        del store
        attempts.append(len(attempts))
        if len(attempts) == 1:
            raise RuntimeError("summary persistence failed")
        synced.set()
        return {"status": "synced"}

    patch_daemon_global(monkeypatch, "_run_headless_cloud_sync", _failing_then_synced)
    daemon = guard_daemon_module.GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60)
    daemon._headless_cloud_sync_interval_seconds = 0.05
    daemon._headless_cloud_sync_backoff_seconds = 0.05

    with caplog.at_level(logging.WARNING, logger="codex_plugin_scanner.guard.daemon.server"):
        daemon.start()
        try:
            assert synced.wait(timeout=5)
        finally:
            daemon.stop()

    unexpected = [record for record in caplog.records if "summary persistence failed" in record.message]
    assert unexpected
    assert unexpected[0].exc_info is not None
    assert unexpected[0].exc_info[0] is RuntimeError
